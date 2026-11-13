# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.storage
------------

SQLite-backed persistence for blocks and the latest state snapshot.

The schema is deliberately simple:

    blocks(level INTEGER PRIMARY KEY, hash TEXT UNIQUE, json TEXT)
    state(key TEXT PRIMARY KEY, json TEXT)
    mempool(hash TEXT PRIMARY KEY, json TEXT, received_at INTEGER, sender TEXT,
            nonce INTEGER, fee INTEGER, size INTEGER)

State snapshots are stored as a single JSON blob keyed by "head",
alongside the level it was taken at ("head_level"). Snapshots are
periodic, not per-block: `maybe_save_state` persists every
`snapshot_interval` blocks (default 16) and the node writes a final
snapshot on clean shutdown. On startup the node loads the latest
snapshot and deterministically replays the stored blocks above it
(see kern.node.load_chain), so crash recovery costs at most
`snapshot_interval` block applications. This bounds the per-block
persistence cost, which previously serialized the full state every
block — O(state) per block. A trie-backed store with incremental
node flushing remains the production design.

The mempool is bounded. ``add_to_mempool`` enforces both a global size
cap and a per-sender cap so that a single sender cannot exhaust node
memory by flooding cheap, never-includable transactions. Both the RPC
injection path and the P2P gossip path go through ``add_to_mempool``, so
the caps protect every intake route. See ``docs/mempool-rpc-hardening.md``.

Each row of the mempool also carries the nonce, the fee and the size of its
transaction. A proposer reads these rows, oldest first, to decide what its
block takes (``waiting``), and decodes only the transactions it takes.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from functools import partial
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import nesting
from .block import Block
from .transaction import Transaction, Waiting


_SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    level INTEGER PRIMARY KEY,
    hash  TEXT NOT NULL UNIQUE,
    json  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    json  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mempool (
    hash  TEXT PRIMARY KEY,
    json  TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    sender TEXT NOT NULL DEFAULT '',
    nonce INTEGER NOT NULL DEFAULT 0,
    fee   INTEGER NOT NULL DEFAULT 0,
    size  INTEGER NOT NULL DEFAULT 0
);
"""

# Default mempool bounds. A single sender cannot hold more than
# MAX_MEMPOOL_PER_SENDER pending transactions, and the mempool as a whole
# cannot exceed MAX_MEMPOOL_SIZE entries. These are deliberately generous
# for a reference node and can be tuned per deployment via the Storage
# constructor.
MAX_MEMPOOL_SIZE = 50_000
MAX_MEMPOOL_PER_SENDER = 256
# What a node answers when one of the two caps is reached: the only refusal
# that says nothing against the transaction, which may come again later.
MEMPOOL_FULL = "mempool full or per-sender limit reached"

# The columns added to the mempool since its first form, in the order they
# came. SQLite has no "ADD COLUMN IF NOT EXISTS": each is added to a database
# that lacks it. A size of zero marks a row written before the column
# existed; no transaction is zero bytes.
_MEMPOOL_COLUMNS = (
    ("sender", "TEXT NOT NULL DEFAULT ''"),
    ("nonce", "INTEGER NOT NULL DEFAULT 0"),
    ("fee", "INTEGER NOT NULL DEFAULT 0"),
    ("size", "INTEGER NOT NULL DEFAULT 0"),
)
_MEMPOOL_INDEXES = """
CREATE INDEX IF NOT EXISTS mempool_arrival ON mempool(received_at);
CREATE INDEX IF NOT EXISTS mempool_sender ON mempool(sender);
"""
_SQLITE_INTEGER_MAX = 2**63 - 1


class Storage:
    def __init__(
        self,
        data_dir: str,
        max_mempool_size: int = MAX_MEMPOOL_SIZE,
        max_mempool_per_sender: int = MAX_MEMPOOL_PER_SENDER,
        snapshot_interval: int = 16,
    ):
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, "kern.sqlite")
        self.max_mempool_size = max_mempool_size
        self.max_mempool_per_sender = max_mempool_per_sender
        self.snapshot_interval = max(1, snapshot_interval)
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        self._migrate_mempool()

    def _migrate_mempool(self) -> None:
        """Bring the mempool of an older database to the present columns,
        and describe the rows that were written without them."""
        present = {row[1] for row in self.conn.execute("PRAGMA table_info(mempool)")}
        for name, definition in _MEMPOOL_COLUMNS:
            if name not in present:
                self.conn.execute(f"ALTER TABLE mempool ADD COLUMN {name} {definition}")
        self.conn.executescript(_MEMPOOL_INDEXES)
        for h, blob in self.conn.execute("SELECT hash, json FROM mempool WHERE size = 0").fetchall():
            try:
                tx = self._read_row(blob)
                if max(tx.nonce, tx.fee) > _SQLITE_INTEGER_MAX:
                    raise ValueError("a nonce or a fee no row can hold")
            except ValueError:
                # Not JSON, not a transaction, or nested without end: nothing a block could take.
                self.conn.execute("DELETE FROM mempool WHERE hash = ?", (h,))
                continue
            self.conn.execute("UPDATE mempool SET sender = ?, nonce = ?, fee = ?, size = ? WHERE hash = ?",
                              (tx.sender, tx.nonce, tx.fee, tx.encoded_size(), h))

    @staticmethod
    def _read_row(text: str) -> Transaction:
        """The transaction a row holds. Raises ValueError when the text is
        not JSON, is not a transaction, or nests deeper than any frame: the
        depth is measured before anything is decoded (kern.nesting), as for
        what comes from a peer, since decoding a text nested without end
        can take the process down."""
        return Transaction.from_dict(nesting.decode(text.encode("utf-8")))

    def close(self) -> None:
        self.conn.close()

    # --- Blocks --------------------------------------------------------------

    def save_block(self, block: Block) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO blocks(level, hash, json) VALUES (?, ?, ?)",
            (block.header.level, block.hash_hex(), json.dumps(block.to_dict())),
        )

    def get_block_by_level(self, level: int) -> Optional[Block]:
        row = self.conn.execute(
            "SELECT json FROM blocks WHERE level = ?", (level,)
        ).fetchone()
        if not row:
            return None
        return Block.from_dict(json.loads(row[0]))

    def get_block_by_hash(self, h: str) -> Optional[Block]:
        row = self.conn.execute(
            "SELECT json FROM blocks WHERE hash = ?", (h,)
        ).fetchone()
        if not row:
            return None
        return Block.from_dict(json.loads(row[0]))

    def head_level(self) -> int:
        row = self.conn.execute("SELECT MAX(level) FROM blocks").fetchone()
        return row[0] if row and row[0] is not None else -1

    def iter_blocks(self) -> Iterator[Block]:
        for row in self.conn.execute("SELECT json FROM blocks ORDER BY level"):
            yield Block.from_dict(json.loads(row[0]))

    # --- State ---------------------------------------------------------------

    def save_state(self, state: dict, level: int = -1) -> None:
        """Persist a full state snapshot, tagged with the level it was
        taken at (-1 = unknown/legacy)."""
        self.conn.execute(
            "INSERT OR REPLACE INTO state(key, json) VALUES ('head', ?)",
            (json.dumps(state),),
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO state(key, json) VALUES ('head_level', ?)",
            (json.dumps(level),),
        )

    def maybe_save_state(self, state: dict, level: int) -> bool:
        """Persist a snapshot only every `snapshot_interval` blocks.
        Returns True if a snapshot was written. The caller is expected to
        also call save_state unconditionally on clean shutdown."""
        if level % self.snapshot_interval == 0:
            self.save_state(state, level)
            return True
        return False

    def load_state(self) -> Optional[dict]:
        row = self.conn.execute("SELECT json FROM state WHERE key = 'head'").fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def load_state_level(self) -> int:
        """Level at which the persisted snapshot was taken, or -1 if the
        snapshot predates leveled snapshots (legacy databases: treat the
        snapshot as the head state, which is what those nodes wrote)."""
        row = self.conn.execute(
            "SELECT json FROM state WHERE key = 'head_level'"
        ).fetchone()
        if not row:
            return -1
        return int(json.loads(row[0]))

    # --- Mempool -------------------------------------------------------------

    def add_to_mempool(self, tx: Transaction) -> bool:
        """Admit ``tx`` to the mempool, subject to size caps.

        Returns ``True`` if the transaction was admitted, or was already
        present, ``False`` if it was rejected because a cap was reached. A
        transaction that is already in the mempool keeps its row and its
        place: it never counts against the caps, so honest resubmission is
        always allowed, and it does not send the transaction behind those
        that came after it.

        A nonce or a fee beyond 2^63 - 1 is refused: no account reaches that
        nonce nor holds that fee, and no row can hold the number.
        """
        if not self.has_a_row_for(tx):
            return False
        h = tx.hash_hex()
        if self.holds(h):
            return True
        if self.mempool_size() >= self.max_mempool_size:
            return False
        if self._mempool_count_for_sender(tx.sender) >= self.max_mempool_per_sender:
            return False
        self.conn.execute(
            "INSERT INTO mempool(hash, json, received_at, sender, nonce, fee, size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (h, json.dumps(tx.to_dict()), int(time.time()), tx.sender, tx.nonce, tx.fee, tx.encoded_size()),
        )
        return True

    @staticmethod
    def has_a_row_for(tx: Transaction) -> bool:
        """Whether the nonce and the fee of `tx` are numbers a row can hold."""
        return max(tx.nonce, tx.fee) <= _SQLITE_INTEGER_MAX

    def holds(self, tx_hash: str) -> bool:
        """Whether a transaction waits under this identifier."""
        return self.conn.execute("SELECT 1 FROM mempool WHERE hash = ?", (tx_hash,)).fetchone() is not None

    def _mempool_count_for_sender(self, sender: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM mempool WHERE sender = ?", (sender,)
        ).fetchone()
        return row[0] if row else 0

    def waiting_of(self, sender: str, nonce: Optional[int] = None) -> List[Waiting]:
        """The transactions of `sender` that wait here, oldest first, as
        rows; with `nonce`, those that hold this nonce."""
        query = "SELECT hash, sender, nonce, fee, size FROM mempool WHERE sender = ?"
        values: Tuple[Any, ...] = (sender,)
        if nonce is not None:
            query, values = query + " AND nonce = ?", (sender, nonce)
        rows = self.conn.execute(query + " ORDER BY received_at, rowid", values).fetchall()
        return [Waiting(h, who, at, fee, size, partial(self.get_from_mempool, h)) for h, who, at, fee, size in rows]

    def waiting_fees(self, sender: str) -> int:
        """What the transactions of `sender` that wait here will pay in
        fees, in all."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(fee), 0) FROM mempool WHERE sender = ?", (sender,)
        ).fetchone()
        return int(row[0])

    def next_free_nonce(self, sender: str, account_nonce: int) -> int:
        """The first nonce, from that of the account, that no transaction
        of `sender` waiting here has taken: the one its next transaction
        can use without leaving a gap behind it."""
        taken = {row[0] for row in self.conn.execute(
            "SELECT nonce FROM mempool WHERE sender = ? AND nonce >= ?", (sender, account_nonce))}
        nonce = account_nonce
        while nonce in taken:
            nonce += 1
        return nonce

    def drain_mempool(self, max_n: int = 1000) -> List[Transaction]:
        """The `max_n` oldest transactions, decoded. Arrival is recorded to
        the second; within a second, the order is that of insertion."""
        rows = self.conn.execute(
            "SELECT json FROM mempool ORDER BY received_at, rowid LIMIT ?", (max_n,)
        ).fetchall()
        txs = [Transaction.from_dict(json.loads(r[0])) for r in rows]
        return txs

    def waiting(self, page: int = 2_000) -> Iterator[Waiting]:
        """Everything that waits, oldest first, as rows: sender, nonce, fee
        and size, without the text of the transaction, which `transaction()`
        reads when a proposer takes it. Read a page at a time, so that a
        proposer whose block is full stops reading."""
        last = (-1, -1)
        while True:
            rows = self.conn.execute(
                "SELECT received_at, rowid, hash, sender, nonce, fee, size FROM mempool "
                "WHERE (received_at, rowid) > (?, ?) ORDER BY received_at, rowid LIMIT ?",
                (last[0], last[1], page),
            ).fetchall()
            for _at, _row, h, sender, nonce, fee, size in rows:
                yield Waiting(h, sender, nonce, fee, size, partial(self.get_from_mempool, h))
            if len(rows) < page:
                return
            last = (rows[-1][0], rows[-1][1])

    def get_from_mempool(self, tx_hash: str) -> Optional[Transaction]:
        """The transaction that waits under this identifier, or None when
        there is none or when its text can no longer be read."""
        row = self.conn.execute("SELECT json FROM mempool WHERE hash = ?", (tx_hash,)).fetchone()
        if row is None:
            return None
        try:
            return self._read_row(row[0])
        except ValueError:
            return None

    def remove_from_mempool(self, hashes: List[str]) -> int:
        """Remove the transactions that wait under these identifiers.
        Returns how many of them were there."""
        # A statement takes a limited number of values: a block of thousands
        # of transactions is removed a few hundred at a time.
        removed = 0
        for start in range(0, len(hashes), 500):
            some = hashes[start:start + 500]
            qmarks = ",".join("?" for _ in some)
            removed += self.conn.execute(f"DELETE FROM mempool WHERE hash IN ({qmarks})", some).rowcount
        return removed

    def remove_consumed(self, accounts: Dict[str, int]) -> None:
        """Remove, for each sender, what waits under a nonce below the one
        its account is at: no block can take it any more."""
        self.conn.executemany("DELETE FROM mempool WHERE sender = ? AND nonce < ?", list(accounts.items()))

    def mempool_size(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM mempool").fetchone()
        return row[0] if row else 0
