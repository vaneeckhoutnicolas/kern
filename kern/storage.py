# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.storage
------------

SQLite-backed persistence for blocks and the latest state snapshot.

The schema is deliberately simple:

    blocks(level INTEGER PRIMARY KEY, hash TEXT UNIQUE, json TEXT)
    state(key TEXT PRIMARY KEY, json TEXT)
    mempool(hash TEXT PRIMARY KEY, json TEXT, received_at INTEGER, sender TEXT)

State snapshots are stored as a single JSON blob keyed by "head". A
production node would maintain incremental state diffs and a state trie
with proof generation; this is sufficient for the reference node.

The mempool is bounded. ``add_to_mempool`` enforces both a global size
cap and a per-sender cap so that a single sender cannot exhaust node
memory by flooding cheap, never-includable transactions. Both the RPC
injection path and the P2P gossip path go through ``add_to_mempool``, so
the caps protect every intake route. See ``docs/mempool-rpc-hardening.md``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator, List, Optional

from .block import Block
from .transaction import Transaction


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
    sender TEXT NOT NULL DEFAULT ''
);
"""

# Default mempool bounds. A single sender cannot hold more than
# MAX_MEMPOOL_PER_SENDER pending transactions, and the mempool as a whole
# cannot exceed MAX_MEMPOOL_SIZE entries. These are deliberately generous
# for a reference node and can be tuned per deployment via the Storage
# constructor.
MAX_MEMPOOL_SIZE = 50_000
MAX_MEMPOOL_PER_SENDER = 256


class Storage:
    def __init__(
        self,
        data_dir: str,
        max_mempool_size: int = MAX_MEMPOOL_SIZE,
        max_mempool_per_sender: int = MAX_MEMPOOL_PER_SENDER,
    ):
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, "kern.sqlite")
        self.max_mempool_size = max_mempool_size
        self.max_mempool_per_sender = max_mempool_per_sender
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        # Migration: older databases created before mempool bounds lack the
        # `sender` column. Add it idempotently; SQLite has no
        # "ADD COLUMN IF NOT EXISTS", so we swallow the duplicate-column error.
        try:
            self.conn.execute(
                "ALTER TABLE mempool ADD COLUMN sender TEXT NOT NULL DEFAULT ''"
            )
        except sqlite3.OperationalError:
            pass  # column already present

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

    def save_state(self, state: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO state(key, json) VALUES ('head', ?)",
            (json.dumps(state),),
        )

    def load_state(self) -> Optional[dict]:
        row = self.conn.execute("SELECT json FROM state WHERE key = 'head'").fetchone()
        if not row:
            return None
        return json.loads(row[0])

    # --- Mempool -------------------------------------------------------------

    def add_to_mempool(self, tx: Transaction) -> bool:
        """Admit ``tx`` to the mempool, subject to size caps.

        Returns ``True`` if the transaction was admitted (or was already
        present and thus re-inserted), ``False`` if it was rejected because a
        cap was reached. Re-inserting a transaction already in the mempool
        (same hash) never counts against the caps, so honest resubmission is
        always allowed.
        """
        h = tx.hash_hex()
        already_present = (
            self.conn.execute(
                "SELECT 1 FROM mempool WHERE hash = ?", (h,)
            ).fetchone()
            is not None
        )
        if not already_present:
            if self.mempool_size() >= self.max_mempool_size:
                return False
            if self._mempool_count_for_sender(tx.sender) >= self.max_mempool_per_sender:
                return False
        self.conn.execute(
            "INSERT OR REPLACE INTO mempool(hash, json, received_at, sender) "
            "VALUES (?, ?, ?, ?)",
            (h, json.dumps(tx.to_dict()), int(time.time()), tx.sender),
        )
        return True

    def _mempool_count_for_sender(self, sender: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM mempool WHERE sender = ?", (sender,)
        ).fetchone()
        return row[0] if row else 0

    def drain_mempool(self, max_n: int = 1000) -> List[Transaction]:
        rows = self.conn.execute(
            "SELECT json FROM mempool ORDER BY received_at LIMIT ?", (max_n,)
        ).fetchall()
        txs = [Transaction.from_dict(json.loads(r[0])) for r in rows]
        return txs

    def remove_from_mempool(self, hashes: List[str]) -> None:
        if not hashes:
            return
        qmarks = ",".join("?" for _ in hashes)
        self.conn.execute(f"DELETE FROM mempool WHERE hash IN ({qmarks})", hashes)

    def mempool_size(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM mempool").fetchone()
        return row[0] if row else 0
