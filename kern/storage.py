# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.storage
------------

SQLite-backed persistence for blocks and the latest state snapshot.

The schema is deliberately simple:

    blocks(level INTEGER PRIMARY KEY, hash TEXT UNIQUE, json TEXT)
    state(key TEXT PRIMARY KEY, json TEXT)
    mempool(hash TEXT PRIMARY KEY, json TEXT, received_at INTEGER)

State snapshots are stored as a single JSON blob keyed by "head". A
production node would maintain incremental state diffs and a state trie
with proof generation; this is sufficient for the reference node.
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
    received_at INTEGER NOT NULL
);
"""


class Storage:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, "kern.sqlite")
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)

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

    def add_to_mempool(self, tx: Transaction) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO mempool(hash, json, received_at) VALUES (?, ?, ?)",
            (tx.hash_hex(), json.dumps(tx.to_dict()), int(time.time())),
        )

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
