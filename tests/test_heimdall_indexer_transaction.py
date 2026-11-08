# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Heimdall indexed a single block and then stopped.

Found by the first real multi-node devnet in Docker (scripts/devnet.py):
the chain was at level 35, Heimdall held one block (level 6) and logged
"cannot commit - no transaction is active" for every later block.

`set_meta` wrapped its write in `with conn:`, which commits the open
transaction. The indexer calls it inside `transaction(conn)` to move its
cursor, so the block was committed half way, the indexer's own COMMIT then
failed, its ROLLBACK failed too, and the error stopped every later block.
It also broke atomicity: the cursor could move without the block's
transactions.

The same run showed a second fault: the node's /chain/block/{level}
returns {"header": {...}, "transactions": [...], ...} with no block hash,
while the indexer read "hash", "timestamp", "parent_hash" and "baker" at
the top level. Every block was stored with an empty hash, no parent, no
proposer and the indexing time. The node now adds "hash" to its block
responses, and the indexer reads the header.

Every test in this file fails on 7c437aa."""

import asyncio
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern_explorer.db import get_meta, init_schema, open_db, set_meta, transaction
from kern_explorer.indexer import Indexer

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture
def conn(tmp_path):
    c = open_db(tmp_path / "heimdall.sqlite")
    init_schema(c)
    yield c
    c.close()


def test_set_meta_inside_a_transaction_does_not_end_it(conn):
    with transaction(conn):
        conn.execute("INSERT INTO blocks(level, hash, parent_hash, timestamp, baker, tx_count, "
                     "indexed_at) VALUES(1, 'h1', 'h0', 0, NULL, 0, 0)")
        set_meta(conn, "indexer.cursor", "1")
        assert conn.in_transaction
    assert get_meta(conn, "indexer.cursor") == "1"


def test_a_failed_block_rolls_back_the_cursor_too(conn):
    set_meta(conn, "indexer.cursor", "0")              # outside a transaction: committed
    with pytest.raises(RuntimeError):
        with transaction(conn):
            set_meta(conn, "indexer.cursor", "1")
            raise RuntimeError("block failed half way")
    assert get_meta(conn, "indexer.cursor") == "0"


class _Rpc:
    """Three blocks, in the format of the node's /chain/block/{level}."""

    def __init__(self):
        self.blocks = {lvl: {"hash": f"{lvl:064x}",
                             "header": {"level": lvl, "payload_round": 0,
                                        "timestamp": 1_700_000_000 + lvl,
                                        "parent_hash": f"{lvl - 1:064x}",
                                        "proposer": "kn1Proposer", "proposer_pubkey": "kpk",
                                        "state_root": "00" * 32, "txs_root": "00" * 32,
                                        "signature": "ksig"},
                             "transactions": [], "commits": [], "endorsements": [],
                             "cert_round": 0}
                       for lvl in range(1, 4)}

    async def block(self, level):
        return self.blocks[level]


def test_the_indexer_indexes_consecutive_blocks(conn):
    idx = Indexer.__new__(Indexer)
    rpc = _Rpc()

    async def go():
        for level in (1, 2, 3):
            await idx._index_block(conn, rpc, level)

    asyncio.run(go())
    assert [r[0] for r in conn.execute("SELECT level FROM blocks ORDER BY level")] == [1, 2, 3]
    assert get_meta(conn, "indexer.cursor") == "3"
    row = conn.execute("SELECT hash, parent_hash, timestamp, baker FROM blocks "
                       "WHERE level = 2").fetchone()
    assert tuple(row) == (f"{2:064x}", f"{1:064x}", 1_700_000_002, "kn1Proposer")


def test_the_node_block_response_carries_its_hash(tmp_path):
    """The RPC adds the header hash to a block, which Block.from_dict
    ignores, so the response still decodes to the same block."""
    from aiohttp.test_utils import TestClient, TestServer
    from kern.block import Block
    from kern.rpc import build_app
    from test_phase_e_invalid_first_proposal import _chain, _keys

    chain = _chain(_keys())

    class _Storage:
        def get_block_by_level(self, level):
            return chain.head if level == 0 else None

        def get_block_by_hash(self, h):
            return chain.head if h == chain.head.hash_hex() else None

    class _Node:
        pass

    node = _Node()
    node.chain, node.storage = chain, _Storage()

    async def go():
        client = TestClient(TestServer(build_app(node)))
        await client.start_server()
        try:
            by_level = await (await client.get("/chain/block/0")).json()
            by_hash = await (await client.get(f"/chain/block/by_hash/{chain.head.hash_hex()}")).json()
        finally:
            await client.close()
        return by_level, by_hash

    by_level, by_hash = asyncio.run(go())
    for d in (by_level, by_hash):
        assert d["hash"] == chain.head.hash_hex()
        assert Block.from_dict(d).hash_hex() == d["hash"]

