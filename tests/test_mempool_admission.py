# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""What a node takes in its mempool.

A node used to take any transaction that was well formed and well signed,
up to 256 for a sender and 50,000 in all. It looked neither at the nonce
nor at what the sender held: transfers signed by keys that held nothing
were stored, passed on to every peer, and tried again at every block.

A node now refuses, from a peer as from a client, what no block built on
its head could charge: a nonce that is consumed or more than 256 above the
account, a sender that cannot pay the fee, a fee under the floor when the
floor is on, a transaction of more than 131,072 bytes, a transaction signed
for another chain. What a proposer would remove is not taken in the first
place (tests/test_proposer_selection.py).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_proposer_selection import (
    ALICE, BOB, CAROL, FLOOR, RICH, _blocks, _node, chain_of, hashes, heavy, key, with_chain,
)

from kern.chain import (
    DROP, MAX_NONCE_AHEAD, MAX_PROPOSED_BLOCK_BYTES, MAX_TX_BYTES, TAKE, WAIT,
    admission_error, fee_params, mempool_verdict, proposed_block_bytes, tx_min_fee,
)
from kern.rpc import build_app
from kern.storage import MAX_MEMPOOL_PER_SENDER, Storage
from kern.transaction import Transaction, Waiting, make_transfer


def state_of(balances=None, **more) -> dict:
    return chain_of(balances, **more)[1]


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------

def test_the_limits_are_those_of_the_schemas():
    assert MAX_TX_BYTES == 131_072 and MAX_PROPOSED_BLOCK_BYTES == 8_388_608
    # A sender has 256 places in a mempool: a nonce further ahead could not be reached by what waits.
    assert MAX_NONCE_AHEAD == MAX_MEMPOOL_PER_SENDER == 256


def test_a_transaction_the_next_block_can_charge_is_taken():
    state = state_of({ALICE.address: 1_000}, nonces={ALICE.address: 4})
    assert admission_error(make_transfer(ALICE, BOB.address, 1, nonce=4, fee=1_000), state) is None
    # What its operation will do is not looked at: it pays its fee, that is enough.
    assert admission_error(make_transfer(ALICE, BOB.address, RICH, nonce=4, fee=1_000), state) is None
    assert admission_error(make_transfer(ALICE, BOB.address, 1, nonce=4, fee=0), state) is None


def test_a_nonce_is_neither_consumed_nor_more_than_256_ahead():
    state = state_of({ALICE.address: RICH}, nonces={ALICE.address: 4})
    answers = {nonce: admission_error(make_transfer(ALICE, BOB.address, 1, nonce=nonce), state)
               for nonce in (0, 3, 4, 5, 260, 261, 10**18)}
    assert [nonce for nonce, answer in answers.items() if answer is None] == [4, 5, 260]
    assert "consumed" in answers[0] and "consumed" in answers[3]
    assert "more than 256 above" in answers[261] and "more than 256 above" in answers[10**18]
    # An account that never signed is at nonce zero.
    fresh = state_of({CAROL.address: RICH})
    assert admission_error(make_transfer(CAROL, BOB.address, 1, nonce=256), fresh) is None
    assert admission_error(make_transfer(CAROL, BOB.address, 1, nonce=257), fresh) is not None


def test_the_sender_holds_the_fee():
    for held, fee, taken in ((1_000, 1_000, True), (999, 1_000, False), (0, 1, False), (0, 0, True)):
        state = state_of({ALICE.address: held})
        answer = admission_error(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), state)
        assert (answer is None) is taken, (held, fee, answer)
    unknown = admission_error(make_transfer(key(7), BOB.address, 1, nonce=0, fee=1), state_of())
    assert "cannot pay the fee" in unknown
    # A nonce that waits is refused too when the sender cannot pay for it.
    assert admission_error(make_transfer(key(7), BOB.address, 1, nonce=3, fee=1), state_of()) is not None


def test_a_transaction_is_131072_bytes_at_most():
    state = state_of()
    assert admission_error(heavy(ALICE, 0, 131_072), state) is None
    assert "131072 bytes at most" in admission_error(heavy(ALICE, 0, 131_073), state)


def test_a_transaction_is_signed_for_this_chain():
    named = state_of(chain_id="kern-test")
    here = with_chain(make_transfer(ALICE, BOB.address, 1, nonce=0), ALICE, "kern-test")
    elsewhere = with_chain(make_transfer(ALICE, BOB.address, 1, nonce=0), ALICE, "another-chain")
    nowhere = make_transfer(ALICE, BOB.address, 1, nonce=0)
    assert admission_error(here, named) is None
    assert "wrong chain_id" in admission_error(elsewhere, named) and "wrong chain_id" in admission_error(nowhere, named)
    # A state without a name takes them all, as its blocks do.
    assert [admission_error(tx, state_of()) for tx in (here, elsewhere, nowhere)] == [None, None, None]


def test_with_the_floor_on_the_fee_is_at_the_floor_or_above():
    state = state_of(fee_cfg=FLOOR)
    fee = 1
    while tx_min_fee(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), fee_params(state)) != fee:
        fee = tx_min_fee(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), fee_params(state))
    assert admission_error(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), state) is None
    assert "below the fee floor" in admission_error(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee - 1), state)
    # The same transfer on a state where the floor is off, or set and not switched on.
    for cfg in (None, {**FLOOR, "fee_floor_enabled": False}):
        below = make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee - 1)
        assert admission_error(below, state_of(fee_cfg=cfg)) is None


VERDICTS = [
    # nonce, fee, size, held, account nonce -> verdict, a word of the reason
    (4, 10, 300, 10, 4, TAKE, ""),
    (5, 10, 300, 10, 4, WAIT, "ahead"),
    (260, 10, 300, 10, 4, WAIT, "ahead"),
    (261, 10, 300, 10, 4, DROP, "more than 256 above"),
    (3, 10, 300, 10, 4, DROP, "consumed"),
    (4, 11, 300, 10, 4, DROP, "cannot pay"),
    (5, 11, 300, 10, 4, DROP, "cannot pay"),            # it waits for nothing: its sender cannot pay for it
    (3, 11, 300, 10, 4, DROP, "consumed"),
    (4, 10, 131_072, 10, 4, TAKE, ""),
    (4, 10, 131_073, 10, 4, DROP, "bytes at most"),
    (0, 0, 300, 0, 0, TAKE, ""),
]


@pytest.mark.parametrize("nonce, fee, size, held, at, verdict, word", VERDICTS)
def test_the_three_verdicts(nonce, fee, size, held, at, verdict, word):
    state = {"balances": {"someone": held}, "nonces": {"someone": at}}
    got, why = mempool_verdict("someone", nonce, fee, size, state, fee_params({}))
    assert got == verdict and word in why and (why == "") is (verdict == TAKE)


def test_the_floor_counts_the_bytes_of_the_transaction():
    fees = fee_params({"fee_params": FLOOR})
    state = {"balances": {"someone": RICH}, "nonces": {}}
    assert mempool_verdict("someone", 0, 700, 300, state, fees)[0] == TAKE          # 100 + 2 x 300
    assert mempool_verdict("someone", 0, 699, 300, state, fees)[0] == DROP
    assert mempool_verdict("someone", 0, 700, 301, state, fees)[0] == DROP
    assert mempool_verdict("someone", 0, 699, 300, state, fee_params({}))[0] == TAKE


def test_a_proposer_fills_what_the_state_allows_and_never_more_than_a_frame_carries():
    def room(**cfg):
        return proposed_block_bytes(fee_params({"fee_params": cfg} if cfg else {}))

    assert room() == 8_388_608
    assert room(fee_floor_enabled=True) == 1_048_576                                 # the default of the floor
    assert room(fee_floor_enabled=True, max_block_bytes=131_072) == 131_072
    assert room(fee_floor_enabled=True, max_block_bytes=8_388_607) == 8_388_607
    assert room(fee_floor_enabled=True, max_block_bytes=8_388_608) == 8_388_608
    assert room(fee_floor_enabled=True, max_block_bytes=2**40) == 8_388_608          # a genesis may say so
    assert room(fee_floor_enabled=True, max_block_bytes=0) == 8_388_608              # zero is no limit for a block
    assert room(fee_floor_enabled=False, max_block_bytes=131_072) == 8_388_608       # set, and not switched on


# ---------------------------------------------------------------------------
# From a peer
# ---------------------------------------------------------------------------

def gossip(node, *transactions):
    async def go():
        for tx in transactions:
            await node._on_tx_msg(tx.to_dict())
        await asyncio.sleep(0)                # let the relay run
    asyncio.run(go())


def test_transfers_signed_by_keys_that_hold_nothing_are_neither_kept_nor_passed_on(tmp_path):
    """The measured case: they used to be stored, sent to every peer, and
    tried at every block."""
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    junk = [make_transfer(key(n // 20), BOB.address, 1, nonce=n % 20) for n in range(60)]
    honest = make_transfer(ALICE, BOB.address, 25, nonce=0)
    gossip(node, *junk, honest)
    assert hashes(storage.drain_mempool()) == [honest.hash_hex()]
    assert node.network.sent == [honest.to_dict()]
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == [honest.hash_hex()] and storage.mempool_size() == 0
    storage.close()


REFUSED = {
    "a nonce that is consumed": lambda: make_transfer(CAROL, BOB.address, 1, nonce=1),
    "a nonce more than 256 above the account": lambda: make_transfer(CAROL, BOB.address, 1, nonce=259),
    "a sender that cannot pay the fee": lambda: make_transfer(BOB, ALICE.address, 1, nonce=0, fee=1_000),
    "more than 131,072 bytes": lambda: heavy(ALICE, 0, 131_073),
}


@pytest.mark.parametrize("what", list(REFUSED))
def test_what_a_node_refuses_from_a_peer_is_neither_kept_nor_passed_on(tmp_path, what):
    node, storage = _node(tmp_path, {ALICE.address: RICH, BOB.address: 999, CAROL.address: RICH})
    node.chain.state["nonces"][CAROL.address] = 2
    gossip(node, REFUSED[what]())
    assert storage.mempool_size() == 0 and node.network.sent == []
    storage.close()


def test_a_transaction_refused_today_is_taken_when_it_comes_again_and_can_be_charged(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    tx = make_transfer(BOB, CAROL.address, 1, nonce=0, fee=1_000)
    gossip(node, tx)
    assert storage.mempool_size() == 0                 # Bob holds nothing yet
    node.chain.state["balances"][BOB.address] = 5_000
    gossip(node, tx, tx)
    assert hashes(storage.drain_mempool()) == [tx.hash_hex()]
    assert node.network.sent == [tx.to_dict()]         # passed on once
    storage.close()


def test_what_waits_for_its_nonce_is_taken_and_passed_on(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    later = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in (2, 1)]
    gossip(node, *later)
    assert storage.mempool_size() == 2 and len(node.network.sent) == 2
    _blocks(node, 1)
    assert node.chain.head.transactions == [] and storage.mempool_size() == 2
    gossip(node, make_transfer(ALICE, BOB.address, 1, nonce=0))
    _blocks(node, 3)
    assert node.chain.state["nonces"][ALICE.address] == 3 and storage.mempool_size() == 0
    storage.close()


# ---------------------------------------------------------------------------
# From a client
# ---------------------------------------------------------------------------

def post(node, tx: Transaction):
    async def go():
        client = TestClient(TestServer(build_app(node)))
        await client.start_server()
        try:
            response = await client.post("/chain/inject_transaction", data=json.dumps(tx.to_dict()).encode())
            answer = await response.json()
            await asyncio.sleep(0)
            return response.status, answer
        finally:
            await client.close()
    return asyncio.run(go())


def test_a_client_is_told_why_its_transaction_is_not_taken(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH, BOB.address: 999, CAROL.address: RICH})
    node.chain.state["nonces"][CAROL.address] = 2
    words = {"a nonce that is consumed": "consumed", "a nonce more than 256 above the account": "more than 256 above",
             "a sender that cannot pay the fee": "cannot pay the fee", "more than 131,072 bytes": "bytes at most"}
    for what, build in REFUSED.items():
        status, answer = post(node, build())
        assert status == 400 and words[what] in answer["error"], (what, answer)
    damaged = make_transfer(ALICE, BOB.address, 1, nonce=0)
    damaged.signature = ALICE.sign_b58(b"not this transaction")
    assert post(node, damaged) == (400, {"error": "invalid signature"})
    assert storage.mempool_size() == 0 and node.network.sent == []
    storage.close()


def test_a_client_whose_transaction_is_taken_gets_its_identifier(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    tx = make_transfer(ALICE, BOB.address, 25, nonce=0)
    assert post(node, tx) == (200, {"hash": tx.hash_hex()})
    assert hashes(storage.drain_mempool()) == [tx.hash_hex()] and node.network.sent == [tx.to_dict()]
    storage.close()


def test_a_full_mempool_is_a_reason_to_come_back_later(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH, CAROL.address: RICH})
    storage.max_mempool_size = 1
    assert post(node, make_transfer(ALICE, BOB.address, 1, nonce=0))[0] == 200
    status, answer = post(node, make_transfer(CAROL, BOB.address, 1, nonce=0))
    assert status == 429 and answer["error"].startswith("mempool full")
    storage.close()


# ---------------------------------------------------------------------------
# The rows of the mempool
# ---------------------------------------------------------------------------

def test_a_row_carries_the_four_facts_and_gives_its_transaction_when_asked(tmp_path, monkeypatch):
    storage = Storage(str(tmp_path))
    txs = [make_transfer(ALICE, BOB.address, 1, nonce=5, fee=1_234), heavy(CAROL, 2, 5_000, fee=99)]
    for tx in txs:
        assert storage.add_to_mempool(tx)
    decoded = []
    real = Transaction.from_dict.__func__
    monkeypatch.setattr(Transaction, "from_dict", classmethod(lambda cls, d: decoded.append(1) or real(cls, d)))
    rows = list(storage.waiting())
    assert [(r.hash_hex, r.sender, r.nonce, r.fee, r.size) for r in rows] == [
        (tx.hash_hex(), tx.sender, tx.nonce, tx.fee, tx.encoded_size()) for tx in txs]
    assert decoded == []                               # nothing was decoded to describe them
    assert [r.transaction().to_dict() for r in rows] == [tx.to_dict() for tx in txs] and len(decoded) == 2
    storage.remove_from_mempool([txs[0].hash_hex()])
    assert rows[0].transaction() is None and storage.get_from_mempool("no such hash") is None
    of = Waiting.of(txs[1])
    assert (of.hash_hex, of.sender, of.nonce, of.fee, of.size) == (
        txs[1].hash_hex(), CAROL.address, 2, 99, 5_000) and of.transaction() is txs[1]
    storage.close()


def test_the_mempool_is_read_in_the_order_of_arrival_a_page_at_a_time(tmp_path, monkeypatch):
    import kern.storage as storage_mod

    storage = Storage(str(tmp_path))
    clock = [1_794_000_000]
    monkeypatch.setattr(storage_mod.time, "time", lambda: clock[0])
    txs = [make_transfer(key(n), BOB.address, 1, nonce=0) for n in range(23)]
    for n, tx in enumerate(txs):
        clock[0] += n % 3 == 0                         # several arrive within the same second
        assert storage.add_to_mempool(tx)
    for page in (1, 2, 5, 22, 23, 24, 2_000):
        assert [r.hash_hex for r in storage.waiting(page=page)] == hashes(txs), page
    assert hashes(storage.drain_mempool(max_n=7)) == hashes(txs[:7])
    # A proposer that has enough stops reading: the rows that follow are not fetched.
    statements = []
    storage.conn.set_trace_callback(statements.append)
    reader = storage.waiting(page=5)
    assert [next(reader).hash_hex for _ in range(5)] == hashes(txs[:5])
    reader.close()
    storage.conn.set_trace_callback(None)
    assert len(statements) == 1
    storage.close()


def test_a_proposer_decodes_only_what_its_block_takes(tmp_path, monkeypatch):
    """Two hundred transactions that wait for their nonce and three that
    can be charged: three are decoded."""
    node, storage = _node(tmp_path, {ALICE.address: RICH, CAROL.address: RICH})
    for n in range(1, 201):
        assert storage.add_to_mempool(make_transfer(CAROL, BOB.address, 1, nonce=n))
    ready = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in range(3)]
    for tx in ready:
        assert storage.add_to_mempool(tx)
    decoded = []
    real = Transaction.from_dict.__func__
    monkeypatch.setattr(Transaction, "from_dict",
                        classmethod(lambda cls, d: decoded.append(d["sender"]) or real(cls, d)))
    block_and_evicted = []

    async def go():
        node._refresh_engine()
        await node._sync_engine_round()
        await node._propose(node.chain.head)
        block_and_evicted.append(len(decoded))
        await node._try_finalize()
    asyncio.run(go())
    monkeypatch.undo()
    assert block_and_evicted == [3] and set(decoded[:3]) == {ALICE.address}
    assert hashes(node.chain.head.transactions) == hashes(ready) and storage.mempool_size() == 200
    storage.close()


@pytest.mark.parametrize("text", ["not json", "[1, 2]", '{"kind": "transfer"}', "[" * 100_000 + "]" * 100_000],
                         ids=["not JSON", "not an object", "not a transaction", "nested without end"])
def test_a_row_that_can_no_longer_be_read_gives_no_transaction_and_leaves_with_the_next_block(tmp_path, text):
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    honest = make_transfer(ALICE, BOB.address, 25, nonce=0)
    storage.conn.execute("INSERT INTO mempool(hash, json, received_at, sender, nonce, fee, size) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?)", ("damaged", text, 1, ALICE.address, 0, 1_000, 300))
    assert storage.add_to_mempool(honest)
    assert storage.get_from_mempool("damaged") is None and [r.hash_hex for r in storage.waiting()][0] == "damaged"
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == [honest.hash_hex()] and storage.mempool_size() == 0
    storage.close()


def test_a_node_puts_in_a_block_the_number_of_transactions_its_operator_set(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH}, max_txs_per_block=50)
    for nonce in range(60):
        assert storage.add_to_mempool(make_transfer(ALICE, BOB.address, 1, nonce=nonce))
    _blocks(node, 1)
    assert len(node.chain.head.transactions) == 50 and storage.mempool_size() == 10
    _blocks(node, 1)
    assert len(node.chain.head.transactions) == 10 and storage.mempool_size() == 0
    storage.close()


def test_thousands_of_transactions_are_removed_from_the_mempool_at_once(tmp_path):
    storage = Storage(str(tmp_path))
    txs = [make_transfer(key(n // 250), BOB.address, 1, nonce=n % 250) for n in range(1_201)]
    for tx in txs:
        assert storage.add_to_mempool(tx)
    storage.remove_from_mempool(hashes(txs[:1_200]) + ["no such hash"])
    assert hashes(storage.drain_mempool()) == [txs[-1].hash_hex()]
    storage.remove_from_mempool([])
    assert storage.mempool_size() == 1
    storage.close()


def test_a_nonce_or_a_fee_no_row_can_hold_is_not_taken(tmp_path):
    storage = Storage(str(tmp_path))
    top = 2**63 - 1
    assert storage.add_to_mempool(make_transfer(ALICE, BOB.address, 1, nonce=top, fee=top)) is True
    assert storage.add_to_mempool(make_transfer(ALICE, BOB.address, 1, nonce=top + 1, fee=1)) is False
    assert storage.add_to_mempool(make_transfer(ALICE, BOB.address, 1, nonce=1, fee=top + 1)) is False
    assert [(r.nonce, r.fee) for r in storage.waiting()] == [(top, top)]
    storage.close()


@pytest.mark.parametrize("columns", ["hash TEXT PRIMARY KEY, json TEXT NOT NULL, received_at INTEGER NOT NULL",
                                     "hash TEXT PRIMARY KEY, json TEXT NOT NULL, received_at INTEGER NOT NULL, "
                                     "sender TEXT NOT NULL DEFAULT ''"],
                         ids=["the first form of the table", "the form with the sender"])
def test_a_mempool_written_by_an_older_node_is_read_by_this_one(tmp_path, columns):
    """The rows it holds get their nonce, fee and size when the database
    is opened; a row that is not a transaction is removed."""
    txs = [make_transfer(ALICE, BOB.address, 1, nonce=n, fee=1_000 + n) for n in range(3)]
    conn = sqlite3.connect(tmp_path / "kern.sqlite")
    conn.execute(f"CREATE TABLE mempool ({columns})")
    with_sender = "sender" in columns
    for at, tx in enumerate(txs):
        row = (tx.hash_hex(), json.dumps(tx.to_dict()), 1_794_000_000 + at) + ((tx.sender,) if with_sender else ())
        conn.execute(f"INSERT INTO mempool VALUES ({', '.join('?' for _ in row)})", row)
    for at, text in enumerate(('{"kind": "transfer"}', "not json", "[1, 2]", "[" * 100_000 + "]" * 100_000)):
        row = (f"junk{at}", text, 1_793_000_000 + at) + (("",) if with_sender else ())
        conn.execute(f"INSERT INTO mempool VALUES ({', '.join('?' for _ in row)})", row)
    conn.commit()
    conn.close()

    for _ in range(2):                                 # opening it again changes nothing
        storage = Storage(str(tmp_path))
        assert [(r.hash_hex, r.sender, r.nonce, r.fee, r.size) for r in storage.waiting()] == [
            (tx.hash_hex(), ALICE.address, tx.nonce, tx.fee, tx.encoded_size()) for tx in txs]
        assert storage._mempool_count_for_sender(ALICE.address) == 3
        storage.close()

    node, storage = _node(tmp_path, {ALICE.address: RICH})
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == hashes(txs) and storage.mempool_size() == 0
    indexes = {row[1] for row in storage.conn.execute("PRAGMA index_list(mempool)")}
    assert {"mempool_arrival", "mempool_sender"} <= indexes
    storage.close()


# ---------------------------------------------------------------------------
# The reports a validator files itself
# ---------------------------------------------------------------------------

def _validator_node(tmp_path, liquid: int):
    """A node of one of four validators, which holds `liquid` outside its stake."""
    from test_phase_d_bonded_stake import STAKE, _genesis, _keys

    from kern.block import Block, BlockHeader, txs_merkle_root_hex
    from kern.chain import Chain, state_root_hex
    from kern.consensus import BakerConfig
    from kern.node import Node

    keys = _keys(4, base=0x60)
    me = keys[0]
    state = _genesis([(k, STAKE) for k in keys], {k.address: STAKE + (liquid if k is me else 0) for k in keys})
    header = BlockHeader(level=0, payload_round=0, timestamp=1_794_000_000, parent_hash="0" * 64,
                         state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                         proposer=me.address, proposer_pubkey=me.public_key_b58)
    header.sign(me)
    chain = Chain(Block(header=header, transactions=[], commits=[]), state["validators"], initial_state=state)
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), chain, storage, BakerConfig(me, me.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)
    return node, storage, keys


def _two_votes(node, offender, level=1):
    from test_phase_d_bonded_stake import _vote

    async def feed():
        await node._ingest_consensus(_vote(offender, "aa" * 32, level), from_wire=True)
        await node._ingest_consensus(_vote(offender, "bb" * 32, level), from_wire=True)
    asyncio.run(feed())


def test_the_next_nonce_of_a_sender_is_the_first_that_nothing_waiting_has_taken(tmp_path):
    storage = Storage(str(tmp_path))
    assert storage.next_free_nonce(ALICE.address, 0) == 0 and storage.next_free_nonce(ALICE.address, 7) == 7
    for nonce in (0, 1, 2, 4, 9):
        assert storage.add_to_mempool(make_transfer(ALICE, BOB.address, 1, nonce=nonce))
    assert storage.add_to_mempool(make_transfer(CAROL, BOB.address, 1, nonce=3))        # another sender
    free = [storage.next_free_nonce(ALICE.address, at) for at in (0, 1, 2, 3, 4, 5, 9, 10)]
    assert free == [3, 3, 3, 3, 5, 5, 10, 10]
    assert storage.next_free_nonce(CAROL.address, 3) == 4
    storage.close()


def test_a_report_takes_the_first_nonce_that_is_free(tmp_path):
    """The node used to count the nonces it had handed out. A report that
    left the mempool without being charged left its nonce behind, and every
    later report waited for it for ever."""
    node, storage, keys = _validator_node(tmp_path, liquid=10_000)
    _two_votes(node, keys[2])
    first, = storage.drain_mempool()
    assert first.nonce == 0 and first.kind.value == "slash_consensus_equivocation"
    storage.remove_from_mempool([first.hash_hex()])               # as a proposer removes what cannot be charged
    _two_votes(node, keys[3])
    second, = storage.drain_mempool()
    assert second.nonce == 0 and second.hash_hex() != first.hash_hex()
    # And one more while the second still waits: the nonce after it.
    _two_votes(node, keys[1])
    assert sorted(tx.nonce for tx in storage.drain_mempool()) == [0, 1]
    storage.close()


def test_a_validator_that_cannot_pay_for_a_report_keeps_its_evidence_until_it_can(tmp_path):
    """Filed at once, the report would wait in a mempool no block could
    take it from, and its nonce would hold back every later one."""
    node, storage, keys = _validator_node(tmp_path, liquid=999)
    me = keys[0]
    _two_votes(node, keys[2])
    assert storage.mempool_size() == 0 and len(node.bft.pending_evidence) == 1
    # It can pay for one: the first report is filed, the second waits in the engine.
    node.chain.state["balances"][me.address] = 1_999
    _two_votes(node, keys[3])
    assert [tx.nonce for tx in storage.drain_mempool()] == [0] and len(node.bft.pending_evidence) == 1
    assert storage.waiting_fees(me.address) == 1_000 and storage.waiting_fees(keys[1].address) == 0
    node.chain.state["balances"][me.address] = 2_000
    node._submit_evidence()
    filed = storage.drain_mempool()
    assert sorted(tx.nonce for tx in filed) == [0, 1] and node.bft.pending_evidence == []
    assert all(tx.fee == 1_000 and tx.sender == me.address and tx.verify_signature() for tx in filed)
    offenders = {tx.params["msg_a"]["validator"] for tx in filed}
    assert offenders == {keys[2].address, keys[3].address}
    node._submit_evidence()                                       # nothing left to file
    assert storage.mempool_size() == 2
    storage.close()


def test_reports_that_wait_in_the_engine_are_filed_together_when_all_can_be_paid(tmp_path):
    node, storage, keys = _validator_node(tmp_path, liquid=0)
    _two_votes(node, keys[2])
    _two_votes(node, keys[3])
    assert storage.mempool_size() == 0 and len(node.bft.pending_evidence) == 2
    node.chain.state["balances"][keys[0].address] = 1_999        # what pays for one, and two are waiting
    node._submit_evidence()
    assert storage.mempool_size() == 0 and len(node.bft.pending_evidence) == 2
    node.chain.state["balances"][keys[0].address] = 2_000
    node._submit_evidence()
    assert sorted(tx.nonce for tx in storage.drain_mempool()) == [0, 1] and node.bft.pending_evidence == []
    storage.close()
