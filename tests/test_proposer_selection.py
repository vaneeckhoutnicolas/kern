# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""What a proposer puts in a block, and what it removes from its mempool.

A block charges a transaction as soon as its chain, its signature, its
nonce and its fee are right: from there the fee is paid whatever happens
next. The proposer used to work otherwise. It tried each of the 5,000
oldest transactions on a full copy of the state, and left out every one
that failed, including those that had paid: a transaction that could only
fail stayed in the mempool for ever, was tried again at every block, and
5,000 of them hid everything that came after. And it never looked at the
fee floor nor at the size of the block, so that with the floor on it built
blocks that every validator, itself included, refused.

Now the proposer looks at four facts before anything else (sender, nonce,
fee, size), takes what the block can charge, keeps what may be charged
later, removes what never will be, and stops when the block is full.
"""

from __future__ import annotations

import asyncio
import copy
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import kern.chain as chain_mod
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, apply_block, fee_params, state_root_hex, tx_min_fee, validate_block
from kern.consensus import BakerConfig, propose_block
from kern.crypto import KernKeypair
from kern.node import Node
from kern.storage import Storage
from kern.transaction import (
    Transaction,
    make_call,
    make_governance_propose,
    make_governance_vote,
    make_origination,
    make_transfer,
)

BAKER = KernKeypair.from_seed(bytes([0xC0]) * 32)
ALICE = KernKeypair.from_seed(bytes([0xA1]) * 32)
BOB = KernKeypair.from_seed(bytes([0xB0]) * 32)
CAROL = KernKeypair.from_seed(bytes([0xCA]) * 32)
FLOOR = {"fee_floor_enabled": True, "fee_floor_base": 100, "fee_floor_per_byte": 2, "max_block_bytes": 131_072}
RICH = 10**12


def key(n: int) -> KernKeypair:
    return KernKeypair.from_seed((0x10000 + n).to_bytes(32, "big"))


def chain_of(balances=None, fee_cfg=None, chain_id=None, nonces=None):
    """A parent block and its state: one validator, who holds the quorum alone."""
    state = {"balances": dict(balances or {ALICE.address: RICH}), "nonces": dict(nonces or {}), "contracts": {},
             "validators": [{"address": BAKER.address, "pubkey": BAKER.public_key_b58, "stake": 10**9}]}
    if fee_cfg is not None:
        state["fee_params"] = dict(fee_cfg)
    if chain_id is not None:
        state["chain_id"] = chain_id
    header = BlockHeader(level=0, payload_round=0, timestamp=1_794_000_000, parent_hash="0" * 64,
                         state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                         proposer=BAKER.address, proposer_pubkey=BAKER.public_key_b58)
    header.sign(BAKER)
    return Block(header=header, transactions=[], commits=[]), state


def propose(parent, state, mempool, **more):
    evicted: list = []
    block = propose_block(parent=parent, mempool=mempool, proposer_keypair=BAKER,
                          proposer_pubkey_b58=BAKER.public_key_b58, state_before=state, evict_out=evicted, **more)
    return block, evicted


def refusal(block, parent, state):
    return validate_block(block, parent.header, state, state["validators"])


def hashes(transactions):
    return [tx.hash_hex() for tx in transactions]


def with_chain(tx: Transaction, kp: KernKeypair, chain_id) -> Transaction:
    tx.chain_id = chain_id
    return tx.sign(kp)


def heavy(kp: KernKeypair, nonce: int, size: int, fee: int = 1_000_000) -> Transaction:
    """An origination of exactly `size` bytes: it pays its fee, and its code is not a contract."""
    empty = make_origination(kp, code="", initial_storage=None, nonce=nonce, fee=fee)
    tx = make_origination(kp, code="x" * (size - empty.encoded_size()), initial_storage=None, nonce=nonce, fee=fee)
    assert tx.encoded_size() == size
    return tx


# ---------------------------------------------------------------------------
# What paid its fee is in the block
# ---------------------------------------------------------------------------

def _fails_after_its_fee():
    return {
        "a transfer of more than the sender holds": make_transfer(ALICE, BOB.address, RICH * 2, nonce=0),
        "a call to a contract that does not exist": make_call(ALICE, BOB.address, "main", None, nonce=0),
        "an origination whose code is not a contract": make_origination(ALICE, code="not a contract",
                                                                        initial_storage=None, nonce=0),
        "a protocol proposal from an account that is not a validator": make_governance_propose(
            sender_kp=ALICE, track="protocol", payload={"params": {"i_max_ppm": 40_000}}, nonce=0),
        "a vote on a proposal that does not exist": make_governance_vote(
            sender_kp=ALICE, track="protocol", proposal_id="00" * 16, vote="yes", nonce=0),
    }


@pytest.mark.parametrize("what", list(_fails_after_its_fee()))
def test_a_transaction_that_pays_its_fee_and_then_fails_is_in_the_block(what):
    tx = _fails_after_its_fee()[what]
    parent, state = chain_of()
    block, evicted = propose(parent, state, [tx])
    assert hashes(block.transactions) == [tx.hash_hex()] and evicted == []
    assert refusal(block, parent, state) is None
    after, results = apply_block(state, block)
    assert [r.ok for r in results] == [False]
    assert after["nonces"][ALICE.address] == 1
    assert after["balances"][ALICE.address] == RICH - tx.fee


def test_what_follows_a_transaction_that_failed_is_in_the_block_too():
    failing = make_transfer(ALICE, BOB.address, RICH * 2, nonce=0)
    then = [make_transfer(ALICE, BOB.address, 7, nonce=1), make_transfer(ALICE, BOB.address, 8, nonce=2)]
    parent, state = chain_of()
    block, evicted = propose(parent, state, [failing] + then)
    assert hashes(block.transactions) == hashes([failing] + then) and evicted == []
    assert refusal(block, parent, state) is None
    after, results = apply_block(state, block)
    assert [r.ok for r in results] == [False, True, True] and after["balances"][BOB.address] == 15


# ---------------------------------------------------------------------------
# What can never be charged leaves the mempool
# ---------------------------------------------------------------------------

def _never_charged():
    damaged = make_transfer(ALICE, BOB.address, 1, nonce=0)
    damaged.signature = ALICE.sign_b58(b"not this transaction")
    return {
        "a nonce that is consumed": (make_transfer(CAROL, BOB.address, 1, nonce=1), {}),
        "a sender that holds less than the fee": (make_transfer(BOB, ALICE.address, 1, nonce=0, fee=1_000), {}),
        "a sender that holds nothing": (make_transfer(key(1), ALICE.address, 1, nonce=0, fee=1), {}),
        "a signature that does not verify": (damaged, {}),
        "a transaction signed for another chain": (
            with_chain(make_transfer(ALICE, BOB.address, 1, nonce=0), ALICE, "another-chain"),
            {"chain_id": "kern-test"}),
        "a transaction signed for no chain, on a chain that has a name": (
            make_transfer(ALICE, BOB.address, 1, nonce=0), {"chain_id": "kern-test"}),
        "a nonce more than 256 above the account": (make_transfer(ALICE, BOB.address, 1, nonce=257), {}),
        "a transaction of more than 131,072 bytes": (heavy(ALICE, 0, 131_073), {}),
        "a fee below the floor": (make_transfer(ALICE, BOB.address, 1, nonce=0, fee=729), {"fee_cfg": FLOOR}),
    }


@pytest.mark.parametrize("what", list(_never_charged()))
def test_what_can_never_be_charged_is_removed_and_stays_out_of_the_block(what):
    junk, chain = _never_charged()[what]
    balances = {ALICE.address: RICH, BOB.address: 999, CAROL.address: RICH}
    parent, state = chain_of(balances, nonces={CAROL.address: 2}, **chain)
    good = with_chain(make_transfer(CAROL, BOB.address, 5, nonce=2), CAROL, chain.get("chain_id"))
    block, evicted = propose(parent, state, [junk, good])
    assert hashes(block.transactions) == [good.hash_hex()]
    assert evicted == [junk.hash_hex()]
    assert refusal(block, parent, state) is None


def _waits():
    return {
        "a nonce one above the account": make_transfer(ALICE, BOB.address, 1, nonce=1),
        "a nonce 256 above the account": make_transfer(ALICE, BOB.address, 1, nonce=256),
    }


@pytest.mark.parametrize("what", list(_waits()))
def test_a_nonce_ahead_waits_in_the_mempool(what):
    waiting = _waits()[what]
    parent, state = chain_of()
    block, evicted = propose(parent, state, [waiting])
    assert block.transactions == [] and evicted == []
    assert refusal(block, parent, state) is None


def test_a_sender_who_can_pay_one_fee_pays_one_and_the_rest_is_removed():
    parent, state = chain_of({BOB.address: 1_500, ALICE.address: RICH})
    three = [make_transfer(BOB, ALICE.address, 1, nonce=n, fee=1_000) for n in range(3)]
    block, evicted = propose(parent, state, three)
    assert hashes(block.transactions) == hashes(three[:1])
    assert evicted == hashes(three[1:])
    assert refusal(block, parent, state) is None


def test_the_transactions_of_a_sender_are_taken_in_the_order_of_their_nonces():
    parent, state = chain_of()
    three = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in range(3)]
    block, evicted = propose(parent, state, three)
    assert hashes(block.transactions) == hashes(three) and evicted == []
    # Received the other way round: the first nonce goes in, the others wait for the next block.
    block, evicted = propose(parent, state, three[::-1])
    assert hashes(block.transactions) == hashes(three[:1]) and evicted == []
    assert refusal(block, parent, state) is None


def test_a_transaction_paid_for_by_an_earlier_one_of_the_block_is_taken():
    parent, state = chain_of({ALICE.address: RICH, BOB.address: 1_000})
    funding = make_transfer(ALICE, BOB.address, 5_000, nonce=0)
    spending = [make_transfer(BOB, CAROL.address, 10, nonce=n, fee=1_000) for n in range(3)]
    block, evicted = propose(parent, state, [funding] + spending)
    assert hashes(block.transactions) == hashes([funding] + spending) and evicted == []
    assert refusal(block, parent, state) is None


# ---------------------------------------------------------------------------
# The price of what is not taken
# ---------------------------------------------------------------------------

def test_the_state_is_not_copied_for_each_transaction(monkeypatch):
    """300 transactions that have no place in a block, and 20 transfers: the
    state used to be copied 320 times."""
    junk = [make_transfer(key(n // 100), BOB.address, 1, nonce=n % 100) for n in range(300)]
    good = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in range(20)]
    parent, state = chain_of()
    copies = []
    real = copy.deepcopy

    def counted(value, *args, **kwargs):
        if isinstance(value, dict) and "balances" in value and "validators" in value:
            copies.append(1)
        return real(value, *args, **kwargs)

    monkeypatch.setattr(copy, "deepcopy", counted)
    block, evicted = propose(parent, state, junk + good)
    monkeypatch.undo()
    assert len(copies) <= 2
    assert hashes(block.transactions) == hashes(good) and evicted == hashes(junk)
    assert refusal(block, parent, state) is None


def test_a_transaction_whose_application_raises_is_removed_and_the_block_is_built(monkeypatch):
    """`apply_transaction` turns every failure into a result. If it ever
    raised, the block would still be built, without that transaction."""
    parent, state = chain_of({ALICE.address: RICH, CAROL.address: RICH})
    three = [make_transfer(ALICE, BOB.address, 1, nonce=0), make_transfer(CAROL, BOB.address, 1, nonce=0),
             make_transfer(ALICE, BOB.address, 2, nonce=1)]
    real = chain_mod.apply_transaction

    def raising(working, tx, baker):
        if tx.sender == CAROL.address:
            working["balances"][CAROL.address] = 0              # half done, then it breaks
            raise RuntimeError("a defect")
        return real(working, tx, baker)

    monkeypatch.setattr(chain_mod, "apply_transaction", raising)
    block, evicted = propose(parent, state, three)
    monkeypatch.undo()
    assert hashes(block.transactions) == hashes([three[0], three[2]])
    assert evicted == [three[1].hash_hex()]
    assert refusal(block, parent, state) is None


# ---------------------------------------------------------------------------
# A full block
# ---------------------------------------------------------------------------

def test_a_block_holds_as_many_transactions_as_the_proposer_allows_and_no_more():
    parent, state = chain_of()
    many = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in range(25)]
    block, evicted = propose(parent, state, many, max_txs=10)
    assert hashes(block.transactions) == hashes(many[:10]) and evicted == []
    assert refusal(block, parent, state) is None


def test_the_proposer_reads_past_what_waits_until_its_block_is_full():
    """Thirty transactions that wait, then twelve that can be charged, and
    room for ten: the proposer used to look at the first ten and stop."""
    parent, state = chain_of({ALICE.address: RICH, CAROL.address: RICH})
    waiting = [make_transfer(CAROL, BOB.address, 1, nonce=n) for n in range(1, 31)]
    ready = [make_transfer(ALICE, BOB.address, 1, nonce=n) for n in range(12)]
    block, evicted = propose(parent, state, waiting + ready, max_txs=10)
    assert hashes(block.transactions) == hashes(ready[:10]) and evicted == []
    assert refusal(block, parent, state) is None


def test_with_the_floor_on_the_block_stays_within_the_bytes_the_state_allows():
    """500 transfers that pay well, and room for 131,072 bytes: the block
    used to hold all of them, and no validator accepted it."""
    parent, state = chain_of(fee_cfg=FLOOR)
    many = [make_transfer(ALICE, BOB.address, 1, nonce=n, fee=10_000) for n in range(500)]
    block, evicted = propose(parent, state, many)
    assert refusal(block, parent, state) is None and evicted == []
    taken = len(block.transactions)
    assert 0 < taken < 500 and hashes(block.transactions) == hashes(many[:taken])
    size = sum(tx.encoded_size() for tx in block.transactions)
    assert size <= 131_072 < size + many[taken].encoded_size()


def test_with_the_floor_on_a_transaction_at_the_floor_is_taken_and_one_below_is_not():
    parent, state = chain_of({ALICE.address: RICH, CAROL.address: RICH}, fee_cfg=FLOOR)
    fee = 1                                             # the fee is part of the size, which sets the floor
    while tx_min_fee(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), fee_params(state)) != fee:
        fee = tx_min_fee(make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee), fee_params(state))
    at_the_floor = make_transfer(ALICE, BOB.address, 1, nonce=0, fee=fee)
    below = make_transfer(CAROL, BOB.address, 1, nonce=0, fee=fee - 1)
    assert at_the_floor.encoded_size() == below.encoded_size()
    assert tx_min_fee(at_the_floor, fee_params(state)) == fee == tx_min_fee(below, fee_params(state))
    block, evicted = propose(parent, state, [below, at_the_floor])
    assert hashes(block.transactions) == [at_the_floor.hash_hex()] and evicted == [below.hash_hex()]
    assert refusal(block, parent, state) is None


def test_without_the_floor_a_block_still_fits_in_a_frame():
    """Seventy transactions of 131,072 bytes: a block of 9 MiB would not be
    sure to travel. The proposer stops at 8,388,608 bytes, which is 64."""
    parent, state = chain_of()
    many = [heavy(ALICE, n, 131_072) for n in range(70)]
    block, evicted = propose(parent, state, many)
    assert hashes(block.transactions) == hashes(many[:64]) and evicted == []
    assert sum(tx.encoded_size() for tx in block.transactions) == 8_388_608
    assert refusal(block, parent, state) is None


def test_a_block_is_filled_to_the_byte_and_a_transaction_that_does_not_fit_ends_it():
    """What does not fit ends the block, and what came after it waits for
    its turn: a small transaction does not pass in front of a large one."""
    parent, state = chain_of({ALICE.address: RICH, CAROL.address: RICH}, fee_cfg=FLOOR)
    small = heavy(ALICE, 1, 400).encoded_size()
    first = heavy(ALICE, 0, 131_072 - small)
    fits, one_too_many = heavy(ALICE, 1, small), heavy(ALICE, 1, small + 1)
    after = make_transfer(CAROL, BOB.address, 1, nonce=0, fee=10_000)
    assert after.encoded_size() < small

    block, evicted = propose(parent, state, [first, fits, after])
    assert hashes(block.transactions) == hashes([first, fits]) and evicted == []
    assert sum(tx.encoded_size() for tx in block.transactions) == 131_072
    assert refusal(block, parent, state) is None

    block, evicted = propose(parent, state, [first, one_too_many, after])
    assert hashes(block.transactions) == [first.hash_hex()] and evicted == []
    assert refusal(block, parent, state) is None


def test_a_row_whose_transaction_can_no_longer_be_read_is_removed():
    from kern.transaction import Waiting

    parent, state = chain_of()
    gone = Waiting("ab" * 32, ALICE.address, 0, 1_000, 300, lambda: None)
    real = make_transfer(ALICE, BOB.address, 1, nonce=0)
    block, evicted = propose(parent, state, [gone, real])
    assert hashes(block.transactions) == [real.hash_hex()] and evicted == ["ab" * 32]
    assert refusal(block, parent, state) is None


def test_the_largest_transaction_fits_in_the_smallest_block():
    parent, state = chain_of(fee_cfg=FLOOR)
    largest = heavy(ALICE, 0, 131_072)
    block, evicted = propose(parent, state, [largest, make_transfer(ALICE, BOB.address, 1, nonce=1, fee=10_000)])
    assert hashes(block.transactions) == [largest.hash_hex()] and evicted == []
    assert refusal(block, parent, state) is None


# ---------------------------------------------------------------------------
# Whatever waits, the block is one every validator accepts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(12))
@pytest.mark.parametrize("floor", [None, FLOOR], ids=["floor off", "floor on"])
def test_whatever_the_mempool_holds_the_block_is_valid_and_charges_all_it_holds(seed, floor):
    rng = random.Random(seed)
    senders = [key(100 + n) for n in range(8)]
    balances = {kp.address: rng.choice([0, 500, 5_000, 50_000, RICH]) for kp in senders}
    nonces = {kp.address: rng.choice([0, 0, 3]) for kp in senders}
    parent, state = chain_of(balances, fee_cfg=floor, nonces=nonces)
    mempool = []
    for kp in senders:
        nonce = nonces[kp.address] + rng.choice([-1, 0, 0, 0, 1])
        for _ in range(rng.randrange(0, 12)):
            if nonce < 0:
                nonce = 0
            fee = rng.choice([0, 300, 1_000, 2_000])
            kind = rng.randrange(5)
            if kind == 0:
                tx = make_transfer(kp, BOB.address, rng.choice([1, RICH * 5]), nonce=nonce, fee=fee)
            elif kind == 1:
                tx = make_call(kp, BOB.address, "main", None, nonce=nonce, fee=fee)
            elif kind == 2:
                tx = make_origination(kp, code="x" * rng.randrange(0, 3_000), initial_storage=None,
                                      nonce=nonce, fee=fee)
            elif kind == 3:
                tx = make_transfer(kp, BOB.address, 1, nonce=nonce, fee=fee)
                tx.signature = kp.sign_b58(b"something else")
            else:
                tx = make_transfer(kp, BOB.address, 1, nonce=nonce, fee=fee)
            mempool.append(tx)
            nonce += rng.choice([1, 1, 1, 2, 0])
    rng.shuffle(mempool)
    block, evicted = propose(parent, state, mempool, max_txs=rng.choice([5, 40, 5_000]))
    assert refusal(block, parent, state) is None
    # Everything in the block was charged: one nonce consumed for each transaction, in order.
    after, _ = apply_block(state, block)
    expected = dict(nonces)
    for tx in block.transactions:
        assert tx.nonce == expected[tx.sender]
        expected[tx.sender] += 1
    assert all(after["nonces"].get(address, 0) == nonce for address, nonce in expected.items())
    # Nothing that was removed could have been charged at the end of this block, and nothing is in both.
    assert not set(evicted) & set(hashes(block.transactions))
    by_hash = {tx.hash_hex(): tx for tx in mempool}
    for h in evicted:
        tx = by_hash[h]
        gone = (not tx.verify_signature() or tx.nonce < after["nonces"].get(tx.sender, 0)
                or tx.fee > after["balances"].get(tx.sender, 0)       # a sender only spends in this block
                or (floor is not None and tx.fee < tx_min_fee(tx, fee_params(state))))
        assert gone, tx


# ---------------------------------------------------------------------------
# On a node: the measured case
# ---------------------------------------------------------------------------

class _Net:
    def __init__(self):
        self.sent = []

    async def broadcast_proposal(self, envelope):
        pass

    async def broadcast_consensus(self, message):
        pass

    async def broadcast_block(self, block):
        pass

    async def broadcast_tx(self, tx):
        self.sent.append(tx)


def _node(tmp_path, balances, max_txs_per_block=50):
    parent, state = chain_of(balances)
    chain = Chain(parent, state["validators"], initial_state=state)
    storage = Storage(str(tmp_path))
    baker = BakerConfig(BAKER, BAKER.public_key_b58, max_txs_per_block=max_txs_per_block)
    node = Node(str(tmp_path), chain, storage, baker, rpc_port=0, p2p_port=0, peers=[], block_time=0.0)
    node.network = _Net()
    node._refresh_engine()
    return node, storage


def _blocks(node, count):
    async def go():
        for _ in range(count):
            node._refresh_engine()
            await node._sync_engine_round()
            await node._propose(node.chain.head)
            await node._try_finalize()
    asyncio.run(go())


def test_transactions_that_can_only_fail_no_longer_hide_the_one_that_follows(tmp_path):
    """Sixty transfers signed by keys that hold nothing, already in the
    mempool, then one transfer from an account that can pay, on a node that
    puts fifty transactions in a block. The transfer used to wait for ever."""
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    junk = [make_transfer(key(n // 20), BOB.address, 1, nonce=n % 20) for n in range(60)]
    for tx in junk:
        assert storage.add_to_mempool(tx)
    honest = make_transfer(ALICE, BOB.address, 25, nonce=0)
    assert storage.add_to_mempool(honest)
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == [honest.hash_hex()]
    assert node.chain.state["balances"][BOB.address] == 25
    assert storage.mempool_size() == 0
    storage.close()


def test_transactions_that_wait_do_not_hide_the_one_that_follows(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH, CAROL.address: RICH})
    waiting = [make_transfer(CAROL, BOB.address, 1, nonce=n) for n in range(1, 61)]
    for tx in waiting:
        assert storage.add_to_mempool(tx)
    honest = make_transfer(ALICE, BOB.address, 25, nonce=0)
    assert storage.add_to_mempool(honest)
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == [honest.hash_hex()]
    assert storage.mempool_size() == 60
    # Their turn comes when the nonce before them does.
    assert storage.add_to_mempool(make_transfer(CAROL, BOB.address, 1, nonce=0))
    _blocks(node, 3)                                   # the first nonce, then fifty, then ten
    assert node.chain.state["nonces"][CAROL.address] == 61 and storage.mempool_size() == 0
    storage.close()


def test_a_transaction_that_failed_after_its_fee_leaves_the_mempool_with_its_block(tmp_path):
    node, storage = _node(tmp_path, {ALICE.address: RICH})
    failing = make_transfer(ALICE, BOB.address, RICH * 2, nonce=0)
    assert storage.add_to_mempool(failing)
    _blocks(node, 1)
    assert hashes(node.chain.head.transactions) == [failing.hash_hex()]
    assert node.chain.state["balances"][ALICE.address] == RICH - failing.fee
    assert storage.mempool_size() == 0
    storage.close()
