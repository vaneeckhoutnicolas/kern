# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A mempool that is full still takes what the next block can charge.

Three ways were left to keep a mempool full for next to nothing, so that a
node refused every transaction that came after:

- transactions whose nonce is ahead of their account, which no block takes
  before the nonces under them have come, and which waited for ever;
- several transactions of one sender with one nonce, of which a block takes
  one at most;
- on a node that does not propose, everything a block had made useless:
  only a proposer removed it, when its turn came.

Four rules of the node close them. None is a rule of consensus:

- a sender has one transaction waiting for each nonce;
- every node removes, when it applies a block, what that block consumed;
- when the mempool is full, a transaction the next block can charge takes
  the place of one that waits, the one farthest ahead of its account, once
  the node has removed what no block could charge any more;
- a transaction that waits takes the place of none.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_mempool_admission import _two_votes, _validator_node
from test_proposer_selection import ALICE, BAKER, BOB, CAROL, RICH, _blocks, _Net, chain_of, key

from kern.chain import Chain
from kern.consensus import BakerConfig
from kern.crypto import KernKeypair
from kern.node import NONCE_TAKEN, Node
from kern.rpc import build_app
from kern.storage import MEMPOOL_FULL, Storage
from kern.transaction import make_transfer

P1, P2, P3 = key(1), key(2), key(3)
ONLOOKER = KernKeypair.from_seed(bytes([0xF0]) * 32)          # holds no stake: a node with this key never proposes
NAMES = {ALICE.address: "alice", BOB.address: "bob", CAROL.address: "carol",
         P1.address: "p1", P2.address: "p2", P3.address: "p3"} | {key(n).address: f"k{n}" for n in range(4, 12)}
FUNDED = {address: RICH for address in NAMES}


def node_of(folder, balances=None, size=8, per_sender=4, nonces=None, keypair=BAKER):
    """A node whose mempool holds `size` transactions, `per_sender` for one sender."""
    parent, state = chain_of(balances or FUNDED, nonces=nonces)
    chain = Chain(parent, state["validators"], initial_state=state)
    storage = Storage(str(folder), max_mempool_size=size, max_mempool_per_sender=per_sender)
    baker = BakerConfig(keypair, keypair.public_key_b58, max_txs_per_block=50)
    node = Node(str(folder), chain, storage, baker, rpc_port=0, p2p_port=0, peers=[], block_time=0.0)
    node.network = _Net()
    node._refresh_engine()
    return node, storage


def pay(kp, nonce, amount=1, fee=1_000):
    return make_transfer(kp, BOB.address, amount, nonce=nonce, fee=fee)


def held(storage):
    """What waits, oldest first, as `sender:nonce`."""
    return [f"{NAMES[w.sender]}:{w.nonce}" for w in storage.waiting()]


def park(node, *rows):
    """Transactions whose nonce is ahead of their account, taken one by one."""
    for kp, nonce in rows:
        assert node.admit_transaction(pay(kp, nonce)) is None, (NAMES[kp.address], nonce)


def post(node, tx):
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


def gossip(node, tx):
    async def go():
        await node._on_tx_msg(tx.to_dict())
        await asyncio.sleep(0)
    asyncio.run(go())


# ---------------------------------------------------------------------------
# One transaction of a sender for each nonce
# ---------------------------------------------------------------------------

def test_a_second_transaction_of_a_sender_with_the_same_nonce_is_refused(tmp_path):
    node, storage = node_of(tmp_path)
    first, twin = pay(ALICE, 0, amount=1), pay(ALICE, 0, amount=2)
    assert node.admit_transaction(first) is None
    assert node.admit_transaction(twin) == NONCE_TAKEN and "already waits" in NONCE_TAKEN
    # The same goes for a nonce that waits, and another sender is not concerned.
    assert node.admit_transaction(pay(ALICE, 3, amount=1)) is None
    assert node.admit_transaction(pay(ALICE, 3, amount=2)) == NONCE_TAKEN
    assert node.admit_transaction(pay(CAROL, 0, amount=2)) is None
    assert held(storage) == ["alice:0", "alice:3", "carol:0"]
    assert storage.get_from_mempool(first.hash_hex()) is not None and storage.get_from_mempool(twin.hash_hex()) is None
    storage.close()


def test_as_many_twins_as_one_likes_take_one_place(tmp_path):
    """What was measured: 256 transactions of one sender with one nonce were all kept."""
    node, storage = node_of(tmp_path, size=50, per_sender=40)
    answers = [node.admit_transaction(pay(ALICE, 0, amount=1 + n)) for n in range(30)]
    assert answers == [None] + [NONCE_TAKEN] * 29 and held(storage) == ["alice:0"]
    storage.close()


def test_the_same_transaction_again_keeps_its_place(tmp_path):
    node, storage = node_of(tmp_path)
    first, second = pay(ALICE, 0), pay(CAROL, 0)
    assert [node.admit_transaction(tx) for tx in (first, second, first)] == [None, None, None]
    # It used to leave its place and go behind the others.
    assert held(storage) == ["alice:0", "carol:0"]
    assert storage.add_to_mempool(first) is True and held(storage) == ["alice:0", "carol:0"]
    # A copy whose signature is damaged has the same identifier: it is refused for its signature all the same.
    damaged = pay(ALICE, 0)
    damaged.signature = ALICE.sign_b58(b"not this transaction")
    assert damaged.hash_hex() == first.hash_hex() and node.admit_transaction(damaged) == "invalid signature"
    storage.close()


def test_the_same_transaction_again_is_taken_even_when_the_mempool_is_full(tmp_path):
    node, storage = node_of(tmp_path, size=2)
    first, second = pay(ALICE, 0), pay(CAROL, 0)
    assert [node.admit_transaction(tx) for tx in (first, second, first, second)] == [None] * 4
    assert held(storage) == ["alice:0", "carol:0"]
    storage.close()


def test_a_twin_takes_the_place_of_a_transaction_its_sender_can_no_longer_pay(tmp_path):
    node, storage = node_of(tmp_path, {ALICE.address: 1_000, CAROL.address: RICH})
    dear, cheap = pay(ALICE, 0, fee=1_000), pay(ALICE, 0, fee=10)
    gossip(node, dear)
    assert held(storage) == ["alice:0"] and dear.hash_hex() in node._seen_txs
    assert node.admit_transaction(cheap) == NONCE_TAKEN
    node.chain.state["balances"][ALICE.address] = 10            # no block can charge the first one any more
    assert node.admit_transaction(cheap) is None
    assert storage.get_from_mempool(dear.hash_hex()) is None and held(storage) == ["alice:0"]
    assert next(storage.waiting()).fee == 10
    # The one that gave way is forgotten: a peer can bring it again the day its sender can pay it.
    assert dear.hash_hex() not in node._seen_txs
    storage.close()


def test_twins_of_which_one_can_still_be_charged_keep_the_nonce(tmp_path):
    """A database from before the rule, with two transactions for one
    nonce: the sender can pay one of them and not the other. The nonce is
    taken as long as one of them can be charged, and nothing is removed."""
    for fees, answer, left in (((5, 2_000), NONCE_TAKEN, [5, 2_000]), ((2_000, 5), NONCE_TAKEN, [2_000, 5]),
                               ((2_000, 3_000), None, [7])):
        node, storage = node_of(tmp_path / str(fees), {ALICE.address: 1_000})
        for fee in fees:
            assert storage.add_to_mempool(pay(ALICE, 0, fee=fee))
        assert node.admit_transaction(pay(ALICE, 0, fee=7)) == answer
        assert [row.fee for row in storage.waiting()] == left
        storage.close()


def test_twins_a_database_already_holds_keep_a_third_one_out(tmp_path):
    """A mempool written before this rule can hold twins: the proposer deals
    with them, and no other comes in while one of them can be charged."""
    node, storage = node_of(tmp_path)
    for amount in (1, 2):
        assert storage.add_to_mempool(pay(ALICE, 0, amount=amount))
    assert node.admit_transaction(pay(ALICE, 0, amount=3)) == NONCE_TAKEN
    assert held(storage) == ["alice:0", "alice:0"]
    _blocks(node, 1)
    assert len(node.chain.head.transactions) == 1 and storage.mempool_size() == 0
    storage.close()


def test_a_client_is_told_that_the_nonce_is_taken(tmp_path):
    node, storage = node_of(tmp_path)
    first, twin = pay(ALICE, 0, amount=1), pay(ALICE, 0, amount=2)
    assert post(node, first) == (200, {"hash": first.hash_hex()})
    # Not a reason to come back later: it is refused for what it is.
    assert post(node, twin) == (400, {"error": NONCE_TAKEN})
    assert node.network.sent == [first.to_dict()]
    storage.close()


def test_a_twin_from_a_peer_is_neither_kept_nor_passed_on_nor_remembered(tmp_path):
    node, storage = node_of(tmp_path)
    first, twin = pay(ALICE, 0, amount=1), pay(ALICE, 0, amount=2)
    gossip(node, first)
    gossip(node, twin)
    assert held(storage) == ["alice:0"] and node.network.sent == [first.to_dict()]
    # Once the first one is in a block, the twin is refused for its nonce: it was not held against it before.
    assert twin.hash_hex() not in node._seen_txs
    storage.close()


# ---------------------------------------------------------------------------
# Every node removes what a block consumed
# ---------------------------------------------------------------------------

def a_proposer_and_an_onlooker(tmp_path, **more):
    proposer, kept_by_proposer = node_of(tmp_path / "proposer", **more)
    onlooker, kept_by_onlooker = node_of(tmp_path / "onlooker", keypair=ONLOOKER, **more)
    return proposer, kept_by_proposer, onlooker, kept_by_onlooker


def follow(onlooker, proposer):
    asyncio.run(onlooker._on_block_msg(proposer.chain.head.to_dict()))
    assert onlooker.chain.height == proposer.chain.height


def test_a_node_that_does_not_propose_removes_what_a_block_consumed(tmp_path):
    """Two peers can each hold another transaction of one sender for one
    nonce. The block takes one. The node that held the other kept it for
    ever: only a proposer removed what no block could charge any more."""
    proposer, proposers, onlooker, kept = a_proposer_and_an_onlooker(tmp_path)
    one, other = pay(ALICE, 0, amount=1), pay(ALICE, 0, amount=2)
    assert proposer.admit_transaction(one) is None
    assert onlooker.admit_transaction(other) is None
    park(onlooker, (ALICE, 1), (ALICE, 3), (CAROL, 0), (CAROL, 2))
    _blocks(proposer, 1)
    assert [tx.hash_hex() for tx in proposer.chain.head.transactions] == [one.hash_hex()]
    follow(onlooker, proposer)
    # alice:0 is consumed. alice:1 is now what the next block can charge, and the rest is as it was.
    assert held(kept) == ["alice:1", "alice:3", "carol:0", "carol:2"]
    for storage in (proposers, kept):
        storage.close()


def test_what_a_block_consumed_is_removed_whatever_its_number(tmp_path):
    """Rows a database already holds, under the nonce of the account or far
    under it: all of them go when a block of their sender is applied."""
    proposer, proposers, onlooker, kept = a_proposer_and_an_onlooker(
        tmp_path, nonces={ALICE.address: 5, CAROL.address: 5})
    for nonce in (0, 4, 5, 6):
        assert kept.add_to_mempool(pay(ALICE, nonce, amount=7))
        assert kept.add_to_mempool(pay(CAROL, nonce, amount=7))
    assert proposer.admit_transaction(pay(ALICE, 5)) is None
    _blocks(proposer, 1)
    follow(onlooker, proposer)
    # The block held a transaction of alice: her account is at 6. It held none of carol: her rows are not looked at.
    assert held(kept) == ["carol:0", "carol:4", "carol:5", "alice:6", "carol:6"]
    # The next block holds one of each: carol is at 6, alice at 7.
    assert proposer.admit_transaction(pay(CAROL, 5)) is None and proposer.admit_transaction(pay(ALICE, 6)) is None
    _blocks(proposer, 1)
    follow(onlooker, proposer)
    assert held(kept) == ["carol:6"]
    for storage in (proposers, kept):
        storage.close()


def test_control_a_block_of_the_node_itself_leaves_nothing_of_what_it_took(tmp_path):
    node, storage = node_of(tmp_path, nonces={ALICE.address: 5})
    assert node.admit_transaction(pay(ALICE, 5)) is None
    assert node.admit_transaction(pay(ALICE, 6)) is None
    _blocks(node, 1)
    assert [tx.nonce for tx in node.chain.head.transactions] == [5, 6] and storage.mempool_size() == 0
    storage.close()


# ---------------------------------------------------------------------------
# A full mempool gives way to what the next block can charge
# ---------------------------------------------------------------------------

def test_transactions_parked_ahead_of_their_account_no_longer_keep_an_honest_one_out(tmp_path):
    """What was measured, in small: two accounts that hold one fee each, and
    never spend it, park four transactions each without the first one. The
    mempool is full, and it stayed full: nothing of it can enter a block."""
    node, storage = node_of(tmp_path, {ALICE.address: RICH, P1.address: 1_000, P2.address: 1_000})
    park(node, *[(P1, n) for n in (1, 2, 3, 4)], *[(P2, n) for n in (1, 2, 3, 4)])
    assert storage.mempool_size() == storage.max_mempool_size == 8
    honest = make_transfer(ALICE, BOB.address, 25, nonce=0)
    assert node.admit_transaction(honest) is None
    # One row gave way: among the two farthest ahead of their accounts, the one that came last.
    assert held(storage) == ["p1:1", "p1:2", "p1:3", "p1:4", "p2:1", "p2:2", "p2:3", "alice:0"]
    _blocks(node, 1)
    assert [tx.hash_hex() for tx in node.chain.head.transactions] == [honest.hash_hex()]
    assert node.chain.state["balances"][BOB.address] == 25
    # The block freed a place. What gave way can take it again, as anything that waits can while there is room.
    assert node.admit_transaction(pay(P2, 4)) is None and storage.mempool_size() == 8
    # The mempool is full again: what waits is refused, and what the next block can charge is not.
    assert node.admit_transaction(pay(ALICE, 2)) == MEMPOOL_FULL
    assert node.admit_transaction(pay(ALICE, 1)) is None
    assert held(storage) == ["p1:1", "p1:2", "p1:3", "p1:4", "p2:1", "p2:2", "p2:3", "alice:1"]
    storage.close()


def test_a_transaction_that_waits_takes_the_place_of_none(tmp_path):
    node, storage = node_of(tmp_path, size=4)
    park(node, (P1, 1), (P1, 2), (P1, 3), (P2, 7))
    before = held(storage)
    for kp, nonce in ((ALICE, 1), (ALICE, 256), (P2, 1), (P1, 4)):
        assert node.admit_transaction(pay(kp, nonce)) == MEMPOOL_FULL, (NAMES[kp.address], nonce)
    assert held(storage) == before
    assert node.admit_transaction(pay(ALICE, 0)) is None and held(storage) == ["p1:1", "p1:2", "p1:3", "alice:0"]
    storage.close()


def test_the_row_that_gives_way_is_the_farthest_ahead_of_its_account_and_then_the_last_that_came(tmp_path):
    """How far ahead is counted from the account, not from zero: p3 is at
    nonce 10, so its transaction 12 is two ahead and waits less far than the
    transaction 3 of an account that never signed."""
    node, storage = node_of(tmp_path, size=6, nonces={P3.address: 10})
    park(node, (P1, 3), (P3, 12), (P2, 1), (P2, 3), (P1, 2), (P3, 11))
    gone = []
    for kp in (ALICE, BOB, CAROL, key(7), key(8), key(9)):
        before = held(storage)
        assert node.admit_transaction(pay(kp, 0)) is None
        gone += [row for row in before if row not in held(storage)]
        assert storage.mempool_size() == 6
    assert gone == ["p2:3", "p1:3", "p1:2", "p3:12", "p3:11", "p2:1"]
    # Everything that is left can be charged by the next block: nothing gives way any more.
    assert held(storage) == ["alice:0", "bob:0", "carol:0", "k7:0", "k8:0", "k9:0"]
    assert node.admit_transaction(pay(key(10), 0)) == MEMPOOL_FULL
    assert held(storage) == ["alice:0", "bob:0", "carol:0", "k7:0", "k8:0", "k9:0"]
    storage.close()


def test_a_full_mempool_first_loses_what_no_block_can_charge_any_more(tmp_path):
    node, storage = node_of(tmp_path, {**FUNDED, BOB.address: 1_000, CAROL.address: RICH}, size=7, per_sender=7,
                            nonces={CAROL.address: 2})
    park(node, (BOB, 0), (BOB, 1), (P1, 1), (CAROL, 2), (P1, 2), (CAROL, 3), (P1, 3))
    node.chain.state["balances"][BOB.address] = 999           # bob can no longer pay
    node.chain.state["nonces"][CAROL.address] = 3              # carol:2 is consumed
    assert node.admit_transaction(pay(ALICE, 0)) is None
    # The three rows that no block could charge are gone, all of them, and no row that waits had to give way.
    assert held(storage) == ["p1:1", "p1:2", "carol:3", "p1:3", "alice:0"]
    storage.close()


def test_a_node_goes_through_its_mempool_once_for_a_head(tmp_path, monkeypatch):
    """Going through 50,000 rows takes a fifth of a second: a node does it
    when its mempool is full, and once for each head at most. What gives
    way afterwards is taken from what it found then."""
    node, storage = node_of(tmp_path, size=4)
    passes = []
    real = storage.waiting
    monkeypatch.setattr(storage, "waiting", lambda *a, **k: passes.append(1) or real(*a, **k))

    def rows():
        return [f"{NAMES[w.sender]}:{w.nonce}" for w in real()]

    park(node, (P1, 1), (P1, 2), (P1, 3), (P1, 4))
    assert passes == []                                         # no pass while there is room
    assert node.admit_transaction(pay(ALICE, 0)) is None and len(passes) == 1
    assert node.admit_transaction(pay(CAROL, 0)) is None and len(passes) == 1
    assert rows() == ["p1:1", "p1:2", "alice:0", "carol:0"]
    # A place is freed and a row comes in after the pass, farther ahead than all the others.
    storage.remove_from_mempool([pay(ALICE, 0).hash_hex()])
    park(node, (P2, 9))
    assert node.admit_transaction(pay(BOB, 0)) is None and node.admit_transaction(pay(key(7), 0)) is None
    assert rows() == ["carol:0", "p2:9", "bob:0", "k7:0"] and len(passes) == 1
    # What the pass found is used up. The row that came after it stays until the head moves.
    assert node.admit_transaction(pay(key(8), 0)) == MEMPOOL_FULL and len(passes) == 1
    _blocks(node, 1)
    assert rows() == ["p2:9"]
    park(node, (P1, 1), (P1, 2), (P1, 3))
    passes.clear()
    assert node.admit_transaction(pay(key(8), 0)) is None and len(passes) == 1
    assert rows() == ["p1:1", "p1:2", "p1:3", "k8:0"]
    storage.close()


def test_a_row_that_left_since_the_pass_is_not_counted_as_a_place(tmp_path):
    node, storage = node_of(tmp_path, size=4)
    park(node, (P1, 1), (P1, 2), (P1, 3), (P1, 4))
    assert node.admit_transaction(pay(ALICE, 0)) is None          # the pass; p1:4 gave way
    storage.remove_from_mempool([pay(P1, 3).hash_hex(), pay(ALICE, 0).hash_hex()])
    park(node, (P2, 1), (P2, 2))
    # p1:3 is the next one the pass found, and it is gone: the place is taken from the one after it.
    assert node.admit_transaction(pay(CAROL, 0)) is None
    assert held(storage) == ["p1:1", "p2:1", "p2:2", "carol:0"]
    storage.close()


def test_when_everything_can_be_charged_nothing_gives_way(tmp_path):
    node, storage = node_of(tmp_path, size=3)
    for kp in (ALICE, CAROL, P1):
        assert node.admit_transaction(pay(kp, 0)) is None
    assert node.admit_transaction(pay(P2, 0)) == MEMPOOL_FULL
    assert held(storage) == ["alice:0", "carol:0", "p1:0"]
    storage.close()


def test_nothing_gives_way_to_a_transaction_no_row_can_hold(tmp_path):
    """A fee above 2^63 - 1 is a number no row of the database holds: the
    transaction cannot come in, whatever room there is."""
    for size in (2, 3):
        node, storage = node_of(tmp_path / str(size), {**FUNDED, ALICE.address: 2**64}, size=size)
        park(node, (P1, 1), (P1, 2))
        assert node.admit_transaction(pay(ALICE, 0, fee=2**63)) == MEMPOOL_FULL
        assert held(storage) == ["p1:1", "p1:2"]
        assert node.admit_transaction(pay(ALICE, 0, fee=2**63 - 1)) is None
        assert held(storage) == (["p1:1", "alice:0"] if size == 2 else ["p1:1", "p1:2", "alice:0"])
        storage.close()


def test_a_report_of_the_validator_finds_a_place_in_a_full_mempool(tmp_path):
    """A report that was refused was lost: the evidence had left the engine.
    And parking costs nothing while the fee floor is off: a key that holds
    nothing does it with a fee of zero."""
    node, storage, keys = _validator_node(tmp_path, liquid=10_000)
    storage.max_mempool_size = 2
    for nonce in (1, 2):
        assert node.admit_transaction(make_transfer(P1, BOB.address, 1, nonce=nonce, fee=0)) is None
    _two_votes(node, keys[2])
    assert [tx.kind.value for tx in storage.drain_mempool()] == ["transfer", "slash_consensus_equivocation"]
    assert [(w.sender == P1.address, w.nonce) for w in storage.waiting()] == [(True, 1), (False, 0)]
    storage.close()


def test_a_report_that_finds_no_room_keeps_its_evidence(tmp_path):
    """A second report, while the first still waits, has a nonce ahead of
    the account: it waits, and takes no place in a full mempool. Its
    evidence goes back to the engine, and the report is filed when it can."""
    node, storage, keys = _validator_node(tmp_path, liquid=10_000)
    me = keys[0].address
    storage.max_mempool_size = 2
    for nonce in (1, 2):
        assert node.admit_transaction(make_transfer(P1, BOB.address, 1, nonce=nonce, fee=0)) is None
    _two_votes(node, keys[2])
    _two_votes(node, keys[3])
    first, = [tx for tx in storage.drain_mempool() if tx.sender == me]
    assert storage.mempool_size() == 2 and [ev.offender for ev in node.bft.pending_evidence] == [keys[3].address]
    node._submit_evidence()                                       # still no room: nothing is lost by trying again
    assert storage.mempool_size() == 2 and [ev.offender for ev in node.bft.pending_evidence] == [keys[3].address]
    # A block takes the first report: the account is at 1, and the second one is what the next block can charge.
    storage.remove_from_mempool([first.hash_hex()])
    node.chain.state["nonces"][me] = 1
    storage.max_mempool_size = 1
    node._submit_evidence()
    second, = storage.drain_mempool()
    assert second.sender == me and second.nonce == 1 and node.bft.pending_evidence == []
    assert second.params["msg_a"]["validator"] == keys[3].address
    storage.close()


def test_a_report_refused_for_what_it_is_is_not_tried_again(tmp_path, monkeypatch):
    """Only a mempool without room says nothing against a report."""
    node, storage, keys = _validator_node(tmp_path, liquid=10_000)
    monkeypatch.setattr(node, "admit_transaction", lambda tx: "invalid signature")
    _two_votes(node, keys[2])
    assert storage.mempool_size() == 0 and node.bft.pending_evidence == []
    storage.close()


# ---------------------------------------------------------------------------
# A sender that has all its places
# ---------------------------------------------------------------------------

def test_a_sender_with_all_its_places_makes_room_among_its_own_transactions(tmp_path):
    node, storage = node_of(tmp_path, size=50)
    park(node, (CAROL, 9), (ALICE, 1), (ALICE, 4), (ALICE, 2), (ALICE, 3))
    assert node.admit_transaction(pay(ALICE, 5)) == MEMPOOL_FULL           # it waits: it takes no place
    assert node.admit_transaction(pay(ALICE, 0)) is None
    # Her own row farthest ahead gave way. The row of carol is farther ahead still, and it is not hers to take:
    # the mempool has room, it is alice who holds all her places.
    assert held(storage) == ["carol:9", "alice:1", "alice:2", "alice:3", "alice:0"]
    storage.close()


def test_a_sender_with_all_its_places_first_loses_what_no_block_can_charge(tmp_path):
    node, storage = node_of(tmp_path, size=50, nonces={ALICE.address: 2, CAROL.address: 5})
    assert storage.add_to_mempool(pay(CAROL, 0))
    for nonce in (0, 1):
        assert storage.add_to_mempool(pay(ALICE, nonce))               # consumed: a database from before
    park(node, (ALICE, 3), (ALICE, 4))
    assert node.admit_transaction(pay(ALICE, 2)) is None
    # Her rows alone were gone through: the mempool is not full, and what carol left behind is still there.
    assert held(storage) == ["carol:0", "alice:3", "alice:4", "alice:2"]
    storage.close()


def test_among_the_rows_of_a_sender_as_far_ahead_the_last_that_came_gives_way(tmp_path):
    """Two transactions for one nonce, in a database written before the rule."""
    node, storage = node_of(tmp_path, size=50)
    first, last = pay(ALICE, 3, amount=1), pay(ALICE, 3, amount=2)
    for tx in (pay(ALICE, 1), first, last, pay(ALICE, 2)):
        assert storage.add_to_mempool(tx)
    assert node.admit_transaction(pay(ALICE, 0)) is None
    assert held(storage) == ["alice:1", "alice:3", "alice:2", "alice:0"]
    assert storage.holds(first.hash_hex()) and not storage.holds(last.hash_hex())
    storage.close()


def test_a_sender_with_all_its_places_in_a_full_mempool(tmp_path):
    node, storage = node_of(tmp_path, size=4)
    park(node, (ALICE, 1), (ALICE, 2), (ALICE, 3), (ALICE, 4))
    assert node.admit_transaction(pay(ALICE, 0)) is None
    assert held(storage) == ["alice:1", "alice:2", "alice:3", "alice:0"]
    storage.close()


# ---------------------------------------------------------------------------
# From a peer, from a client
# ---------------------------------------------------------------------------

def test_from_a_peer_what_takes_a_place_is_passed_on_and_what_gave_way_can_come_again(tmp_path):
    node, storage = node_of(tmp_path, size=4)
    parked = [pay(P1, nonce) for nonce in (1, 2, 3, 4)]
    for tx in parked:
        gossip(node, tx)
    honest = pay(ALICE, 0)
    gossip(node, honest)
    assert held(storage) == ["p1:1", "p1:2", "p1:3", "alice:0"]
    assert node.network.sent == [tx.to_dict() for tx in parked + [honest]]
    # The row that gave way is forgotten: the day there is room, a peer can bring it again.
    gossip(node, parked[3])
    assert held(storage) == ["p1:1", "p1:2", "p1:3", "alice:0"]         # no room today: it waits
    _blocks(node, 1)
    gossip(node, parked[3])
    assert held(storage) == ["p1:1", "p1:2", "p1:3", "p1:4"]
    storage.close()


def test_what_no_block_can_charge_any_more_is_forgotten_too(tmp_path):
    """A sender that could not pay can be paid tomorrow: what the pass
    removed for that reason can come again from a peer."""
    node, storage = node_of(tmp_path, {**FUNDED, BOB.address: 1_000}, size=2)
    late = pay(BOB, 0)
    gossip(node, late)
    gossip(node, pay(P1, 1))
    node.chain.state["balances"][BOB.address] = 0
    gossip(node, pay(ALICE, 0))
    assert held(storage) == ["p1:1", "alice:0"]
    node.chain.state["balances"][BOB.address] = 5_000
    storage.remove_from_mempool([pay(P1, 1).hash_hex()])
    gossip(node, late)
    assert held(storage) == ["alice:0", "bob:0"]
    storage.close()


def test_a_client_is_told_to_come_back_only_when_nothing_can_give_way(tmp_path):
    node, storage = node_of(tmp_path, size=2)
    park(node, (P1, 1), (P1, 2))
    honest = pay(ALICE, 0)
    assert post(node, honest) == (200, {"hash": honest.hash_hex()})
    status, answer = post(node, pay(CAROL, 5))                           # it waits
    assert status == 429 and answer["error"] == MEMPOOL_FULL
    assert post(node, pay(CAROL, 0))[0] == 200                           # p1:1 gave way
    status, answer = post(node, pay(P2, 0))                              # nothing waits any more
    assert status == 429 and answer["error"] == MEMPOOL_FULL
    assert held(storage) == ["alice:0", "carol:0"]
    storage.close()
