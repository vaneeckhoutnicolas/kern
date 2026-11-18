# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A node checks and relays a vote only if its engine can use it.

Found on 13 November 2026, while measuring what a devnet sends. A vote
received from a peer had its signature checked against the public key the
message itself carries, and was then relayed to every connection as soon
as it was new to the node, whatever the engine had made of it. A vote
signed by a key that is not a validator, or for a level far away, was
therefore relayed by every node to all its peers, and its signature was
checked by each of them: one message sent to one node by anybody became
N x C messages on a network of N nodes with C connections each. A copy of
a vote the node already held was checked again before it was recognized.

The node now asks the engine first (`BftEngine.wants`): a PREENDORSE or
an ENDORSE of a validator of the set, for a level and a round inside the
window, that is the first vote of that validator there or the first one
that conflicts with it. Only such a vote has its signature checked, and
only such a vote is relayed. The tests fail on 785bcd1, except the six
marked as controls.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kern.bft import ConsensusMessage, MsgKind
from kern.consensus import BakerConfig
from kern.crypto import KernKeypair

from test_phase_e_invalid_first_proposal import _Net, _chain, _keys, _setup

OUTSIDER = KernKeypair.from_seed(bytes([0xEE]) * 32)
HASH_A, HASH_B, HASH_C = "aa" * 32, "bb" * 32, "cc" * 32


def _vote(kp, kind=MsgKind.PREENDORSE, level=1, round_=0, block_hash=HASH_A):
    message = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=block_hash,
                               validator=kp.address, validator_pubkey=kp.public_key_b58)
    message.sign(kp)
    return message


def _deliver(node, *votes):
    """Hand `votes` to the node as the network layer does, and let the
    relays it schedules run."""
    async def go():
        for vote in votes:
            await node._on_consensus_msg(vote.to_dict())
            for _ in range(5):
                await asyncio.sleep(0)
    asyncio.run(go())


def _relayed(node, kp):
    return [m for m in node.network.votes if m["validator"] == kp.address]


def _ready(tmp_path):
    """A node of a network of four validators, at level 1 and round 0, with
    another validator of the set to send it votes."""
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    node._refresh_engine()                     # what the consensus loop does at each tick
    assert (node.bft.min_level, node.bft.current_round) == (1, 0)
    other = next(k for k in keys if k.address not in (me.address, proposer.address))
    return node, storage, other


def _count_checks(monkeypatch):
    checks = []
    real = ConsensusMessage.verify_signature

    def counting(self):
        checks.append((self.validator, self.level, self.block_hash))
        return real(self)

    monkeypatch.setattr(ConsensusMessage, "verify_signature", counting)
    return checks


# ------------------------------------------------------------- what is relayed

def test_control_a_vote_of_a_validator_is_recorded_and_relayed_once(tmp_path):
    node, storage, other = _ready(tmp_path)
    vote = _vote(other)
    _deliver(node, vote, vote)
    assert node.bft.states[(1, 0)].preendorsements[other.address].block_hash == HASH_A
    assert len(_relayed(node, other)) == 1
    storage.close()


def test_control_the_votes_of_two_validators_for_one_round_are_both_taken(tmp_path):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    node._refresh_engine()
    others = [k for k in keys if k.address != me.address]
    _deliver(node, *[_vote(k) for k in others], *[_vote(k, kind=MsgKind.ENDORSE) for k in others])
    state = node.bft.states[(1, 0)]
    assert set(state.preendorsements) == set(state.endorsements) == {k.address for k in others}
    assert sorted((m["validator"], m["kind"]) for m in node.network.votes) == sorted(
        (k.address, kind) for k in others for kind in ("preendorse", "endorse"))
    storage.close()


def test_a_vote_of_a_key_that_is_not_a_validator_is_not_relayed(tmp_path):
    node, storage, other = _ready(tmp_path)
    assert not node.bft._is_validator(OUTSIDER.address)
    forged = _vote(OUTSIDER)
    assert forged.verify_signature()           # well formed, and signed by the key it names
    _deliver(node, forged)
    assert node.network.votes == []
    assert node.bft.states.get((1, 0)) is None or not node.bft.states[(1, 0)].preendorsements
    storage.close()


def test_a_vote_for_a_level_outside_the_window_is_not_relayed(tmp_path):
    node, storage, other = _ready(tmp_path)
    for level in (0, 4, 10**9):                # the window is levels 1 to 3
        _deliver(node, _vote(other, level=level))
    assert node.network.votes == []
    storage.close()


def test_a_vote_for_a_round_outside_the_window_is_not_relayed(tmp_path):
    node, storage, other = _ready(tmp_path)
    _deliver(node, _vote(other, round_=9), _vote(other, round_=10**6))    # rounds 0 to 8 are in
    assert node.network.votes == []
    _deliver(node, _vote(other, round_=8))
    assert len(_relayed(node, other)) == 1
    storage.close()


def test_a_propose_message_on_the_vote_channel_is_dropped_unchecked(tmp_path, monkeypatch):
    node, storage, other = _ready(tmp_path)
    checks = _count_checks(monkeypatch)
    _deliver(node, _vote(other, kind=MsgKind.PROPOSE))
    assert checks == [] and node.network.votes == []
    storage.close()


def test_only_the_first_conflicting_vote_of_a_validator_is_relayed(tmp_path):
    """The first vote, then the first one that conflicts with it: the two
    every node needs to hold the evidence. A third hash adds nothing."""
    node, storage, other = _ready(tmp_path)
    _deliver(node, _vote(other, block_hash=HASH_A), _vote(other, block_hash=HASH_B),
             _vote(other, block_hash=HASH_C), _vote(other, block_hash=HASH_B))
    assert [m["block_hash"] for m in _relayed(node, other)] == [HASH_A, HASH_B]
    assert node.bft.states[(1, 0)].preendorsements[other.address].block_hash == HASH_A
    assert (other.address, "preendorse", 1, 0) in node.bft._evidence_keys
    storage.close()


def test_forgetting_the_votes_seen_does_not_relay_them_again(tmp_path):
    """The set of votes seen is emptied when it grows past its bound. What
    the engine holds decides, not that set."""
    node, storage, other = _ready(tmp_path)
    vote = _vote(other)
    _deliver(node, vote)
    node._seen_cons.clear()
    _deliver(node, vote)
    assert len(_relayed(node, other)) == 1
    storage.close()


def test_a_vote_that_was_outside_the_window_counts_once_it_is_inside(tmp_path):
    """A vote that came too early is not remembered as seen: when the node
    reaches its level, the same vote is taken."""
    node, storage, other = _ready(tmp_path)
    early = _vote(other, level=4)
    _deliver(node, early)
    assert node.network.votes == []
    node.bft.prune_below(2)                    # level 1 is final: the window is now 2 to 4
    _deliver(node, early)
    assert node.bft.states[(4, 0)].preendorsements[other.address].block_hash == HASH_A
    assert len(_relayed(node, other)) == 1
    storage.close()


def test_a_bad_entry_read_in_a_proposal_does_not_hide_the_real_vote(tmp_path):
    """The endorsements a proposal carries in `commits` are handed to the
    engine as votes. One whose signature does not verify is refused by the
    engine. The real vote, received from a peer afterwards, is still taken:
    it used to be dropped as already seen."""
    node, storage, other = _ready(tmp_path)
    real = _vote(other, kind=MsgKind.ENDORSE)
    bad = ConsensusMessage.from_dict(real.to_dict())
    bad.signature = _vote(other, kind=MsgKind.ENDORSE, block_hash=HASH_B).signature
    assert not bad.verify_signature()
    asyncio.run(node._ingest_consensus(bad, from_wire=False))      # what _ingest_commits does
    held = node.bft.states.get((1, 0))
    assert held is None or other.address not in held.endorsements
    _deliver(node, real)
    assert node.bft.states[(1, 0)].endorsements[other.address].block_hash == HASH_A
    assert len(_relayed(node, other)) == 1
    storage.close()


# ------------------------------------------------------- what is checked

def test_control_a_new_vote_of_a_validator_is_checked(tmp_path, monkeypatch):
    node, storage, other = _ready(tmp_path)
    checks = _count_checks(monkeypatch)
    _deliver(node, _vote(other))
    assert checks and all(check[0] == other.address for check in checks)
    storage.close()


def test_a_vote_the_node_already_holds_is_not_checked_again(tmp_path, monkeypatch):
    node, storage, other = _ready(tmp_path)
    vote = _vote(other)
    _deliver(node, vote)
    checks = _count_checks(monkeypatch)
    _deliver(node, vote, vote, vote)
    assert checks == []
    storage.close()


def test_a_vote_the_engine_cannot_use_is_dropped_before_its_signature_is_checked(tmp_path, monkeypatch):
    node, storage, other = _ready(tmp_path)
    checks = _count_checks(monkeypatch)
    _deliver(node, _vote(OUTSIDER), _vote(other, level=10**9), _vote(other, round_=9))
    assert checks == []
    storage.close()


def test_control_a_forged_copy_changes_nothing(tmp_path):
    """A vote that names a validator under a signature that does not verify
    is neither recorded nor relayed, and the real vote still goes through,
    before it or after it."""
    node, storage, other = _ready(tmp_path)
    real = _vote(other)
    forged = ConsensusMessage.from_dict({**real.to_dict(), "block_hash": HASH_B})   # signature of HASH_A
    assert not forged.verify_signature()
    _deliver(node, forged, real, forged)
    assert [m["block_hash"] for m in _relayed(node, other)] == [HASH_A]
    assert node.bft.states[(1, 0)].preendorsements[other.address].block_hash == HASH_A
    assert node.bft.pending_evidence == [] and not node.bft._evidence_keys
    storage.close()


def test_control_a_node_without_a_validator_key_takes_no_vote(tmp_path):
    """A follower has no engine: it keeps no vote, checks none and relays
    none. It learns of a block when the block reaches it with its quorum."""
    from kern.node import Node
    from kern.storage import Storage
    keys = _keys()
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), _chain(keys), storage, None, rpc_port=0, p2p_port=0, peers=[],
                block_time=1.0)
    node.network = _Net()
    assert node.bft is None
    _deliver(node, _vote(keys[1]), _vote(OUTSIDER))
    assert node.network.votes == []
    storage.close()


# ----------------------------------------------------------- on a network

class _Wire:
    """Delivers what a node broadcasts to every other node, and counts it."""

    def __init__(self, log):
        self.log = log
        self.peers = []

    async def broadcast_consensus(self, msg):
        self.log.append(msg)
        for peer in self.peers:
            await peer._on_consensus_msg(msg)

    async def broadcast_proposal(self, env):
        pass

    async def broadcast_block(self, block):
        pass


def _network(tmp_path):
    from kern.node import Node
    from kern.storage import Storage
    keys, log, nodes, stores = _keys(), [], [], []
    for index, key in enumerate(keys):
        path = tmp_path / f"node{index}"
        path.mkdir()
        stores.append(Storage(str(path)))
        node = Node(str(path), _chain(keys), stores[-1], BakerConfig(key, key.public_key_b58),
                    rpc_port=0, p2p_port=0, peers=[], block_time=1.0)
        node.network = _Wire(log)
        node._refresh_engine()
        nodes.append(node)
    for node in nodes:
        node.network.peers = [peer for peer in nodes if peer is not node]
    return keys, nodes, stores, log


def _inject(node, vote):
    async def go():
        await node._on_consensus_msg(vote.to_dict())
        for _ in range(50):
            await asyncio.sleep(0)
    asyncio.run(go())


def test_control_a_vote_of_a_validator_reaches_every_node(tmp_path):
    keys, nodes, stores, log = _network(tmp_path)
    _inject(nodes[0], _vote(keys[3]))
    for node in nodes:
        assert node.bft.states[(1, 0)].preendorsements[keys[3].address].block_hash == HASH_A
    assert len(log) == len(nodes)              # each node passes it on once
    for store in stores:
        store.close()


def test_a_vote_of_an_outsider_stops_at_the_first_node(tmp_path):
    """On 785bcd1 each of the four nodes relayed it to all the others."""
    keys, nodes, stores, log = _network(tmp_path)
    for index in range(20):
        _inject(nodes[0], _vote(OUTSIDER, level=10**9 + index, block_hash=f"{index:064x}"))
        _inject(nodes[0], _vote(OUTSIDER, block_hash=f"{index:064x}"))
    assert log == []
    for store in stores:
        store.close()
