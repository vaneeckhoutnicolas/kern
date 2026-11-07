# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of e67ed17.

P1. The node kept the first block hash of a (level, round) before
validating the block. When a byzantine proposer sent an invalid block A
first, then a different, valid block B for the same round, A failed
validation and the engine never heard of it; B was then treated as a
conflicting proposal and handed to `BftEngine.on_proposal` without being
validated. The engine had no proposal for that round, took B as the first
one and could pre-endorse it: an honest validator signed a vote for a
block it had never validated. The equivocation was also lost, since the
engine never had the PROPOSE message of A.

The node now keeps the first signed PROPOSE of each (level, round), valid
or not. A later, different one is passed to
`BftEngine.record_proposal_equivocation`, which keeps the two signed
messages as evidence and never votes. Only a validated block reaches
`BftEngine.on_proposal`."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern import node as node_mod
from kern.bft import BftEngine, ConsensusMessage, MsgKind, ProposalEquivocation
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, state_root_hex
from kern.consensus import BakerConfig, propose_block, select_proposer
from kern.crypto import KernKeypair


def _keys(n=4):
    return [KernKeypair.from_seed(bytes([0xC0 + i]) * 32) for i in range(n)]


def _vs(keys):
    return [{"address": k.address, "pubkey": k.public_key_b58, "stake": 100} for k in keys]


def _chain(keys):
    vs = _vs(keys)
    state = {"balances": {}, "nonces": {}, "contracts": {}, "validators": vs}
    h = BlockHeader(level=0, payload_round=0, timestamp=1_700_000_000, parent_hash="0" * 64,
                    state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                    proposer=keys[0].address, proposer_pubkey=keys[0].public_key_b58)
    h.sign(keys[0])
    return Chain(Block(header=h), vs, initial_state=state)


class _Net:
    def __init__(self):
        self.votes = []
        self.proposals = []

    async def broadcast_proposal(self, env):
        self.proposals.append(env)

    async def broadcast_consensus(self, msg):
        self.votes.append(msg)

    async def broadcast_block(self, block):
        pass


def _setup(tmp_path, name="n"):
    from kern.node import Node
    from kern.storage import Storage
    keys = _keys()
    chain = _chain(keys)
    proposer = next(k for k in keys if k.address == select_proposer(
        chain.head.hash_hex(), chain.validators, 0)["address"])
    me = next(k for k in keys if k.address != proposer.address)
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    storage = Storage(str(path))
    node = Node(str(path), chain, storage, BakerConfig(me, me.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)
    node.network = _Net()
    return keys, chain, proposer, me, node, storage


def _envelope(chain, proposer, monkeypatch, ts, invalid=False):
    import kern.consensus as consensus_mod
    from kern.node import Node
    with monkeypatch.context() as mp:
        mp.setattr(consensus_mod.time, "time", lambda: ts)
        block = propose_block(parent=chain.head, mempool=[], proposer_keypair=proposer,
                              proposer_pubkey_b58=proposer.public_key_b58,
                              state_before=chain.state, round_=0)
    if invalid:
        # A wrong state root, under a valid proposer signature: the block
        # is well formed and signed but fails full validation.
        block.header.state_root = "ee" * 32
        block.header.sign(proposer)
    m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=0, block_hash=block.hash_hex(),
                         validator=proposer.address, validator_pubkey=proposer.public_key_b58)
    m.sign(proposer)
    return Node._envelope(block, m, None)


def _run(node, *envelopes):
    async def go():
        for e in envelopes:
            await node._on_proposal_msg(e)
        await asyncio.sleep(0)               # let relayed broadcasts run
    asyncio.run(go())


def _own_votes(node, me):
    votes = [m if isinstance(m, ConsensusMessage) else ConsensusMessage.from_dict(m)
             for m in node.network.votes]
    return [m for m in votes if m.validator == me.address]


# ----------------------------------------------------------------- the finding

def test_no_vote_on_a_valid_block_that_follows_an_invalid_first_proposal(tmp_path, monkeypatch):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    _run(node, bad, good)
    assert _own_votes(node, me) == []                        # nothing signed
    assert [r for r in node.journal.records if r["level"] == 1] == []
    assert node.bft.level_state(1).locked_hash is None
    assert not [k for k in node._pending if k[0] == 1]       # B neither validated nor kept
    storage.close()


def test_the_equivocation_is_kept_when_the_first_proposal_was_invalid(tmp_path, monkeypatch):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    _run(node, bad, good)
    ev = node.bft.proposal_evidence
    assert len(ev) == 1 and ev[0].offender == proposer.address and ev[0].verify()[0]
    assert {ev[0].msg_a.block_hash, ev[0].msg_b.block_hash} == {
        bad["proposal"]["block_hash"], good["proposal"]["block_hash"]}
    storage.close()


def test_the_conflict_relay_carries_both_signed_proposals(tmp_path, monkeypatch):
    """Another node that saw only one of the two proposals receives the
    other through the relay and keeps the same evidence."""
    keys, chain, proposer, me, node, storage = _setup(tmp_path, "a")
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    _run(node, bad, good)
    relayed = {e["proposal"]["block_hash"] for e in node.network.proposals}
    assert relayed == {bad["proposal"]["block_hash"], good["proposal"]["block_hash"]}
    storage.close()

    _, _, _, _, other, storage_b = _setup(tmp_path, "b")
    _run(other, good, *node.network.proposals)               # B first, then the relay
    assert len(other.bft.proposal_evidence) == 1 and other.bft.proposal_evidence[0].verify()[0]
    storage_b.close()


def test_an_invalid_first_proposal_is_validated_once(tmp_path, monkeypatch):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    calls = []
    real = node_mod.validate_and_apply
    monkeypatch.setattr(node_mod, "validate_and_apply",
                        lambda *a, **k: calls.append(1) or real(*a, **k))
    again = dict(bad)
    again["proposal"] = dict(bad["proposal"], valid_round=-1)
    node._seen_proposals.clear()                             # the same block arrives again
    _run(node, bad)
    node._seen_proposals.clear()
    _run(node, again)
    assert len(calls) == 1
    storage.close()


def test_a_valid_first_proposal_is_still_pre_endorsed(tmp_path, monkeypatch):
    """Control: the order valid then invalid keeps working as before."""
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    _run(node, good, bad)
    votes = _own_votes(node, me)
    assert [m.kind for m in votes] == [MsgKind.PREENDORSE]
    assert votes[0].block_hash == good["proposal"]["block_hash"]
    assert len(node.bft.proposal_evidence) == 1
    storage.close()


# ------------------------------------------------------------ engine API

def _engine(keys):
    e = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                  validator_set=_vs(keys), current_round=0)
    e.min_level = 1
    return e


def _prop(kp, h, vr=-1):
    m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=0, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58,
                         valid_round=vr)
    m.sign(kp)
    return m


def test_record_proposal_equivocation_keeps_evidence_and_never_votes():
    keys = _keys()
    e = _engine(keys)
    a, b = _prop(keys[1], "aa" * 32), _prop(keys[1], "bb" * 32)
    assert e.record_proposal_equivocation(a, b) is True
    assert e.record_proposal_equivocation(b, a) is False     # already kept
    assert len(e.proposal_evidence) == 1 and e.proposal_evidence[0].verify()[0]
    state = e.states.get((1, 0))
    assert state is None or state.proposed_block_hash is None
    # The round is still open to a validated proposal.
    assert [m.kind for m in e.on_proposal(1, 0, "aa" * 32, proposal_msg=a)] == [MsgKind.PREENDORSE]


@pytest.mark.parametrize("case", ["same", "other_signer", "forged", "other_round"])
def test_record_proposal_equivocation_refuses_what_is_not_evidence(case):
    keys = _keys()
    e = _engine(keys)
    a, b = _prop(keys[1], "aa" * 32), _prop(keys[1], "bb" * 32)
    if case == "same":
        b = _prop(keys[1], "aa" * 32)
    elif case == "other_signer":
        b = _prop(keys[2], "bb" * 32)
    elif case == "forged":
        b.signature = a.signature
    elif case == "other_round":
        b = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=1, block_hash="bb" * 32,
                             validator=keys[1].address, validator_pubkey=keys[1].public_key_b58)
        b.sign(keys[1])
    assert e.record_proposal_equivocation(a, b) is False
    assert e.proposal_evidence == []
