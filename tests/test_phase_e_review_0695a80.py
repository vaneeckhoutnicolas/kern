# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of 0695a80 (docs/consensus-locking.md section 10.9).

P2 a. A signed PROPOSE whose valid round is malformed or lacks a valid
proof was rejected before the node recorded it as the first proposal of
its (level, round). A second, different proposal from the same proposer
for that round then became the first one, and the two conflicting
signatures were not kept as equivocation evidence.

P2 b. The engine keeps at most MAX_ROUND_STATES round states, and
prune_below only drops whole levels. After many rounds without
finalization at one level, in_window refuses every new round: the level
can no longer finalize, even once the network is stable. A single
validator voting ahead, at the next levels, fills the cap far sooner.

Every test fails on 0695a80 except the two marked as controls, which pass
on both versions."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kern.bft import (BftEngine, ConsensusMessage, MAX_ROUND_DISTANCE, MAX_ROUND_STATES,
                      MsgKind, QuorumCertificate)
from kern.consensus import propose_block, select_proposer
from kern.node import Node

from test_phase_e_invalid_first_proposal import _keys, _own_votes, _run, _setup, _vs


# ---------------------------------------------------------------- P2 a

def _block(chain, kp, monkeypatch, ts, round_):
    import kern.consensus as consensus_mod
    with monkeypatch.context() as mp:
        mp.setattr(consensus_mod.time, "time", lambda: ts)
        return propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                             proposer_pubkey_b58=kp.public_key_b58,
                             state_before=chain.state, round_=round_)


def _signed(kp, kind, h, round_, vr=-1):
    m = ConsensusMessage(kind=kind, level=1, round=round_, block_hash=h, validator=kp.address,
                         validator_pubkey=kp.public_key_b58, valid_round=vr)
    m.sign(kp)
    return m


def _reproposal_setup(tmp_path, monkeypatch):
    """The node sits at round 1. Block X has payload round 0; the proposer
    of round 1 proposes it again with valid round 0."""
    keys, chain, p0, me, node, storage = _setup(tmp_path)
    by_addr = {k.address: k for k in keys}
    p1 = by_addr[select_proposer(chain.head.hash_hex(), chain.validators, 1)["address"]]
    x = _block(chain, p0, monkeypatch, 1_700_000_100, 0)
    h = x.hash_hex()
    good = QuorumCertificate(kind=MsgKind.PREENDORSE, level=1, round=0, block_hash=h,
                             signatures={k.address: _signed(k, MsgKind.PREENDORSE, h, 0).signature
                                         for k in keys[:3]})
    weak = QuorumCertificate(kind=MsgKind.PREENDORSE, level=1, round=0, block_hash=h,
                             signatures=dict(list(good.signatures.items())[:1]))
    pmsg = _signed(p1, MsgKind.PROPOSE, h, 1, vr=0)
    node._round = 1
    node._refresh_engine()
    return keys, chain, p1, me, node, storage, x, pmsg, good, weak


def test_equivocation_kept_when_the_first_proposal_has_an_impossible_valid_round(tmp_path, monkeypatch):
    """The proposer of round 1 signs a new proposal (valid round -1) for a
    block whose payload round is 0: the valid round it signed does not fit
    the block. (A valid round not lower than the round is already refused
    when the message is decoded, so it is not a signed message at all.)"""
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    a = Node._envelope(x, _signed(p1, MsgKind.PROPOSE, x.hash_hex(), 1, vr=-1), None)
    y = _block(chain, p1, monkeypatch, 1_700_000_101, 1)
    b = Node._envelope(y, _signed(p1, MsgKind.PROPOSE, y.hash_hex(), 1), None)
    _run(node, a, b)
    ev = node.bft.proposal_evidence
    assert len(ev) == 1 and ev[0].verify()[0]
    assert {ev[0].msg_a.block_hash, ev[0].msg_b.block_hash} == {x.hash_hex(), y.hash_hex()}
    # As for an invalid first block (section 10.8): no vote in that round,
    # and the second block is neither validated nor kept.
    assert _own_votes(node, me) == []
    assert (1, y.hash_hex()) not in node._pending
    storage.close()


def test_equivocation_kept_when_the_first_reproposal_has_a_bad_proof(tmp_path, monkeypatch):
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    a = Node._envelope(x, pmsg, weak)                    # proof below two thirds
    y = _block(chain, p1, monkeypatch, 1_700_000_101, 1)
    b = Node._envelope(y, _signed(p1, MsgKind.PROPOSE, y.hash_hex(), 1), None)
    _run(node, a, b)
    ev = node.bft.proposal_evidence
    assert len(ev) == 1 and ev[0].verify()[0]
    assert _own_votes(node, me) == []
    storage.close()


@pytest.mark.parametrize("damage", ["missing", "weak"])
def test_control_a_damaged_proof_does_not_condemn_the_round(tmp_path, monkeypatch, damage):
    """Control. The proof is not signed by the proposer: a relay may strip or
    damage it. The same signed proposal, arriving later with its valid
    proof, is still pre-endorsed, and no evidence is made up."""
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    damaged = Node._envelope(x, pmsg, None if damage == "missing" else weak)
    genuine = Node._envelope(x, ConsensusMessage.from_dict(pmsg.to_dict()), good)
    _run(node, damaged, genuine)
    votes = _own_votes(node, me)
    assert [(m.kind, m.round, m.block_hash) for m in votes] == [
        (MsgKind.PREENDORSE, 1, x.hash_hex())]
    assert node.bft.proposal_evidence == []
    storage.close()


# ---------------------------------------------------------------- P2 b

def _engine(keys):
    e = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                  validator_set=_vs(keys), current_round=0)
    e.min_level = 1
    return e


def _vote(kp, kind, r, h):
    m = ConsensusMessage(kind=kind, level=1, round=r, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def _vote_at(kp, kind, level, r, h):
    m = ConsensusMessage(kind=kind, level=level, round=r, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


@pytest.mark.parametrize("pattern", ["one_vote_per_round", "byzantine_votes_ahead"])
def test_a_level_still_finalizes_after_many_rounds_without_finalization(pattern):
    keys = _keys()
    e = _engine(keys)
    stuck = MAX_ROUND_STATES + 4 if pattern == "one_vote_per_round" else 120
    for r in range(stuck):                               # no quorum in any round
        e.enter_round(1, r)
        if pattern == "one_vote_per_round":
            e.on_message(_vote(keys[1], MsgKind.PREENDORSE, r, "aa" * 32))
        else:
            # One validator signs a vote at every (level, round) the window
            # accepts, the next two levels included.
            for lvl in (1, 2, 3):
                for rr in range(max(0, r - MAX_ROUND_DISTANCE), r + MAX_ROUND_DISTANCE + 1):
                    e.on_message(_vote_at(keys[1], MsgKind.PREENDORSE, lvl, rr, "aa" * 32))
    assert len(e.states) <= 3 * (2 * MAX_ROUND_DISTANCE + 1)
    r = stuck                                            # the network is stable again
    e.enter_round(1, r)
    h = "bb" * 32
    assert e.in_window(1, r)
    out = e.on_proposal(1, r, h)
    assert [m.kind for m in out] == [MsgKind.PREENDORSE]
    for kp in keys[1:]:
        e.on_message(_vote(kp, MsgKind.PREENDORSE, r, h))
    for kp in keys[1:]:
        e.on_message(_vote(kp, MsgKind.ENDORSE, r, h))
    assert e.find_endorse_qc(1, h) is not None


def test_the_lock_and_valid_round_outlive_the_window():
    """Old rounds are dropped, but the certificate of the valid round, which a
    re-proposal needs, is kept however far the rounds move on."""
    keys = _keys()
    e = _engine(keys)
    h = "cc" * 32
    e.on_proposal(1, 0, h)
    for kp in keys[1:]:
        e.on_message(_vote(kp, MsgKind.PREENDORSE, 0, h))
    lv = e.level_state(1)
    assert (lv.locked_round, lv.valid_round) == (0, 0)
    for r in range(1, 60):
        e.enter_round(1, r)
        e.on_message(_vote(keys[1], MsgKind.PREENDORSE, r, "aa" * 32))
    assert e.find_preendorse_qc(1, 0, h) is not None
    assert (1, 1) not in e.states and (1, 59) in e.states


def test_node_round_data_follows_the_window(tmp_path, monkeypatch):
    """Proposals and blocks of rounds that left the window are dropped by
    the node, except those of the lock; on 0695a80 they stayed until the
    level finalized."""
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    locked = _block(chain, proposer, monkeypatch, 1_700_000_100, 0)
    lh = locked.hash_hex()
    for r in range(40):
        h = lh if r == 0 else f"{r:064x}"
        node._round_proposal[(1, r)] = (h, None, {})
        node._pending[(1, h)] = locked
        node._invalid_proposals.add((1, f"{r + 100:064x}"))
    node.bft.restore_lock(1, 0, lh, 0, lh)
    asyncio.run(node._set_round(40))
    rounds = sorted(r for (_lvl, r) in node._round_proposal)
    assert rounds == [0] + list(range(40 - MAX_ROUND_DISTANCE, 40))
    assert (1, lh) in node._pending and (1, f"{1:064x}") not in node._pending
    assert len(node._pending) == 1 + MAX_ROUND_DISTANCE
    assert not node._invalid_proposals                   # none referred to by a kept proposal
    storage.close()
