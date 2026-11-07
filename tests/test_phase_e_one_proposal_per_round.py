# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of 7e005a6 (docs/consensus-locking.md section 10.10).

The node returned early only when a second signed PROPOSE for a (level,
round) named another block. The same block with another valid round was
kept as evidence and then went on to `BftEngine.on_proposal`: the comment
"never a vote" did not hold. When the first message had an impossible
valid round (it occupies the round but never reaches the engine, section
10.9), the second one became the engine's proposal and the validator
pre-endorsed it.

Rule now, as in Tendermint: once a signed PROPOSE occupies a (level,
round), only that same signed message can go further (it may come back
with a valid proof, which the proposer does not sign). Any other signed
PROPOSE for that round, same block or not, is evidence only, relayed once
with the first, and never reaches the engine.

Both tests fail on 7e005a6."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kern.bft import ConsensusMessage, MsgKind, QuorumCertificate
from kern.consensus import select_proposer
from kern.node import Node

from test_phase_e_invalid_first_proposal import _own_votes, _run, _setup
from test_phase_e_review_0695a80 import _block, _signed


def _at_round(tmp_path, monkeypatch, round_):
    """Node at `round_`; block X has payload round 0; returns the proposer
    of `round_` and a pre-endorsement certificate for X at any round."""
    keys, chain, p0, me, node, storage = _setup(tmp_path)
    by_addr = {k.address: k for k in keys}
    pr = by_addr[select_proposer(chain.head.hash_hex(), chain.validators, round_)["address"]]
    x = _block(chain, p0, monkeypatch, 1_700_000_100, 0)
    h = x.hash_hex()

    def polka(r):
        return QuorumCertificate(kind=MsgKind.PREENDORSE, level=1, round=r, block_hash=h,
                                 signatures={k.address: _signed(k, MsgKind.PREENDORSE, h, r).signature
                                             for k in keys[:3]})
    node._round = round_
    node._refresh_engine()
    return node, storage, me, pr, x, polka


def test_no_vote_on_a_second_message_for_the_same_block(tmp_path, monkeypatch):
    """The first PROPOSE of round 1 signs an impossible valid round for X
    (-1, while X's payload round is 0); the second signs X with valid
    round 0 and a valid proof."""
    node, storage, me, p1, x, polka = _at_round(tmp_path, monkeypatch, 1)
    a = Node._envelope(x, _signed(p1, MsgKind.PROPOSE, x.hash_hex(), 1, vr=-1), None)
    b = Node._envelope(x, _signed(p1, MsgKind.PROPOSE, x.hash_hex(), 1, vr=0), polka(0))
    _run(node, a, b)
    assert _own_votes(node, me) == []
    ev = node.bft.proposal_evidence
    assert len(ev) == 1 and ev[0].verify()[0]
    assert {ev[0].msg_a.valid_round, ev[0].msg_b.valid_round} == {-1, 0}
    storage.close()


def test_a_second_valid_message_for_the_same_block_never_reaches_the_engine(tmp_path, monkeypatch):
    """Round 2: X proposed with valid round 0, then X again with valid
    round 1, both with valid proofs. Only the first reaches the engine."""
    node, storage, me, p2, x, polka = _at_round(tmp_path, monkeypatch, 2)
    first = Node._envelope(x, _signed(p2, MsgKind.PROPOSE, x.hash_hex(), 2, vr=0), polka(0))
    second = Node._envelope(x, _signed(p2, MsgKind.PROPOSE, x.hash_hex(), 2, vr=1), polka(1))
    calls = []
    real = node.bft.on_proposal
    monkeypatch.setattr(node.bft, "on_proposal",
                        lambda *a, **k: calls.append(k.get("valid_round")) or real(*a, **k))
    _run(node, first, second)
    assert calls == [0]
    votes = _own_votes(node, me)
    assert [(m.kind, m.round) for m in votes] == [(MsgKind.PREENDORSE, 2)]
    assert len(node.bft.proposal_evidence) == 1
    relayed = {ConsensusMessage.from_dict(e["proposal"]).valid_round
               for e in node.network.proposals}
    assert relayed == {0, 1}                              # both, for the other nodes
    storage.close()
