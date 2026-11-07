# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase C, C1: quorum certificates are bound to the proposed block.

External review, point A: the engine counted every vote of a round towards
the quorum, whatever block it was for, then froze a certificate that could
carry a signature over another block. Strict block validation rejected that
certificate and nothing rebuilt it, so one malicious validator out of four
could stop finalization of a round.

The scenario below is the reviewer's: four equal validators, one of them
voting for block B while the three honest ones vote for block A."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.bft import BftEngine, ConsensusMessage, MsgKind, verify_commits
from kern.crypto import KernKeypair

A = "aa" * 32
B = "bb" * 32


def _setup():
    keys = [KernKeypair.from_seed(bytes([0x80 + i]) * 32) for i in range(4)]
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": 100} for k in keys]
    eng = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58, validator_set=vs)
    return keys, vs, eng


def _vote(kp, kind, block_hash, level=1, round_=0):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=block_hash,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def test_hostile_vote_never_enters_a_certificate():
    keys, vs, eng = _setup()
    honest1, honest2, evil = keys[1], keys[2], keys[3]
    eng.on_proposal(1, 0, A)                                  # own PREENDORSE(A)
    eng.on_message(_vote(honest1, MsgKind.PREENDORSE, A))
    eng.on_message(_vote(evil, MsgKind.PREENDORSE, B))        # 3 votes, but only 2 for A
    assert eng.get_preendorse_qc(1, 0) is None
    out = eng.on_message(_vote(honest2, MsgKind.PREENDORSE, A))
    qc = eng.get_preendorse_qc(1, 0)
    assert qc is not None and qc.block_hash == A
    assert evil.address not in qc.signatures
    assert any(m.kind == MsgKind.ENDORSE and m.block_hash == A for m in out)

    eng.on_message(_vote(honest1, MsgKind.ENDORSE, A))
    eng.on_message(_vote(evil, MsgKind.ENDORSE, B))
    assert eng.get_endorse_qc(1, 0) is None                   # no poisoned certificate
    eng.on_message(_vote(honest2, MsgKind.ENDORSE, A))
    eqc = eng.get_endorse_qc(1, 0)
    assert eqc is not None and evil.address not in eqc.signatures
    ok, _ = eqc.verify(vs)
    assert ok
    # The certificate is exactly what block validation accepts.
    entries = [f"{a}:{s}" for a, s in eqc.signatures.items()]
    stake, err = verify_commits(A, 1, 0, entries, vs)
    assert err is None and stake * 3 > 400 * 2


def test_votes_before_the_proposal_are_used_once_it_arrives():
    keys, vs, eng = _setup()
    for kp in keys[1:3]:
        eng.on_message(_vote(kp, MsgKind.PREENDORSE, A))
    eng.on_message(_vote(keys[3], MsgKind.PREENDORSE, B))
    assert eng.get_preendorse_qc(1, 0) is None                # no proposal yet
    out = eng.on_proposal(1, 0, A)
    assert eng.get_preendorse_qc(1, 0).block_hash == A
    assert any(m.kind == MsgKind.ENDORSE for m in out)


def test_votes_for_another_block_do_not_count_toward_quorum():
    keys, vs, eng = _setup()
    eng.on_proposal(1, 0, A)
    for kp in keys[1:]:
        eng.on_message(_vote(kp, MsgKind.PREENDORSE, B))
    assert eng.get_preendorse_qc(1, 0) is None


def test_equivocation_becomes_evidence():
    keys, vs, eng = _setup()
    evil = keys[3]
    eng.on_proposal(1, 0, A)
    eng.on_message(_vote(evil, MsgKind.ENDORSE, A))
    eng.on_message(_vote(evil, MsgKind.ENDORSE, B))
    ev = eng.take_evidence()
    assert len(ev) == 1 and ev[0].offender == evil.address
    assert ev[0].verify()[0]
    assert eng.take_evidence() == []                          # handed over once
    eng.on_message(_vote(evil, MsgKind.ENDORSE, "cc" * 32))   # same offence, same round
    assert eng.take_evidence() == []
