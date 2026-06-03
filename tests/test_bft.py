# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.bft — multi-validator quorum, equivocation, slashing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import (
    BftEngine,
    ConsensusMessage,
    MsgKind,
    QuorumCertificate,
    SlashingEvidence,
)
from kern.crypto import KernKeypair


def _make_validators(n: int, stake_each: int = 1_000_000_000):
    """Return n (KernKeypair, validator dict) pairs."""
    keys = [KernKeypair.generate() for _ in range(n)]
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": stake_each} for k in keys]
    return keys, vs


def _engine_for(kp: KernKeypair, validator_set):
    return BftEngine(
        own_keypair=kp,
        own_pubkey_b58=kp.public_key_b58,
        validator_set=validator_set,
    )


def test_message_sign_and_verify():
    kp = KernKeypair.generate()
    msg = ConsensusMessage(
        kind=MsgKind.PREENDORSE,
        level=1, round=0,
        block_hash="ab" * 32,
        validator=kp.address,
        validator_pubkey=kp.public_key_b58,
    )
    msg.sign(kp)
    assert msg.verify_signature()
    msg.block_hash = "cd" * 32  # tamper
    assert not msg.verify_signature()


def test_three_validator_quorum():
    """3 validators, all pre-endorse, then all endorse → quorum reached."""
    keys, vs = _make_validators(3)
    eng = _engine_for(keys[0], vs)

    block_hash = "ff" * 32

    # Validator 0 sees the proposal (acts as proposer).
    out = eng.on_proposal(level=1, round_=0, block_hash=block_hash)
    assert len(out) == 1
    assert out[0].kind == MsgKind.PREENDORSE
    assert out[0].validator == keys[0].address

    # Validator 1 sends its pre-endorsement (via on_message).
    pre1 = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash=block_hash, validator=keys[1].address,
        validator_pubkey=keys[1].public_key_b58,
    )
    pre1.sign(keys[1])
    out = eng.on_message(pre1)
    # 2/3 of 3 stake: we have 2/3 exactly, need STRICTLY > 2/3 → no endorse yet.
    # Total stake = 3B. signed = 2B. 2 * 3 > 2 * 3? 6 > 6 → False. So no endorsement yet.
    assert len(out) == 0

    # Validator 2's pre-endorsement → quorum.
    pre2 = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash=block_hash, validator=keys[2].address,
        validator_pubkey=keys[2].public_key_b58,
    )
    pre2.sign(keys[2])
    out = eng.on_message(pre2)
    # Now signed = 3B, total = 3B. 3 * 3 > 2 * 3 → True. Endorse emitted.
    assert len(out) == 1
    assert out[0].kind == MsgKind.ENDORSE
    assert out[0].validator == keys[0].address

    # Engine has a pre-endorse QC.
    pre_qc = eng.get_preendorse_qc(1, 0)
    assert pre_qc is not None
    ok, reason = pre_qc.verify(vs)
    assert ok, reason


def test_endorsement_quorum_reaches_finality():
    keys, vs = _make_validators(3)
    eng = _engine_for(keys[0], vs)
    block_hash = "ee" * 32

    # Proposal + pre-endorsements from all three.
    eng.on_proposal(1, 0, block_hash)
    for k in (keys[1], keys[2]):
        m = ConsensusMessage(
            kind=MsgKind.PREENDORSE, level=1, round=0,
            block_hash=block_hash, validator=k.address,
            validator_pubkey=k.public_key_b58,
        )
        m.sign(k)
        eng.on_message(m)

    # Now feed endorsements from the two other validators.
    for k in (keys[1], keys[2]):
        m = ConsensusMessage(
            kind=MsgKind.ENDORSE, level=1, round=0,
            block_hash=block_hash, validator=k.address,
            validator_pubkey=k.public_key_b58,
        )
        m.sign(k)
        eng.on_message(m)

    # Endorse quorum reached.
    eqc = eng.get_endorse_qc(1, 0)
    assert eqc is not None
    ok, reason = eqc.verify(vs)
    assert ok, reason
    assert len(eqc.signatures) == 3


def test_insufficient_quorum_rejected():
    """A QC with only 1/3 of stake should fail verification."""
    keys, vs = _make_validators(3)
    block_hash = "aa" * 32
    sigs = {}
    m = ConsensusMessage(
        kind=MsgKind.ENDORSE, level=1, round=0,
        block_hash=block_hash, validator=keys[0].address,
        validator_pubkey=keys[0].public_key_b58,
    )
    m.sign(keys[0])
    sigs[keys[0].address] = m.signature

    qc = QuorumCertificate(
        kind=MsgKind.ENDORSE, level=1, round=0,
        block_hash=block_hash, signatures=sigs,
    )
    ok, reason = qc.verify(vs)
    assert not ok
    assert "insufficient stake" in reason


def test_qc_rejects_unknown_validator():
    keys, vs = _make_validators(3)
    intruder = KernKeypair.generate()
    block_hash = "bb" * 32
    m = ConsensusMessage(
        kind=MsgKind.ENDORSE, level=1, round=0,
        block_hash=block_hash, validator=intruder.address,
        validator_pubkey=intruder.public_key_b58,
    )
    m.sign(intruder)
    qc = QuorumCertificate(
        kind=MsgKind.ENDORSE, level=1, round=0,
        block_hash=block_hash, signatures={intruder.address: m.signature},
    )
    ok, reason = qc.verify(vs)
    assert not ok
    assert "not in set" in reason


def test_equivocation_evidence():
    """Two pre-endorsements from the same validator on different block hashes
    is a slashable offense."""
    keys, vs = _make_validators(3)
    bad = keys[0]
    a = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash="aa" * 32, validator=bad.address,
        validator_pubkey=bad.public_key_b58,
    )
    a.sign(bad)
    b = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash="bb" * 32, validator=bad.address,
        validator_pubkey=bad.public_key_b58,
    )
    b.sign(bad)

    ev = SlashingEvidence(offender=bad.address, msg_a=a, msg_b=b)
    ok, reason = ev.verify()
    assert ok, reason


def test_equivocation_evidence_same_hash_is_not_offense():
    keys, vs = _make_validators(3)
    bad = keys[0]
    block_hash = "aa" * 32
    a = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash=block_hash, validator=bad.address,
        validator_pubkey=bad.public_key_b58,
    )
    a.sign(bad)
    b = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash=block_hash, validator=bad.address,
        validator_pubkey=bad.public_key_b58,
    )
    b.sign(bad)
    ev = SlashingEvidence(offender=bad.address, msg_a=a, msg_b=b)
    ok, reason = ev.verify()
    assert not ok
    assert "not in conflict" in reason


def test_engine_rejects_message_from_non_validator():
    keys, vs = _make_validators(3)
    eng = _engine_for(keys[0], vs)
    intruder = KernKeypair.generate()
    m = ConsensusMessage(
        kind=MsgKind.PREENDORSE, level=1, round=0,
        block_hash="cc" * 32, validator=intruder.address,
        validator_pubkey=intruder.public_key_b58,
    )
    m.sign(intruder)
    out = eng.on_message(m)
    assert out == []


def test_engine_prunes_old_states():
    keys, vs = _make_validators(3)
    eng = _engine_for(keys[0], vs)
    eng.on_proposal(level=1, round_=0, block_hash="aa" * 32)
    eng.on_proposal(level=2, round_=0, block_hash="bb" * 32)
    eng.on_proposal(level=3, round_=0, block_hash="cc" * 32)
    assert (1, 0) in eng.states and (2, 0) in eng.states and (3, 0) in eng.states
    eng.prune_below(3)
    assert (1, 0) not in eng.states
    assert (2, 0) not in eng.states
    assert (3, 0) in eng.states


if __name__ == "__main__":
    test_message_sign_and_verify()
    test_three_validator_quorum()
    test_endorsement_quorum_reaches_finality()
    test_insufficient_quorum_rejected()
    test_qc_rejects_unknown_validator()
    test_equivocation_evidence()
    test_equivocation_evidence_same_hash_is_not_offense()
    test_engine_rejects_message_from_non_validator()
    test_engine_prunes_old_states()
    print("All BFT tests passed.")
