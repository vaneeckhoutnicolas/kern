# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 5: rollup challenges are decided by an executed step.

Audit 2, point 6: FraudProof was accepted on its shape and
resolve_challenge_for_challenger reverted batches "assuming an external
verifier". These tests run a real mini-EVM program, post an honest or a
fraudulent batch, drive the bisection, and let single_step_verify decide."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.evm import execute
from kern.evm.opcodes import Op
from kern.rollup import Batch, BatchStatus, FraudProof, Rollup, RollupState, program_hash

CODE = bytes([
    Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD,
    Op.PUSH1, 3, Op.ADD,
    Op.PUSH1, 4, Op.ADD,
    Op.STOP,
])
HONEST = execute(CODE)
N = HONEST.n_steps
DIVERGE_AT = 5


def _setup(final_root: str):
    sequencer = KernKeypair.from_seed(bytes([0x71]) * 32)
    rollup = Rollup(
        rollup_id="kern-evm-test",
        bridge_address=KernKeypair.from_seed(bytes([0x72]) * 32).address,
        sequencer_address=sequencer.address,
        sequencer_pubkey=sequencer.public_key_b58,
        sequencer_bond=1,
        challenge_window_seconds=600,
        genesis_state_root=HONEST.commitments[0].hex(),
    )
    state = RollupState(rollup=rollup)
    batch = Batch(
        rollup_id=rollup.rollup_id, batch_index=0,
        parent_state_root=HONEST.commitments[0].hex(), state_root=final_root,
        tx_hashes=[], tx_data_hash=program_hash(CODE), timestamp=int(time.time()),
        sequencer=sequencer.address, sequencer_pubkey=sequencer.public_key_b58,
    )
    batch.sign(sequencer)
    assert state.post_batch(batch, 1, int(time.time()))[0]
    return state


def _seq_commitments_fraud():
    out = [c.hex() for c in HONEST.commitments]
    for i in range(DIVERGE_AT, len(out)):
        out[i] = "ee" * 32
    return out


def _bisect(state, seq, chal):
    bis = state.bisections[0]
    while not bis.is_ready_for_single_step:
        m = bis.mid
        assert state.challenge_round(0, seq[m], chal[m])[0]
    return bis


def test_fraudulent_batch_is_reverted_by_the_executed_step():
    seq = _seq_commitments_fraud()
    chal = [c.hex() for c in HONEST.commitments]
    state = _setup(seq[-1])
    proof = FraudProof("kern-evm-test", 0, "kn1challenger", chal[-1], seq[-1], {"n_steps": N})
    assert state.open_challenge(proof, int(time.time()))[0]
    bis = _bisect(state, seq, chal)
    assert bis.hi == DIVERGE_AT
    ok, winner = state.resolve_challenge(0, CODE, HONEST.states[bis.lo])
    assert ok and winner == "challenger"
    assert state.batches[0].status == BatchStatus.REVERTED


def test_frivolous_challenge_against_honest_batch_fails():
    seq = [c.hex() for c in HONEST.commitments]
    chal = list(seq)
    for i in range(DIVERGE_AT, len(chal)):
        chal[i] = "dd" * 32          # the challenger lies from step 5
    state = _setup(seq[-1])
    proof = FraudProof("kern-evm-test", 0, "kn1challenger", chal[-1], seq[-1], {"n_steps": N})
    assert state.open_challenge(proof, int(time.time()))[0]
    bis = _bisect(state, seq, chal)
    ok, winner = state.resolve_challenge(0, CODE, HONEST.states[bis.lo])
    assert ok and winner == "sequencer"
    assert state.batches[0].status == BatchStatus.PENDING


def test_resolution_requires_the_batch_program():
    seq = _seq_commitments_fraud()
    chal = [c.hex() for c in HONEST.commitments]
    state = _setup(seq[-1])
    state.open_challenge(FraudProof("kern-evm-test", 0, "kn1c", chal[-1], seq[-1], {"n_steps": N}),
                         int(time.time()))
    bis = _bisect(state, seq, chal)
    ok, reason = state.resolve_challenge(0, CODE + b"\x00", HONEST.states[bis.lo])
    assert not ok and "tx_data_hash" in reason


def test_resolution_requires_the_agreed_pre_state():
    seq = _seq_commitments_fraud()
    chal = [c.hex() for c in HONEST.commitments]
    state = _setup(seq[-1])
    state.open_challenge(FraudProof("kern-evm-test", 0, "kn1c", chal[-1], seq[-1], {"n_steps": N}),
                         int(time.time()))
    bis = _bisect(state, seq, chal)
    ok, reason = state.resolve_challenge(0, CODE, HONEST.states[bis.lo + 1])
    assert not ok and "agreed commitment" in reason
    assert state.batches[0].status == BatchStatus.CHALLENGED


def test_proof_without_trace_length_is_not_admitted():
    state = _setup("ee" * 32)
    proof = FraudProof("kern-evm-test", 0, "kn1c", "aa" * 32, "ee" * 32, {"step_proof": "x"})
    ok, reason = state.open_challenge(proof, int(time.time()))
    assert not ok and "n_steps" in reason
