# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.rollup — batch posting, challenges, finality."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.rollup import (
    Batch,
    BatchStatus,
    FraudProof,
    Rollup,
    RollupState,
    BRIDGE_SKALD,
    get_bridge_skald_source,
)


def _make_rollup():
    sequencer = KernKeypair.generate()
    bridge = KernKeypair.generate()
    rollup = Rollup(
        rollup_id="kern-evm-1",
        bridge_address=bridge.address,
        sequencer_address=sequencer.address,
        sequencer_pubkey=sequencer.public_key_b58,
        sequencer_bond=1_000_000_000,
        challenge_window_seconds=10,  # 10s for fast testing
    )
    state = RollupState(rollup=rollup)
    return rollup, state, sequencer


def _make_batch(state: RollupState, sequencer: KernKeypair, idx: int, state_root: str) -> Batch:
    batch = Batch(
        rollup_id=state.rollup.rollup_id,
        batch_index=idx,
        parent_state_root=state.current_state_root(),
        state_root=state_root,
        tx_hashes=["aa" * 32, "bb" * 32],
        tx_data_hash="cc" * 32,
        timestamp=int(time.time()),
        sequencer=sequencer.address,
        sequencer_pubkey=sequencer.public_key_b58,
    )
    batch.sign(sequencer)
    return batch


def test_post_first_batch():
    rollup, state, sequencer = _make_rollup()
    b = _make_batch(state, sequencer, 0, "11" * 32)
    ok, reason = state.post_batch(b, current_level=10, now=int(time.time()))
    assert ok, reason
    assert state.current_state_root() == "11" * 32
    assert b.status == BatchStatus.PENDING


def test_out_of_order_batch_rejected():
    rollup, state, sequencer = _make_rollup()
    b = Batch(
        rollup_id=state.rollup.rollup_id,
        batch_index=5,  # should be 0
        parent_state_root=state.current_state_root(),
        state_root="11" * 32,
        tx_hashes=[],
        tx_data_hash="00" * 32,
        timestamp=int(time.time()),
        sequencer=sequencer.address,
        sequencer_pubkey=sequencer.public_key_b58,
    )
    b.sign(sequencer)
    ok, reason = state.post_batch(b, 10, int(time.time()))
    assert not ok
    assert "expected 0" in reason


def test_wrong_sequencer_rejected():
    rollup, state, sequencer = _make_rollup()
    intruder = KernKeypair.generate()
    b = Batch(
        rollup_id=state.rollup.rollup_id,
        batch_index=0,
        parent_state_root=state.current_state_root(),
        state_root="11" * 32,
        tx_hashes=[],
        tx_data_hash="00" * 32,
        timestamp=int(time.time()),
        sequencer=intruder.address,
        sequencer_pubkey=intruder.public_key_b58,
    )
    b.sign(intruder)
    ok, reason = state.post_batch(b, 10, int(time.time()))
    assert not ok
    assert "current sequencer" in reason


def test_challenge_with_valid_proof():
    rollup, state, sequencer = _make_rollup()
    challenger = KernKeypair.generate()
    b = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b, 10, int(time.time()))

    proof = FraudProof(
        rollup_id=state.rollup.rollup_id,
        batch_index=0,
        challenger=challenger.address,
        expected_state_root="22" * 32,
        claimed_state_root="11" * 32,
        witness_data={"n_steps": 8},
    )
    ok, reason = state.open_challenge(proof, now=int(time.time()))
    assert ok, reason
    assert state.batches[0].status == BatchStatus.CHALLENGED


def test_challenge_with_matching_roots_rejected():
    rollup, state, sequencer = _make_rollup()
    challenger = KernKeypair.generate()
    b = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b, 10, int(time.time()))

    proof = FraudProof(
        rollup_id=state.rollup.rollup_id,
        batch_index=0,
        challenger=challenger.address,
        expected_state_root="11" * 32,
        claimed_state_root="11" * 32,  # same as expected — no fraud
        witness_data={"n_steps": 8},
    )
    ok, reason = state.open_challenge(proof, now=int(time.time()))
    assert not ok


def test_finalization_after_window():
    rollup, state, sequencer = _make_rollup()
    posted_at = int(time.time())
    b = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b, 10, posted_at)
    # Window is 10s; advance "now" past it.
    finalized = state.finalize_pending(now=posted_at + 20)
    assert finalized == [0]
    assert state.batches[0].status == BatchStatus.FINAL


def test_no_finalization_inside_window():
    rollup, state, sequencer = _make_rollup()
    posted_at = int(time.time())
    b = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b, 10, posted_at)
    finalized = state.finalize_pending(now=posted_at + 5)
    assert finalized == []
    assert state.batches[0].status == BatchStatus.PENDING


def test_challenge_cannot_be_decided_without_an_executed_step():
    """Audit 2, point 6: opening a challenge with a well-shaped proof no
    longer allows reverting the batch. There is no public revert path;
    resolution requires a finished bisection and a re-executed step."""
    rollup, state, sequencer = _make_rollup()
    challenger = KernKeypair.generate()
    b0 = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b0, 10, int(time.time()))

    proof = FraudProof(
        rollup_id=state.rollup.rollup_id,
        batch_index=0,
        challenger=challenger.address,
        expected_state_root="99" * 32,
        claimed_state_root="11" * 32,
        witness_data={"n_steps": 8},
    )
    assert state.open_challenge(proof, int(time.time()))[0]
    assert not hasattr(state, "resolve_challenge_for_challenger")
    ok, reason = state.resolve_challenge(0, b"", None)
    assert not ok and "bisection not finished" in reason
    assert state.batches[0].status == BatchStatus.CHALLENGED


def test_withdrawal_only_claimable_after_finality():
    rollup, state, sequencer = _make_rollup()
    posted_at = int(time.time())
    b = _make_batch(state, sequencer, 0, "11" * 32)
    state.post_batch(b, 10, posted_at)
    state.queue_withdrawal(batch_index=0, recipient="kn1" + "a" * 33, amount=500)
    # Inside window: not claimable.
    assert state.claimable_withdrawals() == []
    # After finalization.
    state.finalize_pending(now=posted_at + 20)
    claimable = state.claimable_withdrawals()
    assert len(claimable) == 1
    assert claimable[0]["amount"] == 500


def test_bridge_contract_typechecks():
    """The bridge Skald template must itself type-check."""
    from kern.skald.typecheck import type_check
    errors = type_check(get_bridge_skald_source())
    assert errors == [], f"Bridge contract has type errors: {errors}"


def test_bridge_contract_originates():
    """The bridge Skald template must originate cleanly."""
    from kern.skald import interpret_origination
    storage = interpret_origination(get_bridge_skald_source(), {
        "rollup_id": "kern-evm-1",
        "sequencer": "kn1" + "a" * 33,
        "total_deposited": 0,
        "total_withdrawn": 0,
        "challenge_window": 604800,
    })
    assert storage["total_deposited"] == 0


if __name__ == "__main__":
    test_post_first_batch()
    test_out_of_order_batch_rejected()
    test_wrong_sequencer_rejected()
    test_challenge_with_valid_proof()
    test_challenge_with_matching_roots_rejected()
    test_finalization_after_window()
    test_no_finalization_inside_window()
    test_successful_challenge_reverts_batch()
    test_withdrawal_only_claimable_after_finality()
    test_bridge_contract_typechecks()
    test_bridge_contract_originates()
    print("All rollup tests passed.")
