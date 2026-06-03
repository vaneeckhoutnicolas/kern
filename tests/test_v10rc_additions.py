# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout and Kern contributors
"""Tests for v1.0-rc additions: slashing via transaction, dynamic gas wiring."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.chain import (
    SLASHING_PERCENTAGE, WHISTLEBLOWER_REWARD_PCT,
    apply_transaction, empty_state,
)
from kern.crypto import KernKeypair
from kern.evm import ExecContext, Op, execute
from kern.transaction import OpKind, Transaction, make_slash_equivocation


# ---------------------------------------------------------------------------
# Dynamic gas wiring in vm.py::step()
# ---------------------------------------------------------------------------

def test_sstore_consumes_full_yellow_paper_cost():
    """SSTORE on a fresh slot (zero → non-zero) should cost ~20_000 gas per
    EIP-2200, not the v0.3-v0.9 static 5_000."""
    code = bytes([
        Op.PUSH1, 42, Op.PUSH1, 1, Op.SSTORE,   # 1 SSTORE: G_SSTORE_SET=20_000
        Op.STOP,
    ])
    trace = execute(code, gas=100_000)
    final = trace.states[-1]
    # Pre-SSTORE PUSH+PUSH = 6 gas. SSTORE should consume ~20_000.
    # Total used should be > 20_000 (vs ~5_006 in old model).
    used = 100_000 - final.gas
    assert used > 20_000, f"SSTORE only consumed {used - 6} (vs 20_000 expected)"


def test_sstore_no_op_is_cheap():
    """Writing the same value to a slot is much cheaper (warm-read cost)."""
    code = bytes([
        # First SSTORE: 0 → 42 (set, 20_000)
        Op.PUSH1, 42, Op.PUSH1, 1, Op.SSTORE,
        # Second SSTORE: 42 → 42 (no-op, ~100)
        Op.PUSH1, 42, Op.PUSH1, 1, Op.SSTORE,
        Op.STOP,
    ])
    trace = execute(code, gas=100_000)
    final = trace.states[-1]
    assert not final.reverted
    used = 100_000 - final.gas
    # First SSTORE alone is 20_000+. Second one is no-op (~100).
    # Total should be ~20_000 + small, NOT 40_000.
    assert used < 30_000, f"second SSTORE was not cheap: total={used}"


def test_sha3_charges_per_word():
    """SHA3 should charge 30 base + 6 per input word."""
    # Hash 64 bytes (= 2 words), should cost 30 + 6*2 = 42 + memory expansion.
    code = bytes([
        Op.PUSH1, 64, Op.PUSH1, 0, Op.SHA3,
        Op.STOP,
    ])
    trace = execute(code, gas=10_000)
    final = trace.states[-1]
    assert not final.reverted
    used = 10_000 - final.gas
    # PUSH+PUSH = 6, SHA3 should be ~42+ memory_expansion.
    assert used >= 42 + 6, f"SHA3 word cost not applied: used={used}"


def test_memory_expansion_charges_quadratic():
    """A large memory access should incur quadratic expansion cost."""
    # MSTORE at offset 32 * 200 = 6400 (uses 200+ words of memory).
    code = bytes([
        Op.PUSH1, 1,
        Op.PUSH2, 0x19, 0x00,    # offset = 6400
        Op.MSTORE,
        Op.STOP,
    ])
    trace = execute(code, gas=1_000_000)
    final = trace.states[-1]
    assert not final.reverted
    used = 1_000_000 - final.gas
    # 201 words. cost = 3*201 + 201^2/512 ≈ 603 + 79 = 682. Plus 3+3+3 for opcodes.
    # Compare to writing at offset 0 (1 word, cost = 3).
    assert used > 500, f"Memory expansion not quadratic enough: used={used}"


def test_exp_charges_per_exponent_byte():
    """EXP should cost 10 + 50 per byte of exponent."""
    # base=2, exp=256 (2 bytes)  → 10 + 50*2 = 110.
    code = bytes([
        Op.PUSH2, 0x01, 0x00,    # exp = 256
        Op.PUSH1, 2,             # base = 2
        Op.EXP,
        Op.STOP,
    ])
    trace = execute(code, gas=10_000)
    final = trace.states[-1]
    assert not final.reverted
    used = 10_000 - final.gas
    # PUSH2 + PUSH1 + EXP + STOP = 3 + 3 + 110 + 0 = 116.
    assert used >= 60, f"EXP didn't charge per-byte exponent cost: used={used}"


def test_out_of_gas_correctly_caught():
    """A program with insufficient gas for dynamic SSTORE should halt."""
    code = bytes([
        Op.PUSH1, 42, Op.PUSH1, 1, Op.SSTORE,
        Op.STOP,
    ])
    # 10_000 gas should NOT be enough for SSTORE (needs 20_000+).
    trace = execute(code, gas=10_000)
    final = trace.states[-1]
    assert final.reverted
    assert "out of gas" in (final.last_error or "")


# ---------------------------------------------------------------------------
# Slashing via transaction
# ---------------------------------------------------------------------------

def _validators_state(stakes):
    """Build a state dict with N validators."""
    vs = []
    balances = {}
    for i, s in enumerate(stakes):
        kp = KernKeypair.from_seed(bytes([0xa0 + i]) * 32)
        vs.append({
            "address": kp.address,
            "pubkey": kp.public_key_b58,
            "stake": s,
        })
        balances[kp.address] = 100_000_000   # plenty
    state = empty_state()
    state["validators"] = vs
    state["balances"] = balances
    state["total_supply"] = sum(stakes) + sum(balances.values())
    return state, vs


def test_slash_rejects_when_no_equivocation_record():
    """Submitting a slash for a non-existent equivocation fails."""
    state, vs = _validators_state([1_000_000_000, 1_000_000_000])
    # Pretend there's a proposal but no equivocations.
    state["governance"]["protocol"]["proposals"]["abc123"] = {
        "proposal_id": "abc123",
        "submitter": vs[0]["address"],
        "payload": {"params": {"i_max": 0.05}},
        "submitted_at_level": 0,
        "phase": "exploration",
        "votes": {"exploration": {}, "adoption": {}},
        "phase_transitions": [],
        "equivocations": [],   # empty!
    }
    snitch_kp = KernKeypair.from_seed(bytes([0xc0]) * 32)
    tx = make_slash_equivocation(
        sender_kp=snitch_kp,
        proposal_id="abc123",
        equivocator=vs[1]["address"],
        nonce=0,
    )
    state["balances"][snitch_kp.address] = 100_000_000
    state["nonces"][snitch_kp.address] = 0
    result = apply_transaction(state, tx, baker=vs[0]["address"])
    assert not result.ok
    assert "no unconsumed equivocation" in (result.error or "")


def test_slash_applies_when_equivocation_recorded():
    """A slash on an equivocator with on-chain evidence:
    - Reduces stake by SLASHING_PERCENTAGE
    - Pays WHISTLEBLOWER_REWARD_PCT to the submitter
    - Burns the rest (total_supply decreases)
    - Marks the equivocation 'consumed' (can't be re-submitted)."""
    state, vs = _validators_state([1_000_000_000, 1_000_000_000])
    pre_stake = vs[1]["stake"]
    pre_supply = state["total_supply"]

    # Inject a fake equivocation record into the proposal.
    state["governance"]["protocol"]["proposals"]["pid123"] = {
        "proposal_id": "pid123",
        "submitter": vs[0]["address"],
        "payload": {"params": {"i_max": 0.05}},
        "submitted_at_level": 0,
        "phase": "exploration",
        "votes": {"exploration": {}, "adoption": {}},
        "phase_transitions": [],
        "equivocations": [{
            "voter": vs[1]["address"],
            "phase": "exploration",
            "first_vote": "yes",
            "second_vote": "no",
            "second_at_level": 5,
        }],
    }

    snitch_kp = KernKeypair.from_seed(bytes([0xc0]) * 32)
    state["balances"][snitch_kp.address] = 100_000_000
    state["nonces"][snitch_kp.address] = 0
    pre_snitch_balance = state["balances"][snitch_kp.address]

    tx = make_slash_equivocation(
        sender_kp=snitch_kp,
        proposal_id="pid123",
        equivocator=vs[1]["address"],
        nonce=0,
    )
    result = apply_transaction(state, tx, baker=vs[0]["address"])
    assert result.ok, result.error

    # Math: slash = pre_stake * SLASHING_PERCENTAGE/100, reward = slash * WHISTLEBLOWER_REWARD_PCT/100
    expected_slash = pre_stake * SLASHING_PERCENTAGE // 100
    expected_reward = expected_slash * WHISTLEBLOWER_REWARD_PCT // 100
    expected_burn = expected_slash - expected_reward

    # State checks out.
    assert vs[1]["stake"] == pre_stake - expected_slash
    assert state["total_supply"] == pre_supply - expected_burn
    post_snitch = state["balances"][snitch_kp.address]
    assert post_snitch == pre_snitch_balance - tx.fee + expected_reward

    # Equivocation marked consumed.
    equivs = state["governance"]["protocol"]["proposals"]["pid123"]["equivocations"]
    assert equivs[0].get("consumed") is True
    assert equivs[0].get("reporter") == snitch_kp.address

    # Idempotent: a second slash for the same equivocation fails.
    snitch_kp2 = KernKeypair.from_seed(bytes([0xa1]) * 32)
    state["balances"][snitch_kp2.address] = 100_000_000
    state["nonces"][snitch_kp2.address] = 0
    tx2 = make_slash_equivocation(
        sender_kp=snitch_kp2,
        proposal_id="pid123",
        equivocator=vs[1]["address"],
        nonce=0,
    )
    result2 = apply_transaction(state, tx2, baker=vs[0]["address"])
    assert not result2.ok
    assert "no unconsumed equivocation" in (result2.error or "")


def test_slash_rejects_unknown_proposal():
    """Slashing for a non-existent proposal_id fails."""
    state, vs = _validators_state([1_000_000_000])
    snitch_kp = KernKeypair.from_seed(bytes([0xc0]) * 32)
    state["balances"][snitch_kp.address] = 100_000_000
    state["nonces"][snitch_kp.address] = 0
    tx = make_slash_equivocation(
        sender_kp=snitch_kp,
        proposal_id="nonexistent",
        equivocator=vs[0]["address"],
        nonce=0,
    )
    result = apply_transaction(state, tx, baker=vs[0]["address"])
    assert not result.ok
    assert "proposal not found" in (result.error or "")


def test_slash_rejects_unknown_validator():
    """Slashing a non-validator fails."""
    state, vs = _validators_state([1_000_000_000])
    state["governance"]["protocol"]["proposals"]["pid"] = {
        "proposal_id": "pid", "submitter": vs[0]["address"],
        "payload": {}, "submitted_at_level": 0, "phase": "exploration",
        "votes": {"exploration": {}, "adoption": {}}, "phase_transitions": [],
        "equivocations": [{"voter": "kn1ghost_validator", "phase": "exploration",
                           "first_vote": "yes", "second_vote": "no",
                           "second_at_level": 5}],
    }
    snitch_kp = KernKeypair.from_seed(bytes([0xc0]) * 32)
    state["balances"][snitch_kp.address] = 100_000_000
    state["nonces"][snitch_kp.address] = 0
    tx = make_slash_equivocation(
        sender_kp=snitch_kp,
        proposal_id="pid",
        equivocator="kn1ghost_validator",
        nonce=0,
    )
    result = apply_transaction(state, tx, baker=vs[0]["address"])
    assert not result.ok
    assert "not a current validator" in (result.error or "")


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} v1.0-rc tests passed.")
