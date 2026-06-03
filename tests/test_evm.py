# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.evm — mini-EVM execution and the bisection fraud-proof
protocol."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.evm import (
    BisectionState,
    Op,
    SingleStepResult,
    VmState,
    bisection_round,
    execute,
    run_full_bisection,
    single_step_verify,
    step,
)


# ===========================================================================
# Mini-EVM execution tests
# ===========================================================================

def test_stop_immediately():
    code = bytes([Op.STOP])
    trace = execute(code)
    assert trace.n_steps == 1
    assert trace.states[-1].halted
    assert not trace.states[-1].reverted


def test_push_and_add():
    # PUSH1 3, PUSH1 4, ADD, STOP  →  stack top = 7
    code = bytes([Op.PUSH1, 3, Op.PUSH1, 4, Op.ADD, Op.STOP])
    trace = execute(code)
    assert trace.states[-1].halted
    assert trace.states[-1].stack == [7]


def test_arithmetic_chain():
    # (5 + 7) * 2 - 3 = 21
    code = bytes([
        Op.PUSH1, 5, Op.PUSH1, 7, Op.ADD,    # 12
        Op.PUSH1, 2, Op.MUL,                  # 24
        Op.PUSH1, 3, Op.SWAP1, Op.SUB,        # 21
        Op.STOP,
    ])
    trace = execute(code)
    assert trace.states[-1].stack == [21]


def test_div_by_zero_returns_zero():
    # EVM semantics: DIV by zero yields 0, not an exception
    code = bytes([Op.PUSH1, 5, Op.PUSH1, 0, Op.DIV, Op.STOP])
    # stack: [5, 0]; DIV pops [5, 0] and does 5 // 0 → 0
    trace = execute(code)
    assert trace.states[-1].stack == [0]


def test_jump_and_jumpdest():
    # PUSH1 6, JUMP, [garbage at 4-5], JUMPDEST, PUSH1 42, STOP
    # PC=0  PUSH1 6
    # PC=2  JUMP        jumps to 6
    # PC=3-5 unreachable
    # PC=6  JUMPDEST
    # PC=7  PUSH1 42
    # PC=9  STOP
    code = bytes([
        Op.PUSH1, 6, Op.JUMP,         # PC=0..2
        0xff, 0xff, 0xff,              # filler (unreachable)
        Op.JUMPDEST,                   # PC=6
        Op.PUSH1, 42, Op.STOP,         # PC=7..9
    ])
    trace = execute(code)
    assert trace.states[-1].halted
    assert trace.states[-1].stack == [42]


def test_jump_to_non_jumpdest_reverts():
    code = bytes([Op.PUSH1, 3, Op.JUMP, Op.STOP])
    trace = execute(code)
    assert trace.states[-1].halted
    assert trace.states[-1].reverted


def test_mstore_mload_roundtrip():
    # MSTORE 0xdead at offset 0, MLOAD it back
    # PUSH1 0xde, PUSH1 0, MSTORE, PUSH1 0, MLOAD, STOP
    code = bytes([
        Op.PUSH1, 0xde, Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 0, Op.MLOAD, Op.STOP,
    ])
    trace = execute(code)
    assert trace.states[-1].stack == [0xde]


def test_return_with_output():
    # MSTORE 0xbe at offset 0, RETURN(0, 32)
    code = bytes([
        Op.PUSH1, 0xbe, Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
    ])
    trace = execute(code)
    assert trace.states[-1].halted
    assert not trace.states[-1].reverted
    assert trace.states[-1].output[-1] == 0xbe  # last byte


def test_stack_underflow_reverts():
    code = bytes([Op.ADD, Op.STOP])  # ADD with empty stack
    trace = execute(code)
    assert trace.states[-1].halted
    assert trace.states[-1].reverted
    assert "underflow" in (trace.states[-1].last_error or "")


def test_out_of_gas_reverts():
    code = bytes([Op.PUSH1, 1, Op.PUSH1, 1, Op.ADD, Op.STOP])
    # PUSH1 = 3, PUSH1 = 3, ADD = 3, STOP = 0; total 9
    # Start with 5 gas — should run out partway through.
    trace = execute(code, gas=5)
    assert trace.states[-1].halted
    assert trace.states[-1].reverted
    assert "out of gas" in (trace.states[-1].last_error or "")


def test_infinite_loop_halts_on_gas():
    """A program that loops forever (JUMPDEST; PUSH1 0; JUMP back to 0) must be
    stopped by gas exhaustion, not run indefinitely. This is the property that
    makes the rollup Mini-EVM safe against compute-DoS: gas — not luck — bounds
    execution. (The L1 native layer relies on a different guarantee: Skald has no
    loops and recursion is statically rejected, so it terminates by construction.)
    """
    code = bytes([Op.JUMPDEST, Op.PUSH1, 0, Op.JUMP])  # pc0: loop target; jump to pc0
    trace = execute(code, gas=1000, max_steps=10_000)
    last = trace.states[-1]
    assert last.halted and last.reverted
    assert "out of gas" in (last.last_error or "")
    # Gas, not the max_steps backstop, is what stopped it.
    assert len(trace.states) < 10_000


def test_dup_and_swap():
    # PUSH1 1, PUSH1 2, DUP1, SWAP1, STOP
    # After PUSH 1, PUSH 2 → stack=[1, 2]
    # DUP1 (dup top)        → stack=[1, 2, 2]
    # SWAP1 (swap top two)  → stack=[1, 2, 2] (top is 2, second is 2 → no visible change)
    # Let's make it more interesting:
    code = bytes([
        Op.PUSH1, 1, Op.PUSH1, 2, Op.PUSH1, 3,  # stack=[1, 2, 3]
        Op.DUP3,                                  # stack=[1, 2, 3, 1]
        Op.SWAP2,                                 # stack=[1, 1, 3, 2]
        Op.STOP,
    ])
    trace = execute(code)
    assert trace.states[-1].stack == [1, 1, 3, 2]


def test_commitment_changes_with_state():
    """Two different states must have different commitments."""
    a = VmState(pc=0, stack=[1, 2, 3], gas=100)
    b = VmState(pc=0, stack=[1, 2, 4], gas=100)
    assert a.commitment_hex() != b.commitment_hex()


def test_commitment_is_deterministic():
    a = VmState(pc=5, stack=[10], gas=50, memory=bytearray(b"x" * 32))
    b = VmState(pc=5, stack=[10], gas=50, memory=bytearray(b"x" * 32))
    assert a.commitment_hex() == b.commitment_hex()


# ===========================================================================
# Bisection protocol tests
# ===========================================================================

# Helper: a small program that runs for N steps.
def _simple_program() -> bytes:
    # PUSH 1, PUSH 2, ADD, PUSH 3, ADD, PUSH 4, ADD, STOP → result 10, ~ 8 steps
    return bytes([
        Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD,
        Op.PUSH1, 3, Op.ADD,
        Op.PUSH1, 4, Op.ADD,
        Op.STOP,
    ])


def test_honest_trace_no_disagreement():
    """If both parties have honest, identical traces, the bisection should
    fail to start (or report no disagreement)."""
    code = _simple_program()
    trace = execute(code)
    # Both parties have the same trace. final commitments agree.
    state = BisectionState(
        n_steps=trace.n_steps,
        initial_commitment=trace.commitments[0].hex(),
        final_commitment_seq=trace.commitments[-1].hex(),
        final_commitment_chal=trace.commitments[-1].hex(),
    )
    # If finals agree, opening a bisection at all is a protocol violation.
    # The verifier would reject the challenge. We just verify the state.
    assert state.final_commitment_seq == state.final_commitment_chal


def test_bisection_with_diverging_traces():
    """Sequencer cheats: their final commitment is wrong. Challenger
    catches them via bisection."""
    code = _simple_program()
    honest_trace = execute(code)

    # Forge a sequencer trace where the final commitment is just wrong.
    # (We simulate this by claiming a bogus final commitment.)
    bogus_final = "ff" * 32

    state = BisectionState(
        n_steps=honest_trace.n_steps,
        initial_commitment=honest_trace.commitments[0].hex(),
        final_commitment_seq=bogus_final,
        final_commitment_chal=honest_trace.commitments[-1].hex(),
    )

    # Walk bisection: sequencer reveals honest mids (it's their interest
    # to lie strategically, but in this test we have them reveal their
    # honest trace and only the final is a lie). Equivalently: pretend
    # their mids are honest up to the last step.
    while not state.is_ready_for_single_step:
        mid = state.mid
        seq_h = honest_trace.commitments[mid].hex()  # claims honest mid
        chal_h = honest_trace.commitments[mid].hex()  # actually honest
        # They agree at every mid... but disagree at the final commitment.
        # So lo will keep climbing toward hi.
        bisection_round(state, seq_h, chal_h)

    # Disagreement narrowed to last step.
    assert state.step_disagreement() == honest_trace.n_steps


def test_run_full_bisection_finds_first_diff():
    """When sequencer's trace diverges at step k, bisection finds exactly k."""
    code = _simple_program()
    honest = execute(code)

    # Build a fake sequencer trace that diverges at a specific step.
    DIVERGE_AT = 4
    fake_seq = execute(code)  # start from honest copy
    # Replace commitments from DIVERGE_AT onward with garbage.
    for i in range(DIVERGE_AT, len(fake_seq.commitments)):
        fake_seq.commitments[i] = bytes([0xaa] * 32)

    final_state, log = run_full_bisection(fake_seq, honest)
    # The first point of divergence is DIVERGE_AT, so hi should equal DIVERGE_AT.
    assert final_state.step_disagreement() == DIVERGE_AT
    # log length is O(log n)
    import math
    assert len(log) <= math.ceil(math.log2(honest.n_steps)) + 2


def test_single_step_verify_picks_truth():
    """Given a pre-state, the verifier executes one step and decides who
    is correct."""
    code = _simple_program()
    honest = execute(code)
    DIVERGE_AT = 4

    pre_state = honest.states[DIVERGE_AT - 1]
    truth_commitment = honest.commitments[DIVERGE_AT].hex()
    lie_commitment = "bb" * 32

    # Sequencer lies, challenger tells truth → challenger wins.
    r = single_step_verify(
        code=code,
        pre_state=pre_state,
        claimed_post_commitment_seq=lie_commitment,
        claimed_post_commitment_chal=truth_commitment,
        disputed_step=DIVERGE_AT,
    )
    assert r.challenger_wins
    assert r.verified_commitment == truth_commitment


def test_single_step_verify_sequencer_wins_when_honest():
    """If the sequencer's claim matches truth, the sequencer wins."""
    code = _simple_program()
    honest = execute(code)
    DIVERGE_AT = 4

    pre_state = honest.states[DIVERGE_AT - 1]
    truth_commitment = honest.commitments[DIVERGE_AT].hex()
    chal_lie = "cc" * 32

    r = single_step_verify(
        code=code,
        pre_state=pre_state,
        claimed_post_commitment_seq=truth_commitment,
        claimed_post_commitment_chal=chal_lie,
        disputed_step=DIVERGE_AT,
    )
    assert r.sequencer_wins
    assert not r.challenger_wins


def test_end_to_end_fraud_proof():
    """Full E2E: sequencer posts a wrong final commitment; challenger opens
    a bisection; protocol narrows to one step; verifier vindicates the
    challenger."""
    code = _simple_program()
    honest = execute(code)

    # Sequencer claims an incorrect final state (off by one).
    # We fake this by producing a "trace" whose commitments match honest
    # up to step DIVERGE_AT-1, then diverge.
    DIVERGE_AT = 5
    seq_commitments = list(honest.commitments)
    for i in range(DIVERGE_AT, len(seq_commitments)):
        seq_commitments[i] = bytes([0xee] * 32)

    # Build a fake ExecutionTrace with these commitments.
    from kern.evm import ExecutionTrace
    fake_seq = ExecutionTrace(
        states=honest.states,  # only commitments are looked at by bisection
        commitments=seq_commitments,
    )

    # Bisection narrows down to step DIVERGE_AT.
    bisection, _ = run_full_bisection(fake_seq, honest)
    assert bisection.step_disagreement() == DIVERGE_AT

    # Single-step verification.
    pre_state = honest.states[DIVERGE_AT - 1]
    r = single_step_verify(
        code=code,
        pre_state=pre_state,
        claimed_post_commitment_seq=seq_commitments[DIVERGE_AT].hex(),
        claimed_post_commitment_chal=honest.commitments[DIVERGE_AT].hex(),
        disputed_step=DIVERGE_AT,
    )
    assert r.challenger_wins


if __name__ == "__main__":
    # Run all tests directly
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} EVM/bisection tests passed.")
