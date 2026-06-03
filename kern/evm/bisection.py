# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.bisection
==================

The interactive bisection protocol for optimistic fraud proofs.

Setup
-----

A sequencer posts a batch with claimed end state `S_claimed`. A challenger
claims the correct end state is `S_correct` (different from `S_claimed`).

Both parties have executed the same code on the same input, so they each
have a full execution trace. They agree on the initial state commitment
(it's a function of the input only). They disagree on the final
commitment.

By the pigeonhole principle, there exists a smallest step `k` such that:
- commitments[k-1] of both traces are equal (they agree up to step k-1)
- commitments[k] of both traces differ (their disagreement first appears
  at step k)

The bisection protocol identifies this `k` in O(log n) rounds of L1
messages. Once `k` is found, the on-chain verifier executes that single
step deterministically and decides:

- If verifier(states[k-1]) == challenger.states[k]: challenger wins.
- If verifier(states[k-1]) == sequencer.states[k]: sequencer wins.

(Exactly one of these holds, by determinism.)

Protocol state machine
----------------------

  ChallengeState(lo=0, hi=N)
        │
        │  while hi - lo > 1:
        │      mid = (lo + hi) // 2
        │      ┌─ challenger reveals commitment at mid
        │      ├─ sequencer reveals commitment at mid
        │      ├─ if they agree at mid: lo = mid
        │      └─ if they disagree at mid: hi = mid
        │
        ▼  hi - lo == 1  →  ready for single-step verification
   SingleStepReady(step=lo)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .vm import ExecutionTrace, VmState, step


@dataclass
class BisectionState:
    """The state of an ongoing bisection between two parties.

    `lo` and `hi` are step indices into the execution trace. Invariant
    maintained throughout the protocol:

        - both parties' commitments[lo] are equal (the latest agreement)
        - both parties' commitments[hi] differ  (the earliest disagreement)
    """

    n_steps: int                       # total steps in the (challenger's) trace
    initial_commitment: str            # commitment at step 0 (must agree)
    final_commitment_seq: str          # what the sequencer claims at step N
    final_commitment_chal: str         # what the challenger claims at step N
    lo: int = 0
    hi: int = 0
    # Recorded mid-point commitments for each round, for both parties.
    revealed_seq: dict = field(default_factory=dict)  # step -> hex
    revealed_chal: dict = field(default_factory=dict) # step -> hex

    def __post_init__(self):
        if self.hi == 0:
            self.hi = self.n_steps
        # initial commitments must match
        self.revealed_seq[0] = self.initial_commitment
        self.revealed_chal[0] = self.initial_commitment
        # final commitments are the disputed values
        self.revealed_seq[self.n_steps] = self.final_commitment_seq
        self.revealed_chal[self.n_steps] = self.final_commitment_chal

    @property
    def is_ready_for_single_step(self) -> bool:
        return self.hi - self.lo == 1

    @property
    def mid(self) -> int:
        return (self.lo + self.hi) // 2

    def step_disagreement(self) -> int:
        """If ready, return the index of the first disagreement step."""
        assert self.is_ready_for_single_step
        return self.hi  # i.e. lo + 1


def bisection_round(
    state: BisectionState,
    seq_commitment_at_mid: str,
    chal_commitment_at_mid: str,
) -> BisectionState:
    """Perform one round of the bisection protocol.

    Both parties reveal their commitment at `state.mid`. If they agree,
    the disagreement is in the upper half; we move `lo` up. If they
    disagree, the disagreement is in the lower half; we move `hi` down.

    Returns the updated state. The protocol terminates when
    `state.is_ready_for_single_step` becomes True.
    """
    mid = state.mid
    if mid <= state.lo or mid >= state.hi:
        raise ValueError("bisection already terminated")

    state.revealed_seq[mid] = seq_commitment_at_mid
    state.revealed_chal[mid] = chal_commitment_at_mid

    if seq_commitment_at_mid == chal_commitment_at_mid:
        # They still agree at mid → disagreement is in [mid, hi]
        state.lo = mid
    else:
        # They differ at mid → disagreement is in [lo, mid]
        state.hi = mid

    return state


# ---------------------------------------------------------------------------
# Single-step verification — the "judge" on L1
# ---------------------------------------------------------------------------

@dataclass
class SingleStepResult:
    """Outcome of the on-chain single-step verifier."""

    challenger_wins: bool
    verified_commitment: str          # what the truth is
    disputed_step: int                # which step was verified

    @property
    def sequencer_wins(self) -> bool:
        return not self.challenger_wins


def single_step_verify(
    code: bytes,
    pre_state: VmState,
    claimed_post_commitment_seq: str,
    claimed_post_commitment_chal: str,
    disputed_step: int,
) -> SingleStepResult:
    """The on-chain referee. Given a pre-state both parties agreed to
    (the state at step `disputed_step - 1`), execute one instruction
    and compare the result to each party's claim.

    The party whose claim matches the deterministically-computed truth
    wins. If neither claim matches (e.g., both parties lied), the
    challenger wins by default (the sequencer's claim has been
    refuted).
    """
    truth = step(pre_state, code)
    truth_commitment = truth.commitment_hex()

    if truth_commitment == claimed_post_commitment_seq:
        return SingleStepResult(
            challenger_wins=False,
            verified_commitment=truth_commitment,
            disputed_step=disputed_step,
        )
    # Either the challenger is correct, or both are wrong. In both cases
    # the sequencer's claim is refuted, so the challenger's challenge
    # succeeds. (The sequencer posted invalid state.)
    return SingleStepResult(
        challenger_wins=True,
        verified_commitment=truth_commitment,
        disputed_step=disputed_step,
    )


# ---------------------------------------------------------------------------
# Convenience: drive a complete bisection from two traces
# ---------------------------------------------------------------------------

def run_full_bisection(
    seq_trace: ExecutionTrace,
    chal_trace: ExecutionTrace,
) -> Tuple[BisectionState, List[Tuple[int, str, str]]]:
    """Drive a full bisection between two traces. Both traces must have
    the same length (= same step count). Returns the final BisectionState
    and the per-round log of (mid, seq_commitment, chal_commitment).

    Used in tests and in off-chain simulation; the real L1 protocol
    runs one round per L1 transaction."""
    if seq_trace.n_steps != chal_trace.n_steps:
        raise ValueError("traces must have the same step count for bisection")

    n = seq_trace.n_steps
    state = BisectionState(
        n_steps=n,
        initial_commitment=seq_trace.commitments[0].hex(),
        final_commitment_seq=seq_trace.commitments[-1].hex(),
        final_commitment_chal=chal_trace.commitments[-1].hex(),
    )
    log: List[Tuple[int, str, str]] = []
    while not state.is_ready_for_single_step:
        mid = state.mid
        seq_h = seq_trace.commitments[mid].hex()
        chal_h = chal_trace.commitments[mid].hex()
        log.append((mid, seq_h, chal_h))
        bisection_round(state, seq_h, chal_h)
    return state, log
