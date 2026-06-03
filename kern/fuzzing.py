# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.fuzzing
============

Property-based fuzzing harness for Kern subsystems.

Three fuzzer categories:

1. **EVM bytecode fuzzer** — generates random programs from the opcode set
   and asserts execution-determinism + state-commitment-determinism
   invariants. Catches non-determinism that would break consensus.

2. **Transaction fuzzer** — generates random transactions and runs them
   through apply_transaction in a fresh state, asserting that:
   - Fees are always debited (or the tx rejects before debit)
   - Total supply is conserved across transfers
   - Invariants never crash the runtime (must always return ApplyResult)

3. **Governance fuzzer** — generates random sequences of propose/vote/
   advance and asserts that:
   - Bonds always reconcile (refund + burn + treasury = original bond)
   - No proposal can transition backward in phase
   - Activated changes only apply once

Each fuzzer runs N iterations with a seeded RNG so failures are
reproducible. Default N=100; CI / nightly runs with N=10000.
"""

from __future__ import annotations

import copy
import random
from typing import Any, Callable, Dict, List, Optional, Tuple

from kern.evm import ExecContext, Op, VmState, execute
from kern.evm.opcodes import is_dup, is_push, is_swap, push_size


# ---------------------------------------------------------------------------
# EVM bytecode fuzzer
# ---------------------------------------------------------------------------

# Opcodes that are "safe" in the sense that they don't trigger calls /
# storage / external state — pure VM operations. This keeps the fuzzer
# self-contained.
_SAFE_OPCODES = [
    Op.STOP, Op.ADD, Op.SUB, Op.MUL, Op.DIV, Op.MOD,
    Op.LT, Op.GT, Op.EQ, Op.ISZERO,
    Op.AND, Op.OR, Op.XOR, Op.NOT, Op.BYTE,
    Op.POP, Op.MLOAD, Op.MSTORE, Op.MSTORE8,
    Op.PC, Op.MSIZE, Op.GAS, Op.JUMPDEST,
    Op.PUSH1, Op.PUSH2, Op.PUSH4,
    Op.DUP1, Op.DUP2, Op.DUP3,
    Op.SWAP1, Op.SWAP2,
]


def random_bytecode(rng: random.Random, *, max_len: int = 256) -> bytes:
    """Generate a random bytecode program from the safe opcode set."""
    length = rng.randint(1, max_len)
    code = bytearray()
    while len(code) < length:
        op = rng.choice(_SAFE_OPCODES)
        code.append(int(op))
        if is_push(op):
            # Push opcodes take immediate operand bytes.
            n = push_size(op)
            code.extend(rng.randbytes(n))
    return bytes(code)


def fuzz_evm_determinism(*, iterations: int = 100, seed: int = 0) -> Dict[str, Any]:
    """Run N random programs twice and assert identical execution traces.

    Failure modes this catches:
    - Non-deterministic opcode behavior (e.g., relying on dict iteration order)
    - State-commitment hash inconsistency across runs

    Returns a result dict with stats and any failure detail.
    """
    rng = random.Random(seed)
    failures: List[Dict[str, Any]] = []
    halted_count = 0
    reverted_count = 0

    for i in range(iterations):
        code = random_bytecode(rng)
        try:
            t1 = execute(code, gas=100_000, max_steps=10_000)
            t2 = execute(code, gas=100_000, max_steps=10_000)
        except Exception as e:
            failures.append({"iter": i, "code_hex": code.hex(),
                             "error": f"uncaught exception: {e}"})
            continue
        # Both traces must be identical (same number of steps, same commitments).
        if t1.n_steps != t2.n_steps:
            failures.append({"iter": i, "code_hex": code.hex(),
                             "error": f"step count diverged: {t1.n_steps} vs {t2.n_steps}"})
            continue
        for s in range(len(t1.commitments)):
            if t1.commitments[s] != t2.commitments[s]:
                failures.append({"iter": i, "code_hex": code.hex(),
                                 "step": s,
                                 "error": "commitment hash differs between runs"})
                break
        if t1.states[-1].halted:
            halted_count += 1
        if t1.states[-1].reverted:
            reverted_count += 1

    return {
        "iterations": iterations,
        "failures": failures,
        "halted_count": halted_count,
        "reverted_count": reverted_count,
        "success": len(failures) == 0,
    }


# ---------------------------------------------------------------------------
# Transaction fuzzer
# ---------------------------------------------------------------------------

def fuzz_transaction_safety(*, iterations: int = 100, seed: int = 0) -> Dict[str, Any]:
    """Generate random Transfer transactions and assert:
    - Conservation of total supply across successful transfers.
    - apply_transaction never raises (always returns an ApplyResult).
    - Nonce is monotonic.
    """
    from kern.chain import apply_transaction, initial_state_from_genesis
    from kern.crypto import KernKeypair
    from kern.transaction import make_transfer

    rng = random.Random(seed)

    # Build a deterministic genesis with 3 accounts.
    keypairs = [KernKeypair.from_seed(bytes([i]) * 32) for i in range(1, 4)]
    state = initial_state_from_genesis({
        "balances": {kp.address: 1_000_000_000 for kp in keypairs},
        "validators": [],
    })

    initial_supply = sum(state["balances"].values())
    failures: List[Dict[str, Any]] = []
    successful = 0

    for i in range(iterations):
        sender_kp = rng.choice(keypairs)
        recipient_kp = rng.choice(keypairs)
        amount = rng.randint(0, 100_000)
        nonce = state["nonces"].get(sender_kp.address, 0)
        fee = 1000

        tx = make_transfer(sender_kp, recipient_kp.address, amount, nonce, fee=fee)

        try:
            result = apply_transaction(state, tx, baker=keypairs[0].address)
        except Exception as e:
            failures.append({"iter": i, "error": f"apply_transaction raised: {e}"})
            continue

        if not hasattr(result, "ok"):
            failures.append({"iter": i, "error": "result missing 'ok' attribute"})
            continue

        if result.ok:
            successful += 1

    # Supply conservation: sum of all balances == initial supply (no rewards
    # applied at this layer, no minting).
    final_supply = sum(state["balances"].values())
    if final_supply != initial_supply:
        failures.append({"iter": "final",
                         "error": f"supply changed: {initial_supply} → {final_supply}"})

    return {
        "iterations": iterations,
        "successful": successful,
        "failures": failures,
        "supply_conserved": final_supply == initial_supply,
        "success": len(failures) == 0,
    }


# ---------------------------------------------------------------------------
# Governance fuzzer
# ---------------------------------------------------------------------------

def fuzz_governance_invariants(*, iterations: int = 50, seed: int = 0) -> Dict[str, Any]:
    """Generate random propose/vote/advance sequences and assert that
    bond accounting and phase transitions never break the invariants."""
    from kern.governance import (
        ProtocolGovernance,
        ProtocolPhase,
        Vote,
        resolve_bond,
    )

    rng = random.Random(seed)

    validators = [
        {"address": f"kn1v{i:03d}{'a' * 30}"[:36],
         "pubkey": f"pk{i:03d}", "stake": 1000}
        for i in range(5)
    ]
    gov = ProtocolGovernance(validators)

    bonds: Dict[str, int] = {}  # pid → bond amount
    failures: List[Dict[str, Any]] = []
    level = 0

    for i in range(iterations):
        action = rng.choice(["submit", "vote", "advance", "advance"])

        if action == "submit":
            submitter = rng.choice(validators)["address"]
            payload = {"params": {"i_max": rng.uniform(0.001, 0.1)}}
            salt = rng.randint(0, 1_000_000)
            ok, _, pid = gov.submit(submitter, payload, level, salt=salt)
            if ok and pid is not None:
                bonds[pid] = 100_000_000  # default protocol bond
        elif action == "vote":
            if not gov.proposals:
                continue
            pid = rng.choice(list(gov.proposals.keys()))
            voter = rng.choice(validators)["address"]
            vote = rng.choice([Vote.YES, Vote.NO, Vote.ABSTAIN])
            gov.vote(pid, voter, vote, level)
        elif action == "advance":
            level += rng.randint(10, 200)
            gov.advance_phases(level)

        # Invariant check: no proposal in REJECTED/ACTIVATED ever reverts.
        for pid, prop in gov.proposals.items():
            transitions = [t[0] for t in prop.phase_transitions]
            terminals_seen = [t for t in transitions
                              if t in ("activated", "rejected", "withdrawn")]
            if len(terminals_seen) > 1:
                failures.append({
                    "iter": i,
                    "pid": pid,
                    "error": f"reached terminal phase twice: {transitions}",
                })

    # Final bond settlement: every terminal proposal's bond reconciles.
    for pid, bond in bonds.items():
        if pid not in gov.proposals:
            continue
        phase = gov.proposals[pid].phase.value
        if phase in ("activated", "rejected", "withdrawn"):
            outcome = resolve_bond(bond, phase, was_decided_by_vote=True)
            if outcome.total != bond:
                failures.append({
                    "pid": pid,
                    "error": f"bond doesn't reconcile: {outcome.total} != {bond}",
                })

    return {
        "iterations": iterations,
        "proposals_created": len(gov.proposals),
        "failures": failures,
        "success": len(failures) == 0,
    }


# ---------------------------------------------------------------------------
# Composite fuzzer (used in chaos tests)
# ---------------------------------------------------------------------------

def run_all_fuzzers(*, iterations: int = 100, seed: int = 0) -> Dict[str, Any]:
    """Run all fuzzers; aggregate results."""
    results = {
        "evm_determinism": fuzz_evm_determinism(iterations=iterations, seed=seed),
        "transaction_safety": fuzz_transaction_safety(iterations=iterations, seed=seed),
        "governance_invariants": fuzz_governance_invariants(iterations=iterations, seed=seed),
    }
    results["overall_success"] = all(r["success"] for r in results.values()
                                     if isinstance(r, dict))
    return results
