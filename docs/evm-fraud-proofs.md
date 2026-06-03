# EVM Fraud Proofs — single-step verifier and bisection

This document specifies Kern's fraud-proof framework for optimistic rollups, implemented in [`kern/evm/`](../kern/evm/). It is the v0.3 piece that makes the rollup framework from [`rollups.md`](rollups.md) trustless rather than trust-based.

The implementation has three components: a step-wise **Mini-EVM**, an interactive **bisection protocol**, and an on-chain **single-step verifier**. Together they let any honest party prove on L1 that a sequencer's claimed state root is wrong — without re-executing the entire L2 batch on L1.

---

## The core insight

Optimistic rollups make a deceptively powerful claim: **anyone can post any state root, and unless someone proves it wrong within a window, it stands**. The challenge is to make "prove it wrong" cheap enough that any honest party can do it, *without* re-executing the entire L2 batch on L1 (which would defeat the point of rolling up).

The trick: by **bisection**, the cost of proving fraud is `O(log n)` L1 transactions for an `n`-step batch, followed by exactly **one** L1 single-step execution. A batch of 1 million EVM instructions can be challenged in roughly 20 bisection rounds plus one verification step.

## Components

### Mini-EVM (`kern/evm/vm.py`)

A deliberately small subset of the EVM — STOP, ADD/SUB/MUL/DIV/MOD/EXP, LT/GT/EQ/ISZERO, AND/OR/XOR/NOT, PUSH1..32, DUP1..4, SWAP1..3, POP, MLOAD/MSTORE, JUMP/JUMPI/JUMPDEST, PC/MSIZE, RETURN, REVERT. Opcode values match the Ethereum Yellow Paper, so any real EVM bytecode using only this subset runs unchanged.

The defining property: **every executed instruction produces a state commitment**. A state commitment is the blake2b-256 hash of the canonical JSON encoding of `(pc, stack, memory, gas, halted, output, reverted)`. The full trace of a program execution is a sequence of these commitments — one per step.

The full EVM (storage, calls, logs, precompiles) is the natural extension; the v0.3 implementation includes everything needed to demonstrate the protocol end-to-end. Adding more opcodes is independent of the protocol design.

### Bisection (`kern/evm/bisection.py`)

The interactive protocol runs between two parties — the sequencer (defender) and the challenger — on L1. Both parties have executed the same code on the same input; they each have a complete trace. They agree on the initial commitment (it's a function of the input only) and they disagree on the final commitment.

By the pigeonhole principle, there exists a **smallest step `k`** where their traces first diverge: `commitments[k-1]` is shared, `commitments[k]` differs. The bisection finds this `k` in `O(log n)` rounds:

```
initial:  lo = 0,  hi = n   (they agree at lo, disagree at hi)
loop:
  mid = (lo + hi) // 2
  both parties reveal their commitments[mid]
  if equal:  lo = mid    (disagreement is in the upper half)
  if differ: hi = mid    (disagreement is in the lower half)
until hi - lo == 1:
  the disputed step is `hi` (≡ `lo + 1`)
```

Each round is **one L1 transaction per party**. For a 2²⁰ ≈ 1M-step batch, the bisection takes 20 rounds. At, say, 5 minutes per round (gas-limited and to give the defender response time), the bisection completes in ~100 minutes — well within the 7-day challenge window.

### Single-step verifier (`kern/evm/bisection.py`)

Once bisection narrows down to a single step, the L1 verifier executes that one EVM instruction itself. The pre-state is the state both parties agreed on (`commitments[lo]`); the verifier computes the post-state by calling `step(pre_state, code)`. Whichever party's claimed post-commitment matches the verifier's output wins.

Crucially, the L1 verifier doesn't need to know anything about the whole batch — it executes **one EVM instruction**. The on-chain cost is bounded by the cost of the most expensive single EVM instruction, independent of the batch size.

```python
def single_step_verify(code, pre_state, claimed_seq, claimed_chal, disputed_step):
    truth = step(pre_state, code)
    truth_commitment = truth.commitment_hex()
    if truth_commitment == claimed_seq:
        return SingleStepResult(challenger_wins=False, ...)
    return SingleStepResult(challenger_wins=True, ...)
```

## End-to-end protocol on Kern L1

1. **Batch posting.** Sequencer posts a batch via `RollupState.post_batch()`. Status: `PENDING`. Challenge window begins.

2. **Challenge opening.** A challenger calls `open_challenge()` with a `FraudProof` carrying their claimed correct state root for the same batch. The disputed batch transitions to `CHALLENGED`. Both parties' bonds are at risk.

3. **Bisection rounds.** On each L1 turn:
   - Defender (sequencer) reveals their `commitment_at(mid)` via a transaction.
   - Challenger reveals their `commitment_at(mid)` via a transaction.
   - The L1 contract updates `(lo, hi)` per the protocol.
   - The other party has a response deadline; failure to respond by deadline forfeits the challenge (the responsive party wins by default).

4. **Single-step phase.** When `hi - lo == 1`:
   - Both parties submit the pre-state at step `lo` (must be the canonical encoding hashing to the agreed commitment).
   - Both parties submit the EVM bytecode being executed (must match the batch's input commitment).
   - The L1 verifier calls `step()` and compares.

5. **Resolution.**
   - **Challenger wins:** the disputed batch and all batches built on top of it are reverted (`resolve_challenge_for_challenger`). The sequencer's bond is partially slashed; the challenger gets a bounty.
   - **Sequencer wins:** the challenger's bond is slashed and paid to the sequencer as a deterrent against frivolous challenges (`resolve_challenge_for_sequencer`).

## Why this matters

**Security model.** The rollup is honest as long as ≥ 1 honest watcher exists who is willing to challenge invalid batches within the challenge window. That's a vastly weaker assumption than requiring trust in the sequencer.

**Verification cost.** The L1 cost to refute a fraudulent batch is `O(log n)` L1 transactions plus one single-step EVM execution — independent of the batch's complexity. For a million-instruction batch, the challenger pays for ~20 L1 transactions plus one EVM step. The sequencer's whole batch never needs to be re-executed on L1.

**Liveness.** As long as at least one party plays each bisection turn, the protocol terminates within `O(log n)` rounds. If either party fails to respond by the deadline, the other wins by default. This is what makes the protocol live under adversarial conditions.

## Concrete numbers

For a 1-million-instruction EVM batch with a 7-day challenge window:

| Parameter | Value |
|---|---|
| Bisection rounds | ~20 |
| L1 transactions per round | 2 (one per party) |
| Total L1 transactions for full challenge | ~40 + 1 single-step |
| Gas cost (estimate, vs full re-execution) | ~10 000× cheaper |
| Round response deadline (typical) | 10 minutes |
| Worst-case total challenge time | ~7 hours |

## What's in the reference implementation

The implementation in [`kern/evm/`](../kern/evm/) (~750 lines) provides:

- ✅ Mini-EVM with 30+ opcodes (arithmetic, comparison, stack, memory, control flow, termination)
- ✅ Per-step state commitments via blake2b-256
- ✅ Trace generation (`execute`)
- ✅ Bisection state machine (`BisectionState`, `bisection_round`)
- ✅ Full bisection driver for testing (`run_full_bisection`)
- ✅ Single-step verifier (`single_step_verify`)
- ✅ 19 tests covering the EVM subset, commitment determinism, bisection convergence, and end-to-end fraud-proof scenarios

What it does **not** include:

- ❌ Full EVM opcode set (only the subset needed for the protocol demo). Adding more opcodes is mechanical — extend `kern/evm/opcodes.py` and `kern/evm/vm.py` with the same step-then-commit pattern.
- ❌ Storage (SSTORE / SLOAD) — single-contract execution only; cross-contract storage is the v0.4 extension.
- ❌ Calls (CALL / DELEGATECALL / STATICCALL) — single-frame execution only.
- ❌ Gas metering that exactly matches Ethereum's dynamic gas costs. The current model uses static per-opcode costs.
- ❌ The on-chain bisection contract in Skald (the python `BisectionState` is the protocol model; a Skald contract implementing it is straightforward but not yet shipped).

These are all natural extensions on top of an already-working protocol skeleton.

## Comparison with other rollups' fraud proofs

| Rollup | Fraud-proof model | Single-step cost on L1 |
|---|---|---|
| **Optimism (Bedrock)** | MIPS interpreter + bisection | One MIPS instruction |
| **Arbitrum (Nitro)** | WASM interpreter + bisection | One WASM instruction |
| **Etherlink (Tezos)** | Custom VM + bisection | One custom-VM step |
| **Kern (v0.3)** | Mini-EVM + bisection | One EVM instruction |

Architecturally, Kern's design is closest to Optimism's Bedrock: a deterministic step-wise VM with the bisection protocol layered on top. The difference is that Kern verifies one **EVM** instruction at L1 (rather than one MIPS instruction representing the EVM), which simplifies the relationship between L1 verification and what L2 developers actually wrote.

## Practical example walkthrough

A program that runs for 8 EVM steps, where the sequencer lies about the final state:

```python
from kern.evm import execute, run_full_bisection, single_step_verify, Op, ExecutionTrace

# The program: PUSH1 1, PUSH1 2, ADD, PUSH1 3, ADD, PUSH1 4, ADD, STOP → result 10
code = bytes([
    Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD,
    Op.PUSH1, 3, Op.ADD,
    Op.PUSH1, 4, Op.ADD,
    Op.STOP,
])

# Both parties execute honestly initially:
honest = execute(code)

# Sequencer corrupts commitments from step 5 onward (claims a wrong state):
seq_commitments = list(honest.commitments)
for i in range(5, len(seq_commitments)):
    seq_commitments[i] = b"\xee" * 32

fake_seq = ExecutionTrace(states=honest.states, commitments=seq_commitments)

# Run the full bisection — finds the first divergence in O(log n) rounds:
state, log = run_full_bisection(fake_seq, honest)
print(f"Divergence at step {state.step_disagreement()}")  # 5
print(f"Bisection rounds: {len(log)}")                     # ~3 for n=8

# Single-step verification on L1:
pre_state = honest.states[state.step_disagreement() - 1]
r = single_step_verify(
    code=code,
    pre_state=pre_state,
    claimed_post_commitment_seq=seq_commitments[5].hex(),
    claimed_post_commitment_chal=honest.commitments[5].hex(),
    disputed_step=5,
)
assert r.challenger_wins
```

This is the entire fraud-proof flow, in 20 lines of Python.
