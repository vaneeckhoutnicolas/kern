# EVM Rollups on Kern

This document describes how Kern hosts Ethereum-compatible execution layers as **Optimistic Smart Rollups** — and why this architecture is the right way to give EVM applications access to Kern without compromising Kern's own properties.

The reference implementation lives in [`kern/rollup.py`](../kern/rollup.py).

---

## The core idea

A rollup is a separate execution environment whose state commitments are posted to Kern. The rollup runs an EVM-compatible execution layer (e.g., a Reth or Geth derivative), processes L2 transactions, and periodically posts the resulting state root to Kern as a **batch**. Anyone can challenge a posted batch within a window (default 7 days) by submitting a **fraud proof**; if the challenge succeeds, the disputed batch and everything built on top of it is reverted.

This architecture lets Kern:

- Stay narrow at L1: only batches, commitments, and bridge operations live on Kern itself.
- Inherit EVM developer gravity: existing Ethereum tools (Hardhat, Foundry, MetaMask, Etherscan-style explorers) work against the rollup unchanged.
- Settle assets between rollups: multiple EVM rollups posting to the same Kern L1 can move assets between themselves through L1 settlement.
- Benefit from Kern's deterministic finality at the settlement layer, even when L2 execution is optimistic.

## Why optimistic rather than ZK?

Optimistic rollups assume batches are honest unless proven otherwise; ZK rollups prove every batch correct at posting time. ZK is cryptographically stronger but currently has two costs:

- **Prover hardware and latency.** ZK provers for the full EVM today require specialized hardware and produce proofs minutes after the corresponding L2 block.
- **EVM compatibility friction.** Many EVM opcodes (precompiles, gas-metered loops, MODEXP) are difficult or expensive to prove in a SNARK. Each requires custom circuits.

Optimistic rollups have lower latency (batches post immediately, finality lags by the challenge window) and easier EVM compatibility (the prover is a fraud-proof referee, not a full execution prover). Kern's v0.2 rollup framework is optimistic; a ZK variant is a future addition.

## Components

```
┌──────────────────────────────────────────────────────────────────┐
│                          KERN  (Layer 1)                          │
│                                                                   │
│  ┌──────────────────────────┐    ┌─────────────────────────────┐ │
│  │   Bridge contract        │    │   Rollup state machine       │ │
│  │   (Skald, on-chain)      │    │   (kern.rollup.RollupState)  │ │
│  │                          │    │                              │ │
│  │   - deposit()            │    │   - post_batch()             │ │
│  │   - release(amount)      │◄───┤   - open_challenge()         │ │
│  │   - invariant solvent    │    │   - finalize_pending()       │ │
│  └─────────────┬────────────┘    └──────────────┬───────────────┘ │
│                │                                 │                 │
└────────────────┼─────────────────────────────────┼─────────────────┘
                 │                                 │
                 │ deposits/withdrawals            │ batches & fraud proofs
                 │                                 │
┌────────────────┼─────────────────────────────────┼─────────────────┐
│                ▼                                 │                 │
│   ┌────────────────────────────────────┐         │                 │
│   │       Sequencer                     │         │                 │
│   │   - orders L2 transactions          │─────────┘                 │
│   │   - executes them on EVM            │                           │
│   │   - posts state-root commitments    │                           │
│   └────────────┬───────────────────────┘                           │
│                │                                                     │
│                ▼                                                     │
│   ┌────────────────────────────────────┐                            │
│   │    L2 EVM execution layer           │                            │
│   │  (Reth/Geth derivative running      │                            │
│   │   in rollup-mode)                   │                            │
│   └────────────────────────────────────┘                            │
│                                                                       │
│                       L2  (Rollup)                                    │
└───────────────────────────────────────────────────────────────────────┘
```

## Lifecycle of a batch

1. **Sequencer collects L2 transactions** into an ordered batch.
2. **Sequencer executes the batch** locally, producing a new state root.
3. **Sequencer posts the batch** to Kern via `post_batch`. The L1-side `RollupState` validates: the sequencer's signature, the batch index (must be next-expected), the parent state root (must match L1's view of the current head). On success the batch is marked `PENDING`.
4. **Challenge window begins.** For `challenge_window_seconds` (default 7 days), anyone can submit a `FraudProof` claiming the state root is wrong.
5. **If no challenge:** at the end of the window, `finalize_pending()` marks the batch `FINAL`. Withdrawals authorized by this batch become claimable on L1.
6. **If a challenge:** the batch is marked `CHALLENGED`. An interactive bisection protocol identifies a single VM step where the claimed and challenged executions diverge. That step is verified on L1. The loser's bond is slashed; the winner takes half.

## Bridge contract

The bridge is a Skald contract on L1 with declared invariants. The reference template ([`kern/rollup.py`](../kern/rollup.py), `BRIDGE_SKALD`) declares:

```skald
invariant solvent {
    total_deposited >= total_withdrawn
}
```

This invariant is enforced by Kern's runtime. The bridge contract, as a matter of *protocol*, cannot pay out more than was deposited. There is no implementation bug that can violate this — the chain itself rejects the transaction.

The bridge's `release` entry is callable only by the rollup's sequencer (or its successor under governance rotation). It is invoked once the L2 batch carrying a withdrawal has been marked final by the rollup state machine.

## Sequencer rotation

Each rollup has a designated sequencer at any moment. Sequencer rotation happens through a governance operation that updates the rollup's L1 record. Rotation triggers:

1. The current sequencer's bond is unlocked (subject to a grace period for outstanding challenges).
2. The new sequencer posts a bond.
3. The new sequencer assumes responsibility for posting subsequent batches.

This is intentionally simple: rollups can have permissioned sequencers (e.g., a foundation runs the sequencer initially), with a path to decentralization (sequencer rotation by stake-weighted vote, or even round-robin among a sequencer set in later versions).

## Forced inclusion

A risk in optimistic rollups is sequencer censorship: a malicious sequencer could refuse to include certain transactions. Kern's rollup framework includes a planned **forced-inclusion** path: any user can post a transaction directly to L1, addressed to a specific rollup. The sequencer is then required to include it in a batch within N blocks; failure to do so is itself a slashable offense.

This mechanism is not yet implemented in v0.2 but is part of the v0.3 roadmap.

## Cross-rollup transfers

Two or more EVM rollups posting to the same Kern L1 can move assets between themselves through L1 settlement:

1. User initiates a withdrawal on rollup A.
2. Rollup A's batch carrying the withdrawal finalizes.
3. The bridge contract on L1 credits the user.
4. The user deposits to rollup B's bridge.
5. Rollup B's sequencer credits the user on L2.

This is slow (gated by the challenge window) but trust-minimized. Faster paths via liquidity providers (LP-based bridges where the LP fronts the user the funds on the destination chain and reclaims them after finality) are a normal application layer on top.

## Position vs. competing designs

| Design                       | Finality                   | EVM compat | L1 trust       | Examples                  |
|------------------------------|----------------------------|------------|----------------|---------------------------|
| Ethereum L1 (no rollup)      | Probabilistic (~12 min)    | Native     | High           | Ethereum mainnet           |
| Optimistic rollup on Ethereum| ~7 days (challenge window) | Native     | High           | Optimism, Arbitrum         |
| ZK rollup on Ethereum        | Minutes (proving latency)  | Partial    | High           | Polygon zkEVM, zkSync      |
| **Optimistic rollup on Kern**| **~7 days, settled in 2s** | **Native** | **Deterministic** | **Kern v0.2 (this)**  |
| Tezos's Etherlink            | ~7 days (similar model)    | Native     | Deterministic  | Etherlink                  |

The closest comparison is Etherlink on Tezos — same architectural pattern, same trust assumptions, similar finality model. Kern differs in offering a more developer-friendly L1 environment (dual-track governance, broader Skald features) and a deliberate roadmap toward multi-rollup composition.

## Reference implementation status

The reference module [`kern/rollup.py`](../kern/rollup.py) implements:

- ✅ `Rollup` descriptor and registration
- ✅ `Batch` posting with sequencer signatures
- ✅ Batch-index ordering and parent-state-root chaining
- ✅ `FraudProof` shape and challenge opening
- ✅ Challenge resolution (winner/loser branches)
- ✅ Pending-batch finalization on window elapse
- ✅ Withdrawal queueing and claim-after-finality
- ✅ Bridge Skald contract template with declared `solvent` invariant

It does **not** yet implement:

- ❌ Interactive bisection protocol for fraud-proof verification
- ❌ Single-step EVM verifier on L1
- ❌ Forced-inclusion path for censorship-resistance
- ❌ Cross-rollup LP-bridge primitives
- ❌ ZK variant

These are the natural next steps for a v0.3 rollup framework. The current implementation is sufficient to model the protocol's L1-side state machine end-to-end and to exercise the bridge invariant.
