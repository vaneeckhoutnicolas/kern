# On-chain Governance

This document describes Kern's on-chain governance system, implemented in [`kern/governance.py`](../kern/governance.py). Two parallel tracks — protocol amendments and treasury allocations — let the chain evolve and fund ecosystem work without hard forks or off-chain coordination.

The token economy document ([`tokenomics.md`](tokenomics.md) §7) describes the *intent* of governance. This document describes the *implementation*.

---

## Two tracks, two cycles

Kern governance is deliberately split into two tracks that share no machinery and run in parallel.

| Track | What it changes | Cycle phases | Threshold | Typical duration |
|---|---|---|---|---|
| Protocol amendments | Protocol parameters, KVM, Skald, state-root function | 5 (Submitted, Exploration, Cooldown, Adoption, Activated) | 80% supermajority | 25 days |
| Treasury allocations | Funds out of the on-chain treasury | 2 (Submitted, Voting) | 50% majority | 21 days |

The separation matters because amendments and allocations are **different in character**: protocol changes deserve more deliberation (5 phases, supermajority), while treasury spending is operational and shouldn't be bottlenecked by the slow track.

The reference implementation uses small block windows (100 blocks per phase) for testability. The production protocol uses days-long phases.

## Protocol amendment cycle

The five phases of a protocol amendment:

```
                  ┌───────────────────────────────────────────┐
                  │  SUBMITTED                                 │
                  │  proposal_blocks (~5 days)                 │
                  │  • submitter can withdraw                  │
                  │  • payload is final, no voting yet         │
                  └────────────────────┬───────────────────────┘
                                       │
                                       ▼
                  ┌───────────────────────────────────────────┐
                  │  EXPLORATION                               │
                  │  exploration_blocks (~5 days)              │
                  │  • validators vote yes/no/abstain          │
                  │  • at end: tally                           │
                  └────────────────────┬───────────────────────┘
                                       │
                          ┌────────────┴───────────┐
                          │ yes ≥ 80% &            │ yes < 80% or
                          │ quorum ≥ 25%           │ quorum failure
                          ▼                        ▼
        ┌──────────────────────────────┐    ┌──────────────┐
        │  COOLDOWN                     │    │  REJECTED    │
        │  cooldown_blocks (~5 days)    │    │  (terminal)  │
        │  reflection period            │    └──────────────┘
        └────────────┬──────────────────┘
                     │
                     ▼
        ┌──────────────────────────────┐
        │  ADOPTION                     │
        │  adoption_blocks (~5 days)    │
        │  validators vote a 2nd time   │
        └────────────┬──────────────────┘
                     │
        ┌────────────┴───────────┐
        │ yes ≥ 80% &            │ yes < 80%
        │ quorum ≥ 25%           │
        ▼                        ▼
   ┌──────────┐            ┌──────────┐
   │ACTIVATED │            │ REJECTED │
   │payload   │            └──────────┘
   │applied   │
   └──────────┘
```

### Why two votes?

The double-vote with mandatory cooldown is the same pattern Tezos has used since the Athens upgrade. The first vote (Exploration) tests support; if it passes, the Cooldown period gives the community time to *reconsider* — to back out if new information emerges. The second vote (Adoption) is the final commitment. This dampens momentum-driven decisions and surfaces second thoughts before activation.

### Quorum and supermajority

Both votes require:
- **Quorum**: ≥ 25% of total stake votes yes-or-no (abstain doesn't count toward quorum). Without this, a small clique could activate changes by simply showing up while everyone else is asleep.
- **Supermajority**: yes ≥ 80% of decisive (yes+no) votes. This is intentionally high. Protocol changes that don't have broad agreement should not pass.

### Payload schema

A protocol amendment payload is a small typed dict. Two payload kinds are supported in v0.5:

**Parameter change**:
```json
{"params": {"i_max": 0.05, "block_time_seconds": 1.0}}
```

Valid parameter names are enumerated in `ALLOWED_PARAMS`. Unknown keys are rejected at validation time.

**Function swap**:
```json
{"swap": "state_root_function", "to": "trie"}
```

Used to replace a core protocol function. The v0.5 demonstration: swap `state_root_function` from `"json"` (the v0.1-v0.4 placeholder) to `"trie"` (the v0.4 Merkle trie implementation).

Future versions will support more payload kinds — most importantly, Skald patch payloads (changes to the language itself) and KVM bytecode replacements.

### Activation

When a proposal reaches `ACTIVATED`, its payload is added to `gov.activated_changes`. The chain's `apply_block` reads from this list to:
- Merge parameter changes into the effective IssuanceParams (via `gov.effective_params(...)`)
- Update the state's `state_root_function` key when a swap activates (via `gov.active_swap(...)`)

The change is immediate: starting from the activation block, the new parameter/function is in force.

## Treasury cycle

The two phases of a treasury allocation:

```
        ┌────────────────────────────────────────┐
        │  SUBMITTED                              │
        │  proposal_blocks (~14 days)             │
        │  • anyone can submit                    │
        │  • submitter can withdraw               │
        └────────────────┬───────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────────────┐
        │  VOTING                                 │
        │  vote_blocks (~7 days)                  │
        │  • validators vote yes/no               │
        └────────────────┬───────────────────────┘
                         │
        ┌────────────────┴───────────────┐
        │ yes > 50% &                    │ yes ≤ 50%
        │ quorum ≥ 25%                   │
        ▼                                ▼
   ┌─────────────────────────┐    ┌──────────────┐
   │  EXECUTED                │    │  REJECTED    │
   │  treasury releases funds │    │  (terminal)  │
   │  if balance sufficient   │    └──────────────┘
   │  otherwise → REJECTED    │
   └─────────────────────────┘
```

### Permissionless submission

Anyone — not just validators — can submit a treasury proposal. Voting is restricted to validators (stake-weighted). This setup makes it easy for ecosystem teams to apply for funding without needing to also be validators.

### Drain protection

When a proposal reaches EXECUTED, the runtime checks whether the treasury still has enough balance to fund it. If two passing proposals together exceed the available balance, the second one is rejected at execution time. (A future version may sort by margin-of-passage to give the strongest proposals priority.)

### Payload schema

A treasury payload lists one or more recipients with amounts:

```json
{
  "recipients": [
    {"address": "kn1grantee_a", "amount": 5_000_000},
    {"address": "kn1grantee_b", "amount": 2_000_000}
  ],
  "memo": "Q1 ecosystem grants"
}
```

Batched payouts let related expenses be voted as a single package, reducing governance overhead.

## Vote weighting

Both tracks use stake-weighted voting: a validator's vote counts in proportion to their active stake. This is the same model used by Tezos and Cosmos.

The reference implementation uses **linear** stake weighting in both tracks. The tokenomics document ([`tokenomics.md`](tokenomics.md) §7.1) mentioned a future move to **quadratic** weighting for the treasury track (`weight = sqrt(stake)`) to dampen large-holder dominance. That's a v0.6 governance amendment — once the chain is live, the community can vote to switch.

## On-chain anchors

Two Skald contracts anchor the governance state on-chain. The Python state machine in `kern/governance.py` is the **spec**; the contracts are the **public ledger** of activated changes and treasury releases.

### `ProtocolGovernance` contract

```skald
contract ProtocolGovernance {
    storage {
        cycle_length_blocks: int,
        supermajority_num: int,
        supermajority_den: int,
        quorum_num: int,
        quorum_den: int,
        activated_count: int,
    }
    invariant valid_threshold { supermajority_num <= supermajority_den }
    invariant valid_quorum { quorum_num <= quorum_den }
    invariant nonneg_count { activated_count >= 0 }
    entry record_activation() { activated_count = activated_count + 1; }
    view total_activations() -> int { activated_count }
}
```

The runtime calls `record_activation()` each time a proposal reaches ACTIVATED. The on-chain `activated_count` is the audit trail of how many protocol changes the network has accepted to date.

### `Treasury` contract

```skald
contract Treasury {
    storage {
        governance: address,
        balance: int,
        total_released: int,
        execution_count: int,
    }
    invariant solvent { balance >= 0 }
    invariant nonneg_release { total_released >= 0 }
    entry deposit() { ... }
    entry release(n: int) {
        require sender == governance with "only governance";
        require balance >= n with "insufficient treasury balance";
        balance = balance - n;
        total_released = total_released + n;
        execution_count = execution_count + 1;
    }
    view available() -> int { balance }
}
```

The `release` entry is callable only by the governance contract's address. The `solvent` invariant — `balance >= 0` — is enforced by the runtime, not the contract code. The treasury *cannot* go negative regardless of any bug in the governance state machine.

## End-to-end demonstration: the trie swap

The v0.5 demo case for governance is using it to swap the state-root function itself. This is the most credible test: the chain can replace a core function of itself through its own rails.

Flow:

1. **Submit**. A validator submits `{"swap": "state_root_function", "to": "trie"}`.
2. **Exploration**. Other validators review the proposal. After 5 days they vote.
3. **Cooldown**. 5 days of reflection.
4. **Adoption**. Validators vote again.
5. **Activation**. The runtime reads `gov.active_swap("state_root_function") == "trie"` and updates `state["state_root_function"]`.
6. **Effect**. From the activation block onward, `state_root_hex(state)` dispatches to `state_root_trie_hex(state)` — the trie-based commitment, which supports light-client proofs.

The integration test in [`tests/test_state_root_swap.py`](../tests/test_state_root_swap.py) walks through this complete flow and verifies that:
- Before activation: state root is the JSON-hash root.
- A rejected proposal does NOT change the state root function.
- After activation: state root is the trie root, identical to `state_root_trie_hex(state)`.

This is what "on-chain self-amendment" means in practice. No hard fork; no off-chain coordination; just a governance vote that the chain itself respects.

## What's still on the roadmap

| Feature | Why later |
|---|---|
| Quadratic voting for treasury | v0.6 amendment; the linear baseline is simpler to reason about for v0.5 |
| Slashable equivocation in voting | Same machinery as BFT equivocation; v0.6 lift |
| Delegated voting (vote inherited from delegated stake) | Currently only validators vote; delegated voters proxy through their validator |
| Generic code-replacement payloads | v0.6: payloads that replace arbitrary Python functions; needs a sandboxed runtime |
| Proposal bonds | A bond required to submit, refunded if approved, slashed if frivolous |

## Reference

[`kern/governance.py`](../kern/governance.py) (~450 lines) implements:
- `ProtocolPhase` / `TreasuryPhase` enums
- `ProtocolProposal` / `TreasuryProposal` dataclasses with `phase_transitions` history
- `ProtocolGovernance` / `TreasuryGovernance` state machines with `submit`/`vote`/`advance_phases`
- Payload validation for both tracks
- Two Skald contract templates (`PROTOCOL_GOVERNANCE_SKALD`, `TREASURY_GOVERNANCE_SKALD`)

Tested in [`tests/test_governance.py`](../tests/test_governance.py) (28 tests) and [`tests/test_state_root_swap.py`](../tests/test_state_root_swap.py) (4 integration tests).
