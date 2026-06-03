# Forced Inclusion — censorship resistance for Kern rollups

This document specifies Kern's forced-inclusion mechanism, implemented in [`kern/forced_inclusion.py`](../kern/forced_inclusion.py). It guarantees that any user can transact on any Kern rollup eventually, even if the rollup's sequencer is malicious or unresponsive.

---

## The threat we're guarding against

In an optimistic rollup, the sequencer holds a privileged position: it orders L2 transactions and posts batches to L1. Even with fraud proofs and bisection in place ([`evm-fraud-proofs.md`](evm-fraud-proofs.md)), the sequencer can still **censor** specific users by simply choosing not to include their transactions in any batch.

Without a counter-mechanism, a censored user has no recourse: their transaction sits in the mempool indefinitely, the rollup operates around them, and they can never get on-chain. This makes the rollup permissioned in practice, regardless of its formal design.

## The mechanism

Kern's L1 hosts a **Forced Inclusion Mailbox** for each rollup. The mailbox is a Skald contract conceptually; the state-machine model is implemented in [`kern/forced_inclusion.py`](../kern/forced_inclusion.py).

Any user can post an L2 transaction directly to the mailbox by calling an L1 operation:

```
post_to_mailbox(rollup_id, l2_tx_payload)
```

Once a transaction is posted, the protocol gives the sequencer a deadline — by default **6 L1 hours** (21 600 L1 blocks at 1 s/block) — to include the transaction in a normal L2 batch. After the deadline, the user has **two escape paths**:

### Path 1: Prove omission (slash the sequencer)

Anyone can call `prove_omission(mailbox_entry_hash)` on the L1 mailbox contract. If the entry is past its deadline and still `PENDING`:

1. The entry's status flips to `OMITTED`.
2. A fraction of the sequencer's bond (default 10%) is slashed.
3. Half the slashed amount is burned; half goes to the caller as bounty.

This is the **deterrence** path: it punishes the sequencer financially for each unjustified omission.

### Path 2: Self-include (force the transaction)

Anyone can call `force_include([mailbox_entry_hash, ...])` on L1. The rollup state machine accepts the batch unconditionally (no sequencer signature required); the L2 execution layer must re-execute the listed forced-inclusion transactions in the next L2 block.

This is the **liveness** path: it gets the transaction included regardless of sequencer cooperation.

Both paths are **permissionless**: anyone can trigger them, not just the originally-censored user. This means a single watchful third party can defend everyone.

## State machine

A mailbox entry transitions through these states:

```
┌─────────┐  sequencer includes it       ┌──────────┐
│ PENDING ├─────────────────────────────►│ INCLUDED │
└────┬────┘                              └──────────┘
     │
     │  deadline passes
     ▼
┌───────────┐                            ┌─────────────────┐
│ overdue   │── prove_omission ─────────►│    OMITTED      │
│ (PENDING) │   (slashes sequencer)       │ (deal closed)   │
│           │                              └─────────────────┘
│           │── force_include ──────────►┌─────────────────┐
│           │   (self-included batch)     │ FORCE_INCLUDED  │
└───────────┘                            │ (executed on L2)│
                                          └─────────────────┘
```

## What this guarantees

| Property | Guaranteed? | Notes |
|---|---|---|
| Any user can transact eventually | ✅ | Bounded by the deadline window |
| Sequencer pays for censorship | ✅ | 10% bond slash per proven omission |
| Permissionless enforcement | ✅ | Anyone can trigger both paths |
| Real-time fairness within the window | ❌ | Sequencer can delay up to deadline |
| Order fairness within a batch | ❌ | Sequencer can still re-order tx within their batch |
| Inclusion of malformed transactions | ❌ | Invalid forced-include payloads are dropped by L2 (without slashing the sequencer) |

## Parameters and governance

All three parameters are amendable through on-chain governance:

| Parameter | Default | Effect of increasing |
|---|---:|---|
| `deadline_blocks` | 21 600 (~6h) | More leeway for sequencer; longer max-censorship window |
| `slash_pct` | 10% | Stronger deterrence; risk of over-slashing on legitimate delays |
| `sequencer_bond` | (per-rollup) | Higher slash absolute amount; higher capital requirement on sequencer |

The defaults are tuned for an L1 block time of 1 second. Rollups with their own L2 block times may adjust `deadline_blocks` accordingly.

## On-chain contract

The mailbox is a Skald contract. The relevant excerpts:

```skald
contract Mailbox {
    storage {
        rollup_id: string,
        sequencer: address,
        sequencer_bond: int,
        deadline_blocks: int,
        slash_pct: int,
        total_slashed: int,
        omission_count: int,
    }

    invariant solvent_bond {
        sequencer_bond >= total_slashed
    }

    entry post_bond(n: int) {
        require sender == sequencer with "only sequencer";
        require n > 0 with "bond must be positive";
        sequencer_bond = sequencer_bond + n;
    }

    entry record_omission(amount: int) {
        require amount > 0 with "amount must be positive";
        require sequencer_bond - total_slashed >= amount with "insufficient bond";
        total_slashed = total_slashed + amount;
        omission_count = omission_count + 1;
    }
}
```

The `solvent_bond` invariant is the protocol-level guarantee that the sequencer cannot be slashed more than they bonded. This is enforced by the runtime — there is no implementation bug that can violate it. The contract is in [`kern/forced_inclusion.py`](../kern/forced_inclusion.py) as `MAILBOX_SKALD`.

## Workflow examples

### Example 1: A censored user posts to L1

Alice wants to swap on a rollup-hosted DEX. The sequencer is censoring her (perhaps because of a regulatory takedown, perhaps because of a market-maker conflict of interest). Alice:

1. Posts her swap to the L1 mailbox: `mailbox.post(MailboxEntry(rollup_id="kern-evm-1", sender=alice, l2_tx_payload=<her swap bytes>))`.
2. Waits up to 6 hours.
3. If the sequencer doesn't include her swap by then, Alice (or anyone watching the mailbox) calls `force_include([alice_entry_hash])`.
4. The rollup processes Alice's swap in the next L2 block. The sequencer's bond is also slashed via `prove_omission`.

Worst-case cost to Alice: 1 L1 transaction to post + 1 L1 transaction to force-include + the L2 gas of her swap.

### Example 2: A watchdog earns bounties

A watchdog service monitors the mailbox. Every L1 block, it scans for entries that have just become overdue. For each one, it calls `prove_omission` to slash the sequencer and claim the bounty.

If a rollup has frequent censorship, watchdog services become a profitable business. Their existence raises the cost of sustained censorship for the sequencer to be greater than any reasonable benefit, which makes censorship economically infeasible in equilibrium.

### Example 3: Mass censorship attack

A nation-state coerces a sequencer into censoring an entire class of users (e.g., a particular DApp's users). The sequencer rolls over.

Within hours, watchdog services have force-included all the censored transactions and slashed the sequencer's entire bond. The rollup's L1 record shows the omissions; on-chain governance can rotate the sequencer (via the standard sequencer-rotation operation, see [`rollups.md`](rollups.md)) to a new operator who is not coerced.

The attack doesn't censor users — it just bankrupts the sequencer.

## Limitations

- **Delay, not elimination.** Forced inclusion is bounded by the deadline window. Time-sensitive operations (e.g., arbitrage opportunities) can still be censored for up to the deadline.
- **Cost.** Posting to L1 is more expensive than posting to L2. Forced inclusion is for users who would otherwise be censored — not a routine path.
- **L2 throughput.** Forced inclusion is gated by L1 throughput. A mass-censorship attack can be countered, but a sufficiently large coordinated attack could fill L1 blocks and slow forced-inclusion processing.

These are inherent trade-offs in the rollup model. Forced inclusion brings censorship resistance to the level of L1's censorship resistance — which is the best a rollup can possibly achieve.

## Reference implementation

[`kern/forced_inclusion.py`](../kern/forced_inclusion.py) (~250 lines) provides:

- `MailboxEntry` — a posted entry with hashing and deadline checking
- `Mailbox` — the per-rollup state machine with `post`, `mark_included`, `overdue_entries`, `prove_omission`, `force_include` operations
- `MAILBOX_SKALD` — the L1 Skald contract template
- `get_mailbox_skald_source()` — accessor

Tested in [`tests/test_forced_inclusion.py`](../tests/test_forced_inclusion.py) with 14 scenarios covering:

- Mailbox posting (success, duplicates, wrong rollup ID)
- Sequencer inclusion before deadline
- Overdue detection at the correct level boundary
- `prove_omission` (success, before-deadline rejection, already-included rejection)
- `force_include` (multi-entry success, not-yet-overdue rejection, unknown-hash rejection)
- Mailbox Skald contract typechecks and originates
- Invariant enforcement: cannot slash beyond the bond
