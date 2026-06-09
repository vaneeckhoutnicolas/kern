# Consensus

Kern uses a simplified BFT consensus algorithm in the four-phase family (propose, prevote, precommit, commit). This document describes the protocol as designed; the reference implementation in [`consensus.py`](../kern/consensus.py) implements its single-validator collapse.

## Goals

- **Deterministic finality** under partial synchrony: an endorsed block cannot be reverted.
- **Fast finality** under good network conditions: ≤ 2 blocks (~ 2 seconds).
- **Stake-weighted** participation: voting power is proportional to staked KRN.
- **Accessible validation**: any holder can delegate or self-stake without specialized hardware.

## Roles

- **Baker (validator).** An account that has registered a staking commitment. Bakers propose and endorse blocks. The active baker set rotates per cycle (planned: ~7000 blocks).
- **Delegator.** An account that has delegated its KRN balance to a baker. Delegators do not produce blocks but share in the rewards (Liquid PoS).

## Cycle structure

A **cycle** is a fixed-length window of blocks (planned: 8192 blocks ≈ 2.3 hours at 1s block time). Several protocol events are anchored to cycle boundaries:

- The active validator set is updated.
- Adaptive issuance recomputes block rewards based on the realized staking ratio.
- Treasury allocations vest.

## Round protocol

A **round** is one attempt to add a block at a given level. Most blocks are produced in round 0; rounds 1, 2, ... exist as fallback when network conditions or proposer failure prevent timely finalization.

The round protocol has three message types:

1. **Propose** — the round's selected proposer broadcasts a candidate block.
2. **Pre-endorse** — each validator broadcasts a pre-endorsement signature over the proposed block's hash, signaling its commitment to vote for it.
3. **Endorse** — once a validator has observed pre-endorsements from > 2/3 of the active stake, it broadcasts an endorsement signature.

A block becomes **endorsed** once > 2/3 of stake has endorsed it. The block's level becomes **final** (no longer reorderable) once the chain has built an endorsed block on top of it. Under normal conditions, this means a level is final 2 blocks (~ 2 seconds) after its creation.

## Proposer selection

For each `(level, round)`, the proposer is chosen deterministically and verifiably from the active validator set, weighted by stake. The selection function in [`consensus.py`](../kern/consensus.py) is:

```python
seed = blake2b(parent_hash || round_le_bytes)
rnd  = int(seed[:8])
pick = rnd mod total_stake
proposer = first validator v such that
           sum(v'.stake for v' up to v) > pick
```

This is verifiable (everyone with the parent block can compute it) and stake-weighted (chance of being selected is proportional to stake share).

## Block timing

- **Target block time:** 1 second.
- **Round 0 duration:** 1 second from parent timestamp.
- **Round n duration:** `1 + n` seconds. If round 0 fails to finalize, round 1 begins after 2 seconds; if round 1 fails, round 2 begins after 3 seconds; and so on.

A round "fails" when its proposer's block does not collect > 2/3 endorsements within the round's duration. The next proposer (selected via the round-incremented seed) takes over.

## Liquid Proof-of-Stake

Stake delegation in Kern follows the Liquid PoS model:

1. A holder funds an address and either self-stakes (becoming a baker) or delegates to an existing baker.
2. Delegated balances count toward the baker's stake for proposer-selection and endorsement weight.
3. Rewards are credited to the baker, which is expected to forward a share to its delegators. (This is enforced socially, not protocol-level — typical for Liquid PoS designs.)
4. Delegation can be re-pointed at any time without any lock-up. Withdrawal of self-staked funds is subject to a planned ~14-day unbonding period.

## Adaptive issuance

The protocol targets a staking ratio of approximately 50%. When the actual ratio is below target, block rewards are increased to incentivize staking; when above, rewards are decreased. The function is monotonic in the staking ratio and bounded between a floor (~ 0.25% annualized) and a ceiling (~ 6% annualized).

The full formula is parameterized at the protocol level and is itself subject to on-chain governance.

## Slashing

Two slashable offenses are defined:

- **Double-baking** — producing two distinct blocks at the same level. Penalty: forfeit the baker's deposit for the current cycle.
- **Double-endorsing** — signing two contradictory endorsement messages at the same level. Penalty: forfeit the baker's deposit for the current cycle.

A third party who submits cryptographic proof of either offense receives half the slashed deposit; the rest is burned.

## Reference implementation collapse

The reference implementation in this repository runs a **single validator**. In that degenerate case:

- The proposer selection always returns the sole validator.
- Pre-endorsement and endorsement are not exchanged; the proposer self-commits.
- Finality is immediate (one block, ~ 1 second by default; ~ 500 ms with `--block-time 0.5`).

A multi-validator implementation is a straightforward extension that adds the pre-endorsement and endorsement message exchange to [`network.py`](../kern/network.py) and the corresponding signature aggregation to [`consensus.py`](../kern/consensus.py).
