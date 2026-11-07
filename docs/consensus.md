# Consensus

Kern uses a simplified BFT consensus algorithm in the four-phase family (propose, prevote, precommit, commit). This document describes the protocol as designed. The reference implementation runs the vote exchange over the network ([`bft.py`](../kern/bft.py), [`consensus-wire.md`](consensus-wire.md)); it has not yet run on a network of independent machines.

> **Safety status (Phase E).** Before Phase E the engine had no lock: under message delay alone, with every validator honest, two rounds of the same level could finalize two different blocks. Phase E adds a Tendermint-style lock and valid round, signed proposals and a persistent signing journal ([consensus-locking.md](consensus-locking.md), [consensus-wire.md](consensus-wire.md)). Validated on the network simulator and on four node processes on one machine; not yet run on several machines with independent operators, not audited.

## Goals

- **Deterministic finality** under partial synchrony: an endorsed block cannot be reverted. *Implemented in Phase E; field validation and audit pending, see the status above.*
- **Fast finality** under good network conditions: ≤ 2 blocks (~ 2 seconds).
- **Stake-weighted** participation: voting power is proportional to staked KRN.
- **Accessible validation**: any holder can delegate or self-stake without specialized hardware.

## Roles

- **Baker (validator).** An account that has registered a staking commitment. Bakers propose and endorse blocks. The active baker set rotates per cycle (planned: ~7000 blocks).
- **Delegator.** An account that has bonded KRN to a baker. Delegators do not produce blocks but share in the rewards and in the slashing risk.

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

## Bonded Proof-of-Stake delegation

Stake delegation in Kern works as follows (details in [staking.md](staking.md)):

1. A holder funds an address and either self-stakes (becoming a baker) or delegates to an existing baker.
2. Delegated balances count toward the baker's stake for proposer selection, vote weight and quorum, through the consensus validator set: a snapshot of effective stake (bonded own stake after slashing plus bonded delegations) taken at every epoch boundary (`epoch_blocks`, default 120). A new delegation therefore adds weight at the next boundary, never mid-epoch; a slash or an undelegation lowers the validator's weight immediately (Phase E). See [consensus-wire.md](consensus-wire.md).
3. Rewards are split by the protocol: the baker keeps its commission and the share of its own stake, and each delegator is credited its share in proportion to its delegated balance (`issuance.split_validator_reward`).
4. Delegated KRN are bonded: they leave the delegator's balance and are slashed with the validator. Undelegating starts an unbonding period (`delegation_unbonding_blocks`, default 86 400, never shorter than an epoch) during which the funds carry no weight but remain slashable for offences committed before the undelegation. A slash only reaches the stake exposed at the offence (Phase E). To change validator, undelegate first. A validator's own stake is bonded out of its balance at genesis.

## Adaptive issuance

The protocol targets a staking ratio of approximately 50%. When the actual ratio is below target, block rewards are increased to incentivize staking; when above, rewards are decreased. The function is monotonic in the staking ratio and bounded between a floor (~ 0.25% annualized) and a ceiling (~ 6% annualized).

The full formula is parameterized at the protocol level and is itself subject to on-chain governance.

## Slashing

The slashable consensus offence is **double voting**: signing two PREENDORSE or two ENDORSE messages for different blocks at the same level and round. Anyone can submit the two signed messages in a `SLASH_CONSENSUS_EQUIVOCATION` transaction. The penalty is 30% of the validator's own stake and of every delegated amount exposed at the offence; the reporter receives 10% of the own-stake cut and the rest is burned. Evidence older than the unbonding period is rejected. Proposing two blocks at the same level is not slashable on its own. Governance equivocation is slashable too; see [staking.md](staking.md) §4.

## Single-validator mode

With a single validator, proposer selection always returns that validator and its own votes form the quorum, so each block is final as soon as it is produced (about 1 second by default; about 500 ms with `--block-time 0.5`). The multi-validator path exchanges pre-endorsements and endorsements over the network ([`network.py`](../kern/network.py), [`bft.py`](../kern/bft.py)) and is subject to the status above.
