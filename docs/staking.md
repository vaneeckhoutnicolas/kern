# Staking and Delegation

This document is the reference for how staking works in Kern as the code stands in v1.1-rc. It complements [`tokenomics.md`](tokenomics.md) §6. Every rule below can be checked in [`kern/chain.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/chain.py).

## Definition

**Bonded Proof-of-Stake** is the staking model in which the tokens that secure the chain are locked (bonded) in the protocol for as long as they do so. In Kern:

- **Who bonds.** Each validator bonds its own stake. Any holder can delegate by bonding KRN to one validator, without running a node.
- **Who holds the bond.** The protocol, never the validator. A validator cannot spend or move its delegators' KRN.
- **What a bond does.** It adds to the validator's consensus weight (from the next epoch), earns a share of its rewards, and is slashed if the validator signs conflicting votes.
- **How it ends.** Undelegating removes the weight at once and starts an unbonding period (86 400 blocks by default); the KRN return to their owner at its end, minus any slash for an offence committed while they were exposed.
- **What it is not.** It is not *liquid* staking: bonded KRN cannot be spent while they secure the chain, and no derivative token stands in for them.

The lock is the point: consensus weight always has collateral behind it that can be slashed. The cost is liquidity for the holder.

## Overview

Kern uses **bonded Proof-of-Stake delegation**. Delegated KRN leave the delegator's spendable balance and are held, at protocol level, in a bond to one validator. A bond counts toward that validator's consensus weight, earns a share of its rewards, and is slashed with it. Undelegating starts an unbonding period during which the bond carries no weight but stays locked, and slashable for offences committed before the undelegation. There is no derivative token and no smart-contract counterparty.

> **History.** Before v1.1-rc Phase D, a delegation counted the delegator's *liquid* balance, which stayed spendable. An external review showed that this let consensus weight exist without collateral behind it. Phase D bonded delegations ([phase-d-changes.md](phase-d-changes.md)); Phase E made undelegation lower consensus weight at once and limited slashing to the stake that was exposed at the offence ([phase-e-changes.md](phase-e-changes.md)).

This document covers:

- §1 Validators
- §2 Delegation
- §3 Reward splitting
- §4 Slashing, and how delegators are exposed
- §5 Practical guide

All durations are in blocks. With the default target block time of 1 second, 86 400 blocks is about one day; a chain can set other values in its genesis.

---

## 1. Validators

A validator (also called a *baker*, the Tezos term) runs a node and takes part in consensus by proposing blocks when selected, pre-endorsing and endorsing blocks (the two BFT voting steps), and voting on governance proposals.

### The validator set

In v1.1-rc the validator set is fixed by the genesis file. There is no transaction to register a new validator or to exit as one; both are on the roadmap. Each genesis validator declares an own stake, which is taken out of its genesis balance and bonded (a genesis that declares more stake than the balance covers is refused).

### Consensus weight and epochs

A validator's **effective stake** is its own stake plus every amount currently bonded to it:

```python
effective_stake(state, validator)
  = own_stake_of_validator
  + sum(bond.amount for bond in delegations if bond.validator == validator)
```

Consensus does not read that number directly. It reads an **epoch snapshot**, `state["consensus_set"]`, refreshed every `epoch_blocks` blocks (default 120). The snapshot is used for proposer selection (stake-weighted, seeded by the parent hash and the round) and for the two-thirds quorum of the BFT votes.

- A new or increased delegation adds weight only at the next epoch boundary, so nobody can move weight into a validator just before a vote.
- A slash or an undelegation lowers weight **at once**, in the same transaction.
- Inside an epoch, a validator's weight can only go down.

### Commission

Each validator has a commission rate (default 10%) taken off the top of the rewards before they are split with delegators. Rates live in `state["commission_rates"]` and are set at genesis; a dedicated transaction to change them is not implemented yet.

---

## 2. Delegation

Delegation lets a holder take part in staking without running a node.

### Properties

| Property | Kern (bonded delegation) | Ethereum (PoS) | Cosmos |
|---|---|---|---|
| Custody of delegated KRN | Held by the protocol in a bond, not by the validator | Deposit contract or liquid staking token | Bonded by the protocol |
| Delay to delegate | None; weight counts from the next epoch boundary | Activation queue | None |
| Delay to undelegate | Unbonding period (default 86 400 blocks) | Exit queue and withdrawal delay | 21 days |
| Switch validator | Undelegate first, then delegate again | Exit and re-deposit | Redelegation |
| Minimum delegation | 1 mukrn | 32 ETH native, or a liquid staking token | Usually 1 token |
| Derivative token | No | Often (stETH, rETH) | No |
| Delegated funds spendable | No, until the unbonding period ends | No (or via the derivative token) | No |

Example: Alice has 10 000 KRN and delegates 6 000 to validator V at level 1 000. Her spendable balance becomes 4 000 KRN. The 6 000 KRN are bonded to V; they weigh in V's consensus weight from the next epoch boundary and earn her a share of V's rewards. If V equivocates after level 1 000, 30% of her bond is burned. When she undelegates, V loses that weight immediately, the 6 000 KRN (or what is left after a slash) stay locked for the unbonding period, and then return to her balance.

### The DELEGATE_STAKE transaction

```python
from kern.transaction import make_delegate_stake

tx = make_delegate_stake(
    sender_kp=alice_keypair,
    validator=validator_address,   # kn1...
    nonce=alice_current_nonce,
    amount=6_000 * 1_000_000,      # mukrn to bond
)
```

Effects:
- `tx.amount` leaves the sender's balance and is added to `state["delegations"][sender] = {"validator", "amount", "tranches"}`.
- Each top-up is recorded as a separate tranche with the level at which it was bonded, so a slash only reaches the tranches that were exposed at the offence (§4).

Errors:
- Validator not in the set: rejected.
- Delegating to self: rejected.
- Amount zero or more than the balance: rejected.
- Already delegating to another validator: rejected; undelegate first.

### The UNDELEGATE_STAKE transaction

```python
from kern.transaction import make_undelegate_stake

tx = make_undelegate_stake(sender_kp=alice_keypair, nonce=alice_current_nonce)
```

Effects:
- The delegation record is removed and an entry is added to `state["delegation_unbonding"]`, keyed by its release level (current level plus `delegation_unbonding_blocks`), with the bond's tranches and the level at which unbonding started.
- The validator's consensus weight drops at once.
- At the release level the remaining amount is credited back to the delegator.

The unbonding period can never be shorter than an epoch, and slashing evidence is accepted for as long as the unbonding period, so funds cannot leave before an offence they backed can still be reported.

---

## 3. Reward splitting

When a validator earns a block reward of `R` mukrn, `kern/issuance.py::split_validator_reward` splits it:

```
1. Commission off the top:
       commission = R * commission_pct / 100
       remaining  = R - commission

2. Pro-rata distribution of `remaining`:
       effective         = own_stake + sum(bonded amounts)
       validator_prorata = remaining * own_stake / effective
       delegator_i_share = remaining * bonded_i / effective

3. Rounding leftover (integer division crumbs) goes to the validator.
```

Bonds in the unbonding period earn nothing.

### Worked example

Validator V has an own stake of 100 000 KRN, Alice has 900 000 KRN bonded to it, Bob has just undelegated (his bond is unbonding), the commission is 10% and the reward is 1 000 mukrn.

- Commission = 100 mukrn to V; remaining = 900 mukrn.
- Effective stake = 100 000 + 900 000 = 1 000 000 KRN (Bob's unbonding funds do not count).
- V's pro-rata = 90 mukrn; Alice's = 810 mukrn; Bob gets nothing.
- V receives 190 mukrn, Alice 810 mukrn. Sum: 1 000.

Rewards currently go to the block proposer only. Paying the network endorsers needs per-parent-block accounting that does not exist yet.

---

## 4. Slashing, and how delegators are exposed

Slashable offences in v1.1-rc:

| Offence | Evidence | Transaction |
|---|---|---|
| Consensus equivocation | Two signed PREENDORSE or ENDORSE votes from the same validator, same level and round, different blocks | `SLASH_CONSENSUS_EQUIVOCATION` |
| Governance equivocation | Two different votes from the same voter on the same proposal and phase, recorded by the governance engine | `SLASH_EQUIVOCATION` |
| Attestation equivocation | Two contradictory attestations by the same issuer about the same schema and subject (slashes the attestation bond, see [attestations](attestations.md)) | `SLASH_ATTESTATION_EQUIVOCATION` |

Proposing two different blocks at the same level is not slashable on its own; only the votes are.

### What a validator slash takes

For an offence committed at level `L`:

- 30% of the validator's own stake is removed; 10% of that goes to the reporter and the rest is burned.
- 30% of every **exposed** delegated tranche is burned. A tranche is exposed when it was bonded at or before `L` and its bond had not started unbonding before `L`. This covers live bonds and bonds still in their unbonding period.
- A tranche bonded after the offence, or a bond that started unbonding before it, is not touched: it was not backing the validator at the offence.
- The validator's consensus weight drops at once.
- Liquid balances are never touched.

The level `L` is the vote level for a consensus equivocation and the level of the second, conflicting vote for a governance equivocation. Consensus evidence older than the unbonding period is rejected. The same consensus offence (validator, kind, level, round) can be slashed only once.

Bonds written before Phase E carry no tranche levels; they are treated as bonded at level 0, so they stay exposed as they were under Phase D.

### Why this matters

Without delegator slashing, delegation is pure upside and piling onto one validator becomes the rational strategy. With it, choosing a validator is an economic decision. Limiting the slash to exposed stake keeps the rule fair: a holder who delegates after a fault, or who left before it, does not pay for it.

---

## 5. Practical guide

### As a holder who wants to earn yield

1. **Pick a validator.** The RPC endpoint `/chain/validators` lists the validators with their stake.
2. **Bond an amount.** With the wallet script: `python scripts/kern_wallet.py delegate KEY.json --validator kn1... --amount <KRN>`.
3. **Wait for the next epoch boundary.** Your bond weighs in consensus from there, and earns a share of each reward your validator receives.
4. **To switch:** undelegate, wait for the unbonding period to end, then delegate to the new validator.
5. **To stop:** undelegate. The funds come back to your balance after the unbonding period, minus any slash for an offence your validator committed while they backed it.

### Choosing a validator

- **Commission:** lower is better, all else equal.
- **Uptime:** an offline validator proposes no blocks and earns nothing.
- **Slashing history:** a past slash is a warning sign.
- **Total stake:** spreading delegations across validators keeps the network decentralised.

### Returns to expect

At the target staking ratio of about 50%, adaptive issuance gives roughly 0.25% to 3% a year depending on participation. After a 10% commission, a delegator earns about 90% of that. This is intentionally modest: the value of holding KRN is meant to come from using the network, not from staking yield alone.

---

## Reference

- Code: [`kern/chain.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/chain.py) (`_apply_delegate_stake`, `_apply_undelegate_stake`, `_slash_validator`, `effective_stake`, `delegators_of`, `commission_rate_of`, `_epoch_tick`)
- Reward math: [`kern/issuance.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/issuance.py) (`split_validator_reward`)
- Transactions: [`kern/transaction.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/transaction.py) (`make_delegate_stake`, `make_undelegate_stake`)
- Tests: [`tests/test_delegation.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_delegation.py), [`tests/test_phase_d_bonded_stake.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_phase_d_bonded_stake.py), [`tests/test_phase_e_bond_timing.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_phase_e_bond_timing.py)
