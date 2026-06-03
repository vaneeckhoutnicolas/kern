# Staking and Delegation

This document is the canonical reference for how staking works in Kern. It complements [`tokenomics.md`](tokenomics.md) §6 with deeper detail on the mechanics, the math, and the user flows.

Kern uses **Liquid Proof-of-Stake** — the Tezos design. The fundamental property: **delegators keep custody of their KRN**. There is no lockup, no derivative token, no smart-contract counterparty risk. This is the same model Tezos has used in production since 2018 and the same model Cosmos, NEAR, and most of the modern PoS ecosystem have converged on.

This document covers:

- §1 — How baking works (becoming a validator)
- §2 — How delegation works (delegating to a validator)
- §3 — How rewards are split between validator and delegators
- §4 — How slashing works (and how delegators are exposed)
- §5 — Practical: how to delegate, how to choose a validator, how to switch

---

## 1. Baking (becoming a validator)

A validator (also called a *baker* in Tezos terminology — Kern uses both terms interchangeably) is an account that runs a node and participates in consensus by:

- **Proposing blocks** when it's their turn (proposer selection is stake-weighted)
- **Endorsing blocks** proposed by others (a form of pre-vote in the BFT protocol)
- **Voting on governance proposals** (protocol amendments and treasury allocations)

### Registration

Any account holding at least **10 000 KRN** of own stake can register as a validator by submitting a `register_validator` transaction. This:

1. Adds the account to `state["validators"]` with its declared `stake` amount.
2. Makes it eligible for proposer selection.
3. Subjects it to slashing risk for misbehavior.

The minimum own-stake requirement is a Sybil-resistance measure. Without it, anyone could spawn thousands of validator accounts and game the proposer-selection lottery. 10 000 KRN is calibrated to be meaningful but not prohibitive — at a $1/KRN price (a reasonable Kern mainnet target), that's $10 000 of capital at risk.

### Commission

Each validator sets a commission rate (default 10%) that determines what fraction of delegator rewards the validator takes off the top. This is publicly visible on-chain and can be updated by the validator (a future v1.x will add a dedicated `SET_COMMISSION` transaction; currently it's set by direct state modification at validator registration).

Commission ranges in production PoS networks:

| Network | Typical range | Notes |
|---|---|---|
| Tezos | 5-12% | Most bakers cluster around 8-10% |
| Cosmos | 5-20% | Wider spread; some validators compete on commission |
| NEAR | 0-50% | Wide range; many bakers near 0 to attract delegators |

Kern's **10% default** is the Tezos cluster. Validators can compete on lower commissions, but should weigh that against their operational costs (server, monitoring, on-call).

### Unbonding

A validator who voluntarily exits faces a **14-day unbonding period** before their staked funds become transferable. This window exists so that slashing penalties for offenses committed shortly before exit can still be applied.

If a validator is slashed during the unbonding period, the slash is applied to their unbonding funds (same as if they were still active).

---

## 2. Delegation (Liquid PoS baking delegation)

Delegation is the mechanism by which non-validators participate in staking rewards without running infrastructure.

### Properties

| Property | Kern (Liquid PoS) | Ethereum (PoS) | Cosmos (Cosmos-style) |
|---|---|---|---|
| Custody of delegated KRN | **Delegator keeps it** | Transferred to deposit contract or LST | Transferred to validator |
| Lockup period to delegate | **None** | None on entry, ~9 days on exit (was longer before Shanghai) | None on entry, 21 days on exit |
| Lockup period to undelegate / redelegate | **None** | 9 days unbonding | 21 days unbonding |
| Minimum delegation | **1 mukrn** | 0.01 ETH (via LST) or 32 ETH (native) | varies, usually 1 token |
| LST or derivative token | **No** | Yes (stETH, rETH, …) | No |
| Liquidity of delegated stake | **Full — balance stays spendable** | Locked or held as LST (with depeg risk) | Locked |

The "delegator keeps custody" property is what makes Kern's design distinctive. Compare:

- **Ethereum**: Alice has 10 ETH. She uses Lido. Lido deposits 32 ETH per validator from a pool; Alice gets 10 stETH in return. Her real 10 ETH is now locked in Lido's pool, exposed to Lido's smart contract risk, and only retrievable by selling stETH (which can de-peg from ETH).
- **Kern**: Alice has 10 000 KRN. She delegates to validator V. Her 10 000 KRN stays in her account, fully spendable. The validator V can count those 10 000 KRN toward their effective stake at reward-distribution time, but cannot touch them. If Alice wants to spend her KRN, she just spends it — her delegation drops accordingly (next block's effective_stake calculation uses her new balance).

### The DELEGATE_STAKE transaction

```python
from kern.transaction import make_delegate_stake

tx = make_delegate_stake(
    sender_kp=alice_keypair,
    validator=validator_address,   # kn1...
    nonce=alice_current_nonce,
)
```

Effects:
- `state["delegations"][alice_address] = validator_address`
- If Alice was already delegating to a different validator, the delegation is switched (one delegation per delegator).

Errors:
- Validator not in active set → tx rejected
- Delegating to self → tx rejected (register as a validator instead)

### The UNDELEGATE_STAKE transaction

```python
from kern.transaction import make_undelegate_stake

tx = make_undelegate_stake(
    sender_kp=alice_keypair,
    nonce=alice_current_nonce,
)
```

Effects: `del state["delegations"][alice_address]`. No-op if Alice wasn't delegating.

### What "effective stake" means

```python
effective_stake(state, validator_address) 
  = own_stake_of_validator 
  + sum(balances[d] for d in addresses_delegating_to(validator_address))
```

This number is used in two places:

1. **Proposer selection.** Each block, a proposer is sampled with probability proportional to `effective_stake / total_effective_stake`. More stake (own + delegated) = more blocks proposed = more fees and rewards.

2. **Reward distribution** (next section).

The snapshot of effective stake is taken at **reward time** — that is, the moment `apply_block` credits rewards. Critically: a delegator's balance at that moment is what counts. If a delegator drains their account just before reward distribution, they forfeit that block's yield.

---

## 3. Reward splitting

When a validator earns a block reward of `R` mukrn, the split happens in `kern/issuance.py::split_validator_reward`:

```
1. Commission off the top:
       commission = R * commission_pct / 100
       remaining = R - commission

2. Pro-rata distribution of `remaining`:
       effective = own_stake + sum(delegator_balances)
       
       validator_prorata = remaining * own_stake / effective
       delegator_i_share = remaining * delegator_i_balance / effective

3. Rounding leftover (integer division crumbs) goes to the validator.

4. Validator receives commission + validator_prorata + leftover.
   Each delegator receives their share.
```

### Worked example

Validator V has:
- Own stake: 100 000 KRN
- Delegator Alice: 900 000 KRN
- Delegator Bob: 0 KRN (just stopped delegating; balance is 0)
- Commission rate: 10%
- Block reward earned: 1 000 mukrn

Computation:
- Commission = 1 000 × 10% = 100 mukrn → V
- Remaining = 900 mukrn
- Effective stake = 100k + 900k + 0 = 1M
- V's prorata = 900 × 100k/1M = 90 mukrn
- Alice's prorata = 900 × 900k/1M = 810 mukrn
- Bob's prorata = 900 × 0/1M = 0 mukrn

Final:
- V total: 100 + 90 + 0 (leftover) = 190 mukrn
- Alice: 810 mukrn
- Bob: 0 mukrn

Sum: 190 + 810 + 0 = 1 000 ✓

### Why proportional to balance (not delegated_amount)?

Some PoS systems track a separate `delegated_amount` per (delegator, validator) pair, locked in place. Kern doesn't. The delegation just declares an intent ("count my balance toward V's effective stake"); the actual amount counted is whatever the delegator's balance is at reward time.

This has implications:

- **You can't game it.** If Alice tries to triple-count her balance by splitting into three accounts each delegating to V, she still has the same total balance, which still gets counted once.
- **Drift matters.** A delegator who keeps a lot of liquid balance benefits the validator more. A delegator who drains their account stops contributing.
- **No surprise unbonding.** A validator who loses a delegator (because the delegator drained their account or switched) sees the change immediately in the next block's effective stake. No 21-day delay.

---

## 4. Slashing — and how delegators are exposed

Slashable offenses in Kern (as of v1.0-rc):

| Offense | Detection | Penalty | Reporter reward |
|---|---|---|---|
| Double-baking | Multiple block proposals at same level | 30% of stake | 10% to reporter |
| Double-endorsing | Multiple BFT endorsements at same level | 30% of stake | 10% to reporter |
| **Governance equivocation** | Different votes on same proposal/phase from same voter | **30% of stake** | **10% to reporter** |

Governance equivocation slashing is the v0.8/v1.0-rc addition. It's reportable on-chain via the `SLASH_EQUIVOCATION` transaction by anyone who has the proposal_id and the equivocator address — the runtime checks `state["governance"]["protocol"]["proposals"][pid]["equivocations"]` for matching evidence.

### Proportional delegator slashing

When a validator V is slashed for `S` mukrn, each delegator D of V is also slashed proportionally:

```
delegator_slash = D's balance × SLASHING_PERCENTAGE / 100
```

Same percentage as the validator. The delegator's balance is reduced; the slashed KRN is burned (not paid to the reporter — the reporter reward comes from the validator's own slashed amount, not from delegators).

### Why this matters

Without this, delegation is pure upside: a delegator gets rewards but takes no risk if the validator misbehaves. Mass-delegating to a single validator becomes the rational strategy, defeating decentralization.

With proportional slashing, picking a validator is a real economic decision:

- **High-uptime, well-operated validator**: low slashing risk, modest commission → good for typical users.
- **Cheap-commission validator with sketchy ops**: high slashing risk, low commission → bad bet for serious holders.

This is exactly the dynamic Tezos has had since 2018 and is part of why Tezos has never had a Lido-equivalent concentration problem.

### Cap on delegator slash

A delegator can never be slashed more than their available balance: `min(slash_amount, balances[delegator])`. This is a practical safety bound; it can't cause an account to go negative.

---

## 5. Practical: how to delegate

### As a holder of KRN who wants to earn yield

1. **Pick a validator.** Look at `kern.chain` RPC endpoint `/chain/validators` to see active validators. Each entry shows their stake and commission rate. (A future block explorer will surface uptime, slashing history, and total delegated.)

2. **Submit a `DELEGATE_STAKE` transaction.** From any Kern wallet, sign:
   ```
   {kind: "delegate_stake", params: {validator: "kn1..."}}
   ```

3. **Wait for the next reward distribution.** Your share appears in your balance at the next block where your validator earns a reward.

4. **To switch:** submit another `DELEGATE_STAKE` to a different validator. No waiting period.

5. **To stop:** submit `UNDELEGATE_STAKE`. No waiting period.

### Choosing a validator — what to look for

- **Commission**: lower is better, all else equal. Watch for 0% — that's often a teaser; commissions can be raised by the validator.
- **Uptime**: a validator that's offline doesn't propose blocks and doesn't earn rewards. Aim for ≥ 99% uptime over 30 days.
- **Slashing history**: any past slashes are a yellow flag. Two or more = red flag.
- **Total stake**: don't pile onto the largest validator — that concentrates the network. Spread your delegation. Validators with 5-15% of total stake are typically a good zone.
- **Identity / accountability**: validators with public identities (Twitter, website, GitHub) tend to be more reliable than anonymous ones, because reputation is on the line.

### Returns to expect

At ~50% staking ratio (Kern's target), adaptive issuance produces ~0.25% to ~3% annual yield depending on participation. After a typical 10% commission, a delegator earns ~90% of that, so roughly **0.2% – 2.7% annual yield in KRN** on their delegated balance.

This is intentionally modest. Kern's design assumes that the value of holding KRN comes primarily from network use (transaction demand, governance participation, ecosystem growth) rather than from staking yield alone. A network where staking yield is the only reason to hold the token tends to become extractive and dilutive over time.

### What you don't have to do

- **You don't need to run a node.** That's what the validator is for.
- **You don't need a minimum amount.** 1 mukrn delegations are valid (though gas fees make tiny delegations economically silly).
- **You don't need to wait to undelegate.** No 21-day Cosmos-style cool-down.
- **You don't need to worry about LST de-pegs.** There is no LST.

---

## Reference

- Code: [`kern/chain.py`](../kern/chain.py) (handlers `_apply_delegate_stake`, `_apply_undelegate_stake`, helpers `effective_stake`, `delegators_of`, `commission_rate_of`)
- Reward math: [`kern/issuance.py`](../kern/issuance.py) (function `split_validator_reward`)
- Transactions: [`kern/transaction.py`](../kern/transaction.py) (builders `make_delegate_stake`, `make_undelegate_stake`)
- Tests: [`tests/test_delegation.py`](../tests/test_delegation.py) (20 tests covering math, state, and end-to-end)
