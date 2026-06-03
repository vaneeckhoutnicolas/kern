# Adaptive Issuance — implementation

The token economy document ([`tokenomics.md`](tokenomics.md)) describes adaptive issuance as a design property. This document describes the v0.3 implementation in [`kern/issuance.py`](../kern/issuance.py), with the actual formulas, parameter choices, and per-block accounting.

---

## The formula

The annualized inflation rate `i` is a function of the realized staking ratio `r`:

```
i(r) = i_min + (i_max - i_min) * smoothstep(saturate(1 - r/target))

where:
    saturate(x)   = clamp(x, 0, 1)
    smoothstep(x) = x² * (3 - 2x)        # zero-slope endpoints
```

With the default parameters:

| Parameter | Default | Meaning |
|---|---:|---|
| `i_min` | 0.0025 | 0.25%/yr — floor inflation when stake is at or above target |
| `i_max` | 0.06 | 6%/yr — ceiling inflation when stake approaches zero |
| `target_staking_ratio` | 0.50 | Target fraction of supply that should be staked |
| `target_block_time_seconds` | 1.0 | Used to compute per-block reward |
| `treasury_share` | 0.05 | 5% of every block reward to the protocol treasury |
| `proposer_bonus` | 0.10 | 10% of baker pool to the round's proposer |

## The shape of the curve

```
i(r)
   │
0.06 ●────╮
     │     ╲
     │      ╲
     │       ╲
     │        ╲___
0.0025 │             ╲────────────────────────────●
     │
     └─────────────────────────────────────────────► r
     0                       0.5                  1.0
                          (target)
```

Three intervals:

- **`r = 0`** → `i = i_max = 6%/yr`. Maximum incentive to attract new staking.
- **`0 < r < target`** → `i` decays smoothly from `i_max` to `i_min` via the smoothstep curve.
- **`r ≥ target`** → `i = i_min = 0.25%/yr`. Inflation floor; further staking does not reduce it.

The smoothstep function is `x² * (3 - 2x)`. It has zero derivative at both `x = 0` and `x = 1`, so the curve is flat near both endpoints. This matters because it removes gaming opportunities: a sharp transition at the target would create incentives to push the system just below or just above target for a few blocks at a time. The smooth curve makes such manipulation unprofitable.

## Per-block reward computation

```
reward_per_block = floor(i(r) * total_supply / blocks_per_year)

where:
    blocks_per_year = SECONDS_PER_YEAR / target_block_time_seconds
                    = 31_557_600 for 1s blocks
```

The `floor` operation is deliberate: rewards are integers (mukrn). Rounding artifacts accumulate as a small dust burn — over a year of 1B-supply, that's microscopic and unbiased.

### Example values

With `total_supply = 1_000_000_000` KRN (= 10¹⁵ mukrn):

| Staking ratio | Annual inflation | Per-block reward | KRN/block |
|---|---:|---:|---:|
| 0% | 6.00% | 1 901 285 mukrn | 1.90 KRN |
| 10% | ~5.05% | 1 600 ... | ~1.60 |
| 25% | ~2.16% | 685 ... | ~0.69 |
| 40% | ~0.39% | 124 ... | ~0.12 |
| 50% (target) | 0.25% | 79 220 mukrn | 0.079 KRN |
| 75% (above target) | 0.25% | 79 220 mukrn | 0.079 KRN |

## Reward split

Each block reward is split in two:

```
treasury_credit = floor(total_reward * treasury_share)
baker_pool      = total_reward - treasury_credit
```

The `treasury_credit` is added to the on-chain treasury contract's balance. The `baker_pool` is distributed among the validators who participated in finalizing the block.

## Baker pool distribution

The proposer of the round (the validator who built the block) receives a fixed bonus, and the rest is distributed to endorsing validators proportional to stake:

```
bonus     = floor(baker_pool * proposer_bonus)        # 10% by default
remainder = baker_pool - bonus
total_stake = sum(v.stake for v in endorsers)
for v in endorsers:
    v_reward = floor(remainder * v.stake / total_stake)
# proposer additionally receives `bonus`
# any leftover from rounding goes to the proposer
```

This rewards both proposing (which has higher operational overhead — assembling blocks, broadcasting) and endorsing (which is what gives the block its finality), with explicit weights.

## Why this design

**Self-stabilizing.** When too few KRN are staked, rewards rise, attracting more stake. When too many are staked, rewards fall, reducing the opportunity cost of *not* staking. The system converges around the target without external intervention.

**Bounded.** Inflation is mathematically bounded between `i_min` and `i_max`. Even pathological staking ratios (e.g., 99% of supply staked, or 1% staked for years) keep inflation in `[0.25%, 6%]`. There is no scenario in which the protocol runaway-inflates.

**Predictable for non-stakers.** Holders who choose not to stake know their worst-case dilution: 6%/yr if no one stakes. In practice, since some stake always exists, real dilution is much lower. This bounded dilution is what makes KRN credibly scarce.

**Composable with sinks.** Net inflation = gross issuance − burns. The protocol's storage rent (50% burn), slashing (50% burn), and failed-fee burns ([`tokenomics.md`](tokenomics.md) §3.4) bring effective net inflation well below gross issuance. Combined with the floor of 0.25% gross, steady-state realized inflation is often near zero or even negative when on-chain activity is high.

## Comparison

| Chain | Issuance model | Inflation range |
|---|---|---|
| Ethereum (post-merge) | Validator deposit-curve | ~0.5% to ~2.5%/yr |
| Tezos | Adaptive issuance (since Quebec) | 0.25% to 5%/yr |
| Cardano | Decreasing schedule | Decaying to ~0% |
| Solana | Fixed disinflationary | 8% → 1.5% over 10 yr |
| **Kern** | **Adaptive issuance with smoothstep** | **0.25% to 6%/yr** |

Kern uses an adaptive issuance schedule with two refinements over linear designs: a smoothstep transition (rather than linear) and explicit treasury and proposer-bonus shares baked into the per-block reward function (rather than handled separately).

## Governance

All parameters in `IssuanceParams` are amendable through the protocol-amendment governance cycle ([`tokenomics.md`](tokenomics.md) §7). The defaults are conservative; if the network discovers that, say, `target_staking_ratio = 0.6` works better empirically, governance can change it without a hard fork.

The function shape (smoothstep) is itself code. A future amendment could replace it with a different curve (logarithmic, piecewise-linear, etc.) — though such changes are higher-risk because they alter the system's incentive properties more fundamentally.

## Wiring into block production

The reference implementation provides `compute_block_rewards()` as the single entry point for the chain state machine:

```python
from kern.issuance import compute_block_rewards, IssuanceParams

acc = compute_block_rewards(
    total_supply=current_supply_in_mukrn,
    staked=currently_staked_in_mukrn,
    proposer_addr="kn1...",
    endorsers=[{"address": "kn1...", "stake": ...}, ...],
    treasury_addr="kn1TREASURY...",
)
# acc.treasury_credit:   mukrn to credit to treasury
# acc.per_validator:     dict of {address: mukrn} to credit to each validator
# acc.total_supply_after: new total supply after this block
```

The full integration into `kern/chain.py` is straightforward (called once per applied block, with the credits added to state alongside transaction fees) and is on the v0.4 roadmap. The current v0.3 ships the issuance module and tests; wiring is mechanical.

## Reference implementation

[`kern/issuance.py`](../kern/issuance.py) (~180 lines) provides:

- `IssuanceParams` — the parameter set
- `issuance_rate(staking_ratio, params)` — the inflation curve
- `reward_per_block(total_supply, ratio, params)` — per-block KRN issued
- `split_reward(total_reward, params)` — `(treasury, baker_pool)`
- `distribute_baker_pool(baker_pool, proposer, endorsers, params)` — `{address: mukrn}`
- `compute_block_rewards(...)` — end-to-end accounting (`BlockRewardAccounting`)

Tested in [`tests/test_issuance.py`](../tests/test_issuance.py) with 18 scenarios covering:

- Curve endpoints (0% → max, target → min)
- Above-target plateau at min
- Monotonic decrease across the curve
- Smoothstep zero-slope at endpoints
- Per-block reward at canonical supply levels
- Reward split conservation (treasury + baker = total)
- Baker pool distribution (proposer bonus, stake-proportional remainder)
- Conservation of total under integer rounding
- Annualized issuance accuracy at target and at zero-staking (≤ 0.1% rounding error)
