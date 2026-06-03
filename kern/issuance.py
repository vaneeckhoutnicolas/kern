# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.issuance
=============

Adaptive issuance for Kern.

The protocol targets a fixed staking ratio (default 50%). When realized
staking is below target, block rewards rise (incentivizing more stake);
when above target, rewards fall (reducing dilution of non-stakers).

The emission rate as a function of staking ratio
------------------------------------------------

    i(r) = i_min + (i_max - i_min) * smoothstep(saturate(1 - r/target))

where:
    r           = realized staking ratio (staked / total supply), 0..1
    target      = target staking ratio, default 0.5
    i_min       = floor inflation, default 0.0025  (0.25%/yr)
    i_max       = ceiling inflation, default 0.06  (6%/yr)
    saturate(x) = clamp(x, 0, 1)
    smoothstep(x) = x * x * (3 - 2 * x)

The shape:
    r = 0      →  i = i_max   (max incentive to stake)
    r = target →  i = i_min   (target reached, minimum dilution)
    r > target →  i = i_min   (no need for more stake)

The smoothstep avoids sharp transitions that would create gaming
opportunities around the target.

Per-block reward
----------------

    reward_per_block = (i * total_supply) / blocks_per_year

with blocks_per_year derived from the protocol's target block time:

    blocks_per_year = 365.25 * 24 * 3600 / target_block_time_seconds

For 1-second blocks: ~31_557_600 blocks/year.

Distribution
------------

Each block reward is split:

    treasury_share = 5%  →  on-chain treasury contract
    baker_share    = 95% →  proposer + endorsers (proportional to stake)

The baker_share is further divided proportionally: the round's proposer
receives a fixed proposer_bonus (default 10% of baker_share), and the
remainder is distributed to endorsing validators proportional to their
stake among endorsers.

Concrete API
------------

    >>> p = IssuanceParams()
    >>> issuance_rate(staking_ratio=0.0, params=p)
    0.06
    >>> issuance_rate(staking_ratio=0.5, params=p)
    0.0025
    >>> reward_per_block(total_supply=1_000_000_000_000_000, ratio=0.3, params=p)
    760...

All amounts are integers (mukrn); supply is expressed in mukrn = 10⁻⁶ KRN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


SECONDS_PER_YEAR = int(365.25 * 24 * 3600)  # 31_557_600


@dataclass(frozen=True)
class IssuanceParams:
    """Parameters of the adaptive issuance formula. All amendable through
    on-chain governance."""

    i_min: float = 0.0025                 # 0.25%/yr at target
    i_max: float = 0.06                   # 6%/yr at zero staking
    target_staking_ratio: float = 0.50    # 50%
    target_block_time_seconds: float = 1.0
    treasury_share: float = 0.05          # 5% to treasury
    proposer_bonus: float = 0.10          # 10% of baker share

    def blocks_per_year(self) -> float:
        return SECONDS_PER_YEAR / self.target_block_time_seconds


def _saturate(x: float) -> float:
    if x < 0:
        return 0.0
    if x > 1:
        return 1.0
    return x


def _smoothstep(x: float) -> float:
    """Smoothstep function: x^2 * (3 - 2x). Maps [0,1] to [0,1] with
    zero slope at the endpoints — avoids derivative discontinuities
    that incentive games could exploit."""
    x = _saturate(x)
    return x * x * (3 - 2 * x)


def issuance_rate(staking_ratio: float, params: IssuanceParams = IssuanceParams()) -> float:
    """Annualized inflation rate as a function of realized staking ratio.

    Returns a float, e.g. 0.012 means 1.2% per year."""
    # Distance from zero-staking to target, on [0, 1].
    distance = 1 - staking_ratio / params.target_staking_ratio
    boost = _smoothstep(distance)
    return params.i_min + (params.i_max - params.i_min) * boost


def reward_per_block(
    total_supply: int,
    staking_ratio: float,
    params: IssuanceParams = IssuanceParams(),
) -> int:
    """Per-block reward in the same unit as `total_supply` (mukrn).

    Computed as: (annual_rate * supply) / blocks_per_year, rounded down.
    """
    rate = issuance_rate(staking_ratio, params)
    annual = rate * total_supply
    per_block = annual / params.blocks_per_year()
    return int(per_block)


def split_reward(
    total_reward: int,
    params: IssuanceParams = IssuanceParams(),
) -> Tuple[int, int]:
    """Split a block reward into (treasury, baker_pool).

    treasury_share goes to the protocol treasury contract; the rest is
    available for distribution to the proposer and endorsers."""
    treasury = int(total_reward * params.treasury_share)
    baker_pool = total_reward - treasury
    return treasury, baker_pool


def distribute_baker_pool(
    baker_pool: int,
    proposer_addr: str,
    endorsers: List[dict],
    params: IssuanceParams = IssuanceParams(),
) -> Dict[str, int]:
    """Distribute the baker_pool of a block reward.

    `endorsers` is a list of {"address": ..., "stake": ...} dicts —
    the validators who actually signed an endorsement for this block.

    The proposer (whose address is in `endorsers` as well, presumably)
    additionally receives a `proposer_bonus` fraction of the pool.
    The remainder is distributed to endorsers in proportion to stake.

    Returns a {address: mukrn} dict.
    """
    rewards: Dict[str, int] = {}
    if baker_pool <= 0 or not endorsers:
        return rewards

    bonus = int(baker_pool * params.proposer_bonus)
    rewards[proposer_addr] = rewards.get(proposer_addr, 0) + bonus

    remainder = baker_pool - bonus
    total_stake = sum(v["stake"] for v in endorsers)
    if total_stake <= 0:
        return rewards

    distributed = 0
    for v in endorsers:
        share = remainder * v["stake"] // total_stake
        rewards[v["address"]] = rewards.get(v["address"], 0) + share
        distributed += share

    # Any rounding remainder goes to the proposer.
    leftover = remainder - distributed
    if leftover > 0:
        rewards[proposer_addr] = rewards.get(proposer_addr, 0) + leftover

    return rewards


# ---------------------------------------------------------------------------
# Per-block accounting helper
# ---------------------------------------------------------------------------

@dataclass
class BlockRewardAccounting:
    """Bookkeeping for the rewards paid out at a single block.

    Useful for the chain state machine: build one of these in apply_block,
    apply the credits, and emit the totals to the metrics stream.
    """

    total_supply_before: int
    staking_ratio: float
    total_reward: int
    treasury_credit: int
    per_validator: Dict[str, int]   # address -> mukrn

    @property
    def baker_pool(self) -> int:
        return self.total_reward - self.treasury_credit

    @property
    def total_supply_after(self) -> int:
        return self.total_supply_before + self.total_reward


def compute_block_rewards(
    total_supply: int,
    staked: int,
    proposer_addr: str,
    endorsers: List[dict],
    treasury_addr: str,
    params: IssuanceParams = IssuanceParams(),
) -> BlockRewardAccounting:
    """All the math for a single block, end-to-end."""
    ratio = (staked / total_supply) if total_supply > 0 else 0.0
    total = reward_per_block(total_supply, ratio, params)
    treasury, baker_pool = split_reward(total, params)
    per_validator = distribute_baker_pool(baker_pool, proposer_addr, endorsers, params)
    return BlockRewardAccounting(
        total_supply_before=total_supply,
        staking_ratio=ratio,
        total_reward=total,
        treasury_credit=treasury,
        per_validator=per_validator,
    )


# ---------------------------------------------------------------------------
# Delegation reward splitting (v1.0-rc, Liquid PoS)
# ---------------------------------------------------------------------------

def split_validator_reward(
    reward: int,
    own_stake: int,
    delegators: List[tuple],   # [(delegator_address, balance), ...]
    commission_pct: int,
) -> tuple:
    """Split a validator's block reward between the validator and their
    delegators. Liquid PoS:

    1. Commission: validator takes `commission_pct` % off the top.
    2. Remaining `R'` is split between validator (for their own_stake)
       and each delegator (proportional to their balance) based on
       effective_stake shares.

    Returns (validator_share, {delegator: share}). Rounding leftover
    goes to the validator (anti-griefing).

    Example: reward=1000, own_stake=100, delegators=[(A,300),(B,600)],
             commission_pct=10
        - Commission = 100, taken by validator
        - Remaining = 900
        - effective_stake = 100+300+600 = 1000
        - Validator pro-rata share = 900 * 100/1000 = 90
        - A's share = 900 * 300/1000 = 270
        - B's share = 900 * 600/1000 = 540
        - Total to validator = 100 + 90 = 190
        - Total to A = 270, total to B = 540
        - Sum = 190+270+540 = 1000 ✓
    """
    if reward <= 0:
        return 0, {}

    # Commission off the top.
    commission = reward * commission_pct // 100
    remaining = reward - commission

    # Effective stake.
    total_delegated = sum(bal for _addr, bal in delegators)
    effective = own_stake + total_delegated
    if effective <= 0:
        # No stake at all — pay everything as commission (degenerate case).
        return reward, {}

    # Pro-rata split.
    validator_prorata = remaining * own_stake // effective
    delegator_shares = {}
    distributed = validator_prorata
    for addr, bal in delegators:
        share = remaining * bal // effective
        if share > 0:
            delegator_shares[addr] = share
            distributed += share

    # Validator gets commission + pro-rata + any rounding leftover.
    leftover = remaining - distributed
    validator_total = commission + validator_prorata + leftover

    return validator_total, delegator_shares
