# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.issuance
-------------

Adaptive issuance: per-block rewards with a self-stabilizing emission
curve, computed **entirely in integer arithmetic**.

Why integers only
-----------------

Issuance is consensus-critical: every validator must derive the exact
same reward from the same state, and a future second client (kern-go)
must reproduce the same values bit-for-bit. Floating point is therefore
banned from this module. All rates are expressed in **parts per million
(ppm)**: 1_000_000 ppm = 100%.

The curve
---------

    i(r) = i_min + (i_max - i_min) * smoothstep(1 - r / target)

where (all in ppm):

    r           = realized staking ratio       (staked * PPM // supply)
    target      = target staking ratio,        default 500_000  (50%)
    i_min       = floor inflation,             default   2_500  (0.25%/yr)
    i_max       = ceiling inflation,           default  60_000  (6%/yr)
    smoothstep(x) = x*x*(3*PPM - 2*x) // PPM²   on the clamped domain [0, PPM]

The shape:
    r = 0      →  i = i_max   (max incentive to stake)
    r = target →  i = i_min   (target reached, minimum dilution)
    r > target →  i = i_min   (no need for more stake)

Per-block reward
----------------

    reward_per_block = supply * i_ppm // (PPM * blocks_per_year)

with blocks_per_year an exact integer derived from the target block
time expressed in **milliseconds**:

    blocks_per_year = SECONDS_PER_YEAR * 1000 // target_block_time_ms

For 1-second blocks: 31_557_600 blocks/year.

Distribution
------------

Each block reward is split (ppm shares):

    treasury_share_ppm = 50_000  (5%)  →  on-chain treasury contract
    remainder                          →  proposer + endorsers

The proposer receives proposer_bonus_ppm (default 100_000 = 10%) of the
baker pool; the remainder is distributed to endorsing validators
proportional to stake, with the rounding leftover going to the proposer.

Porting note (kern-go)
----------------------

Intermediate products here can exceed int64: `supply * rate_ppm` reaches
~6e18 at genesis supply and grows with issuance; `remainder * stake`
reaches ~1e23. Python integers are arbitrary precision; the Go client
MUST use math/bits.Mul64+Div64 or math/big for these products. See
docs/go-port-breakpoints.md.

Concrete API
------------

    >>> p = IssuanceParams()
    >>> issuance_rate_ppm(0, p)
    60000
    >>> issuance_rate_ppm(500_000, p)
    2500
    >>> reward_per_block(1_000_000_000_000_000, 300_000, p)
    720587
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


PPM = 1_000_000
SECONDS_PER_YEAR = int(365.25 * 24 * 3600)  # 31_557_600 (exact int)

# Legacy float keys accepted by IssuanceParams.from_dict for state written
# before the integer migration; converted once, at the parsing boundary.
_LEGACY_FLOAT_KEYS = {
    "i_min": "i_min_ppm",
    "i_max": "i_max_ppm",
    "target_staking_ratio": "target_staking_ratio_ppm",
    "treasury_share": "treasury_share_ppm",
    "proposer_bonus": "proposer_bonus_ppm",
}


@dataclass(frozen=True)
class IssuanceParams:
    """Parameters of the adaptive issuance formula, all integers.
    All amendable through on-chain governance."""

    i_min_ppm: int = 2_500                    # 0.25%/yr at target
    i_max_ppm: int = 60_000                   # 6%/yr at zero staking
    target_staking_ratio_ppm: int = 500_000   # 50%
    target_block_time_ms: int = 1_000         # 1 second
    treasury_share_ppm: int = 50_000          # 5% to treasury
    proposer_bonus_ppm: int = 100_000         # 10% of baker share

    def blocks_per_year(self) -> int:
        return SECONDS_PER_YEAR * 1000 // self.target_block_time_ms

    @classmethod
    def from_dict(cls, d: dict) -> "IssuanceParams":
        """Build params from a state dict.

        Accepts the canonical integer ppm keys. For chains whose state was
        written before the integer migration, the legacy float keys
        (i_min, i_max, target_staking_ratio, treasury_share,
        proposer_bonus, target_block_time_seconds) are converted once here
        at the parsing boundary; consensus math itself never sees a float.
        Unknown keys are ignored.
        """
        kw: Dict[str, int] = {}
        for f in (
            "i_min_ppm", "i_max_ppm", "target_staking_ratio_ppm",
            "target_block_time_ms", "treasury_share_ppm", "proposer_bonus_ppm",
        ):
            if f in d:
                kw[f] = int(d[f])
        for legacy, ppm_key in _LEGACY_FLOAT_KEYS.items():
            if legacy in d and ppm_key not in kw:
                kw[ppm_key] = int(round(float(d[legacy]) * PPM))
        if "target_block_time_seconds" in d and "target_block_time_ms" not in kw:
            kw["target_block_time_ms"] = int(round(float(d["target_block_time_seconds"]) * 1000))
        return cls(**kw)


def _saturate_ppm(x: int) -> int:
    if x < 0:
        return 0
    if x > PPM:
        return PPM
    return x


def _smoothstep_ppm(x: int) -> int:
    """Integer smoothstep on the ppm domain: x²(3 - 2x) with x in [0, PPM].

    Exact formula: x*x*(3*PPM - 2*x) // PPM². Maps [0, PPM] to [0, PPM]
    with zero slope at the endpoints — avoids derivative discontinuities
    that incentive games could exploit."""
    x = _saturate_ppm(x)
    return x * x * (3 * PPM - 2 * x) // (PPM * PPM)


def issuance_rate_ppm(staking_ratio_ppm: int, params: IssuanceParams = IssuanceParams()) -> int:
    """Annualized inflation rate in ppm as a function of the realized
    staking ratio in ppm. 60_000 means 6% per year."""
    if params.target_staking_ratio_ppm <= 0:
        return params.i_min_ppm
    distance = PPM - staking_ratio_ppm * PPM // params.target_staking_ratio_ppm
    boost = _smoothstep_ppm(distance)
    return params.i_min_ppm + (params.i_max_ppm - params.i_min_ppm) * boost // PPM


def reward_per_block(
    total_supply: int,
    staking_ratio_ppm: int,
    params: IssuanceParams = IssuanceParams(),
) -> int:
    """Per-block reward in the same unit as `total_supply` (mukrn).

    Computed as supply * rate_ppm // (PPM * blocks_per_year), i.e. floor
    division applied once, at the end, for maximal precision."""
    rate = issuance_rate_ppm(staking_ratio_ppm, params)
    return total_supply * rate // (PPM * params.blocks_per_year())


def split_reward(
    total_reward: int,
    params: IssuanceParams = IssuanceParams(),
) -> Tuple[int, int]:
    """Split a block reward into (treasury, baker_pool)."""
    treasury = total_reward * params.treasury_share_ppm // PPM
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
    The proposer additionally receives a proposer_bonus_ppm fraction of
    the pool. The remainder is distributed to endorsers in proportion to
    stake, iterated in list order (the validator-set order, which is part
    of consensus state and identical on every node). Rounding leftover
    goes to the proposer. Returns a {address: mukrn} dict."""
    rewards: Dict[str, int] = {}
    if baker_pool <= 0 or not endorsers:
        return rewards

    bonus = baker_pool * params.proposer_bonus_ppm // PPM
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

    leftover = remainder - distributed
    if leftover > 0:
        rewards[proposer_addr] = rewards.get(proposer_addr, 0) + leftover

    return rewards


# ---------------------------------------------------------------------------
# Per-block accounting helper
# ---------------------------------------------------------------------------

@dataclass
class BlockRewardAccounting:
    """Bookkeeping for the rewards paid out at a single block."""

    total_supply_before: int
    staking_ratio_ppm: int
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
    """All the math for a single block, end-to-end, in integers."""
    ratio_ppm = _saturate_ppm(staked * PPM // total_supply) if total_supply > 0 else 0
    total = reward_per_block(total_supply, ratio_ppm, params)
    treasury, baker_pool = split_reward(total, params)
    per_validator = distribute_baker_pool(baker_pool, proposer_addr, endorsers, params)
    return BlockRewardAccounting(
        total_supply_before=total_supply,
        staking_ratio_ppm=ratio_ppm,
        total_reward=total,
        treasury_credit=treasury,
        per_validator=per_validator,
    )


# ---------------------------------------------------------------------------
# Delegation reward splitting (v1.0-rc, bonded delegation since Phase D)
# ---------------------------------------------------------------------------

def split_validator_reward(
    reward: int,
    own_stake: int,
    delegators: List[tuple],   # [(delegator_address, balance), ...]
    commission_pct: int,
) -> tuple:
    """Split a validator's block reward between the validator and their
    delegators. Bonded delegation:

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

    commission = reward * commission_pct // 100
    remaining = reward - commission

    total_delegated = sum(bal for _addr, bal in delegators)
    effective = own_stake + total_delegated
    if effective <= 0:
        return reward, {}

    validator_prorata = remaining * own_stake // effective
    delegator_shares = {}
    distributed = validator_prorata
    for addr, bal in delegators:
        share = remaining * bal // effective
        if share > 0:
            delegator_shares[addr] = share
            distributed += share

    leftover = remaining - distributed
    validator_total = commission + validator_prorata + leftover

    return validator_total, delegator_shares
