# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.issuance — adaptive emission, block rewards, splits.

All issuance math is integer-only (ppm fixed point); these tests assert
exact integer values, not approximations, because two independent clients
must reproduce them bit-for-bit."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.issuance import (
    PPM,
    BlockRewardAccounting,
    IssuanceParams,
    SECONDS_PER_YEAR,
    compute_block_rewards,
    distribute_baker_pool,
    issuance_rate_ppm,
    reward_per_block,
    split_reward,
)


# ---------------------------------------------------------------------------
# Emission curve shape
# ---------------------------------------------------------------------------

def test_zero_staking_gives_max_rate():
    p = IssuanceParams()
    assert issuance_rate_ppm(0, p) == p.i_max_ppm


def test_at_target_gives_min_rate():
    p = IssuanceParams()
    assert issuance_rate_ppm(p.target_staking_ratio_ppm, p) == p.i_min_ppm


def test_above_target_stays_at_min_rate():
    p = IssuanceParams()
    assert issuance_rate_ppm(750_000, p) == p.i_min_ppm
    assert issuance_rate_ppm(PPM, p) == p.i_min_ppm


def test_curve_is_monotonic_decreasing():
    """As staking ratio rises from 0 to target, rate must monotonically fall."""
    p = IssuanceParams()
    samples = [issuance_rate_ppm(r, p) for r in range(0, 500_001, 100_000)]
    for i in range(len(samples) - 1):
        assert samples[i] >= samples[i + 1], f"non-monotonic at {i}: {samples}"


def test_smoothstep_at_endpoints_has_zero_slope():
    """Verify the curve is smooth at endpoints — small perturbations
    near r=0 and r=target produce small changes (not jumps)."""
    p = IssuanceParams()
    eps = 100  # 0.01% in ppm
    near_zero = issuance_rate_ppm(eps, p)
    near_target = issuance_rate_ppm(p.target_staking_ratio_ppm - eps, p)
    assert abs(near_zero - p.i_max_ppm) <= 1
    assert abs(near_target - p.i_min_ppm) <= 1


def test_rate_is_deterministic_integer():
    """The whole curve is integers; sample and re-sample identically."""
    p = IssuanceParams()
    for r in range(0, PPM + 1, 50_000):
        a = issuance_rate_ppm(r, p)
        b = issuance_rate_ppm(r, p)
        assert isinstance(a, int)
        assert a == b


# ---------------------------------------------------------------------------
# Reward per block
# ---------------------------------------------------------------------------

def test_reward_at_genesis_supply_zero_staking():
    """With 1B KRN total supply and 0 staking, max rate = 6%/yr.
    At 1s blocks → 31_557_600 blocks/year → ~1.9 KRN/block."""
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000  # 1B KRN in mukrn
    r = reward_per_block(supply, 0, p)
    expected = supply * p.i_max_ppm // (PPM * p.blocks_per_year())
    assert r == expected
    assert 1_500_000 < r < 2_500_000  # ~1.9 KRN/block in mukrn


def test_reward_at_target_is_minimum():
    """At target staking ratio, reward is the floor (0.25%/yr)."""
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    r = reward_per_block(supply, 500_000, p)
    expected = supply * p.i_min_ppm // (PPM * p.blocks_per_year())
    assert r == expected


def test_reward_is_zero_for_empty_supply():
    p = IssuanceParams()
    assert reward_per_block(0, 0, p) == 0


def test_reward_known_vector():
    """Pinned cross-client test vector (also in the module doctest):
    1e15 mukrn supply, 30% staked → exactly 720_587 mukrn per block."""
    p = IssuanceParams()
    assert reward_per_block(1_000_000_000_000_000, 300_000, p) == 720_587


def test_blocks_per_year_is_exact_integer():
    p = IssuanceParams()
    assert p.blocks_per_year() == SECONDS_PER_YEAR  # 1000ms blocks
    p2 = IssuanceParams(target_block_time_ms=500)
    assert p2.blocks_per_year() == SECONDS_PER_YEAR * 2


# ---------------------------------------------------------------------------
# Reward split
# ---------------------------------------------------------------------------

def test_split_reward_treasury_share():
    p = IssuanceParams(treasury_share_ppm=50_000)
    treasury, baker = split_reward(1000, p)
    assert treasury == 50
    assert baker == 950
    assert treasury + baker == 1000


def test_split_preserves_total_exactly():
    p = IssuanceParams()
    for total in [1, 100, 999, 1_234_567, 9_999_999_999]:
        treasury, baker = split_reward(total, p)
        assert treasury + baker == total


# ---------------------------------------------------------------------------
# Baker pool distribution
# ---------------------------------------------------------------------------

def test_distribute_baker_pool_proposer_bonus():
    p = IssuanceParams(proposer_bonus_ppm=100_000)
    proposer = "kn1AAA"
    endorsers = [
        {"address": "kn1AAA", "stake": 100},
        {"address": "kn1BBB", "stake": 100},
        {"address": "kn1CCC", "stake": 100},
    ]
    rewards = distribute_baker_pool(1000, proposer, endorsers, p)
    # 10% bonus to proposer = 100; remaining 900 split 3 ways = 300 each.
    assert rewards["kn1AAA"] == 400
    assert rewards["kn1BBB"] == 300
    assert rewards["kn1CCC"] == 300
    assert sum(rewards.values()) == 1000


def test_distribute_preserves_total():
    p = IssuanceParams()
    endorsers = [
        {"address": f"kn1V{i}", "stake": s}
        for i, s in enumerate([1000, 2000, 3000, 4000, 5000])
    ]
    rewards = distribute_baker_pool(9_999_999, "kn1V0", endorsers, p)
    assert sum(rewards.values()) == 9_999_999


def test_distribute_handles_unequal_stake():
    p = IssuanceParams(proposer_bonus_ppm=0)  # disable bonus for clean math
    endorsers = [
        {"address": "kn1A", "stake": 100},
        {"address": "kn1B", "stake": 300},  # 3x stake of A
    ]
    rewards = distribute_baker_pool(400, "kn1A", endorsers, p)
    assert rewards["kn1A"] == 100
    assert rewards["kn1B"] == 300


def test_distribute_empty_endorsers():
    p = IssuanceParams()
    rewards = distribute_baker_pool(1000, "kn1A", [], p)
    assert rewards == {}


# ---------------------------------------------------------------------------
# End-to-end block reward accounting
# ---------------------------------------------------------------------------

def test_compute_block_rewards_end_to_end():
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000  # 1B KRN
    staked = supply * 3 // 10           # 30% staked
    endorsers = [
        {"address": "kn1V1", "stake": staked // 2},
        {"address": "kn1V2", "stake": staked // 2},
    ]
    acc = compute_block_rewards(
        total_supply=supply,
        staked=staked,
        proposer_addr="kn1V1",
        endorsers=endorsers,
        treasury_addr="kn1TREASURY",
        params=p,
    )
    assert acc.staking_ratio_ppm == 300_000
    assert acc.total_reward > 0
    assert acc.treasury_credit > 0
    assert acc.baker_pool > 0
    assert acc.treasury_credit + acc.baker_pool == acc.total_reward
    assert sum(acc.per_validator.values()) == acc.baker_pool


def test_supply_growth_after_block():
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    acc = compute_block_rewards(
        total_supply=supply,
        staked=supply // 2,  # at target
        proposer_addr="kn1V1",
        endorsers=[{"address": "kn1V1", "stake": supply // 2}],
        treasury_addr="kn1T",
        params=p,
    )
    assert acc.total_supply_after == supply + acc.total_reward


# ---------------------------------------------------------------------------
# Legacy parameter migration
# ---------------------------------------------------------------------------

def test_from_dict_accepts_ppm_keys():
    p = IssuanceParams.from_dict({"i_max_ppm": 40_000, "target_block_time_ms": 500})
    assert p.i_max_ppm == 40_000
    assert p.target_block_time_ms == 500
    assert p.i_min_ppm == 2_500  # default preserved


def test_from_dict_converts_legacy_float_keys():
    p = IssuanceParams.from_dict({"i_max": 0.05, "i_min": 0.01,
                                  "target_block_time_seconds": 2.0})
    assert p.i_max_ppm == 50_000
    assert p.i_min_ppm == 10_000
    assert p.target_block_time_ms == 2_000


def test_from_dict_ppm_wins_over_legacy():
    p = IssuanceParams.from_dict({"i_max_ppm": 30_000, "i_max": 0.06})
    assert p.i_max_ppm == 30_000


def test_from_dict_ignores_unknown_keys():
    p = IssuanceParams.from_dict({"i_max_ppm": 30_000, "not_a_param": 42})
    assert p.i_max_ppm == 30_000


# ---------------------------------------------------------------------------
# Yearly issuance modeling
# ---------------------------------------------------------------------------

def test_yearly_issuance_approximates_annual_rate():
    """Summing per-block rewards over a year lands within rounding error
    of the annualized rate (floor rounding loses < 1 mukrn per block)."""
    p = IssuanceParams()
    supply = 100_000_000 * 1_000_000   # 100M KRN genesis, in mukrn
    per_block = reward_per_block(supply, 0, p)
    yearly = per_block * p.blocks_per_year()
    exact_annual = supply * p.i_max_ppm // PPM
    assert yearly <= exact_annual
    assert exact_annual - yearly < p.blocks_per_year()  # < 1 mukrn/block lost
