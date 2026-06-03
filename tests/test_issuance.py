# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.issuance — adaptive emission, block rewards, splits."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.issuance import (
    BlockRewardAccounting,
    IssuanceParams,
    SECONDS_PER_YEAR,
    compute_block_rewards,
    distribute_baker_pool,
    issuance_rate,
    reward_per_block,
    split_reward,
)


# ---------------------------------------------------------------------------
# Emission curve shape
# ---------------------------------------------------------------------------

def test_zero_staking_gives_max_rate():
    p = IssuanceParams()
    assert issuance_rate(0.0, p) == pytest.approx(p.i_max, rel=1e-6)


def test_at_target_gives_min_rate():
    p = IssuanceParams()
    assert issuance_rate(p.target_staking_ratio, p) == pytest.approx(p.i_min, rel=1e-6)


def test_above_target_stays_at_min_rate():
    p = IssuanceParams()
    assert issuance_rate(0.75, p) == pytest.approx(p.i_min, rel=1e-6)
    assert issuance_rate(1.0, p) == pytest.approx(p.i_min, rel=1e-6)


def test_curve_is_monotonic_decreasing():
    """As staking ratio rises from 0 to target, rate must monotonically fall."""
    p = IssuanceParams()
    samples = [issuance_rate(r, p) for r in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]]
    for i in range(len(samples) - 1):
        assert samples[i] >= samples[i + 1], f"non-monotonic at {i}: {samples}"


def test_smoothstep_at_endpoints_has_zero_slope():
    """Verify the curve is smooth at endpoints — small perturbations
    near r=0 and r=target produce small changes (not jumps)."""
    p = IssuanceParams()
    eps = 1e-4
    near_zero = issuance_rate(eps, p)
    near_target = issuance_rate(p.target_staking_ratio - eps, p)
    # Both should be very close to their endpoint values.
    assert abs(near_zero - p.i_max) < 1e-3
    assert abs(near_target - p.i_min) < 1e-3


# ---------------------------------------------------------------------------
# Reward per block
# ---------------------------------------------------------------------------

def test_reward_at_genesis_supply_zero_staking():
    """With 1B KRN total supply and 0 staking, max rate = 6%/yr.
    At 1s blocks → ~31.5M blocks/year → ~1.9 KRN/block."""
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000  # 1B KRN in mukrn
    r = reward_per_block(supply, staking_ratio=0.0, params=p)
    expected_annual = 0.06 * supply
    expected_per_block = expected_annual / p.blocks_per_year()
    assert r == int(expected_per_block)
    # Sanity: ~1.9 KRN/block at 6% annual on 1B supply
    assert 1_500_000 < r < 2_500_000  # mukrn


def test_reward_at_target_is_minimum():
    """At target staking ratio, reward is the floor (0.25%/yr)."""
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    r = reward_per_block(supply, staking_ratio=0.5, params=p)
    expected = int(0.0025 * supply / p.blocks_per_year())
    assert r == expected


def test_reward_is_zero_for_empty_supply():
    p = IssuanceParams()
    assert reward_per_block(0, 0.0, p) == 0


# ---------------------------------------------------------------------------
# Reward split
# ---------------------------------------------------------------------------

def test_split_reward_treasury_share():
    p = IssuanceParams(treasury_share=0.05)
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
    p = IssuanceParams(proposer_bonus=0.10)
    proposer = "kn1AAA"
    endorsers = [
        {"address": "kn1AAA", "stake": 100},
        {"address": "kn1BBB", "stake": 100},
        {"address": "kn1CCC", "stake": 100},
    ]
    rewards = distribute_baker_pool(1000, proposer, endorsers, p)
    # 10% bonus to proposer = 100; remaining 900 split 3 ways = 300 each.
    # Proposer gets 100 (bonus) + 300 (share) = 400.
    # Others get 300 each.
    assert rewards["kn1AAA"] == 400
    assert rewards["kn1BBB"] == 300
    assert rewards["kn1CCC"] == 300
    # Total ≤ pool (rounding leftover goes to proposer; here exact).
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
    p = IssuanceParams(proposer_bonus=0.0)  # disable bonus for clean math
    endorsers = [
        {"address": "kn1A", "stake": 100},
        {"address": "kn1B", "stake": 300},  # 3x stake of A
    ]
    rewards = distribute_baker_pool(400, "kn1A", endorsers, p)
    # Total stake 400; A gets 100/400 = 25% = 100, B gets 300/400 = 75% = 300
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
    staked = int(supply * 0.3)            # 30% staked
    endorsers = [
        {"address": "kn1V1", "stake": int(staked * 0.5)},
        {"address": "kn1V2", "stake": int(staked * 0.5)},
    ]
    acc = compute_block_rewards(
        total_supply=supply,
        staked=staked,
        proposer_addr="kn1V1",
        endorsers=endorsers,
        treasury_addr="kn1TREASURY",
        params=p,
    )
    assert acc.staking_ratio == pytest.approx(0.3, abs=1e-9)
    assert acc.total_reward > 0
    assert acc.treasury_credit > 0
    assert acc.baker_pool > 0
    assert acc.treasury_credit + acc.baker_pool == acc.total_reward
    # Sum of per-validator equals baker_pool
    assert sum(acc.per_validator.values()) == acc.baker_pool


def test_supply_growth_after_block():
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    acc = compute_block_rewards(
        total_supply=supply,
        staked=int(supply * 0.5),  # at target
        proposer_addr="kn1V1",
        endorsers=[{"address": "kn1V1", "stake": int(supply * 0.5)}],
        treasury_addr="kn1T",
        params=p,
    )
    assert acc.total_supply_after == supply + acc.total_reward


# ---------------------------------------------------------------------------
# Yearly issuance modeling
# ---------------------------------------------------------------------------

def test_annualized_issuance_at_50_pct_staking():
    """Sum of all per-block rewards over a year should yield ~0.25% inflation
    when staking is at target."""
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    bpy = int(p.blocks_per_year())
    per_block = reward_per_block(supply, 0.5, p)
    total_annual = per_block * bpy
    expected = 0.0025 * supply
    # within 0.1% because of integer rounding per block
    assert abs(total_annual - expected) / expected < 0.001


def test_annualized_issuance_at_zero_staking():
    p = IssuanceParams()
    supply = 1_000_000_000 * 1_000_000
    bpy = int(p.blocks_per_year())
    per_block = reward_per_block(supply, 0.0, p)
    total_annual = per_block * bpy
    expected = 0.06 * supply
    assert abs(total_annual - expected) / expected < 0.001


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} issuance tests passed.")
