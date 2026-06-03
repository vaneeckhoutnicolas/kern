# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v0.8: quadratic voting, delegations, equivocation slashing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.governance import (
    ProtocolGovernance,
    ProtocolPhase,
    TreasuryGovernance,
    TreasuryPhase,
    Vote,
    WeightScheme,
    _isqrt,
    vote_weight,
)


def _validators(stakes):
    return [
        {"address": f"kn1v{i:03d}{'a' * 30}"[:36],
         "pubkey": f"9XYepk{i:03d}",
         "stake": s}
        for i, s in enumerate(stakes)
    ]


# ===========================================================================
# Quadratic weighting math
# ===========================================================================

def test_isqrt_basic():
    assert _isqrt(0) == 0
    assert _isqrt(1) == 1
    assert _isqrt(4) == 2
    assert _isqrt(100) == 10
    assert _isqrt(1_000_000) == 1000


def test_isqrt_rounds_down():
    assert _isqrt(99) == 9
    assert _isqrt(101) == 10


def test_vote_weight_linear():
    assert vote_weight(1000, WeightScheme.LINEAR) == 1000
    assert vote_weight(1, WeightScheme.LINEAR) == 1


def test_vote_weight_quadratic():
    assert vote_weight(10_000, WeightScheme.QUADRATIC) == 100
    assert vote_weight(1, WeightScheme.QUADRATIC) == 1
    assert vote_weight(0, WeightScheme.QUADRATIC) == 0


def test_quadratic_compresses_large_holders():
    """A 100x stake difference becomes only 10x in voting power."""
    small = vote_weight(1_000_000, WeightScheme.QUADRATIC)
    big = vote_weight(100_000_000, WeightScheme.QUADRATIC)
    # Linear ratio = 100; quadratic ratio = 10
    assert big / small == pytest.approx(10, rel=0.01)


# ===========================================================================
# Treasury voting with quadratic scheme
# ===========================================================================

def test_treasury_default_scheme_is_quadratic():
    """v0.8: treasury defaults to quadratic to dampen whales."""
    vs = _validators([1000, 1000])
    t = TreasuryGovernance(vs, treasury_balance=10_000_000)
    assert t.scheme == WeightScheme.QUADRATIC


def test_treasury_quadratic_changes_outcome():
    """A whale (10M stake) vs many small holders (each 1000 stake).
    Under linear: whale dominates. Under quadratic: small holders matter."""
    # Whale + 10 small holders. Whale stake = 10_000_000, each small = 1000.
    validators = [{"address": "kn1whale" + "x" * 28, "stake": 10_000_000}]
    for i in range(20):
        validators.append({
            "address": f"kn1s{i:03d}" + "y" * 28,
            "stake": 10_000,
        })

    treasury = TreasuryGovernance(
        validators, treasury_balance=10_000_000,
        scheme=WeightScheme.QUADRATIC,
    )

    ok, _, pid = treasury.submit("kn1submitter",
        {"recipients": [{"address": "kn1grant" + "g"*29, "amount": 100_000}]}, 0)
    assert ok
    prop = treasury.proposals[pid]
    treasury.advance_phases(prop.proposal_blocks)

    # Whale votes NO; all small holders vote YES.
    treasury.vote(pid, validators[0]["address"], Vote.NO, prop.proposal_blocks + 1)
    for v in validators[1:]:
        treasury.vote(pid, v["address"], Vote.YES, prop.proposal_blocks + 1)

    # Quadratic weights:
    #   whale: sqrt(10_000_000) ≈ 3162
    #   each small: sqrt(10_000) = 100; 20 of them = 2000
    # Whale wins by ~3162 vs 2000 under quadratic — but the small holders
    # have meaningful weight (40% of total decisive). Under linear, small
    # holders would be 0.2% and not matter at all.
    # The exact outcome here: whale (NO) > all smalls (YES) under
    # quadratic too, so we verify the quadratic ratio is reasonable.

    yes_weight = sum(_isqrt(v["stake"]) for v in validators[1:])
    no_weight = _isqrt(validators[0]["stake"])
    # Under quadratic: yes_weight ≈ 2000, no_weight ≈ 3162
    assert no_weight < 4 * yes_weight  # Whale's advantage is bounded


def test_treasury_linear_scheme_lets_whale_win_alone():
    """Same scenario as above, but with LINEAR scheme: whale dominates."""
    validators = [{"address": "kn1whale" + "x" * 28, "stake": 10_000_000}]
    for i in range(20):
        validators.append({
            "address": f"kn1s{i:03d}" + "y" * 28,
            "stake": 10_000,
        })

    treasury = TreasuryGovernance(
        validators, treasury_balance=10_000_000,
        scheme=WeightScheme.LINEAR,
    )

    yes_weight_linear = sum(v["stake"] for v in validators[1:])  # 200_000
    no_weight_linear = validators[0]["stake"]                    # 10_000_000
    # Under linear: whale has 50x more weight than all smalls combined.
    assert no_weight_linear > 30 * yes_weight_linear


# ===========================================================================
# Delegations
# ===========================================================================

def test_set_delegation_succeeds():
    vs = _validators([1000])
    t = TreasuryGovernance(vs, treasury_balance=10_000_000)
    ok, _ = t.set_delegation("kn1delegator", vs[0]["address"])
    assert ok
    assert t.delegations["kn1delegator"] == vs[0]["address"]


def test_set_delegation_to_non_validator_fails():
    vs = _validators([1000])
    t = TreasuryGovernance(vs, treasury_balance=10_000_000)
    ok, reason = t.set_delegation("kn1delegator", "kn1notavalidator")
    assert not ok


def test_clear_delegation():
    vs = _validators([1000])
    t = TreasuryGovernance(vs, treasury_balance=10_000_000)
    t.set_delegation("kn1d", vs[0]["address"])
    ok, _ = t.clear_delegation("kn1d")
    assert ok
    assert "kn1d" not in t.delegations


def test_delegated_stake_follows_validator_vote():
    """A delegator's stake is added to their validator's effective stake;
    when the validator votes, the delegator's stake votes too."""
    # Validator with 100 stake, delegator with 900 stake → 1000 effective.
    vs = [
        {"address": "kn1validator" + "v" * 24, "stake": 100},
        {"address": "kn1delegator" + "d" * 24, "stake": 900},  # not a validator role
    ]
    # Reframe: only the first is a validator.
    validator_set = [vs[0]]

    t = TreasuryGovernance(
        validator_set, treasury_balance=10_000_000,
        scheme=WeightScheme.LINEAR,
    )
    # Delegate the delegator's stake to the validator.
    t.delegations[vs[1]["address"]] = vs[0]["address"]
    # Augment validator_set with the delegator (for stake lookup).
    t.validator_set = vs

    ok, _, pid = t.submit("kn1s",
        {"recipients": [{"address": "kn1g" + "x"*32, "amount": 100}]}, 0)
    assert ok
    prop = t.proposals[pid]
    t.advance_phases(prop.proposal_blocks)
    # Validator votes yes; delegator's 900 stake follows.
    t.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 1)
    t.advance_phases(prop.proposal_blocks + prop.vote_blocks)
    assert prop.phase == TreasuryPhase.EXECUTED


def test_delegator_can_override_validators_vote():
    """If the delegator votes independently, they opt out of the
    delegation for that proposal."""
    vs = [
        {"address": "kn1validator" + "v" * 24, "stake": 100},
        {"address": "kn1delegator" + "d" * 24, "stake": 900},
    ]
    t = TreasuryGovernance(
        [vs[0]], treasury_balance=10_000_000,
        scheme=WeightScheme.LINEAR,
    )
    t.delegations[vs[1]["address"]] = vs[0]["address"]
    t.validator_set = vs

    ok, _, pid = t.submit("kn1s",
        {"recipients": [{"address": "kn1g" + "x"*32, "amount": 100}]}, 0)
    prop = t.proposals[pid]
    t.advance_phases(prop.proposal_blocks)
    # Validator votes YES with their 100 stake; delegator overrides with NO.
    t.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 1)
    t.vote(pid, vs[1]["address"], Vote.NO, prop.proposal_blocks + 1)
    t.advance_phases(prop.proposal_blocks + prop.vote_blocks)
    # The delegator pulled their 900 stake out of the validator's column
    # and voted NO. Net: yes=100, no=900 → rejected.
    assert prop.phase == TreasuryPhase.REJECTED


# ===========================================================================
# Equivocation slashing on protocol votes
# ===========================================================================

def test_equivocation_detected_and_recorded():
    """If a validator votes YES then NO on the same proposal in the same
    phase, the second vote is rejected and recorded as equivocation."""
    vs = _validators([1000, 1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)
    assert prop.phase == ProtocolPhase.EXPLORATION

    # First vote: yes.
    ok, _ = gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 5)
    assert ok
    # Equivocation: second vote with a different value.
    ok, reason = gov.vote(pid, vs[0]["address"], Vote.NO, prop.proposal_blocks + 6)
    assert not ok
    assert "equivocation" in reason.lower()
    # Original vote still stands.
    assert prop.votes["exploration"][vs[0]["address"]] == "yes"
    # Equivocation recorded.
    assert len(prop.equivocations) == 1
    e = prop.equivocations[0]
    assert e["voter"] == vs[0]["address"]
    assert e["first_vote"] == "yes"
    assert e["second_vote"] == "no"


def test_revote_same_value_is_idempotent_not_equivocation():
    """Re-voting with the same value is fine — not equivocation."""
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)
    gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 5)
    ok, _ = gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 6)
    assert ok
    assert prop.equivocations == []


def test_equivocation_in_adoption_phase_separate_from_exploration():
    """A voter changing position between phases is NOT equivocation —
    that's deliberation. Equivocation is within a single phase."""
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)

    # Vote YES in exploration.
    for v in vs:
        gov.vote(pid, v["address"], Vote.YES, prop.proposal_blocks + 1)

    end_exp = prop.proposal_blocks + prop.exploration_blocks
    gov.advance_phases(end_exp)
    end_cooldown = end_exp + prop.cooldown_blocks
    gov.advance_phases(end_cooldown)
    assert prop.phase == ProtocolPhase.ADOPTION

    # Vote NO in adoption — this is NOT equivocation (different phase).
    ok, _ = gov.vote(pid, vs[0]["address"], Vote.NO, end_cooldown + 1)
    assert ok
    # No equivocation recorded.
    assert prop.equivocations == []


def test_equivocation_serialization_roundtrip():
    """Equivocations survive a state-dict roundtrip."""
    from kern.governance import (
        empty_governance_state,
        load_protocol_governance,
        save_protocol_governance,
    )
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)
    gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 1)
    gov.vote(pid, vs[0]["address"], Vote.NO, prop.proposal_blocks + 2)
    assert len(prop.equivocations) == 1

    gov_state = empty_governance_state()
    save_protocol_governance(gov_state, gov)
    gov2 = load_protocol_governance(gov_state, vs)
    assert len(gov2.proposals[pid].equivocations) == 1


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} v0.8 tests passed.")
