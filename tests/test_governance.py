# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.governance — protocol amendments + treasury cycles."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.governance import (
    PROTOCOL_GOVERNANCE_SKALD,
    TREASURY_GOVERNANCE_SKALD,
    ProtocolGovernance,
    ProtocolPhase,
    TreasuryGovernance,
    TreasuryPhase,
    Vote,
    proposal_id,
    validate_protocol_payload,
    validate_treasury_payload,
)


def _validators(stakes):
    """Create validator dicts with the given stake values."""
    return [
        {"address": f"kn1v{i:03d}{'a' * 30}"[:36],
         "pubkey": f"9XYepk{i:03d}",
         "stake": s}
        for i, s in enumerate(stakes)
    ]


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------

def test_validate_protocol_payload_accepts_params():
    err = validate_protocol_payload({"params": {"i_max": 0.05}})
    assert err is None


def test_validate_protocol_payload_rejects_unknown_param():
    err = validate_protocol_payload({"params": {"unknown_param": 42}})
    assert err and "unknown param" in err


def test_validate_protocol_payload_accepts_swap():
    err = validate_protocol_payload({"swap": "state_root_function", "to": "trie"})
    assert err is None


def test_validate_protocol_payload_rejects_unknown_swap_value():
    err = validate_protocol_payload({"swap": "state_root_function", "to": "exotic"})
    assert err and "unknown swap value" in err


def test_validate_treasury_payload_basic():
    err = validate_treasury_payload({"recipients": [
        {"address": "kn1a", "amount": 1_000_000},
    ]})
    assert err is None


def test_validate_treasury_payload_rejects_negative():
    err = validate_treasury_payload({"recipients": [
        {"address": "kn1a", "amount": -1},
    ]})
    assert err is not None


def test_proposal_id_is_deterministic():
    p1 = proposal_id("kn1a", {"params": {"i_max": 0.05}})
    p2 = proposal_id("kn1a", {"params": {"i_max": 0.05}})
    assert p1 == p2


def test_proposal_id_changes_with_salt():
    p1 = proposal_id("kn1a", {"params": {}}, salt=0)
    p2 = proposal_id("kn1a", {"params": {}}, salt=1)
    assert p1 != p2


# ---------------------------------------------------------------------------
# Protocol cycle: happy path
# ---------------------------------------------------------------------------

def test_protocol_cycle_happy_path():
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)

    # 1. Submit proposal at level 0.
    ok, _, pid = gov.submit(
        submitter=vs[0]["address"],
        payload={"params": {"i_max": 0.05}},
        current_level=0,
    )
    assert ok
    assert pid is not None
    prop = gov.proposals[pid]
    assert prop.phase == ProtocolPhase.SUBMITTED

    # 2. Advance past proposal window → EXPLORATION.
    gov.advance_phases(current_level=prop.proposal_blocks)
    assert prop.phase == ProtocolPhase.EXPLORATION

    # 3. Validators vote yes during exploration.
    for v in vs:
        gov.vote(pid, v["address"], Vote.YES, current_level=prop.proposal_blocks + 10)

    # 4. End of exploration → COOLDOWN (supermajority met).
    end_exploration = prop.proposal_blocks + prop.exploration_blocks
    gov.advance_phases(current_level=end_exploration)
    assert prop.phase == ProtocolPhase.COOLDOWN

    # 5. End of cooldown → ADOPTION.
    end_cooldown = end_exploration + prop.cooldown_blocks
    gov.advance_phases(current_level=end_cooldown)
    assert prop.phase == ProtocolPhase.ADOPTION

    # 6. Validators vote yes during adoption.
    for v in vs:
        gov.vote(pid, v["address"], Vote.YES, current_level=end_cooldown + 10)

    # 7. End of adoption → ACTIVATED.
    end_adoption = end_cooldown + prop.adoption_blocks
    gov.advance_phases(current_level=end_adoption)
    assert prop.phase == ProtocolPhase.ACTIVATED

    # 8. The change is in the activated_changes list.
    assert len(gov.activated_changes) == 1
    assert gov.activated_changes[0]["params"]["i_max"] == 0.05


def test_protocol_cycle_rejection_at_exploration():
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)
    ok, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]

    gov.advance_phases(prop.proposal_blocks)
    assert prop.phase == ProtocolPhase.EXPLORATION

    # All vote NO.
    for v in vs:
        gov.vote(pid, v["address"], Vote.NO, prop.proposal_blocks + 10)

    end_exploration = prop.proposal_blocks + prop.exploration_blocks
    gov.advance_phases(end_exploration)
    assert prop.phase == ProtocolPhase.REJECTED
    assert gov.activated_changes == []


def test_protocol_cycle_quorum_failure():
    """Even if all who voted said yes, failing quorum rejects."""
    vs = _validators([1000, 1000, 1000, 1000, 1000])  # 5000 total stake
    gov = ProtocolGovernance(vs)
    ok, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]

    gov.advance_phases(prop.proposal_blocks)

    # Only 1 of 5 votes yes → 1000/5000 = 20%, below the 25% quorum.
    gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 10)

    gov.advance_phases(prop.proposal_blocks + prop.exploration_blocks)
    assert prop.phase == ProtocolPhase.REJECTED


def test_protocol_below_supermajority_rejected():
    vs = _validators([1000, 1000, 1000])  # need 80% yes
    gov = ProtocolGovernance(vs)
    ok, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)

    # 2/3 vote yes (66.7%) — below 80%.
    gov.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 5)
    gov.vote(pid, vs[1]["address"], Vote.YES, prop.proposal_blocks + 5)
    gov.vote(pid, vs[2]["address"], Vote.NO, prop.proposal_blocks + 5)

    gov.advance_phases(prop.proposal_blocks + prop.exploration_blocks)
    assert prop.phase == ProtocolPhase.REJECTED


def test_protocol_non_validator_cannot_submit():
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    ok, reason, _ = gov.submit("kn1notaval", {"params": {"i_max": 0.05}}, 0)
    assert not ok
    assert "validator" in reason


def test_protocol_non_validator_cannot_vote():
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)
    ok, reason = gov.vote(pid, "kn1notaval", Vote.YES, prop.proposal_blocks + 1)
    assert not ok


def test_protocol_withdraw_during_submission():
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    ok, _ = gov.withdraw(pid, vs[0]["address"])
    assert ok
    assert gov.proposals[pid].phase == ProtocolPhase.WITHDRAWN


def test_protocol_cannot_withdraw_in_voting():
    vs = _validators([1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)
    ok, _ = gov.withdraw(pid, vs[0]["address"])
    assert not ok


def test_effective_params_applies_activated_changes():
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)
    _, _, pid = gov.submit(vs[0]["address"], {"params": {"i_max": 0.05}}, 0)
    prop = gov.proposals[pid]

    # Drive to ACTIVATED.
    gov.advance_phases(prop.proposal_blocks)
    for v in vs:
        gov.vote(pid, v["address"], Vote.YES, prop.proposal_blocks + 5)
    end_exp = prop.proposal_blocks + prop.exploration_blocks
    gov.advance_phases(end_exp)
    gov.advance_phases(end_exp + prop.cooldown_blocks)
    for v in vs:
        gov.vote(pid, v["address"], Vote.YES,
                 end_exp + prop.cooldown_blocks + 5)
    gov.advance_phases(end_exp + prop.cooldown_blocks + prop.adoption_blocks)
    assert prop.phase == ProtocolPhase.ACTIVATED

    # Check params are now overridden.
    current = {"i_max": 0.06, "i_min": 0.0025}
    effective = gov.effective_params(current)
    assert effective["i_max"] == 0.05
    assert effective["i_min"] == 0.0025


def test_active_swap_returns_latest():
    vs = _validators([1000, 1000])
    gov = ProtocolGovernance(vs)
    # Manually add an activated change (simulates a completed cycle).
    gov.activated_changes.append({"swap": "state_root_function", "to": "trie"})
    assert gov.active_swap("state_root_function") == "trie"
    assert gov.active_swap("nonexistent") is None


# ---------------------------------------------------------------------------
# Treasury cycle
# ---------------------------------------------------------------------------

def test_treasury_happy_path():
    vs = _validators([1000, 1000])
    treasury = TreasuryGovernance(vs, treasury_balance=10_000_000)

    ok, _, pid = treasury.submit(
        submitter="kn1submitter",
        payload={"recipients": [{"address": "kn1grantee", "amount": 5_000_000}]},
        current_level=0,
    )
    assert ok

    prop = treasury.proposals[pid]
    treasury.advance_phases(prop.proposal_blocks)
    assert prop.phase == TreasuryPhase.VOTING

    for v in vs:
        treasury.vote(pid, v["address"], Vote.YES, prop.proposal_blocks + 5)

    end_voting = prop.proposal_blocks + prop.vote_blocks
    treasury.advance_phases(end_voting)
    assert prop.phase == TreasuryPhase.EXECUTED
    assert treasury.treasury_balance == 5_000_000
    assert len(treasury.executions) == 1


def test_treasury_oversubscribed_at_submit():
    vs = _validators([1000])
    treasury = TreasuryGovernance(vs, treasury_balance=1_000_000)
    ok, reason, _ = treasury.submit(
        "kn1s",
        {"recipients": [{"address": "kn1a", "amount": 5_000_000}]},
        0,
    )
    assert not ok
    assert "exceeds" in reason or "balance" in reason


def test_treasury_anyone_can_submit():
    """Treasury submission is open (not validator-only)."""
    vs = _validators([1000])
    treasury = TreasuryGovernance(vs, treasury_balance=10_000_000)
    ok, _, _ = treasury.submit(
        "kn1random_person_not_validator",
        {"recipients": [{"address": "kn1a", "amount": 100}]},
        0,
    )
    assert ok


def test_treasury_only_validators_vote():
    vs = _validators([1000])
    treasury = TreasuryGovernance(vs, treasury_balance=10_000_000)
    _, _, pid = treasury.submit("kn1s",
        {"recipients": [{"address": "kn1a", "amount": 100}]}, 0)
    prop = treasury.proposals[pid]
    treasury.advance_phases(prop.proposal_blocks)
    ok, _ = treasury.vote(pid, "kn1not_validator", Vote.YES, prop.proposal_blocks + 1)
    assert not ok


def test_treasury_simple_majority():
    """50% + 1 (vote weight) is enough — no supermajority required."""
    vs = _validators([100, 100, 100])  # 300 total stake
    treasury = TreasuryGovernance(vs, treasury_balance=10_000_000)
    _, _, pid = treasury.submit("kn1s",
        {"recipients": [{"address": "kn1a", "amount": 500}]}, 0)
    prop = treasury.proposals[pid]
    treasury.advance_phases(prop.proposal_blocks)

    # 2 yes, 1 no → 200 vs 100 → yes wins (66.7% > 50%)
    treasury.vote(pid, vs[0]["address"], Vote.YES, prop.proposal_blocks + 1)
    treasury.vote(pid, vs[1]["address"], Vote.YES, prop.proposal_blocks + 1)
    treasury.vote(pid, vs[2]["address"], Vote.NO,  prop.proposal_blocks + 1)

    treasury.advance_phases(prop.proposal_blocks + prop.vote_blocks)
    assert prop.phase == TreasuryPhase.EXECUTED


def test_treasury_drain_protection():
    """If two proposals are voted but treasury can't fund both, the
    second is rejected at execution time."""
    vs = _validators([1000])
    treasury = TreasuryGovernance(vs, treasury_balance=1_500_000)
    _, _, p1 = treasury.submit("kn1s",
        {"recipients": [{"address": "kn1a", "amount": 1_000_000}]}, 0)
    _, _, p2 = treasury.submit("kn1s",
        {"recipients": [{"address": "kn1b", "amount": 1_000_000}]}, 0)

    pr1 = treasury.proposals[p1]
    pr2 = treasury.proposals[p2]

    # Both go through voting.
    treasury.advance_phases(pr1.proposal_blocks)
    treasury.vote(p1, vs[0]["address"], Vote.YES, pr1.proposal_blocks + 1)
    treasury.vote(p2, vs[0]["address"], Vote.YES, pr1.proposal_blocks + 1)
    treasury.advance_phases(pr1.proposal_blocks + pr1.vote_blocks)

    # One executed, the other rejected because of insufficient funds.
    states = {pr1.phase, pr2.phase}
    assert TreasuryPhase.EXECUTED in states
    assert TreasuryPhase.REJECTED in states


# ---------------------------------------------------------------------------
# Skald contract templates
# ---------------------------------------------------------------------------

def test_protocol_governance_skald_typechecks():
    from kern.skald.typecheck import type_check
    errors = type_check(PROTOCOL_GOVERNANCE_SKALD)
    assert errors == [], f"Errors: {errors}"


def test_treasury_skald_typechecks():
    from kern.skald.typecheck import type_check
    errors = type_check(TREASURY_GOVERNANCE_SKALD)
    assert errors == [], f"Errors: {errors}"


def test_protocol_governance_skald_originates():
    from kern.skald import interpret_origination
    storage = interpret_origination(PROTOCOL_GOVERNANCE_SKALD, {
        "cycle_length_blocks": 500,
        "supermajority_num": 4,
        "supermajority_den": 5,
        "quorum_num": 1,
        "quorum_den": 4,
        "activated_count": 0,
    })
    assert storage["supermajority_num"] == 4


def test_treasury_skald_originates_and_release():
    from kern.skald import interpret_call, interpret_origination, SkaldError
    src = TREASURY_GOVERNANCE_SKALD
    gov = "kn1" + "g" * 33
    storage = interpret_origination(src, {
        "governance": gov,
        "balance": 1_000_000,
        "total_released": 0,
        "execution_count": 0,
    })
    # Governance releases 500_000
    storage = interpret_call(src, storage, "release", {"n": 500_000},
                             sender=gov, amount=0, self_addr="kn1tre")
    assert storage["balance"] == 500_000
    assert storage["total_released"] == 500_000
    assert storage["execution_count"] == 1

    # Non-governance call rejected
    with pytest.raises(SkaldError, match="only governance"):
        interpret_call(src, storage, "release", {"n": 100},
                       sender="kn1other", amount=0, self_addr="kn1tre")

    # Over-release rejected by the `balance >= n` requirement
    with pytest.raises(SkaldError, match="insufficient treasury balance"):
        interpret_call(src, storage, "release", {"n": 999_999_999},
                       sender=gov, amount=0, self_addr="kn1tre")


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} governance tests passed.")
