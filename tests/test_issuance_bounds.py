# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The lowest rate of issuance is not above the highest.

Each value of a protocol proposal had its range, and nothing tied two of
them together: `i_min_ppm` could be set above `i_max_ppm`. The chain went
on with its curve upside down, the rate growing with what is staked. And a
genesis could say anything of the issuance: nothing read `issuance_params`
before the first block, which raised on a block time of zero.

Three places now hold the order of the two bounds:

- a proposal that carries both is refused when they cross;
- a proposal is rejected, at the block that would activate it, when it
  would leave them crossed. Several proposals of one block are looked at
  one after the other, each on top of those activated before it;
- a genesis passes the checks of a proposal: the type and the range of each
  value, then the order of the bounds.

The bounds are read as the node reads them: a name in parts per million
comes before the older name of the same rate, written as a fraction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_genesis_block import _init, a_genesis
from test_governance import _validators
from test_governance_integration import _bake_one_block, _genesis_with_baker, _make_baker_keypair
from test_governance_values import _bake

from kern.chain import initial_state_from_genesis
from kern.crypto import KernKeypair
from kern.governance import ProtocolGovernance, Vote, issuance_error, validate_protocol_payload
from kern.issuance import IssuanceParams, issuance_rate_ppm
from kern.transaction import make_governance_propose, make_governance_vote

ROOT = Path(__file__).resolve().parent.parent
CROSSED = [
    {"i_min_ppm": 60_000, "i_max_ppm": 2_500},
    {"i_min_ppm": 1, "i_max_ppm": 0},
    {"i_min_ppm": 1_000_000, "i_max_ppm": 999_999},
    {"i_min": 0.06, "i_max": 0.0025},
    {"i_min_ppm": 60_000, "i_max": 0.0025},
    {"i_min": 0.06, "i_max_ppm": 2_500},
    # A name in parts per million comes before the older name of the same rate.
    {"i_min_ppm": 30, "i_min": 0.0, "i_max_ppm": 20},
    {"i_min_ppm": 10, "i_max_ppm": 5, "i_max": 1.0},
]
IN_ORDER = [
    {"i_min_ppm": 2_500, "i_max_ppm": 60_000},
    {"i_min_ppm": 40_000, "i_max_ppm": 40_000},
    {"i_min_ppm": 0, "i_max_ppm": 0},
    {"i_min_ppm": 1_000_000, "i_max_ppm": 1_000_000},
    {"i_min": 0.05, "i_max": 0.05},
    {"i_min": 0.0025, "i_max_ppm": 2_500},
    {"i_min_ppm": 10, "i_min": 0.9, "i_max_ppm": 20},
    {"i_min_ppm": 10, "i_max_ppm": 20, "i_max": 0.0},
]
ONE_BOUND = [{"i_min_ppm": 900_000}, {"i_max_ppm": 0}, {"i_min": 1}, {"i_max": 0},
             {"i_min_ppm": 70_000, "treasury_share_ppm": 1}]


def named(cases):
    return [json.dumps(case, sort_keys=True) for case in cases]


# ---------------------------------------------------------------------------
# What the rule is for
# ---------------------------------------------------------------------------

def test_what_crossed_bounds_do_to_the_curve():
    """Nothing raises, and that is the trouble: the rate is the lowest where
    it should be the highest. And a program that rounds toward zero, where
    this one rounds down, gets another rate from the same state."""
    usual, crossed = IssuanceParams(), IssuanceParams(i_min_ppm=60_000, i_max_ppm=2_500)
    assert [issuance_rate_ppm(staked, usual) for staked in (0, 250_000, 500_000)] == [60_000, 31_250, 2_500]
    assert [issuance_rate_ppm(staked, crossed) for staked in (0, 250_000, 500_000)] == [2_500, 31_250, 60_000]
    assert issuance_rate_ppm(123_456, crossed) == 11_285                    # 60,000 + floor(-48,714.5175)
    assert 60_000 + int(-57_500 * 847_209 / 1_000_000) == 11_286            # what a division that truncates gives


# ---------------------------------------------------------------------------
# When a proposal is submitted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("params", CROSSED, ids=named(CROSSED))
def test_a_proposal_that_carries_both_bounds_is_refused_when_they_cross(params):
    error = validate_protocol_payload({"params": params})
    assert error is not None and "above the highest" in error
    assert issuance_error(params) == error


@pytest.mark.parametrize("params", IN_ORDER + ONE_BOUND, ids=named(IN_ORDER + ONE_BOUND))
def test_bounds_in_order_or_one_bound_alone_are_accepted_when_submitted(params):
    # One bound alone is judged when the proposal would be activated: what it crosses is in the state of that day.
    assert validate_protocol_payload({"params": params}) is None


def test_the_refusal_says_the_two_rates():
    error = validate_protocol_payload({"params": {"i_min": 0.06, "i_max_ppm": 2_500}})
    assert error == "the lowest rate of issuance (60000 ppm) is above the highest (2500 ppm)"


def test_a_value_out_of_its_range_is_said_first():
    error = validate_protocol_payload({"params": {"i_min_ppm": 2_000_000, "i_max_ppm": 5}})
    assert error is not None and "i_min_ppm must be an integer" in error


def test_a_crossed_proposal_is_not_kept_by_the_chain():
    state, baker, _ = _genesis_with_baker()
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol",
                                                         payload={"params": CROSSED[0]}, nonce=0)])
    assert state["governance"]["protocol"]["proposals"] == {}


# ---------------------------------------------------------------------------
# When a proposal would be activated
# ---------------------------------------------------------------------------

def decided(issuance, *payloads, say=True):
    """Proposals submitted in this order, and voted by every validator, at
    the block that ends their adoption. `issuance` is what the state holds.
    Returns the phase of each, and what the block activates."""
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)
    pids = []
    for payload in payloads:
        ok, why, pid = gov.submit(submitter=vs[0]["address"], payload={"params": payload}, current_level=0)
        assert ok, why
        pids.append(pid)
    first = gov.proposals[pids[0]]
    level = 0
    for blocks, votes in ((first.proposal_blocks, True), (first.exploration_blocks, False),
                          (first.cooldown_blocks, True), (first.adoption_blocks, False)):
        level += blocks
        if say:
            gov.advance_phases(level, issuance=issuance)
        else:
            gov.advance_phases(level)
        if votes:
            for pid in pids:
                for v in vs:
                    assert gov.vote(pid, v["address"], Vote.YES, current_level=level + 10)[0]
    return [gov.proposals[pid].phase.value for pid in pids], [change["params"] for change in gov.activated_changes]


@pytest.mark.parametrize("held, proposed", [
    ({}, {"i_min_ppm": 60_001}),                                  # the highest rate is 60,000 by default
    ({}, {"i_max_ppm": 2_499}),                                   # and the lowest 2,500
    ({"i_max_ppm": 40_000}, {"i_min_ppm": 40_001}),
    ({"i_min_ppm": 40_000}, {"i_max_ppm": 39_999}),
    ({"i_min_ppm": 40_000, "i_max_ppm": 50_000}, {"i_min_ppm": 50_001, "treasury_share_ppm": 7}),
    ({"i_max": 0.06}, {"i_min": 0.07}),                           # the names the genesis of the repository uses
    ({"i_min": 0.0025, "i_max": 0.06}, {"i_min_ppm": 70_000}),
    ({"i_min_ppm": 2_500, "i_max": 0.06}, {"i_max_ppm": 2_000}),
])
def test_a_proposal_that_would_leave_the_bounds_crossed_is_rejected_when_it_would_be_activated(held, proposed):
    before = dict(held)
    assert validate_protocol_payload({"params": proposed}) is None
    assert decided(held, proposed) == (["rejected"], [])
    assert held == before                                         # what the caller gave is not written to


@pytest.mark.parametrize("held, proposed", [
    ({}, {"i_min_ppm": 60_000}),
    ({}, {"i_max_ppm": 2_500}),
    ({"i_max_ppm": 40_000}, {"i_min_ppm": 40_000}),
    ({"i_min_ppm": 40_000}, {"i_max_ppm": 40_000}),
    ({"i_max": 0.06}, {"i_min": 0.06}),
    ({"i_min_ppm": 40_000, "i_max_ppm": 50_000}, {"i_min_ppm": 60_000, "i_max_ppm": 70_000}),
    # The older name of a rate is not read when the state holds its name in parts per million: nothing moves.
    ({"i_min_ppm": 2_500, "i_max_ppm": 60_000}, {"i_min": 0.9}),
    ({"i_min_ppm": 2_500, "i_max_ppm": 60_000}, {"i_max": 0.0}),
])
def test_control_a_proposal_that_leaves_the_bounds_in_order_is_activated(held, proposed):
    assert decided(held, proposed) == (["activated"], [proposed])


def test_several_proposals_of_one_block_are_looked_at_one_after_the_other():
    raise_low, lower_high = {"i_min_ppm": 50_000}, {"i_max_ppm": 40_000}
    # Each is in order alone, and they cross together: the first one stays.
    assert decided({}, raise_low) == (["activated"], [raise_low])
    assert decided({}, lower_high) == (["activated"], [lower_high])
    assert decided({}, raise_low, lower_high) == (["activated", "rejected"], [raise_low])
    assert decided({}, lower_high, raise_low) == (["activated", "rejected"], [lower_high])


def test_a_proposal_is_judged_on_top_of_those_activated_before_it_in_the_block():
    raise_high, raise_low = {"i_max_ppm": 90_000}, {"i_min_ppm": 70_000}
    assert decided({}, raise_high, raise_low) == (["activated", "activated"], [raise_high, raise_low])
    assert decided({}, raise_low, raise_high) == (["rejected", "activated"], [raise_high])


def test_a_rejected_proposal_leaves_nothing_behind_for_the_next_one():
    # The first one is rejected. Had its lowest rate been kept all the same, the second one would cross it.
    assert decided({"i_max_ppm": 60_000}, {"i_min_ppm": 70_000, "treasury_share_ppm": 7}, {"i_max_ppm": 65_000}) == (
        ["rejected", "activated"], [{"i_max_ppm": 65_000}])
    first, second, third = {"i_min_ppm": 70_000, "i_max_ppm": 80_000}, {"i_min_ppm": 65_000}, {"i_max_ppm": 61_000}
    assert decided({}, first, second, third) == (["activated", "activated", "rejected"], [first, second])


def test_a_proposal_that_does_not_move_the_bounds_is_not_held_to_account_for_them():
    """A state written before this rule can hold crossed bounds. A proposal
    about something else is activated as before; one about the bounds must
    put them in order."""
    crossed = {"i_min_ppm": 60_000, "i_max_ppm": 2_500}
    assert decided(crossed, {"treasury_share_ppm": 70_000}) == (["activated"], [{"treasury_share_ppm": 70_000}])
    assert decided(crossed, {"fee_floor_enabled": True}) == (["activated"], [{"fee_floor_enabled": True}])
    assert decided(crossed, {"i_min_ppm": 60_000}) == (["activated"], [{"i_min_ppm": 60_000}])     # the same value
    assert decided(crossed, {"i_min_ppm": 50_000}) == (["rejected"], [])                           # still crossed
    assert decided(crossed, {"i_max_ppm": 3_000}) == (["rejected"], [])
    assert decided(crossed, {"i_min_ppm": 2_000}) == (["activated"], [{"i_min_ppm": 2_000}])
    assert decided(crossed, {"i_max_ppm": 60_000}) == (["activated"], [{"i_max_ppm": 60_000}])


def test_a_state_whose_issuance_cannot_be_read_stops_no_proposal_here():
    """Such a state stops the chain elsewhere, at the reward of each block.
    This rule judges the order of two numbers and raises on nothing."""
    unreadable = {"i_max_ppm": "abc"}
    assert decided(unreadable, {"i_min_ppm": 5}) == (["activated"], [{"i_min_ppm": 5}])
    assert decided(unreadable, {"i_max_ppm": 40_000}) == (["activated"], [{"i_max_ppm": 40_000}])
    assert decided(unreadable, {"i_max_ppm": 40_000, "i_min_ppm": 39_000}, {"i_min_ppm": 40_001}) == (
        ["activated", "rejected"], [{"i_max_ppm": 40_000, "i_min_ppm": 39_000}])
    for held in ({"i_min": [1]}, {"i_min": float("inf")}, {"i_max": float("nan")}):
        assert decided(held, {"treasury_share_ppm": 1}) == (["activated"], [{"treasury_share_ppm": 1}])


def test_a_caller_that_does_not_say_what_the_state_holds_gets_the_checks_of_the_payload_alone():
    assert decided(None, {"i_min_ppm": 70_000}, say=False) == (["activated"], [{"i_min_ppm": 70_000}])
    # No parameters at all is not the same as saying nothing: 60,000 is then the highest rate.
    assert decided({}, {"i_min_ppm": 70_000}) == (["rejected"], [])


def _run(state, baker, pids, levels=420):
    """Bake up to `levels`, voting yes on every proposal in both votes. No block may raise."""
    for step in range(2, levels):
        txs = None
        if step in (102, 305):
            at = state["nonces"][baker.address]
            txs = [make_governance_vote(sender_kp=baker, track="protocol", proposal_id=pid, vote="yes", nonce=at + n)
                   for n, pid in enumerate(pids)]
        state = _bake(state, baker, txs)
    return state


def _submitted(state, baker, *payloads):
    txs = [make_governance_propose(sender_kp=baker, track="protocol", payload={"params": params}, nonce=n)
           for n, params in enumerate(payloads)]
    state = _bake(state, baker, txs)
    pids = list(state["governance"]["protocol"]["proposals"])
    assert [state["governance"]["protocol"]["proposals"][pid]["payload"]["params"] for pid in pids] == list(payloads)
    return state, pids


def test_on_a_chain_a_proposal_that_would_cross_the_bounds_goes_through_every_phase_and_is_rejected():
    state, baker, _ = _genesis_with_baker()
    state, (pid,) = _submitted(state, baker, {"i_min_ppm": 70_000})
    before = state.get("issuance_params")
    state = _run(state, baker, [pid])
    proposal = state["governance"]["protocol"]["proposals"][pid]
    assert [list(step) for step in proposal["phase_transitions"]] == [
        ["submitted", 1], ["exploration", 101], ["cooldown", 201], ["adoption", 301], ["rejected", 401]]
    assert state.get("issuance_params") == before and state["governance"]["protocol"]["activated_changes"] == []
    # Its bond is settled as for any proposal that is rejected, and the chain goes on.
    assert state["governance"]["protocol"]["bonds"] == {} and state["_current_level"] >= 419


def test_on_a_chain_two_proposals_of_one_block_that_cross_together():
    state, baker, _ = _genesis_with_baker()
    state, pids = _submitted(state, baker, {"i_min_ppm": 50_000}, {"i_max_ppm": 40_000})
    state = _run(state, baker, pids)
    proposals = state["governance"]["protocol"]["proposals"]
    assert [proposals[pid]["phase"] for pid in pids] == ["activated", "rejected"]
    assert state["issuance_params"] == {"i_min_ppm": 50_000}
    assert state["governance"]["protocol"]["activated_changes"] == [{"params": {"i_min_ppm": 50_000}}]


def test_on_a_chain_the_second_proposal_of_a_block_is_judged_on_top_of_the_first():
    state, baker, _ = _genesis_with_baker()
    state, pids = _submitted(state, baker, {"i_max_ppm": 90_000}, {"i_min_ppm": 70_000})
    state = _run(state, baker, pids)
    assert [state["governance"]["protocol"]["proposals"][pid]["phase"] for pid in pids] == ["activated", "activated"]
    assert state["issuance_params"] == {"i_max_ppm": 90_000, "i_min_ppm": 70_000}


def test_on_a_chain_whose_state_already_holds_crossed_bounds():
    state, baker, _ = _genesis_with_baker()
    state["issuance_params"] = {"i_min_ppm": 60_000, "i_max_ppm": 2_500}        # a state from before the rule
    state, pids = _submitted(state, baker, {"i_max_ppm": 3_000}, {"treasury_share_ppm": 70_000}, {"i_min_ppm": 2_000})
    state = _run(state, baker, pids)
    assert [state["governance"]["protocol"]["proposals"][pid]["phase"] for pid in pids] == [
        "rejected", "activated", "activated"]
    assert state["issuance_params"] == {"i_min_ppm": 2_000, "i_max_ppm": 2_500, "treasury_share_ppm": 70_000}


# ---------------------------------------------------------------------------
# In a genesis
# ---------------------------------------------------------------------------

def a_state(params):
    """The first state of a network of one validator whose genesis says `params` of the issuance."""
    baker = _make_baker_keypair()
    treasury = KernKeypair.from_seed(bytes.fromhex("22" * 32)).address
    genesis = {"balances": {baker.address: 12_000_000_000, treasury: 1_000_000_000}, "treasury_address": treasury,
               "validators": [{"address": baker.address, "pubkey": baker.public_key_b58, "stake": 10_000_000_000}]}
    if params is not ...:
        genesis["issuance_params"] = params
    return initial_state_from_genesis(genesis), baker


@pytest.mark.parametrize("params", CROSSED, ids=named(CROSSED))
def test_a_genesis_whose_bounds_cross_is_refused(params):
    with pytest.raises(ValueError, match="issuance_params: the lowest rate of issuance .* is above the highest"):
        a_state(params)


NOT_FOR_A_GENESIS = [
    {"target_block_time_ms": 0}, {"i_max_ppm": "abc"}, {"i_min_ppm": 2_000_000}, {"i_min_ppm": -5},
    {"i_min_ppm": True}, {"treasury_share_ppm": 1.5}, {"proposer_bonus_ppm": None}, {"i_min": 2},
    {"target_block_time_seconds": 0}, {"block_time_seconds": 4_000}, {"i_min_ppm": 2_500, "i_max_ppm": [60_000]},
]


@pytest.mark.parametrize("params", NOT_FOR_A_GENESIS, ids=named(NOT_FOR_A_GENESIS))
def test_a_genesis_gives_each_value_the_type_and_the_range_a_proposal_gives_it(params):
    """A block time of zero, or a text where a number is expected, used to
    be accepted, and the first block raised."""
    assert validate_protocol_payload({"params": params}) is not None
    with pytest.raises(ValueError, match="issuance_params: param .* must be"):
        a_state(params)


@pytest.mark.parametrize("params", [[], [["i_min_ppm", 1]], "i_min_ppm", 7, 0, True, False, 1.5])
def test_the_issuance_of_a_genesis_is_an_object_or_nothing(params):
    with pytest.raises(ValueError, match="genesis issuance_params: the issuance parameters must be an object"):
        a_state(params)


MAY_BE_SAID = IN_ORDER + [
    ..., None, {},
    {"i_min_ppm": 0, "i_max_ppm": 0, "target_staking_ratio_ppm": 0, "target_block_time_ms": 1,
     "treasury_share_ppm": 0, "proposer_bonus_ppm": 0},
    {"i_min_ppm": 1_000_000, "i_max_ppm": 1_000_000, "target_staking_ratio_ppm": 1_000_000,
     "target_block_time_ms": 3_600_000, "treasury_share_ppm": 1_000_000, "proposer_bonus_ppm": 1_000_000},
    {"i_min": 0.0025, "i_max": 0.06, "target_staking_ratio": 0.5, "block_time_seconds": 1.0,
     "treasury_share": 0.10, "proposer_bonus": 0.15},
    # A name no proposal knows is left alone, as the node leaves it alone.
    {"i_min_ppm": 2_500, "anything else": ["at", "all"]},
]


@pytest.mark.parametrize("params", MAY_BE_SAID, ids=[json.dumps(p, sort_keys=True) if p is not ... else "absent"
                                                     for p in MAY_BE_SAID])
def test_what_a_genesis_may_say_of_the_issuance_and_the_first_blocks_apply(params):
    state, baker = a_state(params)
    assert state["issuance_params"] == (None if params is ... else params)
    for _ in range(3):
        state, _block = _bake_one_block(state, baker)
    assert state["_current_level"] == 3


def test_the_error_of_a_genesis_is_the_error_of_a_proposal():
    for params in CROSSED[:1] + NOT_FOR_A_GENESIS:
        expected = validate_protocol_payload({"params": params})
        assert expected is not None and issuance_error(params) == expected
    for params in MAY_BE_SAID:
        assert issuance_error(None if params is ... else params) is None


def test_the_genesis_files_of_the_repository_pass():
    described = json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))["issuance_params"]
    assert described["i_min"] == 0.0025 and described["i_max"] == 0.06 and issuance_error(described) is None
    built = (ROOT / "scripts" / "build_v1_genesis.py").read_text(encoding="utf-8")
    assert '"i_min": 0.0025,' in built and '"i_max": 0.06,' in built


def test_init_refuses_a_genesis_whose_issuance_cannot_be_used_and_initialises_nothing(tmp_path, capsys):
    for n, params in enumerate((CROSSED[0], {"target_block_time_ms": 0}, [])):
        (tmp_path / str(n)).mkdir()
        code, data = _init(tmp_path / str(n), {**a_genesis(), "issuance_params": params})
        assert code == 1 and "invalid genesis: genesis issuance_params" in capsys.readouterr().err
        assert not data.exists()      # nothing was written: the operator corrects the file and starts again


def test_control_init_with_an_issuance_in_order(tmp_path, capsys):
    code, data = _init(tmp_path, {**a_genesis(), "issuance_params": {"i_min_ppm": 2_500, "i_max_ppm": 60_000}})
    assert code == 0 and data.exists()
