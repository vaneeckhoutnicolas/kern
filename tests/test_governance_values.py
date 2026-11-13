# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A governance proposal carries values the node can use, or it is refused.

`validate_protocol_payload` used to check the names of the parameters and
never their values, and `validate_treasury_payload` the amounts and never
the addresses. A proposal with a block time of zero, a rate written as a
text or a recipient that is a list was accepted, voted, and then every
block after its activation raised: the chain stopped.

Every value now has a type and a range when the proposal is submitted. And
a proposal that a state already holds with a value the node cannot use is
rejected when it would be activated or executed, instead of applied.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_governance_integration import _bake_one_block, _genesis_with_baker

from kern.chain import derive_contract_address, fee_params
from kern.crypto import PREFIX_ADDRESS, KernKeypair, address_is_valid, b58check_encode
from kern.governance import ALLOWED_PARAMS, validate_protocol_payload, validate_treasury_payload
from kern.issuance import IssuanceParams
from kern.transaction import make_governance_propose, make_governance_vote

INTEGERS = {
    "i_min_ppm": (0, 1_000_000), "i_max_ppm": (0, 1_000_000), "target_staking_ratio_ppm": (0, 1_000_000),
    "treasury_share_ppm": (0, 1_000_000), "proposer_bonus_ppm": (0, 1_000_000),
    "target_block_time_ms": (1, 3_600_000),
    "fee_floor_base": (0, 10**12), "fee_floor_per_byte": (0, 10**9),
    "max_block_bytes": (131_072, 8_388_608),
}
FRACTIONS = ("i_min", "i_max", "target_staking_ratio", "treasury_share", "proposer_bonus")
SECONDS = ("target_block_time_seconds", "block_time_seconds")
SOMEONE = KernKeypair.from_seed(bytes([0x61]) * 32).address


def protocol(**params) -> str | None:
    return validate_protocol_payload({"params": params})


def treasury(address=SOMEONE, amount=5, **more) -> str | None:
    return validate_treasury_payload({"recipients": [{"address": address, "amount": amount}], **more})


# ---------------------------------------------------------------------------
# Protocol proposals: every value has a type and a range
# ---------------------------------------------------------------------------

def test_every_parameter_has_a_rule():
    assert set(INTEGERS) | set(FRACTIONS) | set(SECONDS) | {"fee_floor_enabled"} == ALLOWED_PARAMS


@pytest.mark.parametrize("name", sorted(INTEGERS))
def test_an_integer_parameter_is_an_integer_in_its_range(name):
    low, high = INTEGERS[name]
    assert protocol(**{name: low}) is None and protocol(**{name: high}) is None
    for value in (low - 1, high + 1, str(low), float(low), True, None, [low], {"v": low}, 10**400, -10**400):
        assert protocol(**{name: value}) is not None, value


def test_the_switch_of_the_fee_floor_is_a_boolean():
    assert protocol(fee_floor_enabled=True) is None and protocol(fee_floor_enabled=False) is None
    for value in (1, 0, "true", None, [True]):
        assert protocol(fee_floor_enabled=value) is not None, value


@pytest.mark.parametrize("name", FRACTIONS)
def test_a_rate_written_as_a_fraction_is_a_number_from_0_to_1(name):
    for value in (0, 1, 0.0, 1.0, 0.05, 0.999999):
        assert protocol(**{name: value}) is None, value
        assert 0 <= IssuanceParams.from_dict({name: value}).__dict__[name + "_ppm"] <= 1_000_000
    for value in (-0.01, 1.01, 2, -1, "0.05", True, None, [0.05], math.nan, math.inf, -math.inf, 10**400):
        assert protocol(**{name: value}) is not None, value


@pytest.mark.parametrize("name", SECONDS)
def test_a_time_written_in_seconds_is_at_least_a_millisecond_and_at_most_an_hour(name):
    for value in (0.001, 0.5, 1, 2, 2.5, 3600, 3600.0):
        assert protocol(**{name: value}) is None, value
    for value in (0, 0.0, 0.0009, 0.0001, -1, 3600.001, 3601, "2", True, None, [2], math.nan, math.inf, 10**400):
        assert protocol(**{name: value}) is not None, value


def test_the_times_in_seconds_that_are_accepted_convert_to_the_range_of_the_milliseconds():
    low, high = INTEGERS["target_block_time_ms"]
    assert IssuanceParams.from_dict({"target_block_time_seconds": 0.001}).target_block_time_ms == low
    assert IssuanceParams.from_dict({"target_block_time_seconds": 3600}).target_block_time_ms == high
    for seconds in (0.001, 0.0010000001, 0.0014, 0.0015, 0.5, 1, 3599.9996, 3600):
        params = IssuanceParams.from_dict({"target_block_time_seconds": seconds})
        assert low <= params.target_block_time_ms <= high and params.blocks_per_year() > 0, seconds


def test_a_payload_with_one_bad_value_among_good_ones_is_refused():
    assert protocol(i_max_ppm=40_000, fee_floor_enabled=True, max_block_bytes=1_048_576) is None
    assert protocol(i_max_ppm=40_000, fee_floor_enabled=True, max_block_bytes=[1]) is not None


@pytest.mark.parametrize("payload", [
    {"swap": ["state_root_function"], "to": "trie"},
    {"swap": {"a": 1}, "to": "trie"},
    {"swap": "state_root_function", "to": ["trie"]},
    {"swap": "state_root_function", "to": {"a": 1}},
    {"swap": "state_root_function", "to": None},
    {"swap": 7, "to": "trie"},
    {"params": ["i_max_ppm"]},
    {"params": {7: 1}},
    {7: 1, "x": 2},
    {("a", "b"): 1, None: 2, "x": 3},
    ["params"],
    None,
])
def test_a_payload_of_the_wrong_shape_is_refused_without_an_exception(payload):
    assert validate_protocol_payload(payload) is not None


def test_control_the_payloads_that_exist_are_still_accepted():
    for payload in ({"params": {"i_max": 0.05}}, {"params": {"i_max": 0.05, "block_time_seconds": 1.5}},
                    {"params": {"i_max_ppm": 40_000}}, {"swap": "state_root_function", "to": "trie"},
                    {"swap": "state_root_function", "to": "json"},
                    {"params": {"fee_floor_enabled": True, "fee_floor_base": 100, "fee_floor_per_byte": 2,
                                "max_block_bytes": 1_048_576}}):
        assert validate_protocol_payload(payload) is None, payload


# ---------------------------------------------------------------------------
# Treasury proposals: every recipient is an address
# ---------------------------------------------------------------------------

def _changed(address: str, at: int) -> str:
    return address[:at] + ("2" if address[at] != "2" else "3") + address[at + 1:]


NOT_ADDRESSES = [
    [1, 2], {"a": 1}, 7, None, True, b"kn1", "", "kn1a", "kn1grantee", "treasury",
    SOMEONE[:-1], SOMEONE + "1", " " + SOMEONE[1:], SOMEONE.upper(),
    _changed(SOMEONE, 0), _changed(SOMEONE, 10), _changed(SOMEONE, 35),      # the prefix, the hash, the checksum
    "0" * 36, "l" * 36, "é" * 36, "\u20ac" * 36,                            # outside the alphabet, outside one byte
    "1" * 36, "1" + SOMEONE[:-1],                                            # zero bytes in front
    KernKeypair.from_seed(bytes([0x61]) * 32).public_key_b58,                # a public key
    "kn1grant" + "g" * 29, "kn1g" + "x" * 32,                                # 36 characters that look like one
]


def test_an_address_is_36_characters_that_carry_the_prefix_twenty_bytes_and_their_checksum():
    assert len(SOMEONE) == 36 and address_is_valid(SOMEONE)
    for fill in (0x00, 0x01, 0x7f, 0xff):
        text = b58check_encode(PREFIX_ADDRESS, bytes([fill]) * 20)
        assert len(text) == 36 and text.startswith("kn1") and address_is_valid(text), text
    for value in NOT_ADDRESSES:
        assert address_is_valid(value) is False, value
    # Another number of bytes never gives 36 characters under this prefix, so
    # the count of the characters is also the count of the bytes.
    for size in list(range(20)) + list(range(21, 41)):
        for fill in (0x00, 0x01, 0xff):
            text = b58check_encode(PREFIX_ADDRESS, bytes([fill]) * size)
            assert len(text) != 36 and not address_is_valid(text), (size, text)
    # The same twenty bytes under the prefix of a public key or of a signature.
    for prefix in (b"\x0d\x0f\x25", b"\x09\xf5\xcd\x86", b"\x05\x95\x9a", b"\x05\x95\x9c"):
        assert not address_is_valid(b58check_encode(prefix, bytes([0x61]) * 20))


def test_a_text_that_is_not_an_address_costs_nothing_to_refuse():
    """Reading 131,072 characters as a number in base 58 takes seconds: the
    count of the characters is looked at first."""
    import time
    start = time.perf_counter()
    for _ in range(200):
        assert not address_is_valid("k" * 131_072)
    assert time.perf_counter() - start < 1


def test_a_recipient_is_an_address_of_an_account_or_of_a_contract():
    assert treasury() is None
    assert treasury(address=derive_contract_address(bytes([0x62]) * 32)) is None
    for address in NOT_ADDRESSES:
        assert treasury(address=address) is not None, address
    two = {"recipients": [{"address": SOMEONE, "amount": 5}, {"address": "kn1grantee", "amount": 5}]}
    assert validate_treasury_payload(two) is not None


def test_an_amount_is_a_positive_integer_and_true_is_not_one():
    assert treasury(amount=1) is None and treasury(amount=2**63 - 1) is None
    for amount in (0, -1, True, False, "5", 1.5, 5.0, None, [5]):
        assert treasury(amount=amount) is not None, amount


# ---------------------------------------------------------------------------
# Through the chain: the cases that were measured
# ---------------------------------------------------------------------------

BAD_PROTOCOL = [{"target_block_time_ms": 0}, {"i_max_ppm": "abc"}, {"max_block_bytes": [1]},
                {"target_block_time_seconds": 0.0001}, {"i_max": math.nan}]


def _bake(state, baker, txs=None):
    state, _ = _bake_one_block(state, baker, txs=txs)
    fee_params(state)                                   # what the validation of a block reads first
    return state


@pytest.mark.parametrize("params", BAD_PROTOCOL, ids=[str(p) for p in BAD_PROTOCOL])
def test_a_protocol_proposal_with_a_value_the_node_cannot_use_is_refused_when_submitted(params):
    state, baker, _ = _genesis_with_baker()
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol",
                                                         payload={"params": params}, nonce=0)])
    assert state["governance"]["protocol"]["proposals"] == {}
    for _ in range(3):
        state = _bake(state, baker)


def test_a_swap_that_is_not_a_text_is_refused_when_submitted():
    state, baker, _ = _genesis_with_baker()
    for payload in ({"swap": ["state_root_function"], "to": "trie"}, {"swap": "state_root_function", "to": ["trie"]}):
        state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol", payload=payload,
                                                             nonce=state["nonces"].get(baker.address, 0))])
        assert state["governance"]["protocol"]["proposals"] == {}, payload
    assert state["state_root_function"] == "json"


def test_a_treasury_proposal_whose_recipient_is_not_an_address_is_refused_when_submitted():
    state, baker, _ = _genesis_with_baker()
    for nonce, address in enumerate(([1, 2], "kn1grantee")):
        payload = {"recipients": [{"address": address, "amount": 5}]}
        state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="treasury", payload=payload,
                                                             nonce=state["nonces"].get(baker.address, 0))])
        assert state["governance"]["treasury"]["proposals"] == {}, address


def _run(state, baker, track, pid, votes_at, levels):
    """Bake up to `levels`, voting yes at the blocks given. No block may raise."""
    for step in range(2, levels):
        txs = None
        if step in votes_at:
            txs = [make_governance_vote(sender_kp=baker, track=track, proposal_id=pid, vote="yes",
                                        nonce=state["nonces"][baker.address])]
        state = _bake(state, baker, txs)
    return state


@pytest.mark.parametrize("params", BAD_PROTOCOL[:3], ids=[str(p) for p in BAD_PROTOCOL[:3]])
def test_a_proposal_a_state_already_holds_with_such_a_value_is_rejected_and_not_activated(params):
    """What a chain started before this rule could hold: the proposal is in
    the state, it is voted, and its payload cannot be applied."""
    state, baker, _ = _genesis_with_baker()
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol",
                                                         payload={"params": {"i_max_ppm": 40_000}}, nonce=0)])
    (pid,) = state["governance"]["protocol"]["proposals"]
    state["governance"]["protocol"]["proposals"][pid]["payload"] = {"params": params}
    before = (state.get("issuance_params"), state.get("fee_params"))
    state = _run(state, baker, "protocol", pid, votes_at=(102, 305), levels=420)
    proposal = state["governance"]["protocol"]["proposals"][pid]
    assert proposal["phase"] == "rejected"
    # At the last moment, and not before: it went through every phase.
    assert [list(step) for step in proposal["phase_transitions"]] == [
        ["submitted", 1], ["exploration", 101], ["cooldown", 201], ["adoption", 301], ["rejected", 401]]
    assert (state.get("issuance_params"), state.get("fee_params")) == before
    assert state["governance"]["protocol"]["activated_changes"] == []
    assert state["governance"]["protocol"]["bonds"] == {}
    assert state["_current_level"] >= 419


ENDS = [
    {name: low for name, (low, _) in INTEGERS.items()} | {"fee_floor_enabled": False},
    {name: high for name, (_, high) in INTEGERS.items()} | {"fee_floor_enabled": True},
    {name: 0 for name in FRACTIONS} | {name: 0.001 for name in SECONDS},
    {name: 1 for name in FRACTIONS} | {name: 3600 for name in SECONDS},
    {name: 1.0 for name in FRACTIONS} | {name: 3600.0 for name in SECONDS},
]


@pytest.mark.parametrize("params", ENDS, ids=["integers low", "integers high", "legacy low", "legacy high",
                                              "legacy high as floats"])
def test_the_ends_of_every_range_are_values_the_chain_goes_on_with(params):
    assert protocol(**params) is None
    state, baker, _ = _genesis_with_baker()
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol",
                                                         payload={"params": params}, nonce=0)])
    (pid,) = state["governance"]["protocol"]["proposals"]
    state = _run(state, baker, "protocol", pid, votes_at=(102, 305), levels=420)
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "activated"
    stored = {**state.get("issuance_params", {}), **state.get("fee_params", {})}
    assert all(stored[name] == value for name, value in params.items())
    assert state["_current_level"] >= 419 and IssuanceParams.from_dict(state["issuance_params"]).blocks_per_year() > 0


def test_control_a_proposal_with_good_values_is_activated():
    state, baker, _ = _genesis_with_baker()
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="protocol",
                                                         payload={"params": {"i_max_ppm": 40_000}}, nonce=0)])
    (pid,) = state["governance"]["protocol"]["proposals"]
    state = _run(state, baker, "protocol", pid, votes_at=(102, 305), levels=420)
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "activated"
    assert state["issuance_params"]["i_max_ppm"] == 40_000


STORED_TREASURY = {
    "a recipient that is a list": {"recipients": [{"address": [1, 2], "amount": 5}]},
    "a recipient that is not an address": {"recipients": [{"address": "kn1grantee", "amount": 5}]},
    "an amount that is a text": {"recipients": [{"address": SOMEONE, "amount": "5"}]},
    "recipients that are not a list": {"recipients": "everyone"},
    "no recipients": {},
}


@pytest.mark.parametrize("stored", list(STORED_TREASURY.values()), ids=list(STORED_TREASURY))
def test_a_treasury_proposal_a_state_already_holds_that_cannot_be_paid_pays_nothing(stored):
    state, baker, treasury_kp = _genesis_with_baker()
    payload = {"recipients": [{"address": SOMEONE, "amount": 5}]}
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="treasury", payload=payload, nonce=0)])
    (pid,) = state["governance"]["treasury"]["proposals"]
    state["governance"]["treasury"]["proposals"][pid]["payload"] = stored
    held = state["balances"][treasury_kp.address]
    accounts = set(state["balances"])
    state = _run(state, baker, "treasury", pid, votes_at=(202,), levels=320)
    proposal = state["governance"]["treasury"]["proposals"][pid]
    assert proposal["phase"] == "rejected"
    assert [list(step) for step in proposal["phase_transitions"]] == [
        ["submitted", 1], ["voting", 201], ["rejected", 301]]
    assert state["balances"][treasury_kp.address] >= held and set(state["balances"]) == accounts
    assert state["governance"]["treasury"]["executions"] == []
    assert state["governance"]["treasury"]["bonds"] == {}
    assert state["_current_level"] >= 319


def test_control_a_treasury_proposal_with_an_address_pays_it():
    state, baker, treasury_kp = _genesis_with_baker()
    payload = {"recipients": [{"address": SOMEONE, "amount": 5}]}
    state = _bake(state, baker, [make_governance_propose(sender_kp=baker, track="treasury", payload=payload, nonce=0)])
    (pid,) = state["governance"]["treasury"]["proposals"]
    state = _run(state, baker, "treasury", pid, votes_at=(202,), levels=320)
    assert state["governance"]["treasury"]["proposals"][pid]["phase"] == "executed"
    assert state["balances"][SOMEONE] == 5
