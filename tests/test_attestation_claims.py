# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Two claims contradict when their JSON differs.

External review of 13 November 2026. `claims_contradict` compared two
claims with the equality of Python, for which `True == 1`, `False == 0`
and `1 == 1.0`. The identifier of an attestation is computed from the
JSON of its claim, where `true` and `1` are different values. An issuer
could therefore record two attestations about one subject, under two
identifiers, with `{"passed": true}` in one and `{"passed": 1}` in the
other, and the evidence was refused: the two claims were found equal.

Two claims now contradict exactly when the JSON the identifier is
computed from differs. The tests fail on 785bcd1, except the controls.
"""

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.attestation import claims_contradict, derive_attestation_id, find_equivocation_pair
from kern.chain import apply_transaction, empty_state
from kern.crypto import KernKeypair
from kern.transaction import Transaction, make_attest, make_slash_attestation_equivocation


def _identifier(claim):
    return derive_attestation_id("kn1issuer", "schema", "subject", claim, 7)


SAME_FOR_PYTHON = [
    ({"passed": True}, {"passed": 1}),
    ({"passed": False}, {"passed": 0}),
    ({"amount": 1}, {"amount": 1.0}),
    ({"amount": 0}, {"amount": -0.0}),
    ({"passed": True}, {"passed": 1.0}),
    ({"checks": [{"ok": True}, 2]}, {"checks": [{"ok": 1}, 2]}),
    ({"a": {"b": {"c": [0]}}}, {"a": {"b": {"c": [False]}}}),
]


@pytest.mark.parametrize("claim_a, claim_b", SAME_FOR_PYTHON)
def test_values_that_python_finds_equal_and_json_does_not_contradict(claim_a, claim_b):
    assert claim_a == claim_b                              # the equality that was used
    assert json.dumps(claim_a) != json.dumps(claim_b)
    assert _identifier(claim_a) != _identifier(claim_b)
    assert claims_contradict(claim_a, claim_b) and claims_contradict(claim_b, claim_a)


def test_control_the_order_of_the_keys_is_not_a_difference():
    claim_a = {"price": 70000, "unit": "usd", "source": {"name": "x", "rank": 1}}
    claim_b = {"source": {"rank": 1, "name": "x"}, "unit": "usd", "price": 70000}
    assert list(claim_a) != list(claim_b)
    assert _identifier(claim_a) == _identifier(claim_b)
    assert not claims_contradict(claim_a, claim_b)


def test_control_a_claim_does_not_contradict_itself():
    for claim in ({}, {"v": None}, {"v": [1, "1", True, 1.5, {"w": []}]}, {"é": "ü"}):
        assert not claims_contradict(claim, json.loads(json.dumps(claim)))


def _value(rng, depth):
    kind = rng.randrange(9 if depth < 3 else 7)
    if kind == 0:
        return rng.choice([True, False])
    if kind in (1, 2):
        return rng.choice([0, 1, 2, -1])
    if kind == 3:
        return rng.choice([0.0, 1.0, -0.0, 2.0, 0.5, -1.0])
    if kind == 4:
        return rng.choice(["", "0", "1", "true", "a"])
    if kind == 5:
        return None
    if kind == 6:
        return rng.choice([[], {}])
    if kind == 7:
        return [_value(rng, depth + 1) for _ in range(rng.randrange(3))]
    return {rng.choice("abc"): _value(rng, depth + 1) for _ in range(rng.randrange(3))}


def test_claims_contradict_exactly_when_their_identifiers_differ():
    """Whatever the two claims, everything else being the same: one
    identifier, no contradiction; two identifiers, a contradiction."""
    rng = random.Random(20261113)
    pairs = [({"v": _value(rng, 0)}, {"v": _value(rng, 0)}) for _ in range(20_000)]
    assert sum(1 for a, b in pairs if a == b and _identifier(a) != _identifier(b)) > 100
    assert sum(1 for a, b in pairs if _identifier(a) == _identifier(b)) > 100
    for claim_a, claim_b in pairs:
        assert claims_contradict(claim_a, claim_b) == (_identifier(claim_a) != _identifier(claim_b)), (
            claim_a, claim_b)


# --------------------------------------------------------------- on the chain

def _issuer_and_reporter():
    issuer = KernKeypair.from_seed(bytes([0x11]) * 32)
    reporter = KernKeypair.from_seed(bytes([0xFF]) * 32)
    state = empty_state()
    state["balances"] = {issuer.address: 10_000_000, reporter.address: 100_000}
    state["nonces"] = {issuer.address: 0, reporter.address: 0}
    state["total_supply"] = 10_100_000
    state["_current_level"] = 100
    return state, issuer, reporter


def _attest(state, issuer, claim, nonce):
    tx = make_attest(issuer, "kyc.basic", "subject", claim, nonce=nonce, bond=1_000_000)
    tx = Transaction.from_dict(json.loads(json.dumps(tx.to_dict())))       # as a node receives it
    result = apply_transaction(state, tx, baker=issuer.address)
    assert result.ok, result.error
    return result.extra["attestation_id"]


@pytest.mark.parametrize("claim_a, claim_b", SAME_FOR_PYTHON[:4])
def test_two_attestations_that_differ_by_the_type_of_a_value_are_slashable(claim_a, claim_b):
    state, issuer, reporter = _issuer_and_reporter()
    first = _attest(state, issuer, claim_a, 0)
    second = _attest(state, issuer, claim_b, 1)
    assert first != second                                  # two attestations are recorded
    assert find_equivocation_pair(state["attestations"], issuer.address, "kyc.basic", "subject",
                                  first, second) is not None
    slash = make_slash_attestation_equivocation(reporter, first, second, nonce=0)
    result = apply_transaction(state, slash, baker=issuer.address)
    assert result.ok, result.error
    assert result.extra["slashed"] == 300_000
    assert state["attestations"][first]["consumed_for_slashing"]
    assert state["attestations"][second]["consumed_for_slashing"]


def test_control_the_same_claim_attested_twice_is_not_slashable():
    state, issuer, reporter = _issuer_and_reporter()
    first = _attest(state, issuer, {"passed": True, "level": 2}, 0)
    second = _attest(state, issuer, {"level": 2, "passed": True}, 1)
    assert first != second                                  # another nonce, another identifier
    slash = make_slash_attestation_equivocation(reporter, first, second, nonce=0)
    assert not apply_transaction(state, slash, baker=issuer.address).ok
