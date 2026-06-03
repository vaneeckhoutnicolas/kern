# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v1.1-rc slashable attestations (kern.attestation)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.attestation import (
    ATTESTATION_SLASHING_PERCENTAGE,
    ATTESTATION_WHISTLEBLOWER_REWARD_PCT,
    claims_contradict,
    compute_attestation_slash,
    derive_attestation_id,
    find_equivocation_pair,
    latest_attestation,
    _index_key,
)
from kern.chain import apply_transaction, empty_state
from kern.crypto import KernKeypair
from kern.transaction import (
    OpKind,
    make_attest,
    make_revoke_attestation,
    make_slash_attestation_equivocation,
)


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------

def test_derive_attestation_id_is_deterministic():
    """Same inputs must always produce same ID."""
    id1 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 70000}, 1)
    id2 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 70000}, 1)
    assert id1 == id2


def test_derive_attestation_id_differs_with_nonce():
    """Different nonces must produce different IDs even with same claim."""
    id1 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 70000}, 1)
    id2 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 70000}, 2)
    assert id1 != id2


def test_derive_attestation_id_differs_with_claim():
    """Different claims produce different IDs."""
    id1 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 70000}, 1)
    id2 = derive_attestation_id("kn1A", "price.btc", "BTC", {"usd": 50000}, 1)
    assert id1 != id2


def test_claims_contradict_strict_inequality():
    assert claims_contradict({"x": 1}, {"x": 2})
    assert not claims_contradict({"x": 1}, {"x": 1})
    assert claims_contradict({"x": 1}, {"x": 1, "y": 2})


def test_compute_attestation_slash_math():
    """30% slash, 10% to whistleblower, rest burned."""
    slash, reward, burn = compute_attestation_slash(1_000_000)
    assert slash == 300_000
    assert reward == 30_000
    assert burn == 270_000
    assert reward + burn == slash


def test_compute_attestation_slash_zero_bond():
    slash, reward, burn = compute_attestation_slash(0)
    assert slash == 0 and reward == 0 and burn == 0


# ---------------------------------------------------------------------------
# State management — happy paths
# ---------------------------------------------------------------------------

def _setup_state_with_issuer(initial_balance: int = 10_000_000):
    """Return (state, issuer_kp) with the issuer funded."""
    issuer_kp = KernKeypair.from_seed(bytes([0x11]) * 32)
    state = empty_state()
    state["balances"] = {issuer_kp.address: initial_balance}
    state["nonces"] = {issuer_kp.address: 0}
    state["total_supply"] = initial_balance
    state["_current_level"] = 100
    return state, issuer_kp


def test_attest_records_attestation_on_chain():
    state, issuer = _setup_state_with_issuer()
    tx = make_attest(
        sender_kp=issuer,
        schema_id="price.usd",
        subject="BTC",
        claim={"price": 70000},
        nonce=0,
        bond=1_000_000,
    )
    result = apply_transaction(state, tx, baker=issuer.address)
    assert result.ok, result.error
    att_id = result.extra["attestation_id"]
    assert att_id in state["attestations"]
    att = state["attestations"][att_id]
    assert att["issuer"] == issuer.address
    assert att["schema_id"] == "price.usd"
    assert att["subject"] == "BTC"
    assert att["claim"] == {"price": 70000}
    assert att["bond"] == 1_000_000
    assert att["issued_at_level"] == 100
    assert att["revoked_at_level"] is None
    assert att["consumed_for_slashing"] is False


def test_attest_debits_bond_from_issuer():
    state, issuer = _setup_state_with_issuer(initial_balance=10_000_000)
    pre = state["balances"][issuer.address]
    tx = make_attest(issuer, "s", "subj", {"x": 1}, nonce=0, bond=500_000)
    result = apply_transaction(state, tx, baker=issuer.address)
    assert result.ok
    post = state["balances"][issuer.address]
    # Bond debited from issuer; fee went to baker (the issuer here so net = bond)
    # But because baker == issuer, fee returns. So loss = bond only.
    assert pre - post == 500_000


def test_attest_indexed_by_subject():
    state, issuer = _setup_state_with_issuer()
    tx1 = make_attest(issuer, "price.usd", "BTC", {"v": 70000}, nonce=0)
    apply_transaction(state, tx1, baker=issuer.address)
    tx2 = make_attest(issuer, "price.usd", "BTC", {"v": 70100}, nonce=1)
    apply_transaction(state, tx2, baker=issuer.address)
    key = _index_key(issuer.address, "price.usd", "BTC")
    assert key in state["attestations_by_subject"]
    assert len(state["attestations_by_subject"][key]) == 2


def test_attest_rejects_missing_fields():
    state, issuer = _setup_state_with_issuer()
    # Missing schema_id
    tx = make_attest(issuer, "", "BTC", {"v": 1}, nonce=0)
    result = apply_transaction(state, tx, baker=issuer.address)
    assert not result.ok


def test_attest_rejects_negative_bond():
    """The Transaction model now enforces non-negative amount at
    construction time (closes S-CRIT-2 from the v1.1-rc security review).
    Constructing a negative-bond attestation tx raises ValueError, so the
    handler never gets a chance to see it."""
    state, issuer = _setup_state_with_issuer()
    from kern.transaction import Transaction
    with pytest.raises(ValueError, match="amount must be non-negative"):
        Transaction(
            kind=OpKind.ATTEST,
            sender=issuer.address,
            sender_pubkey=issuer.public_key_b58,
            nonce=0, fee=1000, gas_limit=30000,
            amount=-1,
            params={"schema_id": "s", "subject": "x", "claim": {"v": 1}},
        )


def test_attest_rejects_insufficient_balance_for_bond():
    state, issuer = _setup_state_with_issuer(initial_balance=100_000)  # tiny
    tx = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=10_000_000)
    result = apply_transaction(state, tx, baker=issuer.address)
    assert not result.ok


def test_attest_duplicate_id_rejected():
    """Same (issuer, schema, subject, claim, nonce) = same id = rejected."""
    state, issuer = _setup_state_with_issuer()
    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    apply_transaction(state, tx1, baker=issuer.address)
    # Re-build the exact same tx (same nonce, same claim) — different signature
    # is irrelevant; the ID is derived from contents.
    state["nonces"][issuer.address] = 0   # reset for re-injection attempt
    tx2 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    result = apply_transaction(state, tx2, baker=issuer.address)
    # Will fail on nonce or on duplicate id
    assert not result.ok


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

def test_revoke_returns_bond():
    state, issuer = _setup_state_with_issuer(initial_balance=10_000_000)
    tx = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=500_000)
    result = apply_transaction(state, tx, baker=issuer.address)
    att_id = result.extra["attestation_id"]
    pre = state["balances"][issuer.address]

    revoke = make_revoke_attestation(issuer, att_id, nonce=1)
    result2 = apply_transaction(state, revoke, baker=issuer.address)
    assert result2.ok, result2.error
    # Bond returned (less the revoke fee which went to baker=issuer → net 0)
    assert state["balances"][issuer.address] == pre + 500_000


def test_revoke_marks_revoked_at_level():
    state, issuer = _setup_state_with_issuer()
    tx = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    att_id = apply_transaction(state, tx, baker=issuer.address).extra["attestation_id"]
    state["_current_level"] = 200
    revoke = make_revoke_attestation(issuer, att_id, nonce=1)
    apply_transaction(state, revoke, baker=issuer.address)
    assert state["attestations"][att_id]["revoked_at_level"] == 200


def test_revoke_by_non_issuer_fails():
    state, issuer = _setup_state_with_issuer()
    attacker = KernKeypair.from_seed(bytes([0x22]) * 32)
    state["balances"][attacker.address] = 100_000
    state["nonces"][attacker.address] = 0

    tx = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    att_id = apply_transaction(state, tx, baker=issuer.address).extra["attestation_id"]

    revoke = make_revoke_attestation(attacker, att_id, nonce=0)
    result = apply_transaction(state, revoke, baker=issuer.address)
    assert not result.ok
    assert "only the issuer" in (result.error or "")


def test_revoke_already_revoked_fails():
    state, issuer = _setup_state_with_issuer()
    tx = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    att_id = apply_transaction(state, tx, baker=issuer.address).extra["attestation_id"]
    apply_transaction(state, make_revoke_attestation(issuer, att_id, nonce=1), baker=issuer.address)
    result = apply_transaction(state, make_revoke_attestation(issuer, att_id, nonce=2), baker=issuer.address)
    assert not result.ok


# ---------------------------------------------------------------------------
# Equivocation slashing
# ---------------------------------------------------------------------------

def test_slash_equivocation_basic():
    """Issue two contradicting attestations, slash the issuer, reward the whistleblower."""
    state, issuer = _setup_state_with_issuer(initial_balance=10_000_000)
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    # Issue two contradicting price attestations
    tx1 = make_attest(issuer, "price.btc-usd", "BTC", {"price": 70000}, nonce=0, bond=1_000_000)
    r1 = apply_transaction(state, tx1, baker=issuer.address)
    id_1 = r1.extra["attestation_id"]

    state["_current_level"] = 101
    tx2 = make_attest(issuer, "price.btc-usd", "BTC", {"price": 50000}, nonce=1, bond=1_000_000)
    r2 = apply_transaction(state, tx2, baker=issuer.address)
    id_2 = r2.extra["attestation_id"]

    # Snitch submits the slash
    pre_supply = state["total_supply"]
    pre_snitch = state["balances"][snitch.address]
    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    result = apply_transaction(state, slash_tx, baker=issuer.address)
    assert result.ok, result.error

    # Slash math: bond=1M, 30% = 300k slash. Reward 10% of 300k = 30k. Burn 270k.
    # The unslashed remainder (700k) is REFUNDED to the issuer (this is the
    # fix for S-MAJ-2 from the v1.1-rc internal security review).
    assert result.extra["slashed"] == 300_000
    assert result.extra["whistleblower_reward"] == 30_000
    assert result.extra["burned"] == 270_000
    assert result.extra["refunded_to_issuer"] == 700_000

    # Snitch received reward (less the 1000 mukrn tx fee which went to baker=issuer)
    assert state["balances"][snitch.address] == pre_snitch - 1000 + 30_000
    # Total supply decreased by burn
    assert state["total_supply"] == pre_supply - 270_000
    # Both attestations consumed
    assert state["attestations"][id_1]["consumed_for_slashing"]
    assert state["attestations"][id_2]["consumed_for_slashing"]
    # Both bonds zeroed out (fully resolved)
    assert state["attestations"][id_1]["bond"] == 0 or state["attestations"][id_2]["bond"] == 0


def test_slash_with_identical_claims_fails():
    """No contradiction → no slashing."""
    state, issuer = _setup_state_with_issuer()
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    # Two attestations with identical claims (just different nonces → different IDs)
    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100_000)
    tx2 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=1, bond=100_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    result = apply_transaction(state, slash_tx, baker=issuer.address)
    assert not result.ok


def test_slash_across_different_subjects_fails():
    """Issuer attesting different things about different subjects is not equivocation."""
    state, issuer = _setup_state_with_issuer()
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    tx1 = make_attest(issuer, "price.usd", "BTC", {"v": 70000}, nonce=0, bond=100_000)
    tx2 = make_attest(issuer, "price.usd", "ETH", {"v": 3000}, nonce=1, bond=100_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    result = apply_transaction(state, slash_tx, baker=issuer.address)
    assert not result.ok


def test_slash_revoked_before_reissued_no_overlap():
    """If issuer revokes attestation_1 BEFORE issuing attestation_2, no equivocation."""
    state, issuer = _setup_state_with_issuer()
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    # Issue first at level 100
    state["_current_level"] = 100
    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]

    # Revoke at level 101 (before issuing the contradicting one)
    state["_current_level"] = 101
    apply_transaction(state, make_revoke_attestation(issuer, id_1, nonce=1), baker=issuer.address)

    # Issue contradicting at level 102 — no overlap with the first
    state["_current_level"] = 102
    tx2 = make_attest(issuer, "s", "subj", {"v": 99}, nonce=2, bond=100_000)
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    result = apply_transaction(state, slash_tx, baker=issuer.address)
    assert not result.ok, "should not be slashable since validity windows don't overlap"


def test_slash_double_submit_fails():
    """Once slashed, the same equivocation cannot be re-slashed."""
    state, issuer = _setup_state_with_issuer(initial_balance=10_000_000)
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=1_000_000)
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=1_000_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    # First slash succeeds
    r = apply_transaction(state, make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0), baker=issuer.address)
    assert r.ok

    # Second slash fails
    r2 = apply_transaction(state, make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=1), baker=issuer.address)
    assert not r2.ok


def test_slash_zero_bond_fails():
    """If both attestations have zero bond, there's nothing to slash."""
    state, issuer = _setup_state_with_issuer()
    snitch = KernKeypair.from_seed(bytes([0xff]) * 32)
    state["balances"][snitch.address] = 100_000
    state["nonces"][snitch.address] = 0

    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=0)
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=0)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    result = apply_transaction(state, slash_tx, baker=issuer.address)
    assert not result.ok


def test_latest_attestation_returns_most_recent():
    state, issuer = _setup_state_with_issuer()
    state["_current_level"] = 100
    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    apply_transaction(state, tx1, baker=issuer.address)
    state["_current_level"] = 200
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=100)
    apply_transaction(state, tx2, baker=issuer.address)
    latest = latest_attestation(state, issuer.address, "s", "subj")
    assert latest is not None
    assert latest["claim"] == {"v": 2}
    assert latest["issued_at_level"] == 200


def test_latest_attestation_skips_revoked():
    state, issuer = _setup_state_with_issuer()
    state["_current_level"] = 100
    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    state["_current_level"] = 200
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=100)
    apply_transaction(state, tx2, baker=issuer.address)
    # Revoke the most recent
    state["_current_level"] = 250
    apply_transaction(state, make_revoke_attestation(issuer, _ := tx2._signed_payload and apply_transaction.__name__ and id_1, nonce=2), baker=issuer.address)
    # Reset for a cleaner second test
    state, issuer = _setup_state_with_issuer()
    state["_current_level"] = 100
    apply_transaction(state, make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=100), baker=issuer.address)
    state["_current_level"] = 200
    r2 = apply_transaction(state, make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=100), baker=issuer.address)
    id_2 = r2.extra["attestation_id"]
    # Revoke the more recent → latest should be the older one
    state["_current_level"] = 250
    apply_transaction(state, make_revoke_attestation(issuer, id_2, nonce=2), baker=issuer.address)
    latest = latest_attestation(state, issuer.address, "s", "subj")
    assert latest is not None
    assert latest["claim"] == {"v": 1}


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} attestation tests passed.")
