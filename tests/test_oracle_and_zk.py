# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v1.1-rc oracle network templates, schema marketplace, and ZK claims."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.skald.typecheck import type_check
from kern.zk_claims import (
    build_zk_claim,
    derive_verifier_key_hash,
    describe_circuit,
    is_zk_claim,
    list_reference_circuits,
    verify_zk_claim,
    REFERENCE_CIRCUITS,
)


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "kern" / "skald" / "examples"

ORACLE_AND_SCHEMA_TEMPLATES = [
    "generic-data-oracle.skald",
    "defi-price-oracle.skald",
    "schema-marketplace.skald",
]


# ===========================================================================
# Oracle templates typecheck + properties
# ===========================================================================

@pytest.mark.parametrize("filename", ORACLE_AND_SCHEMA_TEMPLATES)
def test_oracle_template_typechecks(filename):
    """Each oracle / schema marketplace template must typecheck."""
    path = EXAMPLES_DIR / filename
    assert path.exists(), f"Template {filename} not found"
    src = path.read_text(encoding="utf-8")
    errors = type_check(src)
    assert not errors, f"Type errors in {filename}: {errors[:3]}"


def test_generic_oracle_has_quorum_threshold():
    """Generic oracle must enforce k-of-n threshold."""
    src = (EXAMPLES_DIR / "generic-data-oracle.skald").read_text(encoding="utf-8")
    assert "required_quorum" in src
    assert "quorum not reached" in src
    assert "quorum_bounded" in src


def test_generic_oracle_has_role_separation():
    """Aggregator must be distinct from network admin."""
    src = (EXAMPLES_DIR / "generic-data-oracle.skald").read_text(encoding="utf-8")
    assert "aggregator != network_admin" in src


def test_generic_oracle_has_anomaly_tracking():
    """Anomalous readings (outside tolerance band) are tracked."""
    src = (EXAMPLES_DIR / "generic-data-oracle.skald").read_text(encoding="utf-8")
    assert "anomalous_readings_count" in src
    assert "record_anomalous_reading" in src


def test_generic_oracle_has_staleness_views():
    """Consumers can check freshness."""
    src = (EXAMPLES_DIR / "generic-data-oracle.skald").read_text(encoding="utf-8")
    assert "is_fresh" in src
    assert "max_staleness_levels" in src


def test_generic_oracle_can_abort_round_no_quorum():
    """If quorum cannot be reached, anyone can abort the round."""
    src = (EXAMPLES_DIR / "generic-data-oracle.skald").read_text(encoding="utf-8")
    assert "abort_round_no_quorum" in src
    assert "consecutive_failed_rounds" in src


def test_defi_oracle_has_circuit_breaker():
    """DeFi oracle must have a per-round max-change circuit breaker."""
    src = (EXAMPLES_DIR / "defi-price-oracle.skald").read_text(encoding="utf-8")
    assert "max_round_change_bps" in src
    assert "circuit_breaker_trips" in src


def test_defi_oracle_has_heartbeat():
    """DeFi oracle must have a heartbeat to detect lazy aggregators."""
    src = (EXAMPLES_DIR / "defi-price-oracle.skald").read_text(encoding="utf-8")
    assert "heartbeat_levels" in src
    assert "is_within_heartbeat" in src


def test_defi_oracle_has_decimal_handling():
    """DeFi oracle declares price decimals for consumer normalization."""
    src = (EXAMPLES_DIR / "defi-price-oracle.skald").read_text(encoding="utf-8")
    assert "price_decimals" in src
    assert "decimals_in_range" in src


def test_defi_oracle_circuit_breaker_invariant():
    """Circuit breaker basis points are bounded."""
    src = (EXAMPLES_DIR / "defi-price-oracle.skald").read_text(encoding="utf-8")
    assert "change_limit_range" in src


def test_defi_oracle_first_round_no_breaker():
    """First round should not be subject to circuit breaker (no baseline)."""
    src = (EXAMPLES_DIR / "defi-price-oracle.skald").read_text(encoding="utf-8")
    # The implementation handles the first-round case via latest_round_number == 0 branch
    assert "latest_round_number == 0" in src


# ===========================================================================
# Schema marketplace
# ===========================================================================

def test_schema_marketplace_has_minimum_bond():
    """Marketplace enforces a minimum bond per schema."""
    src = (EXAMPLES_DIR / "schema-marketplace.skald").read_text(encoding="utf-8")
    assert "minimum_bond_mukrn" in src
    assert "min_bond_nonneg" in src


def test_schema_marketplace_has_version_monotonic():
    """Schema versions can only go forward."""
    src = (EXAMPLES_DIR / "schema-marketplace.skald").read_text(encoding="utf-8")
    assert "schema_version" in src
    assert "bump_version" in src
    assert "schema_version = schema_version + 1" in src


def test_schema_marketplace_has_deprecation():
    """Schema can be deprecated; consumers see the status."""
    src = (EXAMPLES_DIR / "schema-marketplace.skald").read_text(encoding="utf-8")
    assert "entry deprecate" in src
    assert "deprecated_at_level" in src
    assert "deprecated_reason" in src


def test_schema_marketplace_tracks_issuer_quality():
    """Marketplace tracks recognized issuer count and slashing rate."""
    src = (EXAMPLES_DIR / "schema-marketplace.skald").read_text(encoding="utf-8")
    assert "recognized_issuer_count" in src
    assert "total_issuer_slashings" in src
    assert "quality_score" in src


# ===========================================================================
# ZK-claims primitives
# ===========================================================================

def test_zk_claim_builder_basic():
    """build_zk_claim assembles a well-formed payload."""
    claim = build_zk_claim(
        verifier_key_hash="ab" * 16,
        public_inputs=[42, 18],
        proof_a=[1, 2],
        proof_b=[[3, 4], [5, 6]],
        proof_c=[7, 8],
        predicate_summary="age over 18",
    )
    assert claim["proof_system"] == "groth16-bn254"
    assert claim["verifier_key_hash"] == "ab" * 16
    assert claim["public_inputs"] == [42, 18]
    assert claim["proof"]["a"] == [1, 2]
    assert claim["proof"]["b"] == [[3, 4], [5, 6]]
    assert claim["proof"]["c"] == [7, 8]


def test_zk_claim_builder_rejects_malformed_inputs():
    """Malformed proof points are rejected by the builder."""
    with pytest.raises(ValueError):
        build_zk_claim(
            verifier_key_hash="ab" * 16,
            public_inputs=[1],
            proof_a=[1],   # Wrong size
            proof_b=[[1, 2], [3, 4]],
            proof_c=[5, 6],
            predicate_summary="bad",
        )
    with pytest.raises(ValueError):
        build_zk_claim(
            verifier_key_hash="ab" * 16,
            public_inputs=[1],
            proof_a=[1, 2],
            proof_b=[[1, 2]],   # Wrong G2 shape
            proof_c=[5, 6],
            predicate_summary="bad",
        )


def test_is_zk_claim_detection():
    """is_zk_claim correctly identifies ZK payloads."""
    valid = build_zk_claim("ab" * 16, [1], [1, 2], [[3, 4], [5, 6]], [7, 8], "x")
    assert is_zk_claim(valid)
    assert not is_zk_claim({"price": 1000})   # plain price claim
    assert not is_zk_claim("string")
    assert not is_zk_claim(None)
    # Missing fields
    assert not is_zk_claim({"proof_system": "groth16-bn254"})


def test_verifier_key_hash_deterministic():
    """Same verifier-key bytes always produce same hash."""
    h1 = derive_verifier_key_hash(b"fake_verifier_key_bytes")
    h2 = derive_verifier_key_hash(b"fake_verifier_key_bytes")
    assert h1 == h2


def test_verifier_key_hash_differs_with_input():
    """Different bytes → different hash."""
    h1 = derive_verifier_key_hash(b"vk1")
    h2 = derive_verifier_key_hash(b"vk2")
    assert h1 != h2


def test_verify_zk_claim_accepts_well_formed():
    """The v1.1-rc stub accepts a well-formed payload."""
    claim = build_zk_claim("ab" * 16, [42], [1, 2], [[3, 4], [5, 6]], [7, 8], "test")
    assert verify_zk_claim(claim) is True


def test_verify_zk_claim_rejects_non_zk_claim():
    """Non-ZK claim payloads are rejected."""
    assert verify_zk_claim({"price": 1000}) is False
    assert verify_zk_claim("not a dict") is False


def test_verify_zk_claim_with_registry():
    """If a registry is provided, the verifier checks key presence."""
    vk_hash = "ab" * 16
    claim = build_zk_claim(vk_hash, [42], [1, 2], [[3, 4], [5, 6]], [7, 8], "x")

    # Unknown vk in registry → reject
    assert verify_zk_claim(claim, verifier_key_registry={}) is False

    # Known vk → accept (in the stub)
    registry = {vk_hash: b"actual_vk_bytes"}
    assert verify_zk_claim(claim, verifier_key_registry=registry) is True


def test_reference_circuits_complete():
    """The 4 reference circuits are documented."""
    names = list_reference_circuits()
    assert "age_threshold_v1" in names
    assert "value_threshold_v1" in names
    assert "account_ownership_v1" in names
    assert "set_membership_v1" in names


def test_each_circuit_has_required_fields():
    """Every reference circuit has a complete description."""
    for name, desc in REFERENCE_CIRCUITS.items():
        assert "predicate" in desc, f"{name} missing predicate"
        assert "private_inputs" in desc, f"{name} missing private_inputs"
        assert "public_inputs" in desc, f"{name} missing public_inputs"
        assert "use_case" in desc, f"{name} missing use_case"


def test_describe_circuit_returns_record():
    """describe_circuit returns the full record for a known name."""
    desc = describe_circuit("age_threshold_v1")
    assert desc is not None
    assert "date_of_birth" in desc["private_inputs"][0]
    assert describe_circuit("nonexistent") is None


# ===========================================================================
# Integration: ZK-claim posted via attestation registry
# ===========================================================================

def test_zk_claim_can_be_attestation_payload():
    """A ZK-claim payload can be posted via make_attest as the claim field."""
    from kern.chain import apply_transaction, empty_state
    from kern.crypto import KernKeypair
    from kern.transaction import make_attest

    issuer = KernKeypair.from_seed(bytes([0x42]) * 32)
    state = empty_state()
    state["balances"] = {issuer.address: 10_000_000}
    state["nonces"] = {issuer.address: 0}
    state["total_supply"] = 10_000_000
    state["_current_level"] = 100

    zk_claim = build_zk_claim(
        verifier_key_hash="cd" * 16,
        public_inputs=[1700000000, 18 * 365 * 86400],  # now, 18 years
        proof_a=[1, 2],
        proof_b=[[3, 4], [5, 6]],
        proof_c=[7, 8],
        predicate_summary="user is over 18 years old",
    )

    tx = make_attest(
        sender_kp=issuer,
        schema_id="identity.age-over-18",
        subject="kn1userAddress",
        claim=zk_claim,
        nonce=0,
        bond=1_000_000,
    )
    result = apply_transaction(state, tx, baker=issuer.address)
    assert result.ok, result.error

    # The stored attestation contains the ZK claim verbatim.
    att_id = result.extra["attestation_id"]
    stored_claim = state["attestations"][att_id]["claim"]
    assert is_zk_claim(stored_claim)
    assert verify_zk_claim(stored_claim) is True


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    for name, obj in inspect.getmembers(me):
        if name.startswith("test_") and callable(obj):
            try:
                if "parametrize" in str(getattr(obj, "pytestmark", [])):
                    for fn in ORACLE_AND_SCHEMA_TEMPLATES:
                        obj(fn)
                else:
                    obj()
                print(f"  ✓ {name}")
            except Exception as e:
                print(f"  ✗ {name}: {e}")
