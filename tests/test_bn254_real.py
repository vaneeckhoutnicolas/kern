# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for the real BN254 pairing via py_ecc (v1.0-rc).

These tests verify that the pairing precompile passes the standard
EIP-197 test vectors when py_ecc is available, and degrades gracefully
to structural validation when it isn't."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.evm.bn254 import (
    P, N, B,
    PY_ECC_AVAILABLE,
    bn_add_precompile,
    bn_mul_precompile,
    bn_pairing_precompile,
    is_on_curve,
    pairing_check,
    point_add,
    point_mul,
)


# ---------------------------------------------------------------------------
# G1 sanity (these work with or without py_ecc)
# ---------------------------------------------------------------------------

# The standard generator of G1 for BN254 (alt_bn128): (1, 2)
G1_GENERATOR = (1, 2)


def test_g1_generator_on_curve():
    assert is_on_curve(G1_GENERATOR)


def test_g1_double_via_add_matches_mul_by_2():
    doubled = point_add(G1_GENERATOR, G1_GENERATOR)
    mul_2 = point_mul(G1_GENERATOR, 2)
    assert doubled == mul_2


def test_g1_mul_by_zero_returns_infinity():
    assert point_mul(G1_GENERATOR, 0) is None


def test_g1_mul_by_n_returns_infinity():
    """The generator has order N. Multiplying by N should give infinity."""
    assert point_mul(G1_GENERATOR, N) is None


def test_bn_add_precompile_generator_plus_itself():
    """G + G should equal multiply(G, 2)."""
    # Encode: G || G
    calldata = (
        (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
        + (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    )
    result = bn_add_precompile(calldata)
    assert result is not None
    assert len(result) == 64
    # Compare to 2G
    expected_pt = point_mul(G1_GENERATOR, 2)
    x_bytes = expected_pt[0].to_bytes(32, "big")
    y_bytes = expected_pt[1].to_bytes(32, "big")
    assert result == x_bytes + y_bytes


def test_bn_mul_precompile():
    """Scalar mul of G by 5 should match point_mul(G, 5)."""
    calldata = (
        (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
        + (5).to_bytes(32, "big")
    )
    result = bn_mul_precompile(calldata)
    assert result is not None
    expected = point_mul(G1_GENERATOR, 5)
    assert int.from_bytes(result[0:32], "big") == expected[0]
    assert int.from_bytes(result[32:64], "big") == expected[1]


def test_bn_add_rejects_off_curve_point():
    """A point not on y² = x³ + 3 should cause the precompile to return None."""
    # (1, 3) is not on the curve: 3² = 9 but 1³ + 3 = 4. 9 ≠ 4.
    calldata = (
        (1).to_bytes(32, "big") + (3).to_bytes(32, "big")
        + (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    )
    result = bn_add_precompile(calldata)
    assert result is None


# ---------------------------------------------------------------------------
# Pairing tests
# ---------------------------------------------------------------------------

def test_pairing_check_empty_input_is_true():
    """e() = 1, the identity. Returns True regardless of py_ecc availability."""
    assert pairing_check([]) is True


def test_bn_pairing_precompile_empty_calldata():
    result = bn_pairing_precompile(b"")
    assert result == b"\x00" * 31 + b"\x01"   # True


def test_bn_pairing_precompile_invalid_length():
    """Calldata not a multiple of 192 should be rejected."""
    result = bn_pairing_precompile(b"\x00" * 100)
    assert result is None


@pytest.mark.skipif(not PY_ECC_AVAILABLE, reason="py_ecc not installed")
def test_pairing_with_real_implementation_basic_property():
    """When py_ecc is available, test e(G1, G2) and e(2*G1, G2) and
    e(G1, 2*G2) — they should all be related as e(aP, bQ) = e(P, Q)^(ab).

    The most basic test: e(P, Q) * e(-P, Q) should equal 1 in F_p^12.
    This is the pairing-check pattern used by Groth16 verifiers."""
    from py_ecc.bn128 import G1 as PYG1, G2 as PYG2, neg, multiply, FQ12
    # Compute G2 point as bytes (EIP-197 encoding)
    # G2 generator coordinates (well-known constants from BN128 spec):
    G2_GEN_X_REAL = 10857046999023057135944570762232829481370756359578518086990519993285655852781
    G2_GEN_X_IMAG = 11559732032986387107991004021392285783925812861821192530917403151452391805634
    G2_GEN_Y_REAL = 8495653923123431417604973247489272438418190587263600148770280649306958101930
    G2_GEN_Y_IMAG = 4082367875863433681332203403145435568316851327593401208105741076214120093531

    def g2_bytes(x_real, x_imag, y_real, y_imag):
        return (
            x_imag.to_bytes(32, "big") + x_real.to_bytes(32, "big")
            + y_imag.to_bytes(32, "big") + y_real.to_bytes(32, "big")
        )

    g2_gen = g2_bytes(G2_GEN_X_REAL, G2_GEN_X_IMAG, G2_GEN_Y_REAL, G2_GEN_Y_IMAG)

    # Test the pairing identity: e(G1, G2) * e(-G1, G2) = 1.
    # In precompile encoding: pair (G1, G2) and pair (-G1, G2).
    g1_x = 1
    g1_y = 2
    # -G1 = (1, P - 2)  (negate y in F_p)
    neg_g1_y = P - 2

    calldata = (
        # First pairing: (G1, G2)
        g1_x.to_bytes(32, "big") + g1_y.to_bytes(32, "big") + g2_gen
        # Second pairing: (-G1, G2)
        + g1_x.to_bytes(32, "big") + neg_g1_y.to_bytes(32, "big") + g2_gen
    )

    result = bn_pairing_precompile(calldata)
    assert result is not None
    # Should be True: e(G1, G2) * e(-G1, G2) = e(G1, G2) * e(G1, G2)^-1 = 1
    assert result == b"\x00" * 31 + b"\x01"


@pytest.mark.skipif(not PY_ECC_AVAILABLE, reason="py_ecc not installed")
def test_pairing_check_negative_case():
    """e(G1, G2) alone should NOT equal 1 — it's a non-trivial element of F_p^12.
    So pairing_check([(G1, G2)]) should return False."""
    # G1 generator
    g1_x = 1
    g1_y = 2
    G2_GEN_X_REAL = 10857046999023057135944570762232829481370756359578518086990519993285655852781
    G2_GEN_X_IMAG = 11559732032986387107991004021392285783925812861821192530917403151452391805634
    G2_GEN_Y_REAL = 8495653923123431417604973247489272438418190587263600148770280649306958101930
    G2_GEN_Y_IMAG = 4082367875863433681332203403145435568316851327593401208105741076214120093531

    calldata = (
        g1_x.to_bytes(32, "big") + g1_y.to_bytes(32, "big")
        + G2_GEN_X_IMAG.to_bytes(32, "big") + G2_GEN_X_REAL.to_bytes(32, "big")
        + G2_GEN_Y_IMAG.to_bytes(32, "big") + G2_GEN_Y_REAL.to_bytes(32, "big")
    )

    result = bn_pairing_precompile(calldata)
    assert result is not None
    # A single non-trivial pairing != 1.
    assert result == b"\x00" * 32   # False


def test_py_ecc_availability_is_reported():
    """The module exposes whether the real pairing is wired or not."""
    # In our test env we install py_ecc, so we expect True here.
    # But the test should still pass either way (just reporting).
    assert isinstance(PY_ECC_AVAILABLE, bool)
    if PY_ECC_AVAILABLE:
        print("py_ecc available: real BN254 pairing active")
    else:
        print("py_ecc NOT available: pairing falls back to structural check")


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} BN254 tests passed.")
