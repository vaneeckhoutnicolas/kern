# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v0.7: BN254 precompiles and dynamic gas costs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.evm import PRECOMPILES, execute_precompile, is_precompile
from kern.evm.bn254 import (
    INFINITY,
    N,
    P,
    bn_add_precompile,
    bn_mul_precompile,
    bn_pairing_precompile,
    is_on_curve,
    point_add,
    point_mul,
)
from kern.evm.dynamic_gas import (
    G_CALL_BASE,
    G_CALL_VALUE,
    G_COLD_ACCOUNT_ACCESS,
    G_SSTORE_RESET,
    G_SSTORE_SET,
    call_cost,
    call_stipend,
    copy_cost,
    create_cost,
    exp_cost,
    log_cost,
    memory_cost,
    memory_expansion_cost,
    sha3_cost,
    sstore_cost,
    sstore_refund,
)


# ===========================================================================
# BN254 — curve arithmetic
# ===========================================================================

# A known generator-style point on BN254 G1: (1, 2). Verify y² = x³ + 3.
G1_GEN = (1, 2)


def test_g1_generator_is_on_curve():
    assert is_on_curve(G1_GEN)


def test_infinity_is_on_curve():
    assert is_on_curve(INFINITY)


def test_off_curve_point_rejected():
    assert not is_on_curve((1, 3))  # y=3 doesn't satisfy y²=4


def test_point_addition_associative_with_infinity():
    """P + O = P, O + P = P."""
    assert point_add(G1_GEN, INFINITY) == G1_GEN
    assert point_add(INFINITY, G1_GEN) == G1_GEN


def test_point_addition_inverse_yields_infinity():
    """P + (-P) = O."""
    x, y = G1_GEN
    neg = (x, (-y) % P)
    assert point_add(G1_GEN, neg) is INFINITY


def test_point_doubling_is_on_curve():
    """2P stays on the curve."""
    doubled = point_add(G1_GEN, G1_GEN)
    assert doubled is not None
    assert is_on_curve(doubled)


def test_scalar_mul_by_zero_yields_infinity():
    assert point_mul(G1_GEN, 0) is INFINITY


def test_scalar_mul_by_one_yields_same_point():
    assert point_mul(G1_GEN, 1) == G1_GEN


def test_scalar_mul_by_two_equals_addition():
    """2P == P + P."""
    via_mul = point_mul(G1_GEN, 2)
    via_add = point_add(G1_GEN, G1_GEN)
    assert via_mul == via_add


def test_scalar_mul_distributive():
    """5P = 2P + 3P."""
    p5 = point_mul(G1_GEN, 5)
    p2 = point_mul(G1_GEN, 2)
    p3 = point_mul(G1_GEN, 3)
    assert p5 == point_add(p2, p3)


def test_scalar_mul_by_order_yields_infinity():
    """N·G = O for any G in the subgroup."""
    assert point_mul(G1_GEN, N) is INFINITY


# ===========================================================================
# BN254 — calldata encoding
# ===========================================================================

def test_bn_add_precompile_with_infinity():
    """0 + 0 = 0."""
    calldata = b"\x00" * 128
    out = bn_add_precompile(calldata)
    assert out == b"\x00" * 64


def test_bn_add_precompile_with_gen_plus_infinity():
    """G + O = G."""
    g_encoded = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    inf_encoded = b"\x00" * 64
    out = bn_add_precompile(g_encoded + inf_encoded)
    assert out == g_encoded


def test_bn_add_precompile_off_curve_returns_none():
    """Invalid input returns None (precompile reports failure)."""
    bad_x = (1).to_bytes(32, "big") + (3).to_bytes(32, "big")  # (1,3) not on curve
    out = bn_add_precompile(bad_x + b"\x00" * 64)
    assert out is None


def test_bn_mul_precompile_by_one():
    """G * 1 = G."""
    g = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    scalar = (1).to_bytes(32, "big")
    out = bn_mul_precompile(g + scalar)
    assert out == g


def test_bn_mul_precompile_by_zero_yields_infinity():
    g = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    scalar = (0).to_bytes(32, "big")
    out = bn_mul_precompile(g + scalar)
    assert out == b"\x00" * 64


def test_bn_pairing_empty_returns_true():
    """Empty pairing product is identity = 1 → returns 0x01."""
    out = bn_pairing_precompile(b"")
    assert out is not None
    assert out[-1] == 1


def test_bn_pairing_wrong_length_returns_none():
    """Pairing input must be a multiple of 192 bytes."""
    out = bn_pairing_precompile(b"\x00" * 100)
    assert out is None


# ===========================================================================
# Precompile registry (v0.7 additions)
# ===========================================================================

def test_bn_precompiles_registered():
    """0x06, 0x07, 0x08 now in PRECOMPILES."""
    for addr in [0x06, 0x07, 0x08]:
        assert addr in PRECOMPILES
        assert is_precompile(addr)


def test_bn_add_via_execute_precompile():
    """Full execute_precompile flow for 0x06."""
    g = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    inf = b"\x00" * 64
    r = execute_precompile(0x06, g + inf, gas=10_000)
    assert r.success
    assert r.return_data == g


# ===========================================================================
# Dynamic gas — memory expansion
# ===========================================================================

def test_memory_cost_zero_words():
    assert memory_cost(0) == 0


def test_memory_cost_linear_for_small():
    """For small word counts, cost is dominated by the linear 3*w term."""
    assert memory_cost(10) == 3 * 10 + (100 // 512)  # 30 + 0 = 30


def test_memory_cost_quadratic_grows():
    """At large word counts, quadratic term dominates."""
    cost_small = memory_cost(100)
    cost_big = memory_cost(10_000)
    # Quadratic in the bigger case: 10000² / 512 ≈ 195312
    assert cost_big > 100 * cost_small


def test_memory_expansion_no_growth_zero_cost():
    """If new size ≤ current size, no cost."""
    assert memory_expansion_cost(1024, 512) == 0
    assert memory_expansion_cost(1024, 1024) == 0


def test_memory_expansion_growth():
    """Cost is the difference between new and current word-cost."""
    # Growing from 0 to 64 bytes (2 words)
    cost = memory_expansion_cost(0, 64)
    assert cost == memory_cost(2) - memory_cost(0)
    assert cost == 6  # 3*2 + 4/512 = 6 + 0


# ===========================================================================
# Dynamic gas — SSTORE
# ===========================================================================

def test_sstore_set_zero_to_nonzero():
    """First-time write to a previously-zero slot."""
    assert sstore_cost(current=0, new=42, original=0) == G_SSTORE_SET


def test_sstore_reset_modify_existing():
    """Modifying an existing nonzero value."""
    assert sstore_cost(current=99, new=42, original=99) == G_SSTORE_RESET


def test_sstore_noop_same_value():
    """Writing the same value is essentially a no-op (warm read cost)."""
    cost = sstore_cost(current=42, new=42, original=42)
    assert cost < G_SSTORE_RESET


def test_sstore_refund_for_clearing():
    """Setting a slot to zero gets a refund."""
    refund = sstore_refund(current=42, new=0, original=42)
    assert refund > 0


def test_sstore_no_refund_for_set():
    refund = sstore_refund(current=0, new=42, original=0)
    assert refund == 0


# ===========================================================================
# Dynamic gas — SHA3
# ===========================================================================

def test_sha3_empty_input():
    """SHA3 of zero bytes = base cost only."""
    assert sha3_cost(0) == 30


def test_sha3_one_word():
    """32 bytes = 1 word: base + 6."""
    assert sha3_cost(32) == 36


def test_sha3_partial_word_rounds_up():
    """1 byte = 1 word's worth of cost."""
    assert sha3_cost(1) == 36


def test_sha3_two_words():
    assert sha3_cost(64) == 42  # 30 + 12


# ===========================================================================
# Dynamic gas — LOG
# ===========================================================================

def test_log0_no_topics():
    assert log_cost(num_topics=0, data_byte_length=0) == 375


def test_log_with_topics_and_data():
    """LOG3 with 100 bytes: 375 + 3*375 + 100*8 = 2300."""
    assert log_cost(num_topics=3, data_byte_length=100) == 375 + 1125 + 800


# ===========================================================================
# Dynamic gas — CALL family
# ===========================================================================

def test_call_base_cost():
    assert call_cost(has_value=False, creates_new_account=False, cold_access=False) == G_CALL_BASE


def test_call_with_value_adds_9000():
    assert call_cost(has_value=True, creates_new_account=False, cold_access=False) == G_CALL_BASE + G_CALL_VALUE


def test_call_creating_new_account_adds_25000():
    assert call_cost(has_value=False, creates_new_account=True, cold_access=False) == G_CALL_BASE + 25_000


def test_call_cold_access_more_expensive_than_warm():
    cold = call_cost(has_value=False, creates_new_account=False, cold_access=True)
    warm = call_cost(has_value=False, creates_new_account=False, cold_access=False)
    assert cold > warm


def test_call_stipend_only_on_value_transfer():
    assert call_stipend(has_value=True) == 2_300
    assert call_stipend(has_value=False) == 0


# ===========================================================================
# Dynamic gas — EXP / copy / create
# ===========================================================================

def test_exp_zero_exponent():
    assert exp_cost(0) == 10


def test_exp_one_byte_exponent():
    assert exp_cost(255) == 10 + 50


def test_exp_two_byte_exponent():
    assert exp_cost(256) == 10 + 100   # exponent is 0x0100, 2 bytes


def test_copy_cost_per_word():
    assert copy_cost(0) == 0
    assert copy_cost(32) == 3       # 1 word
    assert copy_cost(33) == 6       # 2 words (rounds up)


def test_create_cost_base_plus_code_length():
    assert create_cost(deployed_code_length=0) == 32_000
    assert create_cost(deployed_code_length=100) == 32_000 + 20_000


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} v0.7 tests passed.")
