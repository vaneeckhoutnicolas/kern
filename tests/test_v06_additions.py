# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v0.6 additions: more precompiles and bond resolution."""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.evm import PRECOMPILES, execute_precompile, is_precompile
from kern.governance import (
    BOND_BURN_PCT,
    BondOutcome,
    DEFAULT_PROTOCOL_BOND,
    DEFAULT_TREASURY_BOND,
    resolve_bond,
)


# ---------------------------------------------------------------------------
# Precompiles
# ---------------------------------------------------------------------------

def test_ripemd160_precompile_registered():
    assert 0x03 in PRECOMPILES
    assert is_precompile(0x03)


def test_ripemd160_hashes_input():
    r = execute_precompile(0x03, b"hello world", gas=10_000)
    assert r.success
    # Compare to native ripemd160 if available.
    try:
        h = hashlib.new("ripemd160")
        h.update(b"hello world")
        expected = b"\x00" * 12 + h.digest()
        assert r.return_data == expected
    except ValueError:
        # ripemd160 not available; just verify we got 32 zero bytes (fallback)
        assert r.return_data == b"\x00" * 32


def test_modexp_precompile_registered():
    assert 0x05 in PRECOMPILES


def test_modexp_simple_case():
    # base=3, exp=4, mod=5 → 3^4 mod 5 = 81 mod 5 = 1
    calldata = (
        (1).to_bytes(32, "big") +   # base_len
        (1).to_bytes(32, "big") +   # exp_len
        (1).to_bytes(32, "big") +   # mod_len
        (3).to_bytes(1, "big") +
        (4).to_bytes(1, "big") +
        (5).to_bytes(1, "big")
    )
    r = execute_precompile(0x05, calldata, gas=10_000)
    assert r.success
    assert r.return_data == bytes([1])


def test_modexp_zero_modulus():
    """MODEXP with modulus 0 returns mod_len zero bytes."""
    calldata = (
        (1).to_bytes(32, "big") +
        (1).to_bytes(32, "big") +
        (4).to_bytes(32, "big") +
        bytes([2, 3, 0, 0, 0, 0])
    )
    r = execute_precompile(0x05, calldata, gas=10_000)
    assert r.success
    assert r.return_data == b"\x00\x00\x00\x00"


def test_modexp_oversized_input_returns_empty():
    """Pathologically large size fields are rejected."""
    calldata = (10_000).to_bytes(32, "big") * 3 + b"\x00" * 100
    r = execute_precompile(0x05, calldata, gas=10_000)
    assert r.success
    assert r.return_data == b""


def test_blake2f_precompile_registered():
    assert 0x09 in PRECOMPILES


def test_blake2f_returns_64_bytes_for_valid_input():
    calldata = b"\x00" * 213
    r = execute_precompile(0x09, calldata, gas=10_000)
    assert r.success
    assert len(r.return_data) == 64


def test_blake2f_rejects_wrong_size():
    """BLAKE2F requires exactly 213 bytes of input."""
    calldata = b"\x00" * 100  # wrong size
    r = execute_precompile(0x09, calldata, gas=10_000)
    assert r.success  # the call frame succeeds...
    assert r.return_data == b""  # ...but the function returns empty.


# ---------------------------------------------------------------------------
# Bond resolution
# ---------------------------------------------------------------------------

def test_bond_constants_defined():
    assert DEFAULT_PROTOCOL_BOND > 0
    assert DEFAULT_TREASURY_BOND > 0
    # Protocol amendments should require a larger bond than treasury (higher stakes).
    assert DEFAULT_PROTOCOL_BOND > DEFAULT_TREASURY_BOND


def test_bond_refund_on_activation():
    outcome = resolve_bond(1000, "activated", was_decided_by_vote=True)
    assert outcome.refund_to_submitter == 1000
    assert outcome.burn == 0
    assert outcome.to_treasury == 0
    assert outcome.total == 1000


def test_bond_refund_on_execution():
    outcome = resolve_bond(1000, "executed", was_decided_by_vote=True)
    assert outcome.refund_to_submitter == 1000
    assert outcome.total == 1000


def test_bond_refund_on_withdrawal():
    """Withdrawing before voting gets the bond back."""
    outcome = resolve_bond(1000, "withdrawn", was_decided_by_vote=False)
    assert outcome.refund_to_submitter == 1000


def test_bond_split_on_rejection():
    """Rejected: 50% burn, 50% to treasury."""
    outcome = resolve_bond(1000, "rejected", was_decided_by_vote=True)
    assert outcome.refund_to_submitter == 0
    assert outcome.burn == 500
    assert outcome.to_treasury == 500
    assert outcome.total == 1000


def test_bond_split_preserves_total():
    """Whatever the input, the outcome total equals the bond."""
    for bond in [1, 99, 100, 101, 1000, 999_999, 100_000_000_000]:
        for phase in ["activated", "executed", "withdrawn", "rejected"]:
            outcome = resolve_bond(bond, phase, was_decided_by_vote=True)
            assert outcome.total == bond, (
                f"bond={bond}, phase={phase}: total={outcome.total}"
            )


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} tests passed.")
