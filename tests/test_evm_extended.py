# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v0.4 EVM extensions: SSTORE/SLOAD, SHA3, shifts,
ADDMOD/MULMOD, SIGNEXTEND, BYTE, environment opcodes, MSTORE8, GAS."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hashlib

import pytest

from kern.evm import ExecContext, Op, VmState, execute, step


# ---------------------------------------------------------------------------
# Storage (SSTORE / SLOAD)
# ---------------------------------------------------------------------------

def test_sstore_then_sload():
    """SSTORE key=1 value=42; SLOAD key=1 → 42 on stack."""
    code = bytes([
        Op.PUSH1, 42, Op.PUSH1, 1, Op.SSTORE,   # storage[1] = 42
        Op.PUSH1, 1, Op.SLOAD,                   # push storage[1]
        Op.STOP,
    ])
    trace = execute(code, gas=100_000)
    assert trace.states[-1].halted
    assert not trace.states[-1].reverted
    assert trace.states[-1].stack == [42]
    assert trace.states[-1].storage == {1: 42}


def test_sstore_zero_clears_slot():
    """Storing 0 deletes the slot (matches EVM semantics)."""
    code = bytes([
        Op.PUSH1, 99, Op.PUSH1, 5, Op.SSTORE,    # storage[5] = 99
        Op.PUSH1, 0, Op.PUSH1, 5, Op.SSTORE,     # storage[5] = 0 → deleted
        Op.STOP,
    ])
    trace = execute(code, gas=100_000)
    assert trace.states[-1].storage == {}


def test_initial_storage_visible_via_sload():
    code = bytes([Op.PUSH1, 7, Op.SLOAD, Op.STOP])
    trace = execute(code, gas=1000, initial_storage={7: 1234})
    assert trace.states[-1].stack == [1234]


# ---------------------------------------------------------------------------
# SHA3 (KECCAK)
# ---------------------------------------------------------------------------

def test_sha3_empty():
    """SHA3 of empty input should be sha3_256(b'')."""
    code = bytes([
        Op.PUSH1, 0, Op.PUSH1, 0, Op.SHA3, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    expected = int.from_bytes(hashlib.sha3_256(b"").digest(), "big")
    assert trace.states[-1].stack == [expected]


def test_sha3_of_memory_slice():
    """Write some bytes to memory then SHA3 them."""
    # MSTORE 0xabcdef at offset 0 (right-aligned in 32 bytes)
    # SHA3 32 bytes from offset 0
    code = bytes([
        Op.PUSH4, 0x00, 0xab, 0xcd, 0xef, Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.SHA3,
        Op.STOP,
    ])
    trace = execute(code, gas=1000)
    # The 32 bytes in memory are: 28 zero bytes + 0x00abcdef
    expected_input = b"\x00" * 28 + bytes([0x00, 0xab, 0xcd, 0xef])
    expected = int.from_bytes(hashlib.sha3_256(expected_input).digest(), "big")
    assert trace.states[-1].stack == [expected]


# ---------------------------------------------------------------------------
# Shifts
# ---------------------------------------------------------------------------

def test_shl_basic():
    # 1 << 3 = 8
    code = bytes([Op.PUSH1, 1, Op.PUSH1, 3, Op.SHL, Op.STOP])
    # Stack order for SHL: shift (top), value
    # PUSH 1 then PUSH 3 → stack=[1, 3]; SHL pops [3, 1] = shift=3, value=1
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [8]


def test_shr_basic():
    # 16 >> 2 = 4
    code = bytes([Op.PUSH1, 16, Op.PUSH1, 2, Op.SHR, Op.STOP])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [4]


def test_shl_overflow_returns_zero():
    code = bytes([Op.PUSH1, 1, Op.PUSH2, 0x01, 0x00, Op.SHL, Op.STOP])
    # shift=256, value=1 → 0
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [0]


def test_sar_positive():
    """Signed right shift of a positive number = unsigned right shift."""
    code = bytes([Op.PUSH1, 0x40, Op.PUSH1, 2, Op.SAR, Op.STOP])
    # 0x40 = 64, 64 >> 2 = 16
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [16]


# ---------------------------------------------------------------------------
# ADDMOD, MULMOD, SIGNEXTEND
# ---------------------------------------------------------------------------

def test_addmod():
    # (5 + 7) mod 7 = 12 mod 7 = 5
    # Stack order: push n, b, a; ADDMOD pops a (top), b, n
    code = bytes([
        Op.PUSH1, 7, Op.PUSH1, 7, Op.PUSH1, 5, Op.ADDMOD, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [5]


def test_mulmod():
    # (5 * 7) mod 6 = 35 mod 6 = 5
    code = bytes([
        Op.PUSH1, 6, Op.PUSH1, 7, Op.PUSH1, 5, Op.MULMOD, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [5]


def test_addmod_zero_modulus():
    code = bytes([
        Op.PUSH1, 0, Op.PUSH1, 7, Op.PUSH1, 5, Op.ADDMOD, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [0]


def test_signextend_positive():
    """SIGNEXTEND of 0x7f (positive byte) leaves it unchanged."""
    # PUSH1 0x7f, PUSH1 0 (byte position), SIGNEXTEND → 0x7f
    # Order: stack = [0x7f, 0], SIGNEXTEND pops [0, 0x7f] = byte_idx=0, x=0x7f
    code = bytes([Op.PUSH1, 0x7f, Op.PUSH1, 0, Op.SIGNEXTEND, Op.STOP])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [0x7f]


def test_signextend_negative():
    """SIGNEXTEND of 0xff (high bit set) sign-extends to full -1 in 256-bit."""
    code = bytes([Op.PUSH1, 0xff, Op.PUSH1, 0, Op.SIGNEXTEND, Op.STOP])
    trace = execute(code, gas=1000)
    expected = (1 << 256) - 1  # all 1 bits
    assert trace.states[-1].stack == [expected]


# ---------------------------------------------------------------------------
# BYTE
# ---------------------------------------------------------------------------

def test_byte_extracts_byte():
    # Top byte of 0xabcdef... is the most-significant byte
    code = bytes([
        Op.PUSH4, 0x12, 0x34, 0x56, 0x78,
        Op.PUSH1, 31,            # last byte (0x78)
        Op.BYTE, Op.STOP,
    ])
    # PUSH4 gives 32-bit value; BYTE with i=31 extracts the last byte = 0x78
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [0x78]


def test_byte_out_of_range_returns_zero():
    code = bytes([
        Op.PUSH1, 0xff, Op.PUSH1, 32, Op.BYTE, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    assert trace.states[-1].stack == [0]


# ---------------------------------------------------------------------------
# Environment opcodes
# ---------------------------------------------------------------------------

def test_caller_callvalue_address():
    """The execution context's caller, value, and address are observable."""
    ctx = ExecContext(
        address=0xaa,
        caller=0xbb,
        value=12345,
        calldata=b"",
        block_number=99,
        block_timestamp=1700000000,
    )
    code = bytes([Op.CALLER, Op.CALLVALUE, Op.ADDRESS, Op.NUMBER, Op.TIMESTAMP, Op.STOP])
    trace = execute(code, gas=1000, context=ctx)
    assert trace.states[-1].stack == [0xbb, 12345, 0xaa, 99, 1700000000]


def test_calldataload_pads_with_zeros():
    """CALLDATALOAD at offset past the end returns 0."""
    ctx = ExecContext(calldata=b"\xaa\xbb\xcc")  # only 3 bytes
    code = bytes([Op.PUSH1, 0, Op.CALLDATALOAD, Op.STOP])
    trace = execute(code, gas=1000, context=ctx)
    # 3 bytes 0xaabbcc, padded with 29 zero bytes on the right.
    # Most significant in the 32-byte word.
    expected = 0xaabbcc * (1 << (29 * 8))
    assert trace.states[-1].stack == [expected]


def test_calldatasize():
    ctx = ExecContext(calldata=b"hello world")
    code = bytes([Op.CALLDATASIZE, Op.STOP])
    trace = execute(code, gas=1000, context=ctx)
    assert trace.states[-1].stack == [11]


# ---------------------------------------------------------------------------
# MSTORE8 and GAS
# ---------------------------------------------------------------------------

def test_mstore8_writes_single_byte():
    # Write 0xab at offset 0, then MLOAD to check the 32-byte word
    code = bytes([
        Op.PUSH1, 0xab, Op.PUSH1, 0, Op.MSTORE8,
        Op.PUSH1, 0, Op.MLOAD, Op.STOP,
    ])
    trace = execute(code, gas=1000)
    # Memory after MSTORE8: 0xab at byte 0, rest zero.
    # MLOAD reads 32 bytes starting at 0: 0xab followed by 31 zero bytes.
    expected = 0xab << (31 * 8)
    assert trace.states[-1].stack == [expected]


def test_gas_returns_remaining():
    code = bytes([Op.GAS, Op.STOP])
    trace = execute(code, gas=100)
    # GAS cost = 2, so after GAS executes there are 98 gas left;
    # but the GAS op pushes the gas AFTER its own deduction.
    assert trace.states[-1].stack == [98]


# ---------------------------------------------------------------------------
# Storage is committed in state
# ---------------------------------------------------------------------------

def test_storage_commitment_changes():
    """Same code, different initial storage → different state commitments
    along the trace (proving storage is part of the fraud-proof base)."""
    code = bytes([Op.PUSH1, 0, Op.SLOAD, Op.STOP])
    t1 = execute(code, gas=1000, initial_storage={0: 1})
    t2 = execute(code, gas=1000, initial_storage={0: 2})
    assert t1.commitments[-1] != t2.commitments[-1]


def test_storage_after_sstore_visible_in_commitment():
    code = bytes([Op.PUSH1, 99, Op.PUSH1, 1, Op.SSTORE, Op.STOP])
    t = execute(code, gas=100_000)
    # State at end has storage[1] = 99.
    assert t.states[-1].storage == {1: 99}
    # Initial commitment ≠ final commitment because of storage change.
    assert t.commitments[0] != t.commitments[-1]


# ---------------------------------------------------------------------------
# Larger DUP/SWAP work
# ---------------------------------------------------------------------------

def test_dup5_dup8():
    # Build a stack of 10 elements (1..10), then DUP5, DUP8
    # PUSH1 1, PUSH1 2, ..., PUSH1 10
    pushes = []
    for i in range(1, 11):
        pushes.extend([Op.PUSH1, i])
    code = bytes(pushes + [Op.DUP5, Op.DUP8, Op.STOP])
    trace = execute(code, gas=100_000)
    # After 10 pushes: stack = [1..10] (top=10)
    # DUP5 duplicates the 5th-from-top (= 6): stack = [1..10, 6]
    # DUP8 duplicates the 8th-from-top of new stack (= 4): stack = [1..10, 6, 4]
    assert trace.states[-1].stack == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 6, 4]


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} v0.4 EVM tests passed.")
