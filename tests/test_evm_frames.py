# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.evm.frames — multi-frame execution, precompiles,
contract creation."""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.evm import (
    Account,
    CallResult,
    FrameKind,
    Op,
    PRECOMPILES,
    WorldState,
    call_contract,
    create_contract,
    derive_create2_address,
    derive_create_address,
    execute_precompile,
    is_precompile,
)


# ---------------------------------------------------------------------------
# World state
# ---------------------------------------------------------------------------

def test_world_state_get_creates_default_account():
    w = WorldState()
    acc = w.get(0xaa)
    assert acc.balance == 0
    assert acc.code == b""
    assert acc.storage == {}


def test_world_state_transfer_succeeds():
    w = WorldState()
    w.accounts[0xaa] = Account(balance=1000)
    assert w.transfer(0xaa, 0xbb, 300) is True
    assert w.get(0xaa).balance == 700
    assert w.get(0xbb).balance == 300


def test_world_state_transfer_insufficient_balance():
    w = WorldState()
    w.accounts[0xaa] = Account(balance=100)
    assert w.transfer(0xaa, 0xbb, 500) is False
    assert w.get(0xaa).balance == 100  # unchanged
    assert w.get(0xbb).balance == 0


def test_world_state_snapshot_revert():
    w = WorldState()
    w.accounts[0xaa] = Account(balance=1000)
    snap = w.snapshot()
    w.transfer(0xaa, 0xbb, 500)
    assert w.get(0xaa).balance == 500
    w.revert_to(snap)
    assert w.get(0xaa).balance == 1000


# ---------------------------------------------------------------------------
# Precompiles
# ---------------------------------------------------------------------------

def test_is_precompile_recognizes_known_addresses():
    assert is_precompile(0x01)  # ecrecover
    assert is_precompile(0x02)  # sha256
    assert is_precompile(0x04)  # identity
    assert not is_precompile(0x00)
    assert not is_precompile(0xff)


def test_precompile_sha256():
    r = execute_precompile(0x02, b"hello world", gas=10_000)
    assert r.success
    assert r.return_data == hashlib.sha256(b"hello world").digest()


def test_precompile_identity():
    payload = b"\xde\xad\xbe\xef" * 8
    r = execute_precompile(0x04, payload, gas=10_000)
    assert r.success
    assert r.return_data == payload


def test_precompile_out_of_gas():
    r = execute_precompile(0x02, b"x", gas=10)  # need 1000
    assert not r.success


def test_precompile_ecrecover_valid_ed25519():
    from kern.crypto import KernKeypair
    kp = KernKeypair.generate()
    msg = b"\x42" * 32
    sig = kp.sign(msg)
    pubkey = kp.public_key
    # Calldata layout: 32-byte hash + 32-byte pubkey + 64-byte sig.
    calldata = msg + pubkey + sig
    r = execute_precompile(0x01, calldata, gas=10_000)
    assert r.success
    # Expect non-zero address bytes
    assert r.return_data[-20:] != b"\x00" * 20


def test_precompile_ecrecover_bad_signature():
    calldata = b"\x00" * 128
    r = execute_precompile(0x01, calldata, gas=10_000)
    assert r.success  # the call itself succeeds
    # but returns zeros (signature didn't verify)
    assert r.return_data == b"\x00" * 32


# ---------------------------------------------------------------------------
# CALL to a simple contract
# ---------------------------------------------------------------------------

def test_call_returns_value_from_contract():
    """A contract that returns 0x42 padded in a 32-byte word."""
    code = bytes([
        Op.PUSH1, 0x42,
        Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
    ])
    w = WorldState()
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x100,
        value=0, calldata=b"", gas=10_000,
    )
    assert result.success
    assert result.return_data[-1] == 0x42


def test_call_transfers_value():
    """CALL with positive value transfers ETH-equivalent from caller to callee."""
    # Contract that just STOPs.
    code = bytes([Op.STOP])
    w = WorldState()
    w.accounts[0x10] = Account(balance=10_000)
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x100,
        value=3000, calldata=b"", gas=10_000,
    )
    assert result.success
    assert w.get(0x10).balance == 7_000
    assert w.get(0x100).balance == 3000


def test_call_insufficient_balance_fails():
    code = bytes([Op.STOP])
    w = WorldState()
    w.accounts[0x10] = Account(balance=100)
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x100,
        value=999_999, calldata=b"", gas=10_000,
    )
    assert not result.success
    # State unchanged
    assert w.get(0x10).balance == 100
    assert w.get(0x100).balance == 0


def test_call_to_non_contract_succeeds():
    """Calling an EOA: no code, no return data, value transfers."""
    w = WorldState()
    w.accounts[0x10] = Account(balance=1000)
    w.accounts[0x20] = Account(balance=0)  # EOA, no code

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x20,
        value=500, calldata=b"", gas=10_000,
    )
    assert result.success
    assert w.get(0x10).balance == 500
    assert w.get(0x20).balance == 500


def test_call_reverts_rolls_back_state():
    """REVERT inside the call doesn't change balances or storage."""
    # Code that does SSTORE then REVERT.
    code = bytes([
        Op.PUSH1, 99, Op.PUSH1, 1, Op.SSTORE,
        Op.PUSH1, 0, Op.PUSH1, 0, Op.REVERT,
    ])
    w = WorldState()
    w.accounts[0x10] = Account(balance=1000)
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x100,
        value=200, calldata=b"", gas=100_000,
    )
    assert not result.success
    # No value transfer, no storage change.
    assert w.get(0x10).balance == 1000
    assert w.get(0x100).balance == 0
    assert w.get(0x100).storage == {}


def test_call_persists_storage_on_success():
    """SSTORE in a CALL that returns successfully persists to world state."""
    code = bytes([
        Op.PUSH1, 99, Op.PUSH1, 1, Op.SSTORE,
        Op.STOP,
    ])
    w = WorldState()
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.CALL, caller=0x10, address=0x100,
        value=0, calldata=b"", gas=100_000,
    )
    assert result.success
    assert w.get(0x100).storage[1] == 99


# ---------------------------------------------------------------------------
# STATICCALL
# ---------------------------------------------------------------------------

def test_staticcall_succeeds_on_pure_view():
    """A STATICCALL on a pure view function works."""
    # Contract returns 42.
    code = bytes([
        Op.PUSH1, 42, Op.PUSH1, 0, Op.MSTORE,
        Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN,
    ])
    w = WorldState()
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.STATICCALL, caller=0x10, address=0x100,
        value=0, calldata=b"", gas=10_000,
    )
    assert result.success
    assert result.return_data[-1] == 42


def test_staticcall_with_value_fails():
    """STATICCALL with positive value is rejected."""
    code = bytes([Op.STOP])
    w = WorldState()
    w.accounts[0x10] = Account(balance=10_000)
    w.accounts[0x100] = Account(code=code)

    result = call_contract(
        w, kind=FrameKind.STATICCALL, caller=0x10, address=0x100,
        value=100, calldata=b"", gas=10_000,
    )
    assert not result.success
    # No state mutation.
    assert w.get(0x10).balance == 10_000


# ---------------------------------------------------------------------------
# DELEGATECALL: caller's storage is mutated
# ---------------------------------------------------------------------------

def test_delegatecall_mutates_callers_storage():
    """DELEGATECALL: the callee's code runs in the caller's storage context."""
    # Library contract: SSTORE 999 at key 7.
    library_code = bytes([
        Op.PUSH2, 0x03, 0xe7,  # 999
        Op.PUSH1, 7, Op.SSTORE,
        Op.STOP,
    ])
    w = WorldState()
    w.accounts[0x100] = Account(code=library_code)
    # 0x10 is the caller (a contract using the library via DELEGATECALL).
    w.accounts[0x10] = Account(code=b"")  # not a real contract for this test

    result = call_contract(
        w, kind=FrameKind.DELEGATECALL,
        caller=0x10,           # caller's storage will be modified
        address=0x100,         # library code
        value=0, calldata=b"", gas=100_000,
    )
    assert result.success
    # Caller's storage now has the library's write.
    assert w.get(0x10).storage[7] == 999
    # Library's own storage is unchanged.
    assert 7 not in w.get(0x100).storage


# ---------------------------------------------------------------------------
# Contract creation: CREATE / CREATE2
# ---------------------------------------------------------------------------

def test_derive_create_address_is_deterministic():
    a1 = derive_create_address(0xabc, 0)
    a2 = derive_create_address(0xabc, 0)
    assert a1 == a2
    a3 = derive_create_address(0xabc, 1)
    assert a3 != a1


def test_derive_create2_address_is_deterministic():
    code = b"\x60\x42\x60\x00\xf3"
    a1 = derive_create2_address(0xabc, 0xdef, code)
    a2 = derive_create2_address(0xabc, 0xdef, code)
    assert a1 == a2
    a3 = derive_create2_address(0xabc, 0xdef + 1, code)
    assert a3 != a1


def test_create_deploys_returned_code():
    """init_code that RETURNs a constant becomes the deployed code."""
    # init_code: PUSH some bytes into memory, RETURN them.
    # Returned bytes: PUSH1 0x42, STOP  (a trivial "deployed" contract)
    deployed = bytes([Op.PUSH1, 0x42, Op.STOP])

    init_code_list = [
        Op.PUSH1, len(deployed),                  # length
        Op.PUSH1, len(deployed),                  # also length (for source offset)
        Op.PUSH1, 32 - len(deployed),             # destination offset in memory
        Op.MSTORE,                                 # ignored - this is wrong, but simple test
    ]
    # Easier: directly write `deployed` into memory and return it.
    # Use MSTORE8 byte by byte (since our memory is byte-addressable).
    init_code_list = []
    for i, b in enumerate(deployed):
        init_code_list.extend([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
    init_code_list.extend([Op.PUSH1, len(deployed), Op.PUSH1, 0, Op.RETURN])
    init_code = bytes(init_code_list)

    w = WorldState()
    w.accounts[0xabc] = Account(balance=100_000, nonce=0)

    addr, result = create_contract(
        w, creator=0xabc, init_code=init_code, value=0, gas=100_000,
    )
    assert addr is not None
    assert result.success
    # The deployed code at `addr` should be exactly `deployed`.
    assert w.get(addr).code == deployed


def test_create_with_value_funds_new_contract():
    deployed = bytes([Op.STOP])
    init_code_list = []
    for i, b in enumerate(deployed):
        init_code_list.extend([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
    init_code_list.extend([Op.PUSH1, len(deployed), Op.PUSH1, 0, Op.RETURN])
    init_code = bytes(init_code_list)

    w = WorldState()
    w.accounts[0xabc] = Account(balance=10_000, nonce=0)

    addr, result = create_contract(
        w, creator=0xabc, init_code=init_code, value=3000, gas=100_000,
    )
    assert addr is not None
    assert result.success
    assert w.get(addr).balance == 3000
    assert w.get(0xabc).balance == 7000


def test_create_nonce_bumps_even_on_revert():
    """An init_code that REVERTS still bumps the creator's nonce — matches EVM."""
    # Init code that just REVERTs.
    init_code = bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.REVERT])

    w = WorldState()
    w.accounts[0xabc] = Account(balance=10_000, nonce=5)

    addr, result = create_contract(
        w, creator=0xabc, init_code=init_code, value=0, gas=100_000,
    )
    assert addr is None or not result.success
    # Nonce bumped from 5 to 6.
    assert w.get(0xabc).nonce == 6


def test_create2_is_address_predictable():
    """CREATE2 lets the deployer pick the address via salt."""
    deployed = bytes([Op.STOP])
    init_code = bytes()
    for i, b in enumerate(deployed):
        init_code += bytes([Op.PUSH1, b, Op.PUSH1, i, Op.MSTORE8])
    init_code += bytes([Op.PUSH1, len(deployed), Op.PUSH1, 0, Op.RETURN])

    w = WorldState()
    w.accounts[0xabc] = Account(balance=100_000)

    # Predict the address before deploying.
    predicted = derive_create2_address(0xabc, salt=42, init_code=init_code)
    addr, result = create_contract(
        w, creator=0xabc, init_code=init_code, value=0, gas=100_000, salt=42,
    )
    assert result.success
    assert addr == predicted


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} multi-frame tests passed.")
