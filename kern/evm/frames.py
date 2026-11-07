# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.frames
===============

Multi-frame EVM execution: CALL / STATICCALL / DELEGATECALL, contract
creation via CREATE / CREATE2, event LOGs, and the EVM precompiles.

The single-frame `kern.evm.vm` handles one EVM execution context — a
single contract, called once. The frame manager here handles the
recursive case: a contract calling another contract calling another,
each with its own VM state (stack, memory, storage, gas), but sharing a
global world state (account balances + code).

Design
------

A `Frame` is a single VM execution context: code, calldata, caller,
value, gas budget, and a `VmState`. The `FrameStack` holds active
frames; the top frame is what's currently executing. When a CALL
opcode fires, we push a new frame; when a RETURN/STOP/REVERT fires in
the top frame, we pop it and propagate the outcome (success+return
data, or revert+reason) back to the caller frame's stack and memory.

`WorldState` holds the global EVM state: account balances and code,
keyed by address (256-bit). Calls atomically update balances; reverts
roll them back via snapshots.

For v0.5, frame execution is **batched**: we run the top frame to
completion (or until it CALLs), then advance. The step-wise per-
instruction commitment scheme of `kern.evm.vm` still applies *within*
each frame — so the bisection fraud-proof protocol from
`docs/evm-fraud-proofs.md` extends naturally: a fraud proof now
identifies (frame_index, step_index) and the single-step verifier
re-runs that one instruction in that frame.

Multi-frame fraud proofs are handled by hashing the entire frame stack
into the state commitment, so any divergence — within any frame, in
any returned value, in any storage update — is detectable.

Precompiles
-----------

Addresses 0x01..0x09 are reserved for built-in functions:
    0x01: ECRECOVER  (signature recovery)
    0x02: SHA256
    0x03: RIPEMD160
    0x04: IDENTITY   (memcpy)
    0x05: MODEXP     (modular exponentiation)
    0x06: BN_ADD     (elliptic curve add)
    0x07: BN_MUL
    0x08: BN_PAIRING
    0x09: BLAKE2F

This module implements 0x01 (ECRECOVER, using Ed25519 instead of the
secp256k1 used by Ethereum — a Kern-specific choice), 0x02 (SHA256),
and 0x04 (IDENTITY). The others are stubs that revert; adding them is
mechanical.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .opcodes import Op
from .vm import ExecContext, ExecutionTrace, VmState, execute


# Precompile address range.
PRECOMPILE_MIN = 0x01
PRECOMPILE_MAX = 0x09


# ---------------------------------------------------------------------------
# World state
# ---------------------------------------------------------------------------

@dataclass
class Account:
    """An account in the EVM world state.

    For externally-owned accounts (EOAs), `code` is empty.
    For contracts, `code` is the deployed bytecode.
    `storage` is the persistent contract storage (256-bit keys → 256-bit values).
    """

    balance: int = 0
    code: bytes = b""
    storage: Dict[int, int] = field(default_factory=dict)
    nonce: int = 0

    def is_contract(self) -> bool:
        return len(self.code) > 0


@dataclass
class WorldState:
    """Global EVM world state. Address → Account.

    All atomic mutation goes through `snapshot()` + `revert_to()` so that
    failed calls don't corrupt the state."""

    accounts: Dict[int, Account] = field(default_factory=dict)

    def get(self, address: int) -> Account:
        if address not in self.accounts:
            self.accounts[address] = Account()
        return self.accounts[address]

    def transfer(self, from_addr: int, to_addr: int, amount: int) -> bool:
        """Move `amount` from from_addr to to_addr. Returns False on
        insufficient balance."""
        if amount == 0:
            return True
        src = self.get(from_addr)
        if src.balance < amount:
            return False
        src.balance -= amount
        self.get(to_addr).balance += amount
        return True

    def snapshot(self) -> dict:
        """Take a deep snapshot of the world state for potential rollback."""
        import copy
        return copy.deepcopy(self.accounts)

    def revert_to(self, snap: dict) -> None:
        self.accounts = snap


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------

class FrameKind(str, Enum):
    CALL = "call"                  # ordinary call: own storage, given value
    STATICCALL = "staticcall"      # like CALL but no state mutation allowed
    DELEGATECALL = "delegatecall"  # caller's storage, caller's value preserved


@dataclass
class Frame:
    """A single EVM execution frame."""

    address: int                   # contract being executed
    storage_address: int           # whose storage we mutate (different for DELEGATECALL)
    caller: int
    value: int
    code: bytes
    calldata: bytes
    gas: int
    kind: FrameKind = FrameKind.CALL
    is_static: bool = False        # propagated for STATICCALL
    vm_state: Optional[VmState] = None  # last observed VM state (after execution)
    return_data: bytes = b""
    reverted: bool = False
    completed: bool = False
    last_error: Optional[str] = None
    logs: List[dict] = field(default_factory=list)


@dataclass
class CallResult:
    """Result of a CALL / STATICCALL / DELEGATECALL."""

    success: bool
    return_data: bytes
    gas_remaining: int
    logs: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Precompiles
# ---------------------------------------------------------------------------

def _precompile_ecrecover(calldata: bytes) -> bytes:
    """ECRECOVER at address 0x01, Kern variant: Ed25519 signature check.

    Kern accounts use Ed25519, not Ethereum's secp256k1, so this precompile
    does NOT recover a key from (v, r, s). It VERIFIES an Ed25519 signature
    and returns the signer's address. Calldata layout (128 bytes):

        bytes   0..32   message (typically a 32-byte hash)
        bytes  32..64   Ed25519 public key
        bytes  64..128  Ed25519 signature

    Output: 12 zero bytes followed by the 20-byte address payload derived
    exactly as kern.crypto does (blake2b-160, key b"kern.addr"), or 32 zero
    bytes if the input is short or the signature does not verify.

    Phase B (audit 2, point 7): the docstring used to describe the
    secp256k1 (hash, v, r, s) layout, which this code never read. PyNaCl is
    a hard dependency; if it is missing the precompile now raises instead
    of silently returning zeros, because a node that cannot verify must not
    compute a different state from its peers."""
    if len(calldata) < 128:
        return b"\x00" * 32
    msg_hash = calldata[0:32]
    pubkey = calldata[32:64]
    signature = calldata[64:128]
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError, CryptoError
    try:
        VerifyKey(pubkey).verify(msg_hash, signature)
    except (BadSignatureError, CryptoError, ValueError, TypeError):
        return b"\x00" * 32
    addr_bytes = hashlib.blake2b(pubkey, digest_size=20, key=b"kern.addr").digest()
    return b"\x00" * 12 + addr_bytes  # pad to 32 bytes


def _precompile_sha256(calldata: bytes) -> bytes:
    """SHA256: standard SHA-256 hash of the input."""
    return hashlib.sha256(calldata).digest()


def _precompile_identity(calldata: bytes) -> bytes:
    """IDENTITY: returns calldata unchanged. Used as a memcpy primitive."""
    return calldata


def _precompile_ripemd160(calldata: bytes) -> bytes:
    """RIPEMD-160: 160-bit hash, left-padded to 32 bytes for word alignment.

    Phase B (audit 2, point 7): when OpenSSL lacks the legacy provider,
    hashlib has no ripemd160 and this used to return 32 zero bytes, so two
    nodes could compute different state roots for the same bytecode. It
    now falls back to the pure-Python implementation below, which produces
    the same digest on every platform."""
    return b"\x00" * 12 + ripemd160(calldata)


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 digest. Uses hashlib when it provides the algorithm,
    otherwise the portable implementation; both are byte-identical."""
    try:
        h = hashlib.new("ripemd160")
    except ValueError:
        return _ripemd160_pure(data)
    h.update(data)
    return h.digest()


# Portable RIPEMD-160 (Dobbertin, Bosselaers, Preneel, 1996).
_RMD_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
_RMD_RL = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RMD_RR = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_RMD_SL = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_RMD_SR = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rmd_rol(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _ripemd160_pure(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytes(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += (8 * len(data) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i: off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = _rmd_rol(al + _rmd_f(j, bl, cl, dl) + x[_RMD_RL[j]] + _RMD_KL[r], _RMD_SL[j]) + el
            al, el, dl, cl, bl = el, dl, _rmd_rol(cl, 10), bl, t & 0xFFFFFFFF
            t = _rmd_rol(ar + _rmd_f(79 - j, br, cr, dr) + x[_RMD_RR[j]] + _RMD_KR[r], _RMD_SR[j]) + er
            ar, er, dr, cr, br = er, dr, _rmd_rol(cr, 10), br, t & 0xFFFFFFFF
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(v.to_bytes(4, "little") for v in h)


def _precompile_modexp(calldata: bytes) -> bytes:
    """MODEXP: modular exponentiation.

    Calldata layout (simplified from Ethereum's layout):
        [32-byte base_len][32-byte exp_len][32-byte mod_len]
        [base bytes][exp bytes][mod bytes]

    Output: (base ** exp) mod modulus, big-endian, mod_len bytes.
    """
    if len(calldata) < 96:
        return b""
    base_len = int.from_bytes(calldata[0:32], "big")
    exp_len = int.from_bytes(calldata[32:64], "big")
    mod_len = int.from_bytes(calldata[64:96], "big")
    # Reasonable cap: refuse pathologically large inputs.
    if base_len > 1024 or exp_len > 1024 or mod_len > 1024:
        return b""
    offset = 96
    base = int.from_bytes(calldata[offset:offset + base_len], "big") if base_len else 0
    offset += base_len
    exp = int.from_bytes(calldata[offset:offset + exp_len], "big") if exp_len else 0
    offset += exp_len
    mod = int.from_bytes(calldata[offset:offset + mod_len], "big") if mod_len else 0
    if mod == 0:
        return b"\x00" * mod_len
    result = pow(base, exp, mod)
    return result.to_bytes(mod_len, "big") if mod_len else b""


def _precompile_blake2f(calldata: bytes) -> bytes:
    """BLAKE2F: the F compression function of BLAKE2b.

    Calldata layout: 4 rounds bytes + 64 state h + 128 message m +
    16 offset bytes + 1 final flag = 213 bytes total.

    A full implementation is substantial. v0.6 ships a simplified
    blake2b hash of the input as a stand-in — preserves the
    determinism property; full BLAKE2F compression is a v0.7 lift.
    """
    if len(calldata) != 213:
        return b""
    # Stand-in: blake2b of the whole calldata, returning 64 bytes
    # (matching the spec's output size).
    return hashlib.blake2b(calldata, digest_size=64).digest()


def _precompile_bn_add(calldata: bytes) -> bytes:
    """BN254 G1 point addition. v0.7."""
    from .bn254 import bn_add_precompile
    result = bn_add_precompile(calldata)
    return result if result is not None else b""


def _precompile_bn_mul(calldata: bytes) -> bytes:
    """BN254 G1 scalar multiplication. v0.7."""
    from .bn254 import bn_mul_precompile
    result = bn_mul_precompile(calldata)
    return result if result is not None else b""


def _precompile_bn_pairing(calldata: bytes) -> bytes:
    """BN254 pairing check. v0.7."""
    from .bn254 import bn_pairing_precompile
    result = bn_pairing_precompile(calldata)
    return result if result is not None else b""


PRECOMPILES = {
    0x01: _precompile_ecrecover,
    0x02: _precompile_sha256,
    0x03: _precompile_ripemd160,
    0x04: _precompile_identity,
    0x05: _precompile_modexp,
    0x06: _precompile_bn_add,
    0x07: _precompile_bn_mul,
    0x08: _precompile_bn_pairing,
    0x09: _precompile_blake2f,
}


def is_precompile(address: int) -> bool:
    return PRECOMPILE_MIN <= address <= PRECOMPILE_MAX and address in PRECOMPILES


def execute_precompile(address: int, calldata: bytes, gas: int) -> CallResult:
    """Run a precompile and return the result. Precompiles consume a
    fixed gas amount (here simplified to 1000)."""
    if not is_precompile(address):
        return CallResult(success=False, return_data=b"", gas_remaining=gas)
    cost = 1000
    if gas < cost:
        return CallResult(success=False, return_data=b"", gas_remaining=0)
    fn = PRECOMPILES[address]
    try:
        result = fn(calldata)
        return CallResult(success=True, return_data=result, gas_remaining=gas - cost)
    except Exception:
        return CallResult(success=False, return_data=b"", gas_remaining=0)


# ---------------------------------------------------------------------------
# Call dispatch
# ---------------------------------------------------------------------------

def call_contract(
    world: WorldState,
    *,
    kind: FrameKind,
    caller: int,
    address: int,         # call target
    value: int,
    calldata: bytes,
    gas: int,
    block_number: int = 0,
    block_timestamp: int = 0,
    is_static: bool = False,
) -> CallResult:
    """Top-level entry point for a contract call.

    Handles value transfer, precompile dispatch, frame creation,
    execution, and snapshot/revert semantics. Returns a CallResult.
    """
    # 1. Static-call propagation: STATICCALL forces is_static for its subcalls.
    if kind == FrameKind.STATICCALL:
        is_static = True

    # 2. Reject value transfer in static calls.
    if is_static and value != 0:
        return CallResult(success=False, return_data=b"", gas_remaining=0)

    # 3. Snapshot for potential rollback.
    snap = world.snapshot()

    # 4. Value transfer.
    if kind == FrameKind.CALL and value > 0:
        if not world.transfer(caller, address, value):
            world.revert_to(snap)
            return CallResult(success=False, return_data=b"", gas_remaining=gas)

    # 5. Precompile dispatch.
    if is_precompile(address):
        result = execute_precompile(address, calldata, gas)
        if not result.success:
            world.revert_to(snap)
        return result

    # 6. Real contract call.
    callee = world.get(address)
    if not callee.is_contract():
        # Calling a non-contract (EOA): no code to run. The value transfer
        # (if any) already happened above; we return success with empty
        # return data.
        return CallResult(success=True, return_data=b"", gas_remaining=gas)

    # 7. Set up the execution frame.
    # For DELEGATECALL: storage_address = caller, value = preserved from
    # caller frame, caller stays the same as the outer caller.
    if kind == FrameKind.DELEGATECALL:
        storage_address = caller
        effective_value = value      # caller passes through current msg.value
        effective_caller = caller    # preserved
    else:
        storage_address = address
        effective_value = value
        effective_caller = caller

    storage_account = world.get(storage_address)
    ctx = ExecContext(
        address=address,
        caller=effective_caller,
        value=effective_value,
        calldata=calldata,
        block_number=block_number,
        block_timestamp=block_timestamp,
    )

    # 8. Execute. We pass in current storage as a copy; if the call
    # succeeds we merge it back, otherwise we discard.
    trace = execute(
        callee.code, gas=gas, context=ctx,
        initial_storage=dict(storage_account.storage),
    )
    final = trace.states[-1]

    if final.reverted:
        world.revert_to(snap)
        return CallResult(
            success=False, return_data=final.output,
            gas_remaining=final.gas,
        )

    # 9. Success. Merge storage changes back if not static.
    if not is_static:
        # SSTORE writes by the VM update its `storage` dict; final.storage
        # has the latest values. Replace the account's storage atomically.
        storage_account.storage = dict(final.storage)

    return CallResult(
        success=True, return_data=final.output,
        gas_remaining=final.gas,
    )


# ---------------------------------------------------------------------------
# Address derivation for CREATE / CREATE2
# ---------------------------------------------------------------------------

def derive_create_address(creator: int, nonce: int) -> int:
    """CREATE: address = blake2b(creator || nonce)[12:32].

    Real Ethereum uses RLP(creator, nonce); we use blake2b for simplicity
    (preserves the property that the address is determined by creator + nonce).
    """
    payload = creator.to_bytes(20, "big") + nonce.to_bytes(8, "big")
    digest = hashlib.blake2b(payload, digest_size=20, key=b"kern.evm.create").digest()
    return int.from_bytes(digest, "big")


def derive_create2_address(creator: int, salt: int, init_code: bytes) -> int:
    """CREATE2: address = blake2b(creator || salt || hash(init_code))[12:32].

    Allows deterministic-address contract deployment based on salt + code."""
    init_hash = hashlib.blake2b(init_code, digest_size=32, key=b"kern.evm.code").digest()
    payload = creator.to_bytes(20, "big") + salt.to_bytes(32, "big") + init_hash
    digest = hashlib.blake2b(payload, digest_size=20, key=b"kern.evm.create2").digest()
    return int.from_bytes(digest, "big")


def create_contract(
    world: WorldState,
    *,
    creator: int,
    init_code: bytes,
    value: int,
    gas: int,
    salt: Optional[int] = None,
    block_number: int = 0,
    block_timestamp: int = 0,
) -> Tuple[Optional[int], CallResult]:
    """Deploy a new contract by executing `init_code`. The returned bytes
    from init_code are the runtime code stored at the new address.

    Returns (deployed_address or None, CallResult).
    """
    creator_account = world.get(creator)

    # Compute deterministic address.
    if salt is None:
        addr = derive_create_address(creator, creator_account.nonce)
    else:
        addr = derive_create2_address(creator, salt, init_code)

    # Bump creator's nonce regardless of success.
    creator_account.nonce += 1

    # Value transfer to the new (currently empty) account.
    snap = world.snapshot()
    if value > 0:
        if not world.transfer(creator, addr, value):
            world.revert_to(snap)
            return None, CallResult(success=False, return_data=b"", gas_remaining=gas)

    # Execute init_code with no calldata. The returned bytes become the
    # deployed runtime code.
    ctx = ExecContext(
        address=addr, caller=creator, value=value, calldata=b"",
        block_number=block_number, block_timestamp=block_timestamp,
    )
    trace = execute(init_code, gas=gas, context=ctx)
    final = trace.states[-1]

    if final.reverted:
        world.revert_to(snap)
        return None, CallResult(success=False, return_data=final.output,
                                gas_remaining=final.gas)

    # Install the returned runtime code.
    new_account = world.get(addr)
    new_account.code = final.output
    new_account.storage = dict(final.storage)

    return addr, CallResult(success=True, return_data=addr.to_bytes(32, "big"),
                            gas_remaining=final.gas)
