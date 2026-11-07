# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.bn254
==============

BN254 (alt_bn128) elliptic-curve precompiles for EVM addresses 0x06-0x08.

These three precompiles are the prerequisites for on-chain zkSNARK
verification — every Groth16, PLONK, and many other proof-system
verifiers compose these three primitives.

- 0x06: BN_ADD — point addition on the BN254 G1 curve
- 0x07: BN_MUL — scalar multiplication on G1
- 0x08: BN_PAIRING — bilinear pairing check (multi-pair)

Implementation strategy (v1.0-rc)
---------------------------------

The G1 arithmetic (addition, scalar multiplication) is implemented
directly in pure Python — standard finite-field arithmetic.

The pairing (which requires F_p^12 arithmetic, Miller loop, and final
exponentiation — about 1000 lines of code for a correct implementation)
is delegated to **py_ecc** when available. py_ecc is the reference
Python implementation maintained by the Ethereum Foundation; it's the
same code that backs eth-tester and is audit-vetted.

If py_ecc is not installed, a pairing raises BN254BackendUnavailable
(Phase B). Earlier versions fell back to a placeholder
that correctly handles the empty-input case (which is what most
Groth16 verifiers test against: `e(...) == 1`) and structurally
validates inputs. Production nodes MUST have py_ecc installed.

A future v1.x will swap py_ecc for a compiled BN254 backend (mcl or arkworks bindings via FFI) for ~10x speedup. Note: blst implements BLS12-381 only and is not a BN254 option; the Go client uses gnark-crypto (see docs/go-port-breakpoints.md).
"""

from __future__ import annotations

from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# py_ecc detection
# ---------------------------------------------------------------------------

try:
    from py_ecc.bn128 import (
        G1 as PY_ECC_G1,
        G2 as PY_ECC_G2,
        add as py_ecc_add,
        multiply as py_ecc_multiply,
        is_on_curve as py_ecc_is_on_curve,
        b as py_ecc_b,
        b2 as py_ecc_b2,
        FQ as PY_ECC_FQ,
        FQ2 as PY_ECC_FQ2,
        FQ12 as PY_ECC_FQ12,
        neg as py_ecc_neg,
    )
    PY_ECC_AVAILABLE = True
except ImportError:
    PY_ECC_AVAILABLE = False


class BN254BackendUnavailable(RuntimeError):
    """Raised when a pairing is requested and no BN254 backend is installed."""


# ---------------------------------------------------------------------------
# Field parameters (BN254 / alt_bn128)
# ---------------------------------------------------------------------------

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
B = 3
N = 21888242871839275222246405745257275088548364400416034343698204186575808495617

Point = Optional[Tuple[int, int]]
INFINITY: Point = None


def _modinv(a: int, m: int) -> int:
    """Modular inverse via Python's built-in pow with -1."""
    return pow(a, -1, m)


def is_on_curve(pt: Point) -> bool:
    """y² ≡ x³ + 3  (mod p)."""
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - x * x * x - B) % P == 0


# ---------------------------------------------------------------------------
# G1 group operations
# ---------------------------------------------------------------------------

def point_add(p1: Point, p2: Point) -> Point:
    if p1 is INFINITY:
        return p2
    if p2 is INFINITY:
        return p1
    assert p1 is not None and p2 is not None
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return INFINITY
        s = (3 * x1 * x1 * _modinv(2 * y1, P)) % P
    else:
        s = ((y2 - y1) * _modinv((x2 - x1) % P, P)) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(pt: Point, scalar: int) -> Point:
    if pt is INFINITY:
        return INFINITY
    scalar %= N
    if scalar == 0:
        return INFINITY
    result: Point = INFINITY
    addend: Point = pt
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


# ---------------------------------------------------------------------------
# Pairing (uses py_ecc when available)
# ---------------------------------------------------------------------------

def _kern_to_pyecc_g1(pt: Point):
    if pt is INFINITY:
        return None
    assert pt is not None
    x, y = pt
    return (PY_ECC_FQ(x), PY_ECC_FQ(y))


def _bytes_to_pyecc_g2(g2_data: bytes):
    """Parse 128 bytes (4 × 32-byte field elements) into a py_ecc G2 point.

    EVM precompile encoding for G2 (per EIP-197):
        bytes 0..31:    x.imag
        bytes 32..63:   x.real
        bytes 64..95:   y.imag
        bytes 96..127:  y.real

    Returns None for the point at infinity."""
    x_imag = int.from_bytes(g2_data[0:32], "big")
    x_real = int.from_bytes(g2_data[32:64], "big")
    y_imag = int.from_bytes(g2_data[64:96], "big")
    y_real = int.from_bytes(g2_data[96:128], "big")
    if x_imag == 0 and x_real == 0 and y_imag == 0 and y_real == 0:
        return None
    x = PY_ECC_FQ2([x_real, x_imag])
    y = PY_ECC_FQ2([y_real, y_imag])
    return (x, y)


def _to_optimized_g1(g1_pe):
    from py_ecc import optimized_bn128 as ob
    x, y = g1_pe
    return (ob.FQ(int(x.n)), ob.FQ(int(y.n)), ob.FQ.one())


def _to_optimized_g2(g2_pe):
    from py_ecc import optimized_bn128 as ob
    x, y = g2_pe
    return (ob.FQ2([int(c) for c in x.coeffs]), ob.FQ2([int(c) for c in y.coeffs]), ob.FQ2.one())


def pairing_check(pairs: List[Tuple[Point, bytes]]) -> bool:
    """Bilinear pairing check. Returns True iff the product equals 1 in F_p^12.

    Empty input → True (identity). Uses py_ecc's real BN128 pairing.

    Phase B (audit 2, points 3 and 7): without py_ecc this used to accept
    any on-curve input, so a node missing the library would accept proofs
    its peers reject and diverge. A pairing that cannot be computed now
    raises BN254BackendUnavailable; py_ecc is a hard dependency
    (requirements.txt) and the node refuses to start without it."""
    if not pairs:
        return True

    if not PY_ECC_AVAILABLE:
        raise BN254BackendUnavailable(
            "BN254 pairing requires py_ecc; install the dependencies from requirements.txt"
        )

    # Product of Miller loops, then ONE final exponentiation, compared with 1.
    #
    # Phase B: computed with py_ecc's optimized_bn128 module, whose field
    # exponentiation is iterative. The plain bn128 module used before has a
    # recursive FQ12.__pow__ (~2800 frames for the final exponentiation),
    # which raised RecursionError on Windows' smaller thread stack and forced
    # an xfail on that platform. Same curve, same pairing, same result.
    from py_ecc import optimized_bn128 as ob
    acc = ob.FQ12.one()
    for g1, g2_bytes in pairs:
        g1_pe = _kern_to_pyecc_g1(g1)
        g2_pe = _bytes_to_pyecc_g2(g2_bytes)
        if g1_pe is None or g2_pe is None:
            continue
        try:
            if not py_ecc_is_on_curve(g2_pe, py_ecc_b2):
                return False
            if not py_ecc_is_on_curve(g1_pe, py_ecc_b):
                return False
            acc = acc * ob.pairing(_to_optimized_g2(g2_pe), _to_optimized_g1(g1_pe),
                                   final_exponentiate=False)
        except Exception:
            return False
    return ob.final_exponentiate(acc) == ob.FQ12.one()


# ---------------------------------------------------------------------------
# Calldata parsing for EVM precompiles
# ---------------------------------------------------------------------------

def _read_point(data: bytes, offset: int) -> Point:
    if offset + 64 > len(data):
        chunk = data[offset:offset + 64].ljust(64, b"\x00")
    else:
        chunk = data[offset:offset + 64]
    x = int.from_bytes(chunk[0:32], "big")
    y = int.from_bytes(chunk[32:64], "big")
    if x == 0 and y == 0:
        return INFINITY
    return (x, y)


def _write_point(pt: Point) -> bytes:
    if pt is INFINITY:
        return b"\x00" * 64
    assert pt is not None
    x, y = pt
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def bn_add_precompile(calldata: bytes) -> Optional[bytes]:
    """Address 0x06 — point addition. Input: 2 points × 64 bytes = 128.
    Output: resulting point, 64 bytes."""
    p1 = _read_point(calldata, 0)
    p2 = _read_point(calldata, 64)
    if not (is_on_curve(p1) and is_on_curve(p2)):
        return None
    result = point_add(p1, p2)
    return _write_point(result)


def bn_mul_precompile(calldata: bytes) -> Optional[bytes]:
    """Address 0x07 — scalar multiplication. Input: point (64) || scalar (32).
    Output: resulting point, 64 bytes."""
    pt = _read_point(calldata, 0)
    scalar_bytes = calldata[64:96].ljust(32, b"\x00")
    scalar = int.from_bytes(scalar_bytes, "big")
    if not is_on_curve(pt):
        return None
    result = point_mul(pt, scalar)
    return _write_point(result)


def bn_pairing_precompile(calldata: bytes) -> Optional[bytes]:
    """Address 0x08 — pairing check. Input: k × (G1 64 + G2 128) = k × 192.
    Output: 32-byte word: all-zero (false) or 0x...01 (true)."""
    if len(calldata) % 192 != 0:
        return None
    k = len(calldata) // 192
    pairs: List[Tuple[Point, bytes]] = []
    for i in range(k):
        offset = i * 192
        g1 = _read_point(calldata, offset)
        g2_bytes = calldata[offset + 64:offset + 192]
        if g1 is not None and not is_on_curve(g1):
            return None
        pairs.append((g1, g2_bytes))
    result = pairing_check(pairs)
    return b"\x00" * 31 + (b"\x01" if result else b"\x00")
