# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 5: precompiles never return a silent placeholder
(audit 2, point 7)."""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.crypto import KernKeypair
from kern.evm import bn254
from kern.evm.frames import (
    _precompile_ecrecover,
    _precompile_ripemd160,
    _ripemd160_pure,
)

# Official RIPEMD-160 test vectors (Dobbertin, Bosselaers, Preneel).
VECTORS = {
    b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    b"a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
    b"abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    b"1234567890" * 8: "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
}


@pytest.mark.parametrize("msg,digest", list(VECTORS.items()))
def test_portable_ripemd160_matches_reference_vectors(msg, digest):
    assert _ripemd160_pure(msg).hex() == digest


def test_precompile_never_returns_zeros_without_openssl(monkeypatch):
    """Simulate an OpenSSL build without the legacy provider."""
    real_new = hashlib.new

    def no_ripemd(name, *a, **k):
        if name.lower() == "ripemd160":
            raise ValueError("unsupported hash type")
        return real_new(name, *a, **k)

    monkeypatch.setattr(hashlib, "new", no_ripemd)
    out = _precompile_ripemd160(b"abc")
    assert out == b"\x00" * 12 + bytes.fromhex(VECTORS[b"abc"])


def test_ecrecover_is_an_ed25519_verifier():
    kp = KernKeypair.from_seed(bytes([9]) * 32)
    msg = hashlib.sha256(b"hello").digest()
    sig = kp.sign(msg)
    pub = kp.public_key
    out = _precompile_ecrecover(msg + pub + sig)
    expected = hashlib.blake2b(pub, digest_size=20, key=b"kern.addr").digest()
    assert out == b"\x00" * 12 + expected
    bad = bytearray(sig)
    bad[0] ^= 1
    assert _precompile_ecrecover(msg + pub + bytes(bad)) == b"\x00" * 32


def test_pairing_without_backend_raises_instead_of_accepting(monkeypatch):
    monkeypatch.setattr(bn254, "PY_ECC_AVAILABLE", False)
    with pytest.raises(bn254.BN254BackendUnavailable):
        bn254.pairing_check([((1, 2), b"\x00" * 128)])
    assert bn254.pairing_check([]) is True   # empty product is still 1
