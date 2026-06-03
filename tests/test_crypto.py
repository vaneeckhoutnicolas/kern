# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.crypto — keypairs, hashing, addresses, signatures."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import (
    KernKeypair,
    address_from_pubkey,
    blake2b256,
    pubkey_from_b58,
    signature_from_b58,
    verify,
)


def test_keypair_roundtrip():
    seed = os.urandom(32)
    kp1 = KernKeypair.from_seed(seed)
    kp2 = KernKeypair.from_seed(seed)
    assert kp1.public_key == kp2.public_key
    assert kp1.address == kp2.address


def test_address_starts_with_kn1():
    for _ in range(10):
        kp = KernKeypair.generate()
        assert kp.address.startswith("kn1"), f"got {kp.address}"
        assert len(kp.address) == 36


def test_pubkey_b58_roundtrip():
    kp = KernKeypair.generate()
    decoded = pubkey_from_b58(kp.public_key_b58)
    assert decoded == kp.public_key


def test_sign_verify():
    kp = KernKeypair.generate()
    msg = b"hello kern"
    sig_b58 = kp.sign_b58(msg)
    sig = signature_from_b58(sig_b58)
    assert verify(kp.public_key, msg, sig)
    assert not verify(kp.public_key, b"tampered", sig)


def test_address_derivation_is_deterministic():
    kp = KernKeypair.generate()
    addr1 = kp.address
    addr2 = address_from_pubkey(kp.public_key)
    assert addr1 == addr2


def test_blake2b_domain_separation():
    a = blake2b256(b"hello", key=b"kern.block")
    b = blake2b256(b"hello", key=b"kern.tx")
    assert a != b, "domain-separated hashes must differ"


if __name__ == "__main__":
    test_keypair_roundtrip()
    test_address_starts_with_kn1()
    test_pubkey_b58_roundtrip()
    test_sign_verify()
    test_address_derivation_is_deterministic()
    test_blake2b_domain_separation()
    print("All crypto tests passed.")
