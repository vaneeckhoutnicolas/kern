# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.transaction — signing, serialization, verification."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.transaction import OpKind, Transaction, make_call, make_origination, make_transfer


def test_transfer_sign_and_verify():
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    tx = make_transfer(alice, recipient=bob.address, amount=1_000_000, nonce=0)
    assert tx.verify_signature()
    assert tx.kind == OpKind.TRANSFER


def test_signature_does_not_cover_signature_field():
    """A tx must hash the same with and without the signature in place."""
    alice = KernKeypair.generate()
    tx = make_transfer(alice, recipient="kn1" + "0" * 33, amount=10, nonce=0)
    h_signed = tx.hash()
    tx.signature = None
    h_unsigned = tx.hash()
    assert h_signed == h_unsigned


def test_tampering_invalidates_signature():
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    tx = make_transfer(alice, recipient=bob.address, amount=1_000_000, nonce=0)
    assert tx.verify_signature()
    tx.amount = 999_999_999
    assert not tx.verify_signature(), "tampered tx must fail verification"


def test_wrong_sender_pubkey_invalidates():
    alice = KernKeypair.generate()
    mallory = KernKeypair.generate()
    tx = make_transfer(alice, recipient="kn1" + "0" * 33, amount=10, nonce=0)
    # Substitute mallory's pubkey but keep alice's signature & address.
    tx.sender_pubkey = mallory.public_key_b58
    assert not tx.verify_signature()


def test_to_dict_from_dict_roundtrip():
    alice = KernKeypair.generate()
    tx = make_transfer(alice, recipient="kn1" + "0" * 33, amount=42, nonce=7)
    d = tx.to_dict()
    tx2 = Transaction.from_dict(d)
    assert tx2.to_dict() == d
    assert tx2.verify_signature()


def test_originate_transaction():
    alice = KernKeypair.generate()
    code = "contract X { storage { count: int, } invariant nn { count >= 0 } entry tick() { count = count + 1; } }"
    tx = make_origination(alice, code=code, initial_storage={"count": 0}, nonce=0)
    assert tx.verify_signature()
    assert tx.kind == OpKind.ORIGINATE


def test_call_transaction():
    alice = KernKeypair.generate()
    tx = make_call(alice, contract="kn1XYZ", entry="tick", params={}, nonce=1)
    assert tx.verify_signature()
    assert tx.kind == OpKind.CALL


if __name__ == "__main__":
    test_transfer_sign_and_verify()
    test_signature_does_not_cover_signature_field()
    test_tampering_invalidates_signature()
    test_wrong_sender_pubkey_invalidates()
    test_to_dict_from_dict_roundtrip()
    test_originate_transaction()
    test_call_transaction()
    print("All transaction tests passed.")
