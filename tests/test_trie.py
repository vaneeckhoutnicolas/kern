# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.trie — binary Merkle trie with proofs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.trie import (
    MerkleTrie,
    Proof,
    address_to_key,
    decode_account,
    encode_account,
    make_account,
    state_root_trie_hex,
    trie_from_state,
    verify_proof,
)


def test_empty_trie_has_deterministic_root():
    a = MerkleTrie()
    b = MerkleTrie()
    assert a.root_hex() == b.root_hex()


def test_single_set_get():
    t = MerkleTrie()
    key = address_to_key("kn1alice")
    t.set(key, b"hello")
    assert t.get(key) == b"hello"


def test_get_missing_returns_none():
    t = MerkleTrie()
    t.set(address_to_key("kn1alice"), b"a")
    assert t.get(address_to_key("kn1bob")) is None


def test_overwrite_replaces_value():
    t = MerkleTrie()
    key = address_to_key("kn1alice")
    t.set(key, b"v1")
    root1 = t.root_hex()
    t.set(key, b"v2")
    assert t.get(key) == b"v2"
    assert t.root_hex() != root1


def test_root_depends_on_contents():
    t1 = MerkleTrie()
    t1.set(address_to_key("kn1alice"), b"a")
    t2 = MerkleTrie()
    t2.set(address_to_key("kn1bob"), b"a")
    assert t1.root_hex() != t2.root_hex()


def test_root_independent_of_insertion_order():
    """Same set of (key, value) pairs → same root, regardless of insertion order."""
    pairs = [(address_to_key(f"kn1{i:03d}"), f"v{i}".encode()) for i in range(20)]
    t1 = MerkleTrie()
    for k, v in pairs:
        t1.set(k, v)
    t2 = MerkleTrie()
    for k, v in reversed(pairs):
        t2.set(k, v)
    assert t1.root_hex() == t2.root_hex()


def test_many_inserts():
    """Insert 100 distinct entries; verify all are retrievable."""
    t = MerkleTrie()
    pairs = [(address_to_key(f"kn1user{i:04d}"), f"value{i}".encode()) for i in range(100)]
    for k, v in pairs:
        t.set(k, v)
    for k, v in pairs:
        assert t.get(k) == v


def test_proof_round_trip_single():
    t = MerkleTrie()
    key = address_to_key("kn1alice")
    t.set(key, b"alice's value")
    proof = t.prove(key)
    assert proof.value == b"alice's value"
    assert verify_proof(t.root_hex(), proof)


def test_proof_round_trip_many():
    t = MerkleTrie()
    pairs = [(address_to_key(f"kn1user{i:04d}"), f"value{i}".encode()) for i in range(50)]
    for k, v in pairs:
        t.set(k, v)
    root = t.root_hex()
    for k, v in pairs:
        proof = t.prove(k)
        assert proof.value == v
        assert verify_proof(root, proof), f"proof for {k.hex()} failed"


def test_proof_rejects_wrong_value():
    """Tampering with the proof's value should make verification fail."""
    t = MerkleTrie()
    key = address_to_key("kn1alice")
    t.set(key, b"original")
    proof = t.prove(key)
    proof.value = b"tampered"
    assert not verify_proof(t.root_hex(), proof)


def test_proof_rejects_wrong_sibling():
    t = MerkleTrie()
    for i in range(10):
        t.set(address_to_key(f"kn1u{i}"), f"v{i}".encode())
    key = address_to_key("kn1u5")
    proof = t.prove(key)
    if proof.siblings:
        proof.siblings[0] = b"\xff" * 32
        assert not verify_proof(t.root_hex(), proof)


def test_proof_serialization_round_trip():
    t = MerkleTrie()
    for i in range(10):
        t.set(address_to_key(f"kn1u{i}"), f"v{i}".encode())
    proof = t.prove(address_to_key("kn1u3"))
    blob = proof.serialize()
    proof2 = Proof.deserialize(blob)
    assert verify_proof(t.root_hex(), proof2)


def test_proof_for_missing_key_raises():
    t = MerkleTrie()
    t.set(address_to_key("kn1alice"), b"a")
    with pytest.raises(KeyError):
        t.prove(address_to_key("kn1bob"))


def test_account_helpers():
    t = MerkleTrie()
    acc = make_account(balance=1_000_000, nonce=3)
    t.set_account("kn1alice", acc)
    got = t.get_account("kn1alice")
    assert got["balance"] == 1_000_000
    assert got["nonce"] == 3
    assert got["code_hash"] is None


def test_account_proof():
    t = MerkleTrie()
    t.set_account("kn1alice", make_account(balance=100, nonce=1))
    t.set_account("kn1bob", make_account(balance=200, nonce=2))
    t.set_account("kn1carol", make_account(balance=300, nonce=0))

    proof, account = t.prove_account("kn1bob")
    assert account["balance"] == 200
    assert verify_proof(t.root_hex(), proof)


def test_encode_decode_roundtrip():
    acc = make_account(balance=42, nonce=7, code_hash="aabb", storage_root="ccdd")
    blob = encode_account(acc)
    back = decode_account(blob)
    assert back == acc


def test_trie_from_state_basic():
    """Building a trie from a chain state and querying matches expectations."""
    state = {
        "balances": {"kn1alice": 1000, "kn1bob": 2000},
        "nonces": {"kn1alice": 5},
        "contracts": {},
        "validators": [],
    }
    trie = trie_from_state(state)
    alice = trie.get_account("kn1alice")
    assert alice["balance"] == 1000
    assert alice["nonce"] == 5
    bob = trie.get_account("kn1bob")
    assert bob["balance"] == 2000
    assert bob["nonce"] == 0  # not set


def test_trie_root_changes_with_state():
    s1 = {"balances": {"kn1a": 1}, "nonces": {}, "contracts": {}, "validators": []}
    s2 = {"balances": {"kn1a": 2}, "nonces": {}, "contracts": {}, "validators": []}
    assert state_root_trie_hex(s1) != state_root_trie_hex(s2)


def test_trie_proof_for_state():
    """End-to-end: given just (state_root, address, proof, account), a
    light client can verify the account's balance without seeing the
    rest of the state."""
    state = {
        "balances": {f"kn1u{i:03d}": i * 100 for i in range(50)},
        "nonces": {},
        "contracts": {},
        "validators": [],
    }
    trie = trie_from_state(state)
    root = trie.root_hex()

    target = "kn1u017"
    proof, account = trie.prove_account(target)
    assert account["balance"] == 1700
    assert verify_proof(root, proof)

    # Now imagine the light client only knows root, target, proof.
    # They can verify that account["balance"] == 1700 at this state.
    serialized = proof.serialize()
    redeserialized = Proof.deserialize(serialized)
    assert verify_proof(root, redeserialized)


def test_state_root_trie_equals_root_hex_of_built_trie():
    state = {
        "balances": {"kn1a": 1, "kn1b": 2, "kn1c": 3},
        "nonces": {"kn1a": 1},
        "contracts": {},
        "validators": [],
    }
    assert state_root_trie_hex(state) == trie_from_state(state).root_hex()


def test_root_is_32_bytes():
    t = MerkleTrie()
    t.set(address_to_key("kn1a"), b"v")
    root = t.root_hex()
    assert len(bytes.fromhex(root)) == 32


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} trie tests passed.")
