# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The reference vectors of the signature profile are what the note says.

docs/hybrid-signatures.md specifies the release in preparation byte for
byte: canonical JSON, the hash function, Merkle trees, key derivation,
signing contexts, addresses, the leaves of the second root of a block, and
one rule for the verification of Ed25519. Before any of it is implemented
in the node, the specification is held by vectors that two independent
implementations reproduce: tests/profile_reference.py and
tests/ed25519_reference.py (Python standard library, checked here), and
tests/vectors/kern/profile_check.go (Go standard library, run by hand).

Nothing below touches the node: it still hashes with BLAKE2b and signs
with Ed25519.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import nacl.bindings as sodium
import pytest
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ed25519_reference as ed
import profile_reference as ref

ROOT = Path(__file__).resolve().parent.parent
NOTE = (ROOT / "docs" / "hybrid-signatures.md").read_text(encoding="utf-8")
VECTORS = json.loads(ref.VECTORS.read_text(encoding="utf-8"))
CASES = json.loads(ed.CASES.read_text(encoding="utf-8"))["cases"]
NETWORK = bytes.fromhex(VECTORS["network_id"])
OTHER = bytes(range(0xC0, 0xE0))
H = bytes.fromhex

# The three values of each derivation that need ML-DSA: one implementation
# computed them, and the tests of the implementation will check them.
NEEDS_MLDSA = {"mldsa65_public_key_sha3_384", "composite_public_key_sha3_384", "address"}


def _without_mldsa(vectors: dict) -> dict:
    out = dict(vectors)
    out["derivation"] = [{k: v for k, v in d.items() if k not in NEEDS_MLDSA} for d in vectors["derivation"]]
    return out


# ---------------------------------------------------------------------------
# The file is what the reference computes
# ---------------------------------------------------------------------------

def test_every_vector_is_recomputed_by_the_reference(monkeypatch):
    monkeypatch.setattr(ref, "_with_mldsa", lambda *args: {})          # the node has no ML-DSA yet
    assert _without_mldsa(VECTORS) == json.loads(json.dumps(ref.build_vectors()))
    for d in VECTORS["derivation"]:
        assert NEEDS_MLDSA <= set(d)                                   # present, for the implementation


def test_the_ed25519_cases_are_rebuilt_from_rfc_8032():
    rebuilt = ed.build_cases()
    assert [{k: c[k] for k in ("name", "public_key", "message", "signature", "comment")} for c in CASES] == rebuilt
    assert len(CASES) == 31 == len({c["name"] for c in CASES})


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def test_canonical_json_has_one_encoding_per_value():
    for entry in VECTORS["canonical_json"]:
        encoding = H(entry["encoding"])
        assert ref.canonical_json(entry["value"]) == encoding
        assert ref.decode_canonical(encoding) == entry["value"]
    # Keys are sorted by their UTF-8 bytes, at every depth, and nothing is escaped that need not be.
    assert ref.canonical_json({"b": {"d": 1, "c": 2}, "a": "é/"}) == '{"a":"é/","b":{"c":2,"d":1}}'.encode()


@pytest.mark.parametrize("entry", VECTORS["not_canonical"], ids=lambda e: e["why"])
def test_bytes_that_are_not_the_canonical_encoding_are_refused(entry):
    with pytest.raises(ValueError):
        ref.decode_canonical(H(entry["bytes"]))


@pytest.mark.parametrize("value", [None, 1.5, float("nan"), 2**63, -(2**63) - 1, {"a": None}, [1.0],
                                   "\ud800", {1: 2}, b"bytes", (1, 2)],
                         ids=repr)
def test_values_without_a_canonical_form_are_refused(value):
    with pytest.raises(ValueError):
        ref.canonical_json(value)


# ---------------------------------------------------------------------------
# Hash, Merkle trees
# ---------------------------------------------------------------------------

def test_the_hash_is_sha3_384_of_domain_network_and_data():
    import hashlib

    assert ref.H("kern.tx", NETWORK, b"abc") == hashlib.sha3_384(b"\x07kern.tx" + NETWORK + b"abc").digest()
    assert len(ref.H("kern.tx", NETWORK, b"")) == 48
    # Another domain, another network or another split between the fields: another digest.
    digests = {ref.H("kern.tx", NETWORK, b"abc"), ref.H("kern.block", NETWORK, b"abc"),
               ref.H("kern.tx", OTHER, b"abc"), ref.H("kern.t", NETWORK, b"xabc")}
    assert len(digests) == 4
    for bad in (("", NETWORK), ("k" * 256, NETWORK), ("kern.tx", NETWORK[:31])):
        with pytest.raises(ValueError):
            ref.H(bad[0], bad[1], b"")


def test_the_merkle_tree_is_the_one_of_rfc_6962():
    items = [bytes([i]) * 48 for i in range(8)]
    leaf = lambda x: ref.H("kern.merkle.leaf", NETWORK, x)
    node = lambda a, b: ref.H("kern.merkle.node", NETWORK, a + b)
    root = lambda n: ref.merkle_root(NETWORK, items[:n])
    assert root(0) == ref.H("kern.merkle.empty", NETWORK, b"")
    assert root(1) == leaf(items[0])
    assert root(2) == node(leaf(items[0]), leaf(items[1]))
    # Three items: the left subtree holds two (the largest power of two below three).
    assert root(3) == node(node(leaf(items[0]), leaf(items[1])), leaf(items[2]))
    assert root(5) == node(root(4), leaf(items[4]))
    assert root(6) == node(root(4), node(leaf(items[4]), leaf(items[5])))
    assert len({root(n) for n in range(9)}) == 9
    # Nothing is repeated: a list and the same list with its last item twice have other roots.
    for n in range(1, 8):
        assert ref.merkle_root(NETWORK, items[:n] + [items[n - 1]]) != root(n)
    # A leaf is never taken for a node: an item that is the concatenation of two hashes.
    forged = leaf(items[0]) + leaf(items[1])
    assert ref.merkle_root(NETWORK, [forged]) != root(2)
    assert ref.merkle_root(OTHER, items[:3]) != root(3)


# ---------------------------------------------------------------------------
# Keys, contexts, addresses, witness
# ---------------------------------------------------------------------------

def test_key_derivation_is_hkdf_sha512_with_the_stated_info():
    import hashlib
    import hmac

    seed = bytes(range(32))
    first = VECTORS["derivation"][0]
    assert H(first["prk"]) == hmac.new(bytes(64), seed, hashlib.sha512).digest()
    outputs = {}
    for c in first["components"]:
        info = b"KERN-KEY-DERIVATION-V1" + b"\x01" + NETWORK + c["name"].encode()
        assert H(c["info"]) == info and len(info) == 22 + 1 + 32 + len(c["name"])
        t1 = hmac.new(H(first["prk"]), info + b"\x01", hashlib.sha512).digest()
        assert H(c["output"]) == t1[:32] == ref.derive(seed, NETWORK, c["name"])
        outputs[c["name"]] = t1[:32]
    assert set(outputs) == {"mldsa65", "ed25519", "ed25519-standalone"} and len(set(outputs.values())) == 3
    assert H(first["composite_private"]) == outputs["mldsa65"] + outputs["ed25519"]
    # Another network: other keys, from the same seed and whatever the chain is called.
    second = VECTORS["derivation"][1]
    assert second["prk"] == first["prk"] and second["network_id"] != first["network_id"]
    assert not {c["output"] for c in first["components"]} & {c["output"] for c in second["components"]}
    # The Ed25519 public keys, by a third implementation (libsodium).
    for d in VECTORS["derivation"]:
        by_name = {c["name"]: H(c["output"]) for c in d["components"]}
        assert bytes(SigningKey(by_name["ed25519"]).verify_key).hex() == d["ed25519_public_key"]
        assert bytes(SigningKey(by_name["ed25519-standalone"]).verify_key).hex() == d["ed25519_standalone_public_key"]
        assert d["ed25519_public_key"] != d["ed25519_standalone_public_key"]
    for bad_seed, bad_net, bad_name in ((seed[:31], NETWORK, "ed25519"), (seed, NETWORK[:31], "ed25519"),
                                        (seed, NETWORK, "ed448")):
        with pytest.raises(ValueError):
            ref.derive(bad_seed, bad_net, bad_name)


def test_contexts_are_purpose_zero_byte_network():
    contexts = {c["purpose"]: H(c["context"]) for c in VECTORS["contexts"]}
    assert list(contexts) == ["kern.tx", "kern.header", "kern.propose", "kern.preendorse",
                              "kern.endorse", "kern.batch", "kern.rotate"]
    for purpose, context in contexts.items():
        assert context == purpose.encode() + b"\x00" + NETWORK and len(context) <= 48
        assert ref.signing_context(purpose, OTHER) != context
    assert len(set(contexts.values())) == 7
    for bad in (("kern.consensus", NETWORK), ("kern.tx", NETWORK + b"\x00"), ("", NETWORK)):
        with pytest.raises(ValueError):
            ref.signing_context(*bad)


def test_an_address_is_75_characters_and_belongs_to_one_network():
    key = bytes((7 * i + 3) % 256 for i in range(1984))
    address = ref.account_address(NETWORK, key)
    assert address == VECTORS["address"]["address"]
    assert len(address) == 75 and address.startswith("kn1")
    assert ref.account_address(OTHER, key) == VECTORS["address"]["address_other_network"] != address
    # Whatever the hash, with this prefix: 75 characters that begin with kn1.
    for digest in (bytes(48), b"\xff" * 48):
        text = ref.address_from_hash(NETWORK, digest)
        assert len(text) == 75 and text.startswith("kn1")
    # The checksum is the first four bytes of H("kern.checksum", network, prefix || hash).
    digest = H(VECTORS["address"]["hash"])
    body = bytes.fromhex("7b0339") + digest
    assert address == ref.base58(body + ref.H("kern.checksum", NETWORK, body)[:4])
    assert address != ref.base58(body + ref.H("kern.checksum", OTHER, body)[:4])


def test_the_witness_leaf_covers_the_identifier_the_key_and_every_signature():
    w = VECTORS["witness"]
    tx_id = H(w["transaction_id"])
    key = bytes((7 * i + 3) % 256 for i in range(1984))
    sig = bytes((5 * i + 1) % 256 for i in range(3373))
    second = bytes((3 * i + 2) % 256 for i in range(3373))
    leaves = {                                  # by value of the flags byte
        "0": ref.witness_leaf(NETWORK, tx_id, sig),
        "1": ref.witness_leaf(NETWORK, tx_id, sig, key),
        "2": ref.witness_leaf(NETWORK, tx_id, sig, None, second),
        "3": ref.witness_leaf(NETWORK, tx_id, sig, key, second),
    }
    assert {k: v.hex() for k, v in leaves.items()} == w["leaves_by_flags"] and len(set(leaves.values())) == 4
    assert leaves["0"] == ref.H("kern.witness", NETWORK, tx_id + b"\x00" + sig)
    assert leaves["1"] == ref.H("kern.witness", NETWORK, tx_id + b"\x01" + key + sig)
    assert leaves["2"] == ref.H("kern.witness", NETWORK, tx_id + b"\x02" + sig + second)
    assert leaves["3"] == ref.H("kern.witness", NETWORK, tx_id + b"\x03" + key + sig + second)
    # One byte of a signature, another transaction, another network: another leaf.
    other_sig = bytes([sig[0] ^ 1]) + sig[1:]
    assert ref.witness_leaf(NETWORK, tx_id, other_sig) != leaves["0"]
    assert ref.witness_leaf(NETWORK, tx_id[::-1], sig) != leaves["0"]
    assert ref.witness_leaf(OTHER, tx_id, sig) != leaves["0"]
    with pytest.raises(ValueError):
        ref.witness_leaf(NETWORK, tx_id, sig[:-1])


# ---------------------------------------------------------------------------
# Ed25519: one verdict
# ---------------------------------------------------------------------------

def _rule_over_libsodium(pk: bytes, message: bytes, signature: bytes) -> bool:
    """The rule of section 2.5 with libsodium doing the arithmetic."""
    if len(pk) != 32 or len(signature) != 64:
        return False
    if not sodium.crypto_core_ed25519_is_valid_point(pk):       # canonical, prime order, not the identity
        return False
    if ed.decode_strictly(signature[:32]) in (None, ed.IDENTITY):
        return False
    if int.from_bytes(signature[32:], "little") >= ed.L:
        return False
    try:
        VerifyKey(pk).verify(message, signature)
        return True
    except (CryptoError, ValueError, TypeError):
        return False


def _libsodium_alone(pk: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(pk).verify(message, signature)
        return True
    except (CryptoError, ValueError, TypeError):
        return False


def test_the_ed25519_rule_gives_one_verdict_whoever_computes_it():
    verdicts = {}
    for c in CASES:
        pk, message, signature = H(c["public_key"]), H(c["message"]), H(c["signature"])
        assert ed.strict_verify(pk, message, signature) == c["valid"], c["name"]          # mathematics
        assert _rule_over_libsodium(pk, message, signature) == c["valid"], c["name"]      # a library
        assert ed.lenient_verify(pk, message, signature) == c["lenient"], c["name"]
        verdicts[c["name"]] = (c["valid"], c["lenient"], _libsodium_alone(pk, message, signature))
    # One ordinary signature is valid. A verifier that makes only the checks of RFC 8032
    # accepts sixteen more: the figures of section 2.5.
    assert [name for name, v in verdicts.items() if v[0]] == ["honest"]
    assert sum(v[1] for v in verdicts.values()) == 17
    # The rule is not "what libsodium answers": libsodium accepts a public key of mixed order.
    stricter_than_libsodium = sorted(name for name, v in verdicts.items() if v[2] and not v[0])
    assert stricter_than_libsodium == ["public key and R of mixed order, small parts cancel",
                                       "public key of mixed order, challenge multiple of 8"]
    # Nothing the rule accepts is refused by a verifier that follows RFC 8032.
    assert all(v[1] for v in verdicts.values() if v[0])


def test_the_reference_agrees_with_libsodium_on_ordinary_keys_and_signatures():
    for seed in (bytes(32), bytes(range(32)), b"\xff" * 32):
        key = SigningKey(seed)
        assert ed.public_key(seed) == bytes(key.verify_key)
        for message in (b"", b"kern", b"x" * 200):
            signature = key.sign(message).signature
            assert ed.sign(seed, message) == signature
            assert ed.strict_verify(bytes(key.verify_key), message, signature)
            assert not ed.strict_verify(bytes(key.verify_key), message + b"!", signature)
    points = ed.torsion_points()
    assert [ed.order(p) for p in points] == [1, 2, 4, 4, 8, 8, 8, 8]
    assert sorted({p[1] for p in points}) == sorted({0, 1, ed.P - 1, *(p[1] for p in points if ed.order(p) == 8)})


# ---------------------------------------------------------------------------
# The note and the vectors say the same thing
# ---------------------------------------------------------------------------

def test_the_note_states_what_the_vectors_were_computed_with():
    for stated in ("tests/vectors/kern/profile.json", "tests/vectors/kern/ed25519_edge_cases.json",
                   "tests/vectors/kern/profile_check.go", "`KERN-KEY-DERIVATION-V1`",
                   "`0x" + ref.ADDRESS_PREFIX.hex() + "`", "SHA3-384( len(domain) || domain || network_id || data )"):
        assert stated in NOTE, stated
    for purpose in ref.PURPOSES:
        assert re.search(rf"^\| `{re.escape(purpose)}` \|", NOTE, re.M), purpose
    for component in ref.COMPONENTS:
        assert f"`{component}`" in NOTE, component
    # Every domain the reference hashes under is in the table of domains of the note.
    table = set(re.findall(r"^\| `(kern\.[a-z0-9_.]+)` \|", NOTE, re.M))
    used = set(re.findall(r'H\("(kern\.[a-z0-9_.]+)"', Path(ref.__file__).read_text(encoding="utf-8")))
    assert used and used <= table, used - table
    assert "31 cases" in NOTE and "16 of them" in NOTE
