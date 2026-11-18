# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The reference vectors of the signature profile are what the note says.

docs/hybrid-signatures.md specifies the release in preparation byte for
byte: canonical JSON, the hash function, Merkle trees, key derivation,
signing contexts, text forms, addresses, the leaves of the second root of
a block, the state trie and the state root, the data hashed under every
domain, and one rule for the verification of Ed25519. Before any of it is
implemented in the node, the specification is held by vectors that two
independent implementations reproduce: tests/profile_reference.py and
tests/ed25519_reference.py (Python standard library, checked here), and
tests/vectors/kern/profile_check.go (Go standard library, run by the
continuous integration on every pull request).

The two programs also exchange composite signatures, kept in
tests/vectors/kern/composite_signatures.json. The Go program verifies them
whole, and so does tests/test_composite.py with kern.composite. What is
checked here needs no ML-DSA: the message both components sign and the
Ed25519 half, with the references alone.

Nothing below touches the node: it still hashes with BLAKE2b and signs
with Ed25519.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
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
SIGNED = json.loads(ref.SIGNATURES.read_text(encoding="utf-8"))
CASES = json.loads(ed.CASES.read_text(encoding="utf-8"))["cases"]
NETWORK = bytes.fromhex(VECTORS["network_id"])
OTHER = bytes(range(0xC0, 0xE0))
H = bytes.fromhex

# The three values of each derivation that need ML-DSA. The `cryptography`
# package computes them when the vectors are built, and here; the Go program
# computes them with crypto/mldsa, and tests/test_keys.py with kern.keys.
NEEDS_MLDSA = {"mldsa65_public_key_sha3_384", "composite_public_key_sha3_384", "address"}


# ---------------------------------------------------------------------------
# The file is what the reference computes
# ---------------------------------------------------------------------------

def test_every_vector_is_recomputed_by_the_reference():
    assert VECTORS == json.loads(json.dumps(ref.build_vectors()))
    for d in VECTORS["derivation"]:
        assert NEEDS_MLDSA <= set(d)


def test_the_ed25519_cases_are_rebuilt_from_rfc_8032():
    rebuilt = ed.build_cases()
    assert [{k: c[k] for k in ("name", "public_key", "message", "signature", "comment")} for c in CASES] == rebuilt
    assert len(CASES) == 31 == len({c["name"] for c in CASES})
    # The public keys under rule 2 alone, added to the file after the freeze: an ordinary
    # key, and that key plus each of the seven points of small order other than the identity.
    keys = json.loads(ed.CASES.read_text(encoding="utf-8"))["public_keys"]
    assert [{k: c[k] for k in ("name", "public_key", "comment")} for c in keys] == ed.build_key_cases()
    assert [c["valid"] for c in keys] == [ed.is_a_key(H(c["public_key"])) for c in keys] == [True] + [False] * 7


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
# What is hashed under the other domains, byte for byte
# ---------------------------------------------------------------------------

def test_the_proposer_draw_is_eight_bytes_of_the_hash_of_the_parent_and_the_round():
    for entry in VECTORS["proposer"]:
        parent, round_ = H(entry["parent_hash"]), entry["round"]
        data = parent + round_.to_bytes(4, "big")                       # 48 bytes, then the round on 4 bytes
        assert data.hex() == entry["data"] and len(data) == 52
        draw = int.from_bytes(ref.H("kern.proposer", NETWORK, data)[:8], "big")
        assert str(draw) == entry["draw"] == str(ref.proposer_draw(NETWORK, parent, round_))
    assert [e["round"] for e in VECTORS["proposer"]] == [0, 1, 258, 2**32 - 1]
    assert len({e["draw"] for e in VECTORS["proposer"]}) == 4
    parent = H(VECTORS["proposer"][0]["parent_hash"])
    assert ref.proposer_draw(OTHER, parent, 0) != ref.proposer_draw(NETWORK, parent, 0)
    for bad_parent, bad_round in ((parent[:47], 0), (parent, -1), (parent, 2**32)):
        with pytest.raises(ValueError):
            ref.proposer_draw(NETWORK, bad_parent, bad_round)


def test_a_contract_address_is_the_hash_of_its_origination_under_its_own_domain():
    c = VECTORS["contract_address"]
    tx_id = H(c["transaction_id"])
    digest = ref.H("kern.addr.contract", NETWORK, tx_id)
    assert digest.hex() == c["hash"]
    assert ref.contract_address(NETWORK, tx_id) == c["address"] == ref.address_from_hash(NETWORK, digest)
    assert len(c["address"]) == 75 and c["address"].startswith("kn1")
    # Not the domain of accounts: the same bytes hashed as a key give another address.
    assert ref.address_from_hash(NETWORK, ref.H("kern.addr", NETWORK, tx_id)) != c["address"]
    assert ref.contract_address(OTHER, tx_id) != c["address"]
    with pytest.raises(ValueError):
        ref.contract_address(NETWORK, tx_id[:47])


def test_the_addresses_of_the_mini_evm_are_twenty_bytes_of_a_hash_of_kern():
    e = VECTORS["evm"]
    creator, salt, code = H(e["creator"]), H(e["salt"]), H(e["creation_code"])
    assert (len(creator), len(salt), e["nonce"]) == (20, 32, 258)
    # CREATE: the creator on 20 bytes, then its nonce on 8 bytes.
    create = ref.H("kern.evm.create", NETWORK, creator + (258).to_bytes(8, "big"))[:20]
    assert create.hex() == e["create"] == ref.evm_create_address(NETWORK, creator, 258).hex()
    # CREATE2: the creator, the salt on 32 bytes, then the hash of the creation code, 48 bytes.
    code_hash = ref.H("kern.evm.code", NETWORK, code)
    assert code_hash.hex() == e["code_hash"] and len(code_hash) == 48
    create2 = ref.H("kern.evm.create2", NETWORK, creator + salt + code_hash)[:20]
    assert create2.hex() == e["create2"] == ref.evm_create2_address(NETWORK, creator, salt, code).hex()
    # Another nonce, salt, code or network: another address.
    assert len({create, create2, ref.evm_create_address(NETWORK, creator, 259),
                ref.evm_create_address(OTHER, creator, 258),
                ref.evm_create2_address(NETWORK, creator, salt[::-1], code),
                ref.evm_create2_address(NETWORK, creator, salt, code + b"\x00")}) == 6
    for bad in ((creator[:19], 0), (creator, -1), (creator, 2**64)):
        with pytest.raises(ValueError):
            ref.evm_create_address(NETWORK, *bad)
    with pytest.raises(ValueError):
        ref.evm_create2_address(NETWORK, creator, salt[:31], code)
    # Precompile 0x01 returns twenty bytes for the Ed25519 key it verified: a hash under a
    # domain of the Mini-EVM, not the address of an account, whose key is composite.
    key = H(e["signer_public_key"])
    assert e["signer_public_key"] == VECTORS["derivation"][0]["ed25519_standalone_public_key"]
    signer = ref.H("kern.evm.signer", NETWORK, key)[:20]
    assert signer.hex() == e["signer"] == ref.evm_signer_address(NETWORK, key).hex()
    assert signer != ref.H("kern.addr", NETWORK, key)[:20] and signer != ref.H("kern.addr", NETWORK, b"\x01" + key)[:20]
    assert ref.evm_signer_address(OTHER, key) != signer
    with pytest.raises(ValueError):
        ref.evm_signer_address(NETWORK, key + b"\x00")


@pytest.mark.parametrize("entry", VECTORS["objects"], ids=lambda e: e["domain"])
def test_an_object_is_hashed_as_its_canonical_json(entry):
    encoding = H(entry["encoding"])
    assert ref.canonical_json(entry["object"]) == encoding
    assert ref.decode_canonical(encoding) == entry["object"]
    assert ref.H(entry["domain"], NETWORK, encoding).hex() == entry["digest"]


def test_the_header_example_has_the_nine_fields_of_the_note():
    (header,) = [e["object"] for e in VECTORS["objects"] if e["domain"] == "kern.block"]
    assert sorted(header) == sorted(["version", "level", "payload_round", "timestamp", "parent_hash",
                                     "state_root", "txs_root", "witness_root", "proposer"])
    assert header["version"] == 1
    for name in ("parent_hash", "state_root", "txs_root", "witness_root"):
        assert re.fullmatch(r"[0-9a-f]{96}", header[name]), name
    for name in sorted(header):
        assert f"`{name}`" in NOTE, name


def _bits(key: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in key)


def test_a_trie_leaf_states_how_many_bits_of_its_key_it_holds():
    account = VECTORS["trie"]["accounts"][0]
    key, value = H(account["position"]), H(account["value"])
    bits = _bits(key)
    assert [leaf["depth"] for leaf in VECTORS["trie"]["leaves"]] == list(ref.LEAF_DEPTHS)
    for leaf in VECTORS["trie"]["leaves"]:
        depth = leaf["depth"]
        left = bits[depth:]                                             # the bits of the key that are left
        packed = int(left.ljust(-(-len(left) // 8) * 8, "0") or "0", 2).to_bytes(-(-len(left) // 8), "big")
        data = len(left).to_bytes(2, "big") + packed + len(value).to_bytes(4, "big") + value
        assert ref.H("kern.trie.leaf", NETWORK, data).hex() == leaf["digest"], depth
        assert ref.trie_leaf(NETWORK, key, depth, value).hex() == leaf["digest"]
    assert len({leaf["digest"] for leaf in VECTORS["trie"]["leaves"]}) == len(ref.LEAF_DEPTHS)
    # At depth 0 the leaf holds the whole key; at depth 384 it holds no bit.
    assert ref.trie_leaf(NETWORK, key, 0, value) == ref.H(
        "kern.trie.leaf", NETWORK, (384).to_bytes(2, "big") + key + len(value).to_bytes(4, "big") + value)
    assert ref.trie_leaf(NETWORK, key, 384, value) == ref.H(
        "kern.trie.leaf", NETWORK, bytes(2) + len(value).to_bytes(4, "big") + value)
    # The number of bits is hashed, not the number of bytes: "1" and "10" fill the
    # same byte, 0x80, and are two leaves.
    one, one_zero = bytes(47) + b"\x01", bytes(47) + b"\x02"
    assert _bits(one)[383:] == "1" and _bits(one_zero)[382:] == "10"
    assert ref.trie_leaf(NETWORK, one, 383, value) != ref.trie_leaf(NETWORK, one_zero, 382, value)
    for bad_key, bad_depth in ((key[:47], 0), (key, -1), (key, 385)):
        with pytest.raises(ValueError):
            ref.trie_leaf(NETWORK, bad_key, bad_depth, value)


def _two_entries_by_hand(first: tuple[bytes, bytes], second: tuple[bytes, bytes]) -> bytes:
    """The root of a trie of two entries, built from the bottom: the two
    leaves under the branch where their keys part, then one branch with a
    single child for every bit they share."""
    a, b = _bits(first[0]), _bits(second[0])
    shared = next(i for i in range(384) if a[i] != b[i])
    leaves = {a[shared]: ref.trie_leaf(NETWORK, first[0], shared + 1, first[1]),
              b[shared]: ref.trie_leaf(NETWORK, second[0], shared + 1, second[1])}
    node = ref.H("kern.trie.branch", NETWORK, leaves["0"] + leaves["1"])
    for i in range(shared - 1, -1, -1):
        node = ref.H("kern.trie.branch", NETWORK, node + bytes(48) if a[i] == "0" else bytes(48) + node)
    return node


def test_the_state_trie_has_one_shape_for_one_set_of_accounts():
    trie = VECTORS["trie"]
    entries = [(H(a["position"]), H(a["value"])) for a in trie["accounts"]]
    for account in trie["accounts"]:
        assert ref.trie_key(NETWORK, account["address"]).hex() == account["position"]
        assert ref.canonical_json(account["object"]).hex() == account["value"]
        assert len(account["address"]) == 75 and len(H(account["position"])) == 48
    assert [r["accounts"] for r in trie["roots"]] == [0, 1, 2, 3, 4]
    for r in trie["roots"]:
        assert ref.trie_node(NETWORK, entries[:r["accounts"]]).hex() == r["root"]
    assert trie["roots"][0]["root"] == "00" * 48                           # no account: 48 zero bytes
    assert trie["roots"][1]["root"] == ref.trie_leaf(NETWORK, entries[0][0], 0, entries[0][1]).hex()   # one: a leaf
    assert len({r["root"] for r in trie["roots"]}) == 5
    # A branch is the hash of its two children; an empty child is 48 zero bytes.
    branch = trie["branch"]
    assert ref.H("kern.trie.branch", NETWORK, H(branch["left"]) + H(branch["right"])).hex() == branch["digest"]
    assert branch["right"] == "00" * 48
    # Two entries, every pair, against a tree built by hand from the bottom.
    for i in range(4):
        for j in range(i + 1, 4):
            assert ref.trie_node(NETWORK, [entries[i], entries[j]]) == _two_entries_by_hand(entries[i], entries[j])
    # The vectors hold a pair whose keys share more than their first byte: it sits
    # under at least nine branches with a single child.
    shared = max(next(k for k in range(384) if _bits(entries[i][0])[k] != _bits(entries[j][0])[k])
                 for i in range(4) for j in range(i + 1, 4))
    assert shared >= 9
    # The order in which the accounts are given changes nothing.
    root = ref.trie_node(NETWORK, entries)
    shuffled = list(entries)
    for seed in range(5):
        random.Random(seed).shuffle(shuffled)
        assert ref.trie_node(NETWORK, shuffled) == root
    assert ref.trie_node(OTHER, entries) != root
    with pytest.raises(ValueError):
        ref.trie_node(NETWORK, [entries[0], (entries[0][0], b"another value")])


def test_the_state_root_covers_every_field_of_the_state_with_both_functions():
    as_json, as_trie, other_stake = VECTORS["state"][:3]
    for entry in VECTORS["state"]:
        hashed = ref.canonical_json(ref.hashed_state(NETWORK, entry["state"]))
        assert hashed.hex() == entry.get("hashed", hashed.hex())           # given for the states without a registry
        assert ref.H("kern.state", NETWORK, hashed).hex() == entry["root"]
        assert ref.state_root(NETWORK, entry["state"]).hex() == entry["root"]
    assert len(VECTORS["state"]) == 9 == len({entry["root"] for entry in VECTORS["state"]})
    assert all("hashed" in entry for entry in VECTORS["state"][:3])
    # With the function json, the object that is hashed is the state, whole.
    state = as_json["state"]
    assert state["state_root_function"] == "json" and ref.hashed_state(NETWORK, state) == state
    # With the function trie, the three maps keyed by address become one root, and
    # every other field stays.
    state = as_trie["state"]
    hashed = ref.hashed_state(NETWORK, state)
    assert set(hashed) == (set(state) - {"balances", "nonces", "contracts"}) | {"accounts_root"}
    assert all(hashed[name] == state[name] for name in hashed if name != "accounts_root")
    assert hashed["accounts_root"] == VECTORS["trie"]["roots"][4]["root"] == ref.accounts_root(NETWORK, state).hex()
    # A field outside the accounts changes the root with both functions.
    assert other_stake["state"]["validators"] != state["validators"]
    assert ref.accounts_root(NETWORK, other_stake["state"]) == ref.accounts_root(NETWORK, state)
    assert other_stake["root"] != as_trie["root"]
    for function in ("json", "trie"):
        base = dict(state, state_root_function=function)
        roots = {ref.state_root(NETWORK, base),
                 ref.state_root(NETWORK, dict(base, total_supply=base["total_supply"] + 1)),
                 ref.state_root(NETWORK, dict(base, validators=[])),
                 ref.state_root(NETWORK, dict(base, a_new_field={"x": 1})),
                 ref.state_root(NETWORK, dict(base, balances={**base["balances"], "kn1new": 1})),
                 ref.state_root(OTHER, base)}
        assert len(roots) == 6, function
    # The state names its function, and the name is hashed with the rest.
    for bad in ({k: v for k, v in state.items() if k != "state_root_function"},
                dict(state, state_root_function="other")):
        with pytest.raises(ValueError):
            ref.state_root(NETWORK, bad)


def test_a_change_in_the_key_registry_changes_the_state_root_with_both_functions():
    """The registry is what the rule of section 4.6 was written for: the key
    that is current for an address, the keys it had before, and the level
    from which each was current."""
    import base64

    patterns = [bytes((m * i + c) % 256 for i in range(1984)) for m, c in ((7, 3), (11, 5), (13, 7))]
    first, rotated, another = (ref.key_text(key) for key in patterns)
    by_function = {"json": VECTORS["state"][3:6], "trie": VECTORS["state"][6:9]}
    for function, (base, later, other_key) in by_function.items():
        states = [entry["state"] for entry in (base, later, other_key)]
        assert all(state["state_root_function"] == function for state in states)
        (address,) = states[0]["keys"]
        # A first key, then the key a rotation gave, current from the level after its block.
        assert states[0]["keys"][address] == [{"from": 0, "public_key": first}, {"from": 121, "public_key": rotated}]
        assert states[1]["keys"][address] == [{"from": 0, "public_key": first}, {"from": 122, "public_key": rotated}]
        assert states[2]["keys"][address] == [{"from": 0, "public_key": first}, {"from": 121, "public_key": another}]
        # Nothing else differs between the three states, and each has its own root.
        assert all({k: v for k, v in state.items() if k != "keys"} ==
                   {k: v for k, v in states[0].items() if k != "keys"} for state in states)
        assert len({base["root"], later["root"], other_key["root"]}) == 3
        for state in states:
            hashed = ref.hashed_state(NETWORK, state)
            assert hashed["keys"] == state["keys"]                        # hashed as it is, with both functions
            assert ("accounts_root" in hashed) == (function == "trie")
        # The registry is not in the trie: the root of the accounts does not move, the state root does.
        assert len({ref.accounts_root(NETWORK, state) for state in states}) == 1
        # Without the registry the root is the one of the first vectors: the registry is what changed it.
        bare = {k: v for k, v in states[0].items() if k != "keys"}
        assert ref.state_root(NETWORK, bare).hex() == VECTORS["state"][0 if function == "json" else 1]["root"]
        assert ref.state_root(NETWORK, bare).hex() != base["root"]
    # The same registry with the two functions: two roots.
    assert by_function["json"][0]["root"] != by_function["trie"][0]["root"]
    # A public key in the registry is its text: kpk1. and 1,984 bytes in base64url without padding.
    for text, key in zip((first, rotated, another), patterns):
        assert len(text) == 2651 and text.startswith("kpk1.") and "=" not in text
        assert base64.urlsafe_b64decode(text[5:] + "==") == key
    with pytest.raises(ValueError):
        ref.key_text(patterns[0][:-1])
    assert "kpk1." in VECTORS["state_registry_rule"] and "`kpk1.`" in NOTE


def test_an_account_of_the_trie_is_a_balance_a_nonce_and_for_a_contract_two_hashes():
    state = VECTORS["state"][0]["state"]
    by_address = {a["address"]: a["object"] for a in VECTORS["trie"]["accounts"]}
    assert set(by_address) == set(state["balances"]) | set(state["nonces"]) | set(state["contracts"])
    (contract,) = state["contracts"]
    for address, account in by_address.items():
        assert account == ref.account_object(NETWORK, state, address)
        assert account["balance"] == state["balances"].get(address, 0)      # absent from a map: zero
        assert account["nonce"] == state["nonces"].get(address, 0)
        assert set(account) == ({"balance", "nonce", "code_hash", "storage_root"} if address == contract
                                else {"balance", "nonce"})
    entry = state["contracts"][contract]
    assert by_address[contract]["code_hash"] == ref.H("kern.code", NETWORK, entry["code"].encode()).hex()
    assert by_address[contract]["storage_root"] == ref.H(
        "kern.storage", NETWORK, ref.canonical_json(entry["storage"])).hex()
    (code,) = [h for h in VECTORS["hash"] if h["domain"] == "kern.code"]
    assert code["digest"] == by_address[contract]["code_hash"]


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
# Composite signatures made by two programs
# ---------------------------------------------------------------------------

MLDSA_KEY, MLDSA_SIG = ref.MLDSA_PUBLIC_KEY_BYTES, ref.MLDSA_SIGNATURE_BYTES

# The cases of `invalid` whose Ed25519 half is right: only their ML-DSA half
# refuses them. The Go program checks that; the node will once it has ML-DSA.
WRONG_IN_MLDSA_ONLY = {
    "ML-DSA part of another message, Ed25519 part right",
    "one bit changed in the ML-DSA part",
    "ML-DSA part signed with an empty ML-DSA context instead of the Label",
}


def _ed25519_half_is_valid(public_key: bytes, message: bytes, signature: bytes, context: bytes) -> bool:
    """What can be checked of a composite signature without ML-DSA: the
    lengths, the message both components sign, and the Ed25519 component
    under the rule of section 2.5."""
    if len(public_key) != ref.PUBLIC_KEY_BYTES or len(signature) != ref.SIGNATURE_BYTES:
        return False
    return _rule_over_libsodium(public_key[MLDSA_KEY:], ref.message_representative(message, context),
                                signature[MLDSA_SIG:])


def test_both_components_sign_the_message_representative_of_rfc_10073():
    context = ref.signing_context("kern.tx", NETWORK)
    message = H(SIGNED["message"])
    representative = ref.message_representative(message, context)
    assert representative == (b"CompositeAlgorithmSignatures2025" + b"COMPSIG-MLDSA65-Ed25519-SHA512"
                              + bytes([len(context)]) + context + hashlib.sha512(message).digest())
    assert len(representative) == 32 + 30 + 1 + 40 + 64
    assert ref.message_representative(message, b"") == (ref.PREFIX + ref.LABEL + b"\x00"
                                                        + hashlib.sha512(message).digest())
    assert ref.message_representative(message, bytes(255))[62] == 255
    with pytest.raises(ValueError):
        ref.message_representative(message, bytes(256))
    for stated in ("CompositeAlgorithmSignatures2025", "COMPSIG-MLDSA65-Ed25519-SHA512"):
        assert stated in NOTE


def test_the_signed_key_is_the_one_of_the_derivation_vectors():
    derivation = VECTORS["derivation"][0]
    assert (SIGNED["seed"], SIGNED["network_id"]) == (derivation["seed"], derivation["network_id"])
    public_key = H(SIGNED["public_key"])
    assert len(public_key) == 1984
    assert public_key[MLDSA_KEY:].hex() == derivation["ed25519_public_key"]
    assert hashlib.sha3_384(public_key[:MLDSA_KEY]).hexdigest() == derivation["mldsa65_public_key_sha3_384"]
    assert hashlib.sha3_384(public_key).hexdigest() == derivation["composite_public_key_sha3_384"]
    assert ref.account_address(NETWORK, public_key) == derivation["address"]


@pytest.mark.parametrize("maker", ["python", "go"])
def test_signatures_of_both_programs_have_a_valid_ed25519_half_in_their_context_only(maker):
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    assert [c["purpose"] for c in SIGNED[maker]] == list(ref.PURPOSES)
    for c in SIGNED[maker]:
        signature = H(c["signature"])
        assert len(signature) == 3373
        assert _ed25519_half_is_valid(public_key, message, signature, ref.signing_context(c["purpose"], NETWORK))
        for other in ref.PURPOSES:
            if other != c["purpose"]:
                assert not _ed25519_half_is_valid(public_key, message, signature, ref.signing_context(other, NETWORK))
        assert not _ed25519_half_is_valid(public_key, message, signature, ref.signing_context(c["purpose"], OTHER))
        assert not _ed25519_half_is_valid(public_key, message + b" ", signature,
                                          ref.signing_context(c["purpose"], NETWORK))
    # One of them with the arithmetic of RFC 8032 and no library.
    first = SIGNED[maker][0]
    representative = ref.message_representative(message, ref.signing_context(first["purpose"], NETWORK))
    assert ed.strict_verify(public_key[MLDSA_KEY:], representative, H(first["signature"])[MLDSA_SIG:])
    # Ed25519 is deterministic: both programs give the same half for the same message. The
    # ML-DSA halves differ, since one program signs in the randomized mode.
    for mine, theirs in zip(SIGNED["python"], SIGNED["go"]):
        assert mine["signature"][2 * MLDSA_SIG:] == theirs["signature"][2 * MLDSA_SIG:]
        assert mine["signature"][:2 * MLDSA_SIG] != theirs["signature"][:2 * MLDSA_SIG]
    assert len({c["signature"] for c in SIGNED["python"] + SIGNED["go"]}) == 14


def test_what_a_verifier_must_refuse_is_refused_as_far_as_ed25519_tells():
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    context = ref.signing_context("kern.tx", NETWORK)
    passing = set()
    for c in SIGNED["invalid"]:
        key = H(c["public_key"]) if "public_key" in c else public_key
        if _ed25519_half_is_valid(key, message, H(c["signature"]), context):
            passing.add(c["why"])
    assert passing == WRONG_IN_MLDSA_ONLY
    reasons = [c["why"] for c in SIGNED["invalid"]]
    assert len(reasons) == 17 == len(set(reasons))
    # The case of section 2.5: a key whose Ed25519 part is the point of order 1, with
    # the signature a verifier that only follows RFC 8032 accepts for it.
    (case,) = [c for c in SIGNED["invalid"] if c["why"].startswith("Ed25519 public key of order 1")]
    key, signature = H(case["public_key"]), H(case["signature"])
    representative = ref.message_representative(message, context)
    assert ed.lenient_verify(key[MLDSA_KEY:], representative, signature[MLDSA_SIG:])
    assert not ed.strict_verify(key[MLDSA_KEY:], representative, signature[MLDSA_SIG:])
    assert key[:MLDSA_KEY] == public_key[:MLDSA_KEY]                       # the ML-DSA part is the right one


# ---------------------------------------------------------------------------
# Text forms
# ---------------------------------------------------------------------------

TEXT_KINDS = {
    "public_key": ("kpk1.", ref.PUBLIC_KEY_BYTES, 2651, ref.key_text, ref.key_from_text),
    "signature": ("ksig1.", ref.SIGNATURE_BYTES, 4504, ref.signature_text, ref.signature_from_text),
}
BASE64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_a_key_and_a_signature_have_one_text():
    forms = VECTORS["text_forms"]
    assert [e["kind"] for e in forms["accepted"]] == ["public_key"] * 4 + ["signature"] * 4
    for entry in forms["accepted"]:
        prefix, size, characters, encode, decode = TEXT_KINDS[entry["kind"]]
        data = bytes((entry["factor"] * i + entry["offset"]) % 256 for i in range(size))
        text = entry["text"]
        assert encode(data) == text and decode(text) == data
        assert len(text) == characters and text.startswith(prefix) and set(text[len(prefix):]) <= BASE64URL
    # The last character holds two bits of the last byte, then four unused bits that are
    # zero: it is A, Q, g or w, and the accepted texts of each kind show the four.
    for kind in TEXT_KINDS:
        assert sorted(e["text"][-1] for e in forms["accepted"] if e["kind"] == kind) == list("AQgw")
    # The first text of each kind is the one of the bytes used elsewhere in the vectors.
    assert (forms["accepted"][0]["factor"], forms["accepted"][0]["offset"]) == (7, 3)
    assert (forms["accepted"][4]["factor"], forms["accepted"][4]["offset"]) == (5, 1)
    for stated in ("`kpk1.`", "`ksig1.`", "(2,651 characters)", "(4,504 characters)", "**One text per value.**"):
        assert stated in NOTE, stated


def test_every_other_spelling_of_a_key_or_a_signature_is_refused():
    refused = VECTORS["text_forms"]["refused"]
    assert len(refused) == 40 == len({(e["kind"], e["why"]) for e in refused})
    first = {kind: next(e["text"] for e in VECTORS["text_forms"]["accepted"] if e["kind"] == kind)
             for kind in TEXT_KINDS}
    for entry in refused:
        assert entry["text"] != first[entry["kind"]]
        for kind, (_, _, _, _, decode) in TEXT_KINDS.items():     # by the decoder of its kind, and by the other
            with pytest.raises(ValueError):
                decode(entry["text"])
    # What the note names: padding, another alphabet, spaces, a last character whose unused bits are set.
    reasons = {e["why"] for e in refused if e["kind"] == "public_key"}
    assert reasons == {e["why"] for e in refused if e["kind"] == "signature"}
    for named in ("padding added", "the alphabet of standard base64: + and / in place of - and _",
                  "a space at the end", "the last character with one of its four unused bits set"):
        assert named in reasons, named
    # A text that differs from an accepted one in its unused bits only decodes, leniently, to the same bytes.
    for kind, (prefix, _, _, _, decode) in TEXT_KINDS.items():
        (spelling,) = [e["text"] for e in refused if e["kind"] == kind and "unused bits" in e["why"]]
        assert base64.urlsafe_b64decode(spelling[len(prefix):] + "==") == decode(first[kind])


# ---------------------------------------------------------------------------
# The note and the vectors say the same thing
# ---------------------------------------------------------------------------

def test_the_note_states_what_the_vectors_were_computed_with():
    for stated in ("tests/vectors/kern/profile.json", "tests/vectors/kern/ed25519_edge_cases.json",
                   "tests/vectors/kern/composite_signatures.json",
                   "tests/vectors/kern/profile_check.go", "`KERN-KEY-DERIVATION-V1`",
                   "`0x" + ref.ADDRESS_PREFIX.hex() + "`", "SHA3-384( len(domain) || domain || network_id || data )"):
        assert stated in NOTE, stated
    for purpose in ref.PURPOSES:
        assert re.search(rf"^\| `{re.escape(purpose)}` \|", NOTE, re.M), purpose
    for component in ref.COMPONENTS:
        assert f"`{component}`" in NOTE, component
    # Every domain the reference hashes under is in the table of domains of the note.
    table = _domains_of_the_note()
    used = set(re.findall(r'H\("(kern\.[a-z0-9_.]+)"', Path(ref.__file__).read_text(encoding="utf-8")))
    assert used and used <= table, used - table
    assert "31 cases" in NOTE and "16 of them" in NOTE


def _domains_of_the_note() -> set[str]:
    purposes = set(ref.PURPOSES) - {"kern.tx", "kern.batch"}               # two names are both
    return set(re.findall(r"^\| `(kern\.[a-z0-9_.]+)` \|", NOTE, re.M)) - purposes


# Where the vectors exercise a domain without naming it.
DOMAINS_BY_SECTION = {
    "merkle": {"kern.merkle.empty", "kern.merkle.leaf", "kern.merkle.node"},
    "address": {"kern.addr", "kern.checksum"},
    "contract_address": {"kern.addr.contract"},
    "witness": {"kern.witness"},
    "proposer": {"kern.proposer"},
    "evm": {"kern.evm.code", "kern.evm.create", "kern.evm.create2", "kern.evm.signer"},
    "trie": {"kern.trie.key", "kern.trie.leaf", "kern.trie.branch", "kern.code", "kern.storage"},
    "state": {"kern.state"},
}


def test_every_domain_of_the_note_has_a_vector_and_there_is_no_other():
    table = _domains_of_the_note()
    assert len(table) == 27
    exercised = {entry["domain"] for entry in VECTORS["hash"] + VECTORS["objects"]}
    for section, domains in DOMAINS_BY_SECTION.items():
        assert VECTORS[section], section
        exercised |= domains
    assert exercised == table, exercised ^ table
