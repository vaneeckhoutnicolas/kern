# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""kern.keys against the reference vectors of the signature profile.

kern.keys is the profile of docs/hybrid-signatures.md over the mechanism of
kern.composite: one hash function and its domains, canonical JSON, Merkle
trees, key derivation for one network, signing contexts, the text forms of
keys and signatures, addresses. These tests hold it to the vectors of
tests/vectors/kern, which two reference programs already reproduce
(tests/profile_reference.py, and profile_check.go with the Go standard
library), and to what the note says in words: what is refused, and that no
component key is ever handed out.

Nothing in the node uses the module yet.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import profile_reference as ref
from kern import composite, keys

ROOT = Path(__file__).resolve().parent.parent
NOTE = (ROOT / "docs" / "hybrid-signatures.md").read_text(encoding="utf-8")
VECTORS = json.loads(ref.VECTORS.read_text(encoding="utf-8"))
SIGNED = json.loads(ref.SIGNATURES.read_text(encoding="utf-8"))
EDGE = json.loads((ref.VECTORS.parent / "ed25519_edge_cases.json").read_text(encoding="utf-8"))
NETWORK = bytes.fromhex(VECTORS["network_id"])
OTHER = bytes(range(0xC0, 0xE0))
SEED = bytes(range(32))
H = bytes.fromhex
MLDSA_KEY = composite.MLDSA_PUBLIC_KEY_BYTES


def _pattern(size: int, factor: int, offset: int) -> bytes:
    return bytes((factor * i + offset) % 256 for i in range(size))


def _refuses(function, *args) -> bool:
    """True if the call raises ValueError: the way these functions refuse."""
    try:
        function(*args)
    except ValueError:
        return True
    return False


def _table_after(sentence: str) -> list[str]:
    """The names in the first column of the table that follows `sentence`
    in the note."""
    names = []
    for line in NOTE.split(sentence, 1)[1].lstrip("\n").split("\n"):
        if not line.startswith("|"):
            break
        names += re.findall(r"^\| `(kern\.[a-z0-9_.]+)` \|", line)
    return names


# ---------------------------------------------------------------------------
# Sizes and names
# ---------------------------------------------------------------------------

def test_the_sizes_and_the_names_are_those_of_the_note():
    assert (keys.SCHEME, keys.NETWORK_ID_BYTES, keys.SEED_BYTES, keys.HASH_BYTES) == (1, 32, 32, 48)
    assert (keys.PUBLIC_KEY_BYTES, keys.SIGNATURE_BYTES) == (1984, 3373)
    assert (keys.PUBLIC_KEY_TEXT_PREFIX, keys.PUBLIC_KEY_TEXT_CHARACTERS) == ("kpk1.", 2651)
    assert (keys.SIGNATURE_TEXT_PREFIX, keys.SIGNATURE_TEXT_CHARACTERS) == ("ksig1.", 4504)
    assert (keys.ADDRESS_PREFIX, keys.ADDRESS_CHARACTERS) == (bytes.fromhex("7b0339"), 75)
    for stated in ("(2,651 characters)", "(4,504 characters)", "`kpk1.`", "`ksig1.`", "`0x7b0339`",
                   "an address has 75 characters and begins with `kn1`"):
        assert stated in NOTE, stated
    # The seven purposes and the 27 domains, in the order of the tables of the note.
    assert list(keys.PURPOSES) == _table_after("| Purpose | Signed object |\n|---|---|") == list(ref.PURPOSES)
    assert list(keys.BYTE_DOMAINS) == _table_after("Domains whose data is a string of bytes:\n\n"
                                                   "| Domain | Data | What the hash is |\n|---|---|---|")
    assert list(keys.OBJECT_DOMAINS) == _table_after("Domains whose data is an object:\n\n"
                                                     "| Domain | Object | Fields |\n|---|---|---|")
    assert (len(keys.BYTE_DOMAINS), len(keys.OBJECT_DOMAINS), len(keys.DOMAINS)) == (17, 10, 27)
    assert keys.DOMAINS == set(keys.BYTE_DOMAINS) | set(keys.OBJECT_DOMAINS)
    # Every domain the module itself hashes under is one of them.
    used = set(re.findall(r'H\("(kern\.[a-z0-9_.]+)"', Path(keys.__file__).read_text(encoding="utf-8")))
    assert used == {"kern.merkle.empty", "kern.merkle.leaf", "kern.merkle.node",
                    "kern.addr", "kern.addr.contract", "kern.checksum"}
    assert used <= keys.DOMAINS


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def test_canonical_json_is_the_one_of_the_vectors():
    for entry in VECTORS["canonical_json"]:
        encoding = H(entry["encoding"])
        assert keys.canonical_json(entry["value"]) == encoding
        assert keys.decode_canonical(encoding) == entry["value"]
    for entry in VECTORS["objects"]:
        assert keys.canonical_json(entry["object"]) == H(entry["encoding"]), entry["domain"]
        assert keys.decode_canonical(H(entry["encoding"])) == entry["object"]
    assert keys.canonical_json({"b": {"d": 1, "c": 2}, "a": "é/"}) == '{"a":"é/","b":{"c":2,"d":1}}'.encode()


def test_bytes_that_are_not_the_canonical_encoding_are_refused():
    assert len(VECTORS["not_canonical"]) == 24
    for entry in VECTORS["not_canonical"]:
        assert _refuses(keys.decode_canonical, H(entry["bytes"])), entry["why"]
    for not_bytes in ('{"a":1}', None, 5, bytearray(b'{"a":1}'), ["a"]):
        assert _refuses(keys.decode_canonical, not_bytes), not_bytes


def _nested(depth: int, opening: bytes = b"[", closing: bytes = b"]", inside: bytes = b"") -> bytes:
    return opening * depth + inside + closing * depth


def test_arrays_and_objects_are_nested_64_deep_at_most(monkeypatch):
    """A limit of the implementation, which the note does not set: the same
    bytes must get the same answer whatever interpreter decodes them, so the
    bound is counted on the bytes and never left to the decoder."""
    assert keys.MAX_NESTING == 64
    shapes = ((b"[", b"]", b""), (b'{"a":', b"}", b"1"), (b'[{"a":', b"}]", b"[]"))
    for opening, closing, inside in shapes:
        levels = opening.count(b"[") + opening.count(b"{")
        extra = inside.count(b"[")
        deepest = _nested((64 - extra) // levels, opening, closing, inside)
        value = keys.decode_canonical(deepest)
        assert keys.canonical_json(value) == deepest
        too_deep = _nested((64 - extra) // levels + 1, opening, closing, inside)
        assert _refuses(keys.decode_canonical, too_deep), opening
    # The same bound when encoding: 64 arrays inside one another, then 65.
    value: list = []
    for _ in range(63):
        value = [value]
    assert keys.canonical_json(value) == _nested(64)
    assert _refuses(keys.canonical_json, [value])
    assert _refuses(keys.canonical_json, {"a": value})
    # Brackets inside a string are not nesting, whatever surrounds them.
    brackets = "[" * 200 + "{" * 200
    for text in (brackets, '"' + brackets, "\\" + brackets, brackets + "\\", '\\"' + brackets + '"'):
        for held in ([text], {text: text}, [[text], {"a": text}]):
            assert keys.decode_canonical(keys.canonical_json(held)) == held
    # Many arrays side by side are not deep either.
    wide = [[[]] for _ in range(500)]
    assert keys.decode_canonical(keys.canonical_json(wide)) == wide
    # A string that ends with a reverse solidus does not hide what follows it.
    assert keys.decode_canonical(b'["\\\\",' + _nested(63) + b"]") == ["\\", keys.decode_canonical(_nested(63))]
    assert _refuses(keys.decode_canonical, b'["\\\\",' + _nested(64) + b"]")

    # A quotation mark that is never closed opens a string that runs to the end: what
    # follows it is not nesting, and the count stays one pass over the bytes.
    keys._check_nesting(b"[" * 60 + b'"' + b"[" * 70)
    keys._check_nesting(b"[" * 60 + b'"' + b'\\"[' * 70 + b"\\")
    assert _refuses(keys.decode_canonical, b"[" * 60 + b'"' + b"[" * 70)        # not JSON, for another reason

    # The decoder of the standard library is never given more than 64 levels: the count
    # is made first, on the bytes, well formed or not.
    def never(*args, **kwargs):
        raise AssertionError("decoded before the nesting was counted")

    monkeypatch.setattr(keys.json, "loads", never)
    for data in (_nested(65), _nested(1000), b"[" * 65, b"{" * 65, b'[{"a":' * 33,
                 b'["\\\\",' + _nested(64) + b"]", b'["[",' + _nested(64) + b"]",
                 b'"' + b"[" * 10 + b'"' + b"[" * 65, b"]" * 10 + b"[" * 75,
                 b"[" * 65 + b'"an open string'):
        assert _refuses(keys.decode_canonical, data), data[:20]


def test_values_without_a_canonical_form_are_refused():
    for value in (None, 1.5, float("nan"), float("inf"), 2**63, -(2**63) - 1, {"a": None}, [1.0], "\ud800",
                  {1: 2}, b"bytes", (1, 2), {"a": {"b": [{1}]}}, {"a": bytearray(b"x")}):
        assert _refuses(keys.canonical_json, value), repr(value)
    assert keys.canonical_json([2**63 - 1, -(2**63), True, False]) == b"[9223372036854775807,-9223372036854775808,true,false]"


# ---------------------------------------------------------------------------
# Hash, Merkle trees
# ---------------------------------------------------------------------------

def test_the_hash_is_the_one_of_the_vectors():
    for entry in VECTORS["hash"]:
        network = H(entry["network_id"]) if "network_id" in entry else NETWORK
        digest = keys.H(entry["domain"], network, H(entry["data"]))
        assert digest.hex() == entry["digest"] and len(digest) == 48
    for entry in VECTORS["objects"]:
        assert keys.H(entry["domain"], NETWORK, keys.canonical_json(entry["object"])).hex() == entry["digest"]
    # SHA3-384( len(domain) || domain || network_id || data ), for every domain.
    for domain in sorted(keys.DOMAINS):
        expected = hashlib.sha3_384(bytes([len(domain)]) + domain.encode() + NETWORK + b"data").digest()
        assert keys.H(domain, NETWORK, b"data") == expected == ref.H(domain, NETWORK, b"data")
        assert keys.H(domain, OTHER, b"data") != expected


def test_a_hash_under_another_name_is_not_a_hash_of_the_protocol():
    for domain in ("kern.other", "kern.tx ", "KERN.TX", "", "tx", b"kern.tx", None, "kern.header", "kern.rotate"):
        with pytest.raises(ValueError):
            keys.H(domain, NETWORK, b"")                                            # type: ignore[arg-type]
    for network in (b"", bytes(31), bytes(33), NETWORK.hex(), None, bytearray(NETWORK)):
        with pytest.raises(ValueError):
            keys.H("kern.tx", network, b"")                                         # type: ignore[arg-type]
    for data in ("text", None, 5, bytearray(b"data"), ["a"]):
        with pytest.raises(TypeError):
            keys.H("kern.tx", NETWORK, data)                                        # type: ignore[arg-type]


def test_the_merkle_tree_is_the_one_of_the_vectors():
    assert [len(entry["items"]) for entry in VECTORS["merkle"]] == list(range(9))
    for entry in VECTORS["merkle"]:
        assert keys.merkle_root(NETWORK, [H(item) for item in entry["items"]]).hex() == entry["root"]
    # Beyond the vectors, the same root as the reference, which is written as the note is.
    items = [bytes([i]) * (i % 5) for i in range(40)]
    for n in (9, 15, 16, 17, 31, 32, 33, 40):
        assert keys.merkle_root(NETWORK, items[:n]) == ref.merkle_root(NETWORK, items[:n])
        assert keys.merkle_root(NETWORK, tuple(items[:n])) == ref.merkle_root(NETWORK, items[:n])
    # The order counts, nothing is repeated to fill a level, and a leaf is never taken for a node.
    a, b, c = (bytes([i]) * 48 for i in range(3))
    assert keys.merkle_root(NETWORK, [a, b]) != keys.merkle_root(NETWORK, [b, a])
    assert keys.merkle_root(NETWORK, [a, b, c]) != keys.merkle_root(NETWORK, [a, b, c, c])
    inner = keys.merkle_root(NETWORK, [a]) + keys.merkle_root(NETWORK, [b])
    assert keys.merkle_root(NETWORK, [inner]) != keys.merkle_root(NETWORK, [a, b])
    assert keys.merkle_root(OTHER, [a, b]) != keys.merkle_root(NETWORK, [a, b])
    for bad in (["text"], [a, None], [bytearray(a)]):
        with pytest.raises(TypeError):
            keys.merkle_root(NETWORK, bad)                                          # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def test_key_derivation_follows_the_vectors_step_by_step():
    assert [d["network_id"] for d in VECTORS["derivation"]] == [NETWORK.hex(), OTHER.hex()]
    for d in VECTORS["derivation"]:
        seed, network = H(d["seed"]), H(d["network_id"])
        prk = keys._prk(seed)
        assert prk.hex() == d["prk"]
        assert [c["name"] for c in d["components"]] == ["mldsa65", "ed25519", "ed25519-standalone"]
        for c in d["components"]:
            assert keys._info(network, c["name"]).hex() == c["info"]
            assert keys._output(prk, keys._info(network, c["name"])).hex() == c["output"]
        # What the module hands out: a key pair, its public key and its address.
        pair = keys.Keypair(seed, network)
        assert pair.public_key == composite.public_key_from_private(H(d["composite_private"]))
        assert hashlib.sha3_384(pair.public_key[:MLDSA_KEY]).hexdigest() == d["mldsa65_public_key_sha3_384"]
        assert pair.public_key[MLDSA_KEY:].hex() == d["ed25519_public_key"]
        assert hashlib.sha3_384(pair.public_key).hexdigest() == d["composite_public_key_sha3_384"]
        assert pair.address == d["address"] == keys.account_address(network, pair.public_key)
        assert pair.network_id == network and keys.public_key_is_valid(pair.public_key)


def test_one_seed_gives_another_key_on_another_network():
    here, there = keys.Keypair(SEED, NETWORK), keys.Keypair(SEED, OTHER)
    assert here.public_key != there.public_key and here.address != there.address
    assert here.public_key[:MLDSA_KEY] != there.public_key[:MLDSA_KEY]
    assert here.public_key[MLDSA_KEY:] != there.public_key[MLDSA_KEY:]
    again = keys.Keypair(SEED, NETWORK)
    assert (again.public_key, again.address) == (here.public_key, here.address)      # deterministic
    assert keys.Keypair(bytes(32), NETWORK).public_key != here.public_key
    for bad_seed in (b"", bytes(31), bytes(33), bytes(64), "text", None, bytearray(SEED)):
        with pytest.raises(ValueError):
            keys.Keypair(bad_seed, NETWORK)                                         # type: ignore[arg-type]
    for bad_network in (b"", bytes(31), bytes(33), NETWORK.hex(), None, "kern-devnet"):
        with pytest.raises(ValueError):
            keys.Keypair(SEED, bad_network)                                         # type: ignore[arg-type]
        with pytest.raises(ValueError):
            keys.contract_key(SEED, bad_network)                                    # type: ignore[arg-type]


def test_the_key_for_contracts_is_another_secret_than_the_account_key():
    for d in VECTORS["derivation"]:
        seed, network = H(d["seed"]), H(d["network_id"])
        outputs = {c["name"]: c["output"] for c in d["components"]}
        contract_seed = keys.contract_key(seed, network)
        assert contract_seed.hex() == outputs["ed25519-standalone"]
        assert bytes(SigningKey(contract_seed).verify_key).hex() == d["ed25519_standalone_public_key"]
        # Not a component of the account key, and not its seed.
        assert contract_seed.hex() not in d["composite_private"]
        assert contract_seed not in (seed, H(outputs["mldsa65"]), H(outputs["ed25519"]))
        assert d["ed25519_standalone_public_key"] != d["ed25519_public_key"]
        assert bytes(SigningKey(contract_seed).verify_key) not in keys.Keypair(seed, network).public_key
    assert VECTORS["evm"]["signer_public_key"] == VECTORS["derivation"][0]["ed25519_standalone_public_key"]


# ---------------------------------------------------------------------------
# Contexts and signatures
# ---------------------------------------------------------------------------

def test_a_context_is_purpose_zero_byte_network():
    assert [c["purpose"] for c in VECTORS["contexts"]] == list(keys.PURPOSES)
    for c in VECTORS["contexts"]:
        context = keys.signing_context(c["purpose"], NETWORK)
        assert context.hex() == c["context"] and context == c["purpose"].encode() + b"\x00" + NETWORK
        assert len(context) <= 48
    for bad in ("kern.vote", "kern.tx\x00", "KERN.TX", "", b"kern.tx", None, "kern.block", ["kern.tx"]):
        with pytest.raises(ValueError):
            keys.signing_context(bad, NETWORK)                                      # type: ignore[arg-type]
    for bad in (b"", bytes(31), bytes(33), NETWORK.hex(), None, bytearray(NETWORK)):
        with pytest.raises(ValueError):
            keys.signing_context("kern.tx", bad)                                    # type: ignore[arg-type]


def test_a_signature_holds_for_one_purpose_on_one_network():
    here, there = keys.Keypair(SEED, NETWORK), keys.Keypair(SEED, OTHER)
    message = b'{"kind":"example"}'
    for purpose in keys.PURPOSES:
        signature = here.sign(message, purpose)
        assert len(signature) == keys.SIGNATURE_BYTES
        for other in keys.PURPOSES:
            assert keys.verify(here.public_key, message, signature, other, NETWORK) == (other == purpose)
        assert not keys.verify(here.public_key, message, signature, purpose, OTHER)
        assert not keys.verify(there.public_key, message, signature, purpose, OTHER)
        assert not keys.verify(here.public_key, message + b" ", signature, purpose, NETWORK)
        # It is the composite signature of the message in the context of the purpose.
        assert composite.verify(here.public_key, message, signature, ref.signing_context(purpose, NETWORK))
        assert not composite.verify(here.public_key, message, signature)
    # Signing is randomized: the bytes of a signature never identify what was signed.
    assert here.sign(message, "kern.tx") != here.sign(message, "kern.tx")
    # Nothing signed for one network is accepted on the other, by either key of the seed.
    elsewhere = there.sign(message, "kern.tx")
    assert keys.verify(there.public_key, message, elsewhere, "kern.tx", OTHER)
    assert not keys.verify(there.public_key, message, elsewhere, "kern.tx", NETWORK)
    assert not keys.verify(here.public_key, message, elsewhere, "kern.tx", NETWORK)
    assert not keys.verify(here.public_key, message, elsewhere, "kern.tx", OTHER)


def test_signing_outside_the_purposes_raises_and_verifying_answers_no():
    pair, message = keys.Keypair(SEED, NETWORK), b"a statement"
    signature = pair.sign(message, "kern.tx")
    for bad in ("kern.vote", "", "kern.tx\x00", b"kern.tx", None, "kern.block", ["kern.tx"]):
        with pytest.raises(ValueError):
            pair.sign(message, bad)                                                 # type: ignore[arg-type]
        assert not keys.verify(pair.public_key, message, signature, bad, NETWORK)   # type: ignore[arg-type]
    for bad in (b"", bytes(31), bytes(33), NETWORK.hex(), None, bytearray(NETWORK), "kern-devnet"):
        assert not keys.verify(pair.public_key, message, signature, "kern.tx", bad)  # type: ignore[arg-type]
    for bad in (None, "text", 5, bytearray(signature), signature[:-1], signature + b"\x00", b"",
                signature[:composite.MLDSA_SIGNATURE_BYTES], signature[composite.MLDSA_SIGNATURE_BYTES:]):
        assert not keys.verify(pair.public_key, message, bad, "kern.tx", NETWORK)   # type: ignore[arg-type]
        assert not keys.verify(bad, message, signature, "kern.tx", NETWORK)         # type: ignore[arg-type]
    assert not keys.verify(pair.public_key, "a statement", signature, "kern.tx", NETWORK)  # type: ignore[arg-type]
    for bad_message in ("text", None, bytearray(message)):
        with pytest.raises(TypeError):
            pair.sign(bad_message, "kern.tx")                                       # type: ignore[arg-type]
    assert keys.verify(pair.public_key, message, signature, "kern.tx", NETWORK)


@pytest.mark.parametrize("maker", ["python", "go"])
def test_the_signatures_of_both_programs_verify_through_the_profile(maker):
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    assert H(SIGNED["network_id"]) == NETWORK and H(SIGNED["seed"]) == SEED
    assert keys.Keypair(SEED, NETWORK).public_key == public_key          # the key of the first derivation
    assert [c["purpose"] for c in SIGNED[maker]] == list(keys.PURPOSES)
    for c in SIGNED[maker]:
        signature = H(c["signature"])
        for purpose in keys.PURPOSES:
            assert keys.verify(public_key, message, signature, purpose, NETWORK) == (purpose == c["purpose"])
        assert not keys.verify(public_key, message, signature, c["purpose"], OTHER)


def test_what_a_verifier_must_refuse_is_refused_through_the_profile():
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    assert len(SIGNED["invalid"]) == 17
    for c in SIGNED["invalid"]:
        key = H(c["public_key"]) if "public_key" in c else public_key
        assert not keys.verify(key, message, H(c["signature"]), "kern.tx", NETWORK), c["why"]


# ---------------------------------------------------------------------------
# Text forms
# ---------------------------------------------------------------------------

TEXT_KINDS = {
    "public_key": (keys.PUBLIC_KEY_BYTES, keys.public_key_text, keys.public_key_from_text),
    "signature": (keys.SIGNATURE_BYTES, keys.signature_text, keys.signature_from_text),
}


def test_a_key_and_a_signature_have_one_text():
    forms = VECTORS["text_forms"]
    assert [(e["kind"], e["factor"], e["offset"]) for e in forms["accepted"]] == [
        (kind, *pattern) for kind in TEXT_KINDS for pattern in ref.TEXT_FORM_PATTERNS[kind]]
    for entry in forms["accepted"]:
        size, encode, decode = TEXT_KINDS[entry["kind"]]
        data = _pattern(size, entry["factor"], entry["offset"])
        assert encode(data) == entry["text"] and decode(entry["text"]) == data
    assert len(forms["accepted"][0]["text"]) == 2651 and len(forms["accepted"][4]["text"]) == 4504
    # The texts of the key registry in the state vectors are read back the same way.
    registry = [s["state"]["keys"] for s in VECTORS["state"] if "keys" in s["state"]]
    texts = {entry["public_key"] for keys_of in registry for history in keys_of.values() for entry in history}
    assert len(texts) == 3
    for text in texts:
        assert keys.public_key_text(keys.public_key_from_text(text)) == text
    # A real key and a real signature.
    pair = keys.Keypair(SEED, NETWORK)
    signature = pair.sign(b"a statement", "kern.tx")
    assert keys.public_key_from_text(keys.public_key_text(pair.public_key)) == pair.public_key
    assert keys.signature_from_text(keys.signature_text(signature)) == signature
    for size, encode, _ in TEXT_KINDS.values():
        for bad in (bytes(size - 1), bytes(size + 1), b"", "text", None, bytearray(size)):
            with pytest.raises(ValueError):
                encode(bad)                                                         # type: ignore[arg-type]


def test_every_other_spelling_of_a_key_or_a_signature_is_refused():
    refused = VECTORS["text_forms"]["refused"]
    assert len(refused) == 40 and {e["kind"] for e in refused} == set(TEXT_KINDS)
    assert len({(e["kind"], e["why"]) for e in refused}) == 40
    for entry in refused:
        for kind, (_, _, decode) in TEXT_KINDS.items():       # by the decoder of its kind, and by the other one
            assert _refuses(decode, entry["text"]), (entry["kind"], entry["why"], kind)
    for _, _, decode in TEXT_KINDS.values():
        for bad in (None, 5, b"kpk1.AAAA", ["kpk1."], bytearray(b"ksig1.")):
            assert _refuses(decode, bad), bad


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

def test_an_address_is_75_characters_and_belongs_to_one_network():
    stated, key = VECTORS["address"], _pattern(1984, 7, 3)
    address = keys.account_address(NETWORK, key)
    assert address == stated["address"] and len(address) == 75 and address.startswith("kn1")
    assert keys.account_address(OTHER, key) == stated["address_other_network"] != address
    assert keys.hash_from_address(NETWORK, address).hex() == stated["hash"]
    assert keys.address_from_hash(NETWORK, H(stated["hash"])) == address
    # An address of another network fails its checksum.
    with pytest.raises(ValueError):
        keys.hash_from_address(NETWORK, stated["address_other_network"])
    with pytest.raises(ValueError):
        keys.hash_from_address(OTHER, address)
    # The hash covers the scheme number and the public key, under the domain of accounts.
    assert stated["hash"] == keys.H("kern.addr", NETWORK, b"\x01" + key).hex()
    for bad in (key[:-1], key + b"\x00", b"", "text", None, bytearray(key)):
        with pytest.raises(ValueError):
            keys.account_address(NETWORK, bad)                                      # type: ignore[arg-type]


def test_the_address_of_a_contract_is_hashed_under_its_own_domain():
    stated = VECTORS["contract_address"]
    transaction_id = H(stated["transaction_id"])
    address = keys.contract_address(NETWORK, transaction_id)
    assert address == stated["address"] and len(address) == 75 and address.startswith("kn1")
    assert keys.hash_from_address(NETWORK, address).hex() == stated["hash"]
    assert stated["hash"] == keys.H("kern.addr.contract", NETWORK, transaction_id).hex()
    assert keys.contract_address(OTHER, transaction_id) != address
    for bad in (transaction_id[:-1], transaction_id + b"\x00", b"", stated["transaction_id"], None):
        with pytest.raises(ValueError):
            keys.contract_address(NETWORK, bad)                                     # type: ignore[arg-type]


def test_what_is_not_an_address_of_this_network_is_refused():
    address = VECTORS["address"]["address"]
    digest = H(VECTORS["address"]["hash"])
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    assert set(address) <= set(alphabet)

    def with_prefix(prefix: bytes) -> str:              # a well-formed text, with its own checksum
        body = prefix + digest
        return ref.base58(body + ref.H("kern.checksum", NETWORK, body)[:4])

    assert with_prefix(keys.ADDRESS_PREFIX) == address
    last = alphabet[(alphabet.index(address[-1]) + 1) % 58]
    middle = alphabet[(alphabet.index(address[40]) + 1) % 58]
    refused = {
        "another last character": address[:-1] + last,
        "another character in the middle": address[:40] + middle + address[41:],
        "one character short": address[:-1],
        "one character long": address + "1",
        "a zero digit in front, the same number on 76 characters": "1" + address,
        "a character that is not in the alphabet": address[:40] + "0" + address[41:],
        "a letter that is not in the alphabet": address[:40] + "l" + address[41:],
        "a space at the end": address + " ",
        "a space at the start": " " + address,
        "a line feed at the end": address + "\n",
        "a letter outside ASCII": address[:40] + "é" + address[41:],
        "another prefix, 75 characters and its own checksum": with_prefix(bytes.fromhex("7b033a")),
        "the prefix of today's addresses": with_prefix(bytes.fromhex("05959b")),
        "75 times the first digit": "1" * 75,
        "the hash in hexadecimal": digest.hex(),
        "an empty text": "",
    }
    assert len(refused["another prefix, 75 characters and its own checksum"]) == 75
    # 75 digits and the prefix of an address leave one text per value: every number with a
    # prefix from 0x7b031f to 0x7b0353 has exactly 75 digits in base 58.
    assert 58**74 <= 0x7B031F << 416 and (0x7B0354 << 416) <= 58**75
    for why, text in refused.items():
        assert text != address and _refuses(keys.hash_from_address, NETWORK, text), why
    for not_text in (None, 5, address.encode(), [address]):
        assert _refuses(keys.hash_from_address, NETWORK, not_text), not_text
    for bad in (digest[:-1], digest + b"\x00", b"", digest.hex(), None):
        with pytest.raises(ValueError):
            keys.address_from_hash(NETWORK, bad)                                    # type: ignore[arg-type]
    with pytest.raises(ValueError):
        keys.hash_from_address(bytes(31), address)


# ---------------------------------------------------------------------------
# What is checked before a key is recorded
# ---------------------------------------------------------------------------

def test_a_public_key_is_checked_before_it_is_recorded():
    """Section 4.5, rule 4: the right length, and an Ed25519 part that
    passes rule 2 of section 2.5. Any 1,952 bytes are an ML-DSA-65 public
    key, so that part has nothing more to check."""
    mldsa_part = keys.Keypair(SEED, NETWORK).public_key[:MLDSA_KEY]
    assert [c["valid"] for c in EDGE["public_keys"]] == [True] + [False] * 7
    for c in EDGE["public_keys"]:
        assert keys.public_key_is_valid(mldsa_part + H(c["public_key"])) == c["valid"], c["name"]
        assert keys.public_key_is_valid(bytes(MLDSA_KEY) + H(c["public_key"])) == c["valid"], c["name"]
    for c in EDGE["cases"]:                              # the keys of the 31 cases: one is a key
        ed25519_part = H(c["public_key"])
        expected = c["public_key"] == EDGE["public_keys"][0]["public_key"]
        assert keys.public_key_is_valid(mldsa_part + ed25519_part) == expected, c["name"]
    good = mldsa_part + H(EDGE["public_keys"][0]["public_key"])
    for bad in (good[:-1], good + b"\x00", b"", good[MLDSA_KEY:], "text", None, bytearray(good)):
        assert not keys.public_key_is_valid(bad)                                    # type: ignore[arg-type]
    # The bytes of the address vectors are not a key, and still have an address: the
    # address is computed for any 1,984 bytes, the check is made when a key is recorded.
    assert not keys.public_key_is_valid(_pattern(1984, 7, 3))


# ---------------------------------------------------------------------------
# No component key
# ---------------------------------------------------------------------------

def test_the_module_gives_no_access_to_a_component_key():
    """Section 3.3: no function of Kern signs with one component, and none
    returns a component key. What the module offers is listed here: a
    function added to it changes this test."""
    pair = keys.Keypair(SEED, NETWORK)
    derivation = VECTORS["derivation"][0]
    assert [name for name in dir(pair) if not name.startswith("_")] == ["address", "network_id", "public_key", "sign"]
    assert not hasattr(pair, "__dict__")
    for name in ("address", "network_id", "public_key"):
        with pytest.raises(AttributeError):
            setattr(pair, name, getattr(pair, name))
    assert repr(pair) == f"<Keypair {pair.address}>"
    defined = {name for name, value in vars(keys).items()
               if not name.startswith("_") and (inspect.isfunction(value) or inspect.isclass(value))
               and value.__module__ == keys.__name__}
    assert defined == {
        "canonical_json", "decode_canonical", "H", "merkle_root", "signing_context",
        "public_key_text", "public_key_from_text", "signature_text", "signature_from_text",
        "address_from_hash", "hash_from_address", "account_address", "contract_address",
        "public_key_is_valid", "contract_key", "Keypair", "verify"}
    # Nothing a key pair holds or returns is a secret of the derivation: neither the seed,
    # nor a component seed, nor the composite private key.
    secrets = [SEED, H(derivation["composite_private"])] + [H(c["output"]) for c in derivation["components"][:2]]
    held = [getattr(pair, name) for name in ("address", "network_id", "public_key")]
    held.append(pair.sign(b"a statement", "kern.tx"))
    for value in held:
        raw = value.encode() if isinstance(value, str) else value
        assert not any(secret in raw for secret in secrets)
    # The one function that returns a secret returns the key for contracts.
    assert keys.contract_key(SEED, NETWORK) == H(derivation["components"][2]["output"])
