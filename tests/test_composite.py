# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""kern.composite against the official vectors, and what it must refuse.

The module implements the signature mechanism of RFC 10073 for one
combination, ML-DSA-65 with Ed25519, and the one rule Kern fixes for the
verification of Ed25519 (docs/hybrid-signatures.md, section 2.5). These
tests run it, and the library under it, on the vectors kept whole in
tests/vectors: those of the working group that wrote the RFC, those of
NIST for ML-DSA and those of Project Wycheproof for ML-DSA-65 and Ed25519.
They verify, both halves, the signatures the two reference programs
exchanged. Then they check what no vector says: that one valid component
is never enough, and that the module refuses to load over a library that
would give another verdict.

Nothing in the node uses the module yet.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
import sys
from collections import Counter
from pathlib import Path

import nacl.bindings as sodium
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ed25519_reference as ed
import profile_reference as ref
from kern import composite

VECTORS = Path(__file__).resolve().parent / "vectors"
H = bytes.fromhex
PK, SIG = composite.MLDSA_PUBLIC_KEY_BYTES, composite.MLDSA_SIGNATURE_BYTES


def _load(relative: str) -> dict:
    return json.loads((VECTORS / relative).read_text(encoding="utf-8"))


EDGE = _load("kern/ed25519_edge_cases.json")
SIGNED = _load("kern/composite_signatures.json")
NETWORK = H(SIGNED["network_id"])
OTHER_NETWORK = bytes(range(0xC0, 0xE0))


def _key(seed: int = 7) -> composite.CompositePrivateKey:
    return composite.CompositePrivateKey(bytes([seed]) * 64)


def _mldsa_verifies(public_key: bytes, signature: bytes, message: bytes, context: bytes) -> bool:
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message, context)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# RFC 10073
# ---------------------------------------------------------------------------

def test_the_parameters_are_those_of_the_combination():
    assert (composite.PREFIX, composite.LABEL) == (ref.PREFIX, ref.LABEL)
    assert composite.PREFIX == b"CompositeAlgorithmSignatures2025"
    assert composite.LABEL == b"COMPSIG-MLDSA65-Ed25519-SHA512"
    assert (composite.PRIVATE_KEY_BYTES, composite.PUBLIC_KEY_BYTES, composite.SIGNATURE_BYTES) == (64, 1984, 3373)
    assert (composite.MLDSA_PUBLIC_KEY_BYTES, composite.MLDSA_SIGNATURE_BYTES) == (1952, 3309)
    assert (composite.PUBLIC_KEY_BYTES, composite.SIGNATURE_BYTES) == (ref.PUBLIC_KEY_BYTES, ref.SIGNATURE_BYTES)
    for message, context in ((b"", b""), (b"a statement", b"kern.tx\x00" + bytes(32)), (b"x" * 500, bytes(255))):
        assert composite.message_representative(message, context) == ref.message_representative(message, context)


def test_the_vectors_of_rfc_10073_for_this_combination():
    doc = _load("rfc10073/testvectors.json")
    message, context = base64.b64decode(doc["m"]), base64.b64decode(doc["ctx"])
    assert len(doc["tests"]) == 21                      # every combination of the standard; Kern uses one
    (vector,) = [t for t in doc["tests"] if t["tcId"] == "id-MLDSA65-Ed25519-SHA512"]
    public_key, private_key, plain, with_context = (
        base64.b64decode(vector[k]) for k in ("pk", "sk", "s", "sWithContext"))
    # Serialization: ML-DSA seed then Ed25519 seed; ML-DSA part then Ed25519 part.
    assert (len(private_key), len(public_key), len(plain), len(with_context)) == (64, 1984, 3373, 3373)
    assert composite.public_key_from_private(private_key) == public_key
    assert context and composite.verify(public_key, message, plain)
    assert composite.verify(public_key, message, with_context, context)
    # A signature holds for one context and one message.
    assert not composite.verify(public_key, message, plain, context)
    assert not composite.verify(public_key, message, with_context)
    assert not composite.verify(public_key, message + b".", plain)
    # What both components sign (RFC 10073, section 2.2).
    assert composite.message_representative(message, context) == (
        b"CompositeAlgorithmSignatures2025" + b"COMPSIG-MLDSA65-Ed25519-SHA512"
        + bytes([len(context)]) + context + hashlib.sha512(message).digest())
    # Our own signatures verify, in their context only.
    key = composite.CompositePrivateKey(private_key)
    ours = key.sign(message, context)
    assert len(ours) == 3373 and ours != with_context
    assert composite.verify(public_key, message, ours, context)
    assert not composite.verify(public_key, message, ours)
    assert composite.verify(public_key, message, composite.sign(private_key, message))


# ---------------------------------------------------------------------------
# NIST (ACVP) and Wycheproof: ML-DSA-65
# ---------------------------------------------------------------------------

def test_nist_key_generation_vectors_for_mldsa65():
    doc = _load("nist-acvp/ML-DSA-keyGen-FIPS204.json")
    (group,) = [g for g in doc["testGroups"] if g["parameterSet"] == "ML-DSA-65"]
    assert len(group["tests"]) == 25
    for t in group["tests"]:
        key = mldsa.MLDSA65PrivateKey.from_seed_bytes(H(t["seed"]))
        assert key.public_key().public_bytes_raw() == H(t["pk"]), t["tcId"]


def test_nist_signature_verification_vectors_for_mldsa65():
    doc = _load("nist-acvp/ML-DSA-sigVer-FIPS204.json")
    (group,) = [g for g in doc["testGroups"]
                if g["parameterSet"] == "ML-DSA-65" and g["signatureInterface"] == "external"
                and g["preHash"] == "pure"]
    verdicts, reasons = Counter(), Counter()
    for t in group["tests"]:
        got = _mldsa_verifies(H(t["pk"]), H(t["signature"]), H(t["message"]), H(t["context"]))
        assert got == t["testPassed"], t["tcId"]
        verdicts[got] += 1
        if not t["testPassed"]:
            reasons[t["reason"]] += 1
    assert verdicts == {True: 3, False: 12}
    assert set(reasons) == {"modified signature - z", "modified signature - hint",
                            "modified signature - commitment", "modified message"}


def test_wycheproof_verification_vectors_for_mldsa65():
    doc = _load("wycheproof/mldsa_65_verify_test.json")
    verdicts, flags = Counter(), Counter()
    for group in doc["testGroups"]:
        for t in group["tests"]:
            got = _mldsa_verifies(H(group["publicKey"]), H(t["sig"]), H(t["msg"]), H(t.get("ctx", "")))
            assert got == (t["result"] == "valid"), (t["tcId"], t["flags"])
            verdicts[t["result"]] += 1
            flags.update(t["flags"])
    assert verdicts == {"valid": 79, "invalid": 131} and doc["numberOfTests"] == 210
    # The malformed encodings that a verifier must refuse are in there.
    for flag in ("InvalidHintsEncoding", "InfinityNormViolation", "IncorrectSignatureLength",
                 "IncorrectPublicKeyLength", "InvalidContext", "ZeroPublicKey"):
        assert flags[flag], flag


def test_wycheproof_seeds_give_the_published_keys_and_signatures_for_mldsa65():
    doc = _load("wycheproof/mldsa_65_sign_seed_test.json")
    keys = refused_seeds = verified = refused_contexts = without_message = 0
    for group in doc["testGroups"]:
        try:
            key = mldsa.MLDSA65PrivateKey.from_seed_bytes(H(group["privateSeed"]))
        except (ValueError, TypeError):
            refused_seeds += 1
            assert all(t["result"] == "invalid" for t in group["tests"])
            continue
        assert key.public_key().public_bytes_raw() == H(group["publicKey"])
        keys += 1
        for t in group["tests"]:
            if "msg" not in t:                      # vectors given as a precomputed digest only
                without_message += 1
                continue
            message, context = H(t["msg"]), H(t.get("ctx", ""))
            if t["result"] == "invalid":
                with pytest.raises((ValueError, TypeError)):
                    key.sign(message, context)
                refused_contexts += 1
                continue
            assert _mldsa_verifies(H(group["publicKey"]), H(t["sig"]), message, context), t["tcId"]
            verified += 1
    assert (keys, refused_seeds, verified, refused_contexts, without_message) == (39, 3, 84, 1, 17)


# ---------------------------------------------------------------------------
# Ed25519: one verdict
# ---------------------------------------------------------------------------

def test_the_ed25519_rule_on_the_cases_where_implementations_disagree():
    cases = EDGE["cases"]
    for c in cases:
        got = composite.ed25519_verify(H(c["public_key"]), H(c["message"]), H(c["signature"]))
        assert got == c["valid"], c["name"]
    assert len(cases) == 31
    assert sum(c["valid"] for c in cases) == 1 and sum(c["lenient"] for c in cases) == 17


def test_the_ed25519_rule_on_the_wycheproof_vectors():
    doc = _load("wycheproof/ed25519_test.json")
    verdicts, left_open = Counter(), Counter()
    for group in doc["testGroups"]:
        public_key = H(group["publicKey"]["pk"])
        for t in group["tests"]:
            got = composite.ed25519_verify(public_key, H(t["msg"]), H(t["sig"]))
            verdicts[(t["result"], got)] += 1
            if t["result"] == "acceptable":
                left_open.update(t["flags"])
    # What the vectors call valid is accepted, what they call invalid is refused, and
    # the cases they leave to the implementation are all refused: a public key of small
    # or mixed order is not a key (section 2.5).
    assert verdicts == {("valid", True): 117, ("invalid", False): 64, ("acceptable", False): 29}
    assert left_open == {"SmallOrderPublicKey": 8, "MixedOrderPublicKey": 21}


def test_the_checks_on_r_and_s_are_made_by_the_module_whatever_the_library_refuses(monkeypatch):
    """What a library answers is a test of conformance, never the
    specification. libsodium refuses by itself an R of small order and an
    S that is not reduced; the rule must not rest on that. Here the
    library is replaced by a verifier that only checks the equation
    [S]B = R + [k]A, on points decoded leniently and with S as it comes:
    the verdicts on the 31 cases do not change."""
    def equation_only(self, smessage, signature=None, *args, **kwargs):
        public_key = bytes(self)
        a, r = ed.decode_leniently(public_key), ed.decode_leniently(signature[:32])
        s, k = int.from_bytes(signature[32:], "little"), ed.challenge(signature[:32], public_key, smessage)
        if a is None or r is None or ed.mul(s, ed.B) != ed.add(r, ed.mul(k, a)):
            raise BadSignatureError("the equation does not hold")
        return smessage

    monkeypatch.setattr(VerifyKey, "verify", equation_only)
    # Such a verifier accepts an S that is not reduced, the identity as R, and an
    # encoding of R that is not canonical: rules 4 and 3 are what refuses them.
    for name in ("S plus the group order", "honest key, R is the identity",
                 "honest key, R is the identity written as p + 1"):
        c = _case(name)
        assert VerifyKey(H(c["public_key"])).verify(H(c["message"]), H(c["signature"])) == H(c["message"]), name
    for c in EDGE["cases"]:
        got = composite.ed25519_verify(H(c["public_key"]), H(c["message"]), H(c["signature"]))
        assert got == c["valid"], c["name"]


def test_public_keys_under_rule_2_alone():
    """The check made when a key is recorded, on the keys added to the
    vectors for it: an ordinary key, and that key plus each point of small
    order. The verdict in the file, the arithmetic and the module agree."""
    keys = EDGE["public_keys"]
    assert [{k: c[k] for k in ("name", "public_key", "comment")} for c in keys] == ed.build_key_cases()
    assert [c["valid"] for c in keys] == [True] + [False] * 7
    for c in keys:
        public_key = H(c["public_key"])
        assert ed.is_a_key(public_key) == c["valid"], c["name"]
        assert composite.ed25519_public_key_is_valid(public_key) == c["valid"], c["name"]
    # Each refused key is on the curve, in canonical encoding, and is the ordinary key
    # plus a point of order 2, 4, 4, 8, 8, 8, 8.
    ordinary = ed.decode_strictly(H(keys[0]["public_key"]))
    assert ordinary is not None
    small_parts = []
    for c in keys[1:]:
        point = ed.decode_strictly(H(c["public_key"]))
        assert point is not None, c["name"]
        small_parts.append(ed.order(ed.add(point, ed.neg(ordinary))))
    assert small_parts == [2, 4, 4, 8, 8, 8, 8]
    # The 31 cases have keys of mixed order with a point of order 8 only: the keys with a
    # point of order 2 or 4 are what this list adds.
    in_the_cases = {c["public_key"] for c in EDGE["cases"]}
    assert [c["public_key"] in in_the_cases for c in keys] == [True, False, False, False, True, False, False, False]


def test_an_ed25519_public_key_is_a_point_of_prime_order():
    """What libsodium answers on a public key is what the arithmetic says:
    on the keys of the 31 cases, and on the keys of the Wycheproof vectors
    whose verdict is left to the implementation."""
    ours = {H(c["public_key"]) for c in EDGE["cases"]}
    groups = _load("wycheproof/ed25519_test.json")["testGroups"]
    left_open = {H(g["publicKey"]["pk"]) for g in groups if any(t["result"] == "acceptable" for t in g["tests"])}
    signing = {H(g["publicKey"]["pk"]) for g in groups if any(t["result"] == "valid" for t in g["tests"])}
    assert (len(ours), len(left_open), len(signing)) == (19, 29, 55)
    assert len({g["publicKey"]["pk"] for g in groups}) == 85
    by_arithmetic = {public_key: ed.is_a_key(public_key) for public_key in sorted(ours | left_open)}
    for public_key, expected in by_arithmetic.items():
        assert composite.ed25519_public_key_is_valid(public_key) == expected, public_key.hex()
    # One key among them is a key: the ordinary one of the 31 cases. None of those the
    # vectors leave open is.
    assert [k for k, is_a_key in by_arithmetic.items() if is_a_key] == [H(EDGE["public_keys"][0]["public_key"])]
    assert not any(by_arithmetic[k] for k in left_open)
    # A key that has a valid signature in the vectors is a key.
    assert not signing & left_open
    assert all(composite.ed25519_public_key_is_valid(k) for k in signing)
    honest = bytes(SigningKey(bytes(range(32))).verify_key)
    assert composite.ed25519_public_key_is_valid(honest)
    for bad in (b"", honest[:31], honest + b"\x00", "text", None, 5, bytearray(honest)):
        assert not composite.ed25519_public_key_is_valid(bad)          # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The library under the rule answers as expected, or the module does not load
# ---------------------------------------------------------------------------

def _case(name: str) -> dict:
    (case,) = [c for c in EDGE["cases"] if c["name"] == name]
    return case


def _a_fresh_copy_of_the_module():
    """Execute the source of kern.composite again, under another name: what
    happens when a node starts, without touching the module the other tests
    use."""
    spec = importlib.util.spec_from_file_location("kern_composite_probe", composite.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_known_answers_asked_at_import_are_those_of_the_vectors():
    honest, mixed = _case("honest"), _case("honest key, R of mixed order")
    keys = EDGE["public_keys"]
    assert composite._KNOWN_KEY == H(keys[0]["public_key"]) == H(honest["public_key"]) == H(mixed["public_key"])
    assert keys[0]["valid"]
    # A key plus a point of order 2, of order 4 and of order 8, then the identity.
    refused = {c["name"]: H(c["public_key"]) for c in keys if not c["valid"]}
    assert composite._KNOWN_NOT_KEYS == (
        refused["ordinary key plus a point of order 2"], refused["ordinary key plus a point of order 4, point 1"],
        refused["ordinary key plus a point of order 8, point 1"], ed.encode(ed.IDENTITY))
    assert not any(ed.is_a_key(point) for point in composite._KNOWN_NOT_KEYS)
    assert composite._KNOWN_SIGNATURE == (H(honest["message"]), H(honest["signature"])) and honest["valid"]
    assert composite._KNOWN_COFACTORED_ONLY == (H(mixed["message"]), H(mixed["signature"])) and not mixed["valid"]
    # The second signature holds after multiplication by the cofactor, and not before.
    message, signature = composite._KNOWN_COFACTORED_ONLY
    a, r = ed.decode_strictly(composite._KNOWN_KEY), ed.decode_strictly(signature[:32])
    assert a is not None and r is not None
    s, k = int.from_bytes(signature[32:], "little"), ed.challenge(signature[:32], composite._KNOWN_KEY, message)
    exact_left, exact_right = ed.mul(s, ed.B), ed.add(r, ed.mul(k, a))
    assert exact_left != exact_right and ed.mul(8, exact_left) == ed.mul(8, exact_right)
    # The constants of the rule.
    assert (composite._P, composite._L, composite._IDENTITY) == (ed.P, ed.L, ed.encode(ed.IDENTITY))


def test_the_installed_libsodium_gives_the_expected_answers():
    assert composite.libsodium_shortcomings() == []
    assert _a_fresh_copy_of_the_module().verify is not composite.verify       # it loads


def test_the_module_does_not_load_over_a_libsodium_that_takes_a_point_of_mixed_order_for_a_key(monkeypatch):
    """libsodium before the correction published as CVE-2025-69277, which
    PyNaCl ships from version 1.6.2: a point of prime order plus the point
    of order 2 passed for a point of the subgroup. A node over it would
    record keys, and accept signatures, that the other clients refuse."""
    plus_order_2 = composite._KNOWN_NOT_KEYS[0]
    real = sodium.crypto_core_ed25519_is_valid_point
    monkeypatch.setattr(sodium, "crypto_core_ed25519_is_valid_point",
                        lambda point: True if point == plus_order_2 else real(point))
    assert composite.ed25519_public_key_is_valid(plus_order_2)                # what such a library answers
    (found,) = composite.libsodium_shortcomings()
    assert "outside the subgroup of prime order" in found and "CVE-2025-69277" in found
    with pytest.raises(ImportError, match="PyNaCl 1.6.2 or later"):
        _a_fresh_copy_of_the_module()


def test_the_module_does_not_load_over_a_libsodium_that_verifies_with_the_cofactor(monkeypatch):
    """RFC 8032 allows a verifier to check the equation after multiplication
    by the cofactor. Such a library accepts signatures that rule 5 refuses."""
    message, signature = composite._KNOWN_COFACTORED_ONLY
    real = VerifyKey.verify

    def with_the_cofactor(self, smessage, signature_=None, *args, **kwargs):
        if (bytes(self), smessage, signature_) == (composite._KNOWN_KEY, message, signature):
            return smessage
        return real(self, smessage, signature_, *args, **kwargs)

    assert not composite.ed25519_verify(composite._KNOWN_KEY, message, signature)
    monkeypatch.setattr(VerifyKey, "verify", with_the_cofactor)
    assert composite.ed25519_verify(composite._KNOWN_KEY, message, signature)  # what such a library answers
    (found,) = composite.libsodium_shortcomings()
    assert "after multiplication by the cofactor" in found
    with pytest.raises(ImportError, match="does not give the answers"):
        _a_fresh_copy_of_the_module()


def test_the_module_does_not_load_over_a_libsodium_without_the_point_operations(monkeypatch):
    monkeypatch.setattr(sodium, "has_crypto_core_ed25519", False)
    (found,) = composite.libsodium_shortcomings()
    assert "minimal build" in found
    with pytest.raises(ImportError, match="minimal build"):
        _a_fresh_copy_of_the_module()


# ---------------------------------------------------------------------------
# Both components, always
# ---------------------------------------------------------------------------

def test_a_signature_needs_both_components():
    key, message, context = _key(), b"a statement", b"kern.tx\x00" + bytes(32)
    signature = key.sign(message, context)
    assert composite.verify(key.public_key, message, signature, context)
    # One flipped bit in either component.
    for position in (0, PK // 2, SIG - 1, SIG, SIG + 31, SIG + 32, len(signature) - 1):
        damaged = bytearray(signature)
        damaged[position] ^= 1
        assert not composite.verify(key.public_key, message, bytes(damaged), context), position
    # A valid component of another signature in place of the right one.
    other = key.sign(b"another statement", context)
    assert not composite.verify(key.public_key, message, signature[:SIG] + other[SIG:], context)
    assert not composite.verify(key.public_key, message, other[:SIG] + signature[SIG:], context)
    # Another key, and each half of another key.
    stranger = _key(9)
    assert not composite.verify(stranger.public_key, message, signature, context)
    assert not composite.verify(key.public_key[:PK] + stranger.public_key[PK:], message, signature, context)
    assert not composite.verify(stranger.public_key[:PK] + key.public_key[PK:], message, signature, context)


def test_one_component_alone_is_never_a_signature():
    seed = bytes([7]) * 64
    key, message = composite.CompositePrivateKey(seed), b"a statement"
    representative = composite.message_representative(message)
    ed25519_key = SigningKey(seed[32:])
    mldsa_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[:32])
    for alone in (ed25519_key.sign(message).signature,                 # Ed25519 over the message
                  ed25519_key.sign(representative).signature,          # the Ed25519 component itself
                  mldsa_key.sign(message),                             # ML-DSA over the message
                  mldsa_key.sign(representative, composite.LABEL)):    # the ML-DSA component itself
        assert not composite.verify(key.public_key, message, alone)
        assert not composite.verify(key.public_key, message, alone.ljust(composite.SIGNATURE_BYTES, b"\x00"))
        assert not composite.verify(key.public_key, message, alone.rjust(composite.SIGNATURE_BYTES, b"\x00"))
    # A valid Ed25519 component next to an ML-DSA component made for another context of ML-DSA.
    forged = mldsa_key.sign(representative) + ed25519_key.sign(representative).signature
    assert len(forged) == composite.SIGNATURE_BYTES and not composite.verify(key.public_key, message, forged)
    # And the components are not signatures of the message for a plain verifier.
    signature = key.sign(message)
    assert not composite.ed25519_verify(key.public_key[PK:], message, signature[SIG:])
    assert composite.ed25519_verify(key.public_key[PK:], representative, signature[SIG:])
    with pytest.raises(InvalidSignature):
        mldsa_key.public_key().verify(signature[:SIG], message)


def test_a_composite_key_with_an_ed25519_part_of_small_order_signs_nothing():
    """The case of section 2.5: the holder of an account owns the ML-DSA key
    and gives himself an Ed25519 part for which a lenient verifier accepts
    a made-up signature. One client would accept and another refuse."""
    seed = bytes([7]) * 64
    mldsa_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[:32])
    message = b"a statement"
    representative = composite.message_representative(message)
    identity = (1).to_bytes(32, "little")
    public_key = mldsa_key.public_key().public_bytes_raw() + identity
    signature = mldsa_key.sign(representative, composite.LABEL) + identity + bytes(32)
    assert ed.lenient_verify(identity, representative, identity + bytes(32))     # a lenient verifier says yes
    assert not composite.verify(public_key, message, signature)


def test_signing_is_randomized_and_verification_never_raises():
    key, message = _key(), b"a statement"
    first, second = key.sign(message), key.sign(message)
    assert first != second
    assert composite.verify(key.public_key, message, first) and composite.verify(key.public_key, message, second)
    # A context is at most 255 bytes: signing raises, verifying answers no.
    assert composite.verify(key.public_key, message, key.sign(message, bytes(255)), bytes(255))
    with pytest.raises(ValueError):
        key.sign(message, bytes(256))
    assert not composite.verify(key.public_key, message, first, bytes(256))
    for bad in (None, "text", 5, bytearray(first), first[:-1], first + b"\x00", b""):
        assert not composite.verify(key.public_key, message, bad)                  # type: ignore[arg-type]
        assert not composite.verify(bad, message, first)                           # type: ignore[arg-type]
    assert not composite.verify(key.public_key, "text", first)                     # type: ignore[arg-type]
    assert not composite.verify(key.public_key, message, first, "text")            # type: ignore[arg-type]
    # Any 1,952 bytes are an ML-DSA public key: such a key verifies nothing.
    assert not composite.verify(bytes(PK) + key.public_key[PK:], message, first)
    for bad_key in (b"", bytes(63), bytes(65), "text", None):
        with pytest.raises(ValueError):
            composite.CompositePrivateKey(bad_key)                                  # type: ignore[arg-type]
    for bad_message in ("text", None, bytearray(message)):
        with pytest.raises(TypeError):
            key.sign(bad_message)                                                   # type: ignore[arg-type]


def test_the_module_gives_no_access_to_a_component_key():
    """RFC 10073 forbids using a component key outside the composite, and
    the note says that no function of Kern signs with one component or
    returns one (section 3.3). What the module offers is listed here: a
    function added to it changes this test."""
    key = _key()
    assert "CompositePrivateKey" in repr(key) and bytes([7]).hex() * 8 not in repr(key)
    assert [name for name in dir(key) if not name.startswith("_")] == ["public_key", "sign"]
    assert not hasattr(key, "__dict__")                                 # nothing else can be attached to it
    defined = {name for name, value in vars(composite).items()
               if not name.startswith("_") and (inspect.isfunction(value) or inspect.isclass(value))
               and value.__module__ == composite.__name__}
    assert defined == {"message_representative", "libsodium_shortcomings", "ed25519_public_key_is_valid",
                       "ed25519_verify", "CompositePrivateKey", "public_key_from_private", "sign", "verify"}
    # The two functions about Ed25519 alone verify, for precompile 0x01 and for the check
    # of a key that is recorded. Nothing signs with Ed25519 alone, or with ML-DSA alone.
    signing = {name for name in defined if "sign" in name and name != "message_representative"}
    assert signing == {"sign"}


# ---------------------------------------------------------------------------
# The signatures the two reference programs exchanged, both halves
# ---------------------------------------------------------------------------

# The cases of `invalid` in which one half is right: only the other half refuses them.
WRONG_IN_MLDSA_ONLY = {
    "ML-DSA part of another message, Ed25519 part right",
    "one bit changed in the ML-DSA part",
    "ML-DSA part signed with an empty ML-DSA context instead of the Label",
}
WRONG_IN_ED25519_ONLY = {
    "Ed25519 part of another message, ML-DSA part right",
    "one bit changed in the Ed25519 part",
    "Ed25519 public key of order 1, with the signature a lenient verifier accepts for it",
}


@pytest.mark.parametrize("maker", ["python", "go"])
def test_the_signatures_of_both_programs_verify_whole_in_their_context_only(maker):
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    assert [c["purpose"] for c in SIGNED[maker]] == list(ref.PURPOSES) and len(ref.PURPOSES) == 7
    for c in SIGNED[maker]:
        signature = H(c["signature"])
        assert composite.verify(public_key, message, signature, ref.signing_context(c["purpose"], NETWORK))
        for other in ref.PURPOSES:
            if other != c["purpose"]:
                assert not composite.verify(public_key, message, signature, ref.signing_context(other, NETWORK))
        assert not composite.verify(public_key, message, signature, ref.signing_context(c["purpose"], OTHER_NETWORK))
        assert not composite.verify(public_key, message + b" ", signature, ref.signing_context(c["purpose"], NETWORK))
        assert not composite.verify(public_key, message, signature)                # no context at all


def test_the_signed_key_is_the_one_the_derivation_vectors_give():
    derivation = json.loads(ref.VECTORS.read_text(encoding="utf-8"))["derivation"][0]
    assert (SIGNED["seed"], SIGNED["network_id"]) == (derivation["seed"], derivation["network_id"])
    assert composite.public_key_from_private(H(derivation["composite_private"])) == H(SIGNED["public_key"])


def test_what_a_verifier_must_refuse_is_refused_and_by_which_half():
    public_key, message = H(SIGNED["public_key"]), H(SIGNED["message"])
    context = ref.signing_context("kern.tx", NETWORK)
    representative = composite.message_representative(message, context)
    assert len(SIGNED["invalid"]) == 17 == len({c["why"] for c in SIGNED["invalid"]})
    ed25519_right, mldsa_right = set(), set()
    for c in SIGNED["invalid"]:
        key, signature = (H(c["public_key"]) if "public_key" in c else public_key), H(c["signature"])
        assert not composite.verify(key, message, signature, context), c["why"]
        if len(key) != composite.PUBLIC_KEY_BYTES or len(signature) != composite.SIGNATURE_BYTES:
            continue
        if composite.ed25519_verify(key[PK:], representative, signature[SIG:]):
            ed25519_right.add(c["why"])
        if _mldsa_verifies(key[:PK], signature[:SIG], representative, composite.LABEL):
            mldsa_right.add(c["why"])
    # Either component broken, the other one right: refused both ways.
    assert ed25519_right == WRONG_IN_MLDSA_ONLY
    assert mldsa_right == WRONG_IN_ED25519_ONLY


# ---------------------------------------------------------------------------
# The values of the reference vectors that need ML-DSA
# ---------------------------------------------------------------------------

def test_the_derivation_vectors_give_the_stated_public_keys_and_addresses():
    for d in json.loads(ref.VECTORS.read_text(encoding="utf-8"))["derivation"]:
        public_key = composite.public_key_from_private(H(d["composite_private"]))
        assert hashlib.sha3_384(public_key[:PK]).hexdigest() == d["mldsa65_public_key_sha3_384"]
        assert public_key[PK:].hex() == d["ed25519_public_key"]
        assert hashlib.sha3_384(public_key).hexdigest() == d["composite_public_key_sha3_384"]
        assert ref.account_address(H(d["network_id"]), public_key) == d["address"]
