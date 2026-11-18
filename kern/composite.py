# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.composite
--------------

Composite ML-DSA signatures as standardized by the IETF (RFC 10073), in the
one combination Kern uses: ML-DSA-65 with Ed25519
(id-MLDSA65-Ed25519-SHA512).

A composite signature is an ML-DSA-65 signature followed by an Ed25519
signature, both made over the same message representative M'. It is valid
only if both are: there is no mode in which one component is enough.

This module is the mechanism of the RFC and nothing else. It knows nothing
of Kern: no network, no purpose, no key derivation, no text form, no
address. Those belong to the profile (docs/hybrid-signatures.md), and to
kern.keys.

Nothing in the node uses this module yet: every signature the chain checks
is still Ed25519 (docs/cryptographic-inventory.md).

What a caller must keep in mind (RFC 10073, sections 9.2 and 9.3):
- signing is randomized: two signatures of one message have other bytes;
- whoever breaks Ed25519 can replace the Ed25519 component of a signature
  he has seen, so a message is never identified by the bytes of its
  signature;
- a component key is never used alone, and this module offers no way to.
"""

from __future__ import annotations

import hashlib

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Kern requires the `cryptography` package, for ML-DSA. Install the "
        "requirements: `pip install -r requirements.txt`."
    ) from exc

try:
    import nacl.bindings as sodium  # type: ignore
    from nacl.exceptions import CryptoError  # type: ignore
    from nacl.signing import SigningKey, VerifyKey  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Kern requires PyNaCl. Install with `pip install pynacl`."
    ) from exc


# --- Parameters of id-MLDSA65-Ed25519-SHA512 --------------------------------

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"

MLDSA_SEED_BYTES = 32
ED25519_SEED_BYTES = 32
PRIVATE_KEY_BYTES = MLDSA_SEED_BYTES + ED25519_SEED_BYTES              # 64

MLDSA_PUBLIC_KEY_BYTES = 1952
ED25519_PUBLIC_KEY_BYTES = 32
PUBLIC_KEY_BYTES = MLDSA_PUBLIC_KEY_BYTES + ED25519_PUBLIC_KEY_BYTES   # 1,984

MLDSA_SIGNATURE_BYTES = 3309
ED25519_SIGNATURE_BYTES = 64
SIGNATURE_BYTES = MLDSA_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES      # 3,373

MAX_CONTEXT_BYTES = 255

try:
    # Version 47 of the package has the module and no ML-DSA behind it, and so
    # does a build of the package over a library that has none. A node that
    # cannot verify must not start, rather than refuse everything.
    mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(MLDSA_SEED_BYTES))
except UnsupportedAlgorithm as exc:  # pragma: no cover
    raise ImportError(
        "The installed `cryptography` package does not provide ML-DSA-65, "
        "which it has from version 48. Install the requirements: "
        "`pip install -r requirements.txt`."
    ) from exc


def message_representative(message: bytes, context: bytes = b"") -> bytes:
    """M' of RFC 10073, section 2.2: the bytes both components sign.

    `context` is the context of the application, at most 255 bytes. It is
    not the context parameter of ML-DSA, which is always the label.
    """
    if not isinstance(message, bytes) or not isinstance(context, bytes):
        raise TypeError("message and context must be bytes")
    if len(context) > MAX_CONTEXT_BYTES:
        raise ValueError("a context is at most 255 bytes")
    return PREFIX + LABEL + bytes([len(context)]) + context + hashlib.sha512(message).digest()


# --- Ed25519, one verdict ---------------------------------------------------
#
# Implementations of Ed25519 do not all accept the same signatures: RFC 8032
# leaves a choice in the verification equation and says nothing of points of
# small order. Two clients that disagreed on one signature would split the
# chain, so Kern fixes one rule (docs/hybrid-signatures.md, section 2.5).
# With B the base point, L the order of the subgroup it generates and
# p = 2^255 - 19:
#
#   1. the public key A is 32 bytes and the signature 64 bytes, R then S;
#   2. A is the canonical encoding of a point of the curve, that point is in
#      the subgroup of prime order ([L]A = O) and is not the identity O;
#   3. R is the canonical encoding of a point of the curve, and is not O;
#   4. S is below L;
#   5. [S]B = R + [k]A holds exactly, not after multiplication by the
#      cofactor, with k = SHA-512(R || A || message) mod L.
#
# The rule is a definition of Kern, not the behaviour of a library:
# libsodium alone accepts a public key of mixed order, which rule 2 refuses.
# tests/ed25519_reference.py computes the same rule as plain arithmetic, and
# tests/vectors/kern/ed25519_edge_cases.json holds the cases on which
# implementations disagree.
#
# libsodium does the arithmetic here: it answers whether A is a point of the
# subgroup (rule 2), and it checks the equation (rule 5). Both answers have
# differed from one library, and from one version, to another. Before its
# correction published as CVE-2025-69277, which PyNaCl ships from version
# 1.6.2, libsodium took a point of prime order plus the point of order 2
# for a point of the subgroup. And a library may check the equation after
# multiplication by the cofactor, as RFC 8032 allows: it then accepts
# signatures that rule 5 refuses. The version of PyNaCl does not settle
# either question: PyNaCl can be built over the libsodium of the system.
# So this module asks the library a few questions whose answers are known,
# once, when it is imported, and refuses to load if one answer is not the
# expected one: a node that would give another verdict than the other
# clients must not start.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_IDENTITY = (1).to_bytes(32, "little")

# The known answers. All of them are in tests/vectors/kern/ed25519_edge_cases.json,
# where tests/ed25519_reference.py computes their verdicts with no library.
_KNOWN_KEY = bytes.fromhex("1a532ac3aab123c61d37c5e916422f8446069dc637a030ba1a5615cc5894616d")
_KNOWN_NOT_KEYS = (
    # The key above plus a point of order 2, of order 4, of order 8: on the
    # curve, in canonical encoding, and not in the subgroup of prime order.
    bytes.fromhex("d3acd53c554edc39e2c83a16e9bdd07bb9f96239c85fcf45e5a9ea33a76b9e92"),
    bytes.fromhex("b8bd074086377c793e4519880ee48066419410e9e8eba5dfae9c2023c19d7f77"),
    bytes.fromhex("1bad1d43116a7bc3268364dc50420617e512f41f3f6067b2348f4004ae796f60"),
    _IDENTITY,
)
_KNOWN_SIGNATURE = (b"kern", bytes.fromhex(
    "ff657608fc94de147a66ea827a5145e0c3bc3d6a22a50393f7a44574a865f421"
    "178d4a6946b0f1432e99608bc71f3a3910a918237620a040d1dbc66dae39bf0d"))
# By the same key, with a nonce point of mixed order: 8[S]B = 8R + 8[k]A
# holds, [S]B = R + [k]A does not.
_KNOWN_COFACTORED_ONLY = (b"kern mixed R", bytes.fromhex(
    "3deb8ca9e3d031548d729bed3aa7f3840e256888362f1ea239c189f03b281f24"
    "b57dd366f1bdad71189aa8aba2fe4f512fdd782cce3597032f64be36a7a50a07"))


def _libsodium_verifies(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except CryptoError:
        return False


def libsodium_shortcomings() -> list[str]:
    """What the installed libsodium answers wrongly, for the rule above:
    an empty list when it can be relied on. Called once at import."""
    if not getattr(sodium, "has_crypto_core_ed25519", False):
        return ["it was built without the operations on points of the curve (a minimal build)"]
    found = []
    if not sodium.crypto_core_ed25519_is_valid_point(_KNOWN_KEY):
        found.append("it refuses a public key of the subgroup of prime order")
    if any(sodium.crypto_core_ed25519_is_valid_point(point) for point in _KNOWN_NOT_KEYS):
        found.append("it takes a point outside the subgroup of prime order for a public key "
                     "(corrected in libsodium as CVE-2025-69277)")
    if not _libsodium_verifies(_KNOWN_KEY, *_KNOWN_SIGNATURE):
        found.append("it refuses an ordinary signature")
    if _libsodium_verifies(_KNOWN_KEY, *_KNOWN_COFACTORED_ONLY):
        found.append("it accepts a signature that only holds after multiplication by the cofactor")
    return found


_shortcomings = libsodium_shortcomings()
if _shortcomings:  # pragma: no cover
    raise ImportError(
        "The installed libsodium does not give the answers the Ed25519 rule of Kern "
        "relies on: " + "; ".join(_shortcomings) + ". Kern requires PyNaCl 1.6.2 or "
        "later, with the libsodium it ships: `pip install -r requirements.txt`."
    )


def ed25519_public_key_is_valid(public_key: bytes) -> bool:
    """Rule 2: 32 bytes that are the canonical encoding of a point of the
    subgroup of prime order, other than the identity. Checked whenever a
    key is recorded and whenever a signature is verified."""
    if not isinstance(public_key, bytes) or len(public_key) != ED25519_PUBLIC_KEY_BYTES:
        return False
    # libsodium: canonical, on the curve, on the main subgroup, not of small order.
    return bool(sodium.crypto_core_ed25519_is_valid_point(public_key))


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature under the rule above. Never raises:
    anything malformed is an invalid signature."""
    try:
        if not (isinstance(message, bytes) and isinstance(signature, bytes)):
            return False
        if len(signature) != ED25519_SIGNATURE_BYTES or not ed25519_public_key_is_valid(public_key):
            return False
        r = signature[:31] + bytes([signature[31] & 0x7F])          # y, without the sign bit
        if int.from_bytes(r, "little") >= _P or r == _IDENTITY:
            return False
        if int.from_bytes(signature[32:], "little") >= _L:
            return False
        # The exact equation. It also refuses an R that is not a point, and,
        # A being in the subgroup of prime order, an R that is not in it.
        VerifyKey(public_key).verify(message, signature)
        return True
    except (CryptoError, ValueError, TypeError):
        return False


# --- Keys, signing, verification --------------------------------------------

class CompositePrivateKey:
    """A composite private key: the ML-DSA seed followed by the Ed25519
    seed, 64 bytes (RFC 10073, section 4.2). Both component keys are
    expanded once, when the object is made.

    The object signs with both components and with nothing less. It gives
    no access to a component key.
    """

    __slots__ = ("_mldsa", "_ed25519", "public_key")

    def __init__(self, private_key: bytes) -> None:
        if not isinstance(private_key, bytes) or len(private_key) != PRIVATE_KEY_BYTES:
            raise ValueError("a composite private key is 64 bytes")
        self._mldsa = mldsa.MLDSA65PrivateKey.from_seed_bytes(private_key[:MLDSA_SEED_BYTES])
        self._ed25519 = SigningKey(private_key[MLDSA_SEED_BYTES:])
        # ML-DSA public key, then Ed25519 public key: 1,984 bytes.
        self.public_key: bytes = (self._mldsa.public_key().public_bytes_raw()
                                  + bytes(self._ed25519.verify_key))

    def sign(self, message: bytes, context: bytes = b"") -> bytes:
        """Return a composite signature of `message` in `context`: the
        ML-DSA signature followed by the Ed25519 signature, 3,373 bytes.
        Raises on a context longer than 255 bytes. Two calls return
        different bytes."""
        representative = message_representative(message, context)
        return (self._mldsa.sign(representative, LABEL)
                + self._ed25519.sign(representative).signature)

    def __repr__(self) -> str:
        return "<CompositePrivateKey>"


def public_key_from_private(private_key: bytes) -> bytes:
    """The public key of a 64-byte composite private key."""
    return CompositePrivateKey(private_key).public_key


def sign(private_key: bytes, message: bytes, context: bytes = b"") -> bytes:
    """Sign with a 64-byte composite private key. Callers that sign more
    than once keep a `CompositePrivateKey`, which expands the key once."""
    return CompositePrivateKey(private_key).sign(message, context)


def verify(public_key: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
    """True if `signature` is a composite signature of `message` in
    `context` under `public_key`, which takes both components to be valid.

    Never raises. A key or a signature of another length, a context that is
    too long, a value that is not bytes: all of it is an invalid signature.
    An Ed25519 signature alone, or an ML-DSA signature alone, has the wrong
    length and is refused like the rest.
    """
    try:
        if not (isinstance(public_key, bytes) and isinstance(signature, bytes)):
            return False
        if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
            return False
        representative = message_representative(message, context)
        if not ed25519_verify(public_key[MLDSA_PUBLIC_KEY_BYTES:], representative,
                              signature[MLDSA_SIGNATURE_BYTES:]):
            return False
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key[:MLDSA_PUBLIC_KEY_BYTES]).verify(
            signature[:MLDSA_SIGNATURE_BYTES], representative, LABEL)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
