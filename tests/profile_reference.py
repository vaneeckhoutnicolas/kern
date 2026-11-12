# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The functions of the signature profile, written with the standard library.

Not a test file and not the node. docs/hybrid-signatures.md specifies, byte
for byte, how the release in preparation encodes, hashes, derives keys and
builds addresses. This file is that specification as executable text: it
produced tests/vectors/kern/profile.json, and the Go program kept next to
that file computes the same values with the Go standard library alone.

Nothing here is used by the node, which still hashes with BLAKE2b and signs
with Ed25519 (docs/cryptographic-inventory.md). Running this file rebuilds
the vectors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

SCHEME = 1
NETWORK_ID_BYTES = 32
HASH_BYTES = 48

# ---------------------------------------------------------------------------
# Section 4.3: canonical JSON
# ---------------------------------------------------------------------------

INT_MIN, INT_MAX = -(2**63), 2**63 - 1


def _check_value(value: object) -> None:
    """Only objects, arrays, strings, integers of 64 bits and booleans."""
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if not INT_MIN <= value <= INT_MAX:
            raise ValueError("integer outside the signed 64-bit range")
        return
    if isinstance(value, list):
        for item in value:
            _check_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("object keys are strings")
            _check_value(item)
        return
    raise ValueError(f"{type(value).__name__} has no canonical form")     # null, floats, anything else


def canonical_json(value: object) -> bytes:
    """The one encoding of a value: UTF-8, no white space, keys sorted by
    their UTF-8 bytes, integers in decimal, strings with the shortest
    escapes (RFC 8785, section 3.2.2.2). Raises ValueError on a value that
    has none (null, a float, an integer too large, an invalid string)."""
    _check_value(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except UnicodeEncodeError as exc:                 # a lone surrogate
        raise ValueError("string that is not valid Unicode") from exc


def _refuse(literal: str) -> object:
    raise ValueError(f"{literal!r} is not an integer")


def decode_canonical(data: bytes) -> object:
    """Decode bytes that must be the canonical encoding of their value.
    Anything else is refused: white space, another key order, a repeated
    key, a float, an exponent, a leading zero, null, another spelling of a
    string, bytes that are not UTF-8."""
    try:
        text = data.decode("utf-8")
        value = json.loads(text, parse_float=_refuse, parse_constant=_refuse)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("not JSON in UTF-8") from exc
    if canonical_json(value) != data:
        raise ValueError("not the canonical encoding")
    return value


# ---------------------------------------------------------------------------
# Section 4.1: one hash function
# ---------------------------------------------------------------------------

def H(domain: str, network_id: bytes, data: bytes) -> bytes:
    """SHA3-384( len(domain) || domain || network_id || data )."""
    name = domain.encode("ascii")
    if not 1 <= len(name) <= 255 or len(network_id) != NETWORK_ID_BYTES:
        raise ValueError("domain of 1 to 255 bytes, network identifier of 32 bytes")
    return hashlib.sha3_384(bytes([len(name)]) + name + network_id + data).digest()


# ---------------------------------------------------------------------------
# Section 4.4: Merkle trees (the structure of RFC 6962, section 2.1)
# ---------------------------------------------------------------------------

def merkle_root(network_id: bytes, items: list[bytes]) -> bytes:
    n = len(items)
    if n == 0:
        return H("kern.merkle.empty", network_id, b"")
    if n == 1:
        return H("kern.merkle.leaf", network_id, items[0])
    k = 1
    while k * 2 < n:                                  # the largest power of two below n
        k *= 2
    return H("kern.merkle.node", network_id,
             merkle_root(network_id, items[:k]) + merkle_root(network_id, items[k:]))


# ---------------------------------------------------------------------------
# Section 3.2: key derivation (HKDF with SHA-512, RFC 5869)
# ---------------------------------------------------------------------------

DERIVATION_LABEL = b"KERN-KEY-DERIVATION-V1"
COMPONENTS = ("mldsa65", "ed25519", "ed25519-standalone")


def hkdf_extract(seed: bytes) -> bytes:
    """PRK = HMAC-SHA-512(salt, IKM), with the 64 zero bytes RFC 5869 uses
    when no salt is given."""
    if len(seed) != 32:
        raise ValueError("a seed is 32 bytes")
    return hmac.new(bytes(64), seed, hashlib.sha512).digest()


def derivation_info(network_id: bytes, component: str) -> bytes:
    if len(network_id) != NETWORK_ID_BYTES or component not in COMPONENTS:
        raise ValueError("network identifier of 32 bytes, known component")
    return DERIVATION_LABEL + bytes([SCHEME]) + network_id + component.encode("ascii")


def derive(seed: bytes, network_id: bytes, component: str) -> bytes:
    """The 32-byte seed of one component: the first 32 bytes of
    T(1) = HMAC-SHA-512(PRK, info || 0x01)."""
    info = derivation_info(network_id, component)
    return hmac.new(hkdf_extract(seed), info + b"\x01", hashlib.sha512).digest()[:32]


def composite_private_key(seed: bytes, network_id: bytes) -> bytes:
    """ML-DSA seed, then Ed25519 seed: the 64 bytes of RFC 10073."""
    return derive(seed, network_id, "mldsa65") + derive(seed, network_id, "ed25519")


# ---------------------------------------------------------------------------
# Section 6.2: signing contexts
# ---------------------------------------------------------------------------

PURPOSES = ("kern.tx", "kern.header", "kern.propose", "kern.preendorse",
            "kern.endorse", "kern.batch", "kern.rotate")


def signing_context(purpose: str, network_id: bytes) -> bytes:
    if purpose not in PURPOSES or len(network_id) != NETWORK_ID_BYTES:
        raise ValueError("unknown purpose, or network identifier that is not 32 bytes")
    return purpose.encode("ascii") + b"\x00" + network_id


# ---------------------------------------------------------------------------
# Section 5: addresses
# ---------------------------------------------------------------------------

ADDRESS_PREFIX = bytes.fromhex("7b0339")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data: bytes) -> str:
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def address_from_hash(network_id: bytes, digest: bytes) -> str:
    """prefix || hash || checksum in base 58. The checksum is the first
    four bytes of H("kern.checksum", network, prefix || hash): Kern's own,
    not the one of Bitcoin."""
    if len(digest) != HASH_BYTES:
        raise ValueError("an address holds a hash of 48 bytes")
    body = ADDRESS_PREFIX + digest
    return base58(body + H("kern.checksum", network_id, body)[:4])


def account_address(network_id: bytes, public_key: bytes) -> str:
    return address_from_hash(network_id, H("kern.addr", network_id, bytes([SCHEME]) + public_key))


# ---------------------------------------------------------------------------
# Section 6.3: what a transaction carries besides what it signs
# ---------------------------------------------------------------------------

PUBLIC_KEY_BYTES, SIGNATURE_BYTES = 1984, 3373


def witness_leaf(network_id: bytes, transaction_id: bytes, signature: bytes,
                 public_key: bytes | None = None, second_signature: bytes | None = None) -> bytes:
    """H("kern.witness", network, transaction_id || flags || [public key]
    || signature || [second signature]). Bit 0 of the flags says that the
    public key of the sender is carried (first transaction of an account),
    bit 1 that a second signature is (the new key, in `rotate_key`)."""
    if len(transaction_id) != HASH_BYTES or len(signature) != SIGNATURE_BYTES:
        raise ValueError("identifier of 48 bytes, signature of 3,373 bytes")
    if public_key is not None and len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("public key of 1,984 bytes")
    if second_signature is not None and len(second_signature) != SIGNATURE_BYTES:
        raise ValueError("signature of 3,373 bytes")
    flags = (1 if public_key is not None else 0) | (2 if second_signature is not None else 0)
    return H("kern.witness", network_id,
             transaction_id + bytes([flags]) + (public_key or b"") + signature + (second_signature or b""))


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------

def _with_mldsa(mldsa_seed: bytes, ed25519_public_key: bytes, network_id: bytes) -> dict:
    """The values that need ML-DSA.KeyGen_internal (FIPS 204, algorithm 6).
    They are computed with the `cryptography` package when the vectors are
    rebuilt, and checked by the tests that come with the implementation:
    the node does not depend on that package yet."""
    from cryptography.hazmat.primitives.asymmetric import mldsa

    mldsa_public_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed).public_key().public_bytes_raw()
    public_key = mldsa_public_key + ed25519_public_key
    return {
        "mldsa65_public_key_sha3_384": hashlib.sha3_384(mldsa_public_key).hexdigest(),
        "composite_public_key_sha3_384": hashlib.sha3_384(public_key).hexdigest(),
        "address": account_address(network_id, public_key),
    }


VECTORS = Path(__file__).resolve().parent / "vectors" / "kern" / "profile.json"

CANONICAL_VALUES: list[object] = [
    {},
    [],
    {"b": 1, "a": 2},
    {"level": 7, "valid_round": -1, "block_hash": "ab", "kind": "propose"},
    {"a": [True, False, {"z": [], "y": {}}], "A": 0},
    {"min": INT_MIN, "max": INT_MAX, "zero": 0},
    {"text": "quote \" backslash \\ slash / tab \t newline \n"},
    {"text": "\b\f\r\u0000\u001f\u007f"},
    {"text": "café   \U0001f600 <&>"},
    {"é": 1, "z": 2, "": 3, "\U0001f600": 4, "": 5},
    ["1", 1, "01", "-0", "1.0", "true"],
]

NOT_CANONICAL: list[tuple[str, bytes]] = [
    ("space after a colon", b'{"a": 1}'),
    ("line feed at the end", b'{"a":1}\n'),
    ("keys not sorted", b'{"b":1,"a":2}'),
    ("key repeated", b'{"a":1,"a":2}'),
    ("null", b'{"a":null}'),
    ("decimal point", b'{"a":1.0}'),
    ("exponent", b'{"a":1e3}'),
    ("leading zero", b'{"a":01}'),
    ("minus zero", b'{"a":-0}'),
    ("plus sign", b'{"a":+1}'),
    ("integer above 2^63 - 1", b'{"a":9223372036854775808}'),
    ("integer below -2^63", b'{"a":-9223372036854775809}'),
    ("slash escaped", b'{"a":"\\/"}'),
    ("letter written as an escape", b'{"a":"\\u0061"}'),
    ("accented letter written as an escape", b'{"a":"\\u00e9"}'),
    ("control character escaped in upper case", b'{"a":"\\u001F"}'),
    ("tab written as \\u0009", b'{"a":"\\u0009"}'),
    ("lone surrogate", b'{"a":"\\ud800"}'),
    ("byte order mark", b'\xef\xbb\xbf{"a":1}'),
    ("bytes that are not UTF-8", b'{"a":"\xff"}'),
    ("NaN", b'{"a":NaN}'),
    ("single quotes", b"{'a':1}"),
    ("comma at the end", b'{"a":1,}'),
    ("nothing", b""),
]


def build_vectors() -> dict:
    seed = bytes(range(32))
    network = bytes(range(0xA0, 0xC0))
    other_network = bytes(range(0xC0, 0xE0))
    key_bytes = bytes((7 * i + 3) % 256 for i in range(PUBLIC_KEY_BYTES))          # any 1,984 bytes
    signature = bytes((5 * i + 1) % 256 for i in range(SIGNATURE_BYTES))           # any 3,373 bytes
    second = bytes((3 * i + 2) % 256 for i in range(SIGNATURE_BYTES))
    transaction_id = H("kern.tx", network, b"a transaction")
    items = [bytes([i]) * HASH_BYTES for i in range(8)]

    def derivation(net: bytes) -> dict:
        import ed25519_reference                          # Ed25519 from RFC 8032, no library
        out = {
            "seed": seed.hex(), "network_id": net.hex(), "salt": bytes(64).hex(),
            "prk": hkdf_extract(seed).hex(),
            "components": [{"name": c, "info": derivation_info(net, c).hex(), "output": derive(seed, net, c).hex()}
                           for c in COMPONENTS],
            "composite_private": composite_private_key(seed, net).hex(),
            "ed25519_public_key": ed25519_reference.public_key(derive(seed, net, "ed25519")).hex(),
            "ed25519_standalone_public_key":
                ed25519_reference.public_key(derive(seed, net, "ed25519-standalone")).hex(),
        }
        out.update(_with_mldsa(derive(seed, net, "mldsa65"), bytes.fromhex(out["ed25519_public_key"]), net))
        return out

    return {
        "description": "Reference vectors of docs/hybrid-signatures.md. Bytes are in hexadecimal. "
                       "Rebuilt by tests/profile_reference.py; tests/vectors/kern/profile_check.go "
                       "computes the same values with the Go standard library, except the three of "
                       "each derivation that need ML-DSA (mldsa65_public_key_sha3_384, "
                       "composite_public_key_sha3_384, address), which come from one implementation.",
        "network_id": network.hex(),
        "canonical_json": [{"value": v, "encoding": canonical_json(v).hex()} for v in CANONICAL_VALUES],
        "not_canonical": [{"why": why, "bytes": data.hex()} for why, data in NOT_CANONICAL],
        "hash": [{"domain": d, "data": x.hex(), "digest": H(d, network, x).hex()}
                 for d, x in (("kern.tx", b""), ("kern.block", b"abc"), ("kern.state", bytes(range(256))),
                              ("kern.merkle.empty", b""))]
                + [{"domain": "kern.tx", "network_id": other_network.hex(), "data": "",
                    "digest": H("kern.tx", other_network, b"").hex()}],
        "merkle": [{"items": [i.hex() for i in items[:n]], "root": merkle_root(network, items[:n]).hex()}
                   for n in (0, 1, 2, 3, 4, 5, 6, 7, 8)],
        "derivation": [derivation(network), derivation(other_network)],
        "contexts": [{"purpose": p, "context": signing_context(p, network).hex()} for p in PURPOSES],
        "address": {"public_key_rule": "byte i is (7 * i + 3) mod 256, for 1,984 bytes: not a real key",
                    "address": account_address(network, key_bytes),
                    "address_other_network": account_address(other_network, key_bytes),
                    "hash": H("kern.addr", network, bytes([SCHEME]) + key_bytes).hex()},
        "witness": {"transaction_id": transaction_id.hex(),
                    "public_key_rule": "byte i is (7 * i + 3) mod 256, for 1,984 bytes",
                    "signature_rule": "byte i is (5 * i + 1) mod 256, for 3,373 bytes",
                    "second_signature_rule": "byte i is (3 * i + 2) mod 256, for 3,373 bytes",
                    "leaves_by_flags": {
                        "0": witness_leaf(network, transaction_id, signature).hex(),
                        "1": witness_leaf(network, transaction_id, signature, key_bytes).hex(),
                        "2": witness_leaf(network, transaction_id, signature, None, second).hex(),
                        "3": witness_leaf(network, transaction_id, signature, key_bytes, second).hex()}},
    }


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    VECTORS.parent.mkdir(parents=True, exist_ok=True)
    VECTORS.write_text(json.dumps(build_vectors(), indent=1, ensure_ascii=False) + "\n",
                       encoding="utf-8", newline="\n")
    print(f"wrote {VECTORS}")
