# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.crypto
-----------

Cryptographic primitives for Kern:
- Ed25519 signature scheme (public keys, signing, verification)
- blake2b-256 hashing
- Address derivation (kn1... format, base58check)

Choice notes:
- Ed25519 chosen for fast verification, deterministic signatures, and 32-byte
  public keys. Schnorr/BLS aggregation is a planned upgrade.
- blake2b-256 chosen over SHA-256 for speed and because it admits a keyed
  variant useful for domain separation across protocol contexts.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Tuple

try:
    from nacl.signing import SigningKey, VerifyKey  # type: ignore
    from nacl.exceptions import BadSignatureError  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Kern requires PyNaCl. Install with `pip install pynacl`."
    ) from exc


# --- Hashing ---------------------------------------------------------------

def blake2b256(data: bytes, *, key: bytes = b"") -> bytes:
    """Return the 32-byte blake2b-256 digest of `data`.

    A non-empty `key` enables domain separation. The protocol uses keyed
    hashes for block ids ("kern.block"), transaction ids ("kern.tx"),
    and address derivation ("kern.addr").
    """
    h = hashlib.blake2b(data, digest_size=32, key=key)
    return h.digest()


def block_hash(header_bytes: bytes) -> bytes:
    return blake2b256(header_bytes, key=b"kern.block")


def tx_hash(tx_bytes: bytes) -> bytes:
    return blake2b256(tx_bytes, key=b"kern.tx")


# --- Base58check (Bitcoin-derived encoding) -------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    # leading zero bytes -> leading '1's
    for b in data:
        if b == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    return out[::-1].decode("ascii")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ord(ch))
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def b58check_encode(prefix: bytes, payload: bytes) -> str:
    body = prefix + payload
    checksum = blake2b256(body)[:4]
    return _b58encode(body + checksum)


def b58check_decode(s: str, expected_prefix: bytes) -> bytes:
    raw = _b58decode(s)
    body, checksum = raw[:-4], raw[-4:]
    if blake2b256(body)[:4] != checksum:
        raise ValueError("invalid checksum")
    if not body.startswith(expected_prefix):
        raise ValueError(f"unexpected prefix; want {expected_prefix.hex()}")
    return body[len(expected_prefix):]


# Prefixes — chosen so that encoded forms have a stable, recognizable
# leading substring for the most common case (20-byte payload for
# addresses, 32-byte for public keys, 64-byte for signatures). Addresses
# always begin with "kn1...".
PREFIX_ADDRESS = b"\x05\x95\x9b"         # 'kn1' prefix (20-byte payload)
PREFIX_PUBKEY = b"\x0d\x0f\x25"          # public key, prints as e.g. '9XYe...'
PREFIX_SIGNATURE = b"\x09\xf5\xcd\x86"   # signature, prints as e.g. 'edsig...'


# --- Keys & addresses -----------------------------------------------------

@dataclass(frozen=True)
class KernKeypair:
    """An Ed25519 keypair. `seed` is the 32-byte secret; everything else
    is derived from it."""

    seed: bytes  # 32 bytes

    @classmethod
    def generate(cls) -> "KernKeypair":
        return cls(seed=os.urandom(32))

    @classmethod
    def from_seed(cls, seed: bytes) -> "KernKeypair":
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(seed=seed)

    @property
    def _signing_key(self) -> SigningKey:
        return SigningKey(self.seed)

    @property
    def public_key(self) -> bytes:
        return bytes(self._signing_key.verify_key)

    @property
    def public_key_b58(self) -> str:
        return b58check_encode(PREFIX_PUBKEY, self.public_key)

    @property
    def address(self) -> str:
        """The on-chain account identifier. blake2b-160 of the public key,
        base58check-encoded with the 'kn1' prefix."""
        h = hashlib.blake2b(self.public_key, digest_size=20, key=b"kern.addr").digest()
        return b58check_encode(PREFIX_ADDRESS, h)

    def sign(self, message: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over `message`."""
        return self._signing_key.sign(message).signature

    def sign_b58(self, message: bytes) -> str:
        return b58check_encode(PREFIX_SIGNATURE, self.sign(message))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff `signature` is a valid Ed25519 signature over
    `message` by `public_key`.

    Fails *closed* on every error path. A malformed public key or
    signature (wrong length, non-bytes) makes PyNaCl raise ``ValueError``
    or ``TypeError`` rather than ``BadSignatureError``; treating those as
    a verification failure (rather than letting them propagate) keeps this
    primitive safe to call on fully attacker-controlled input. Callers in
    transaction/block/bft/rollup already guard this, but defence in depth
    means the primitive must never raise on bad input.
    """
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def address_from_pubkey(public_key: bytes) -> str:
    h = hashlib.blake2b(public_key, digest_size=20, key=b"kern.addr").digest()
    return b58check_encode(PREFIX_ADDRESS, h)


def pubkey_from_b58(s: str) -> bytes:
    return b58check_decode(s, PREFIX_PUBKEY)


def signature_from_b58(s: str) -> bytes:
    return b58check_decode(s, PREFIX_SIGNATURE)
