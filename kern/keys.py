# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.keys
---------

The signature profile of Kern (docs/hybrid-signatures.md) over the
mechanism of kern.composite: what binds a hash, a key, a signature and an
address to one network.

- one hash function, SHA3-384 with a domain and the network identifier,
  and the 27 domains of the protocol (section 4.1);
- canonical JSON: one sequence of bytes per value (section 4.3);
- Merkle trees built as in RFC 6962 (section 4.4);
- key derivation: one 32-byte seed gives, for one network, one account key
  and one key for contracts (section 3.2);
- signing contexts: a purpose and the network (section 6.2);
- the text forms of public keys and signatures (section 5);
- addresses of accounts and of contracts (section 5).

Every byte rule here is held by the vectors of tests/vectors/kern, which
tests/profile_reference.py and a Go program reproduce independently.

Nothing in the node uses this module yet: it still hashes with BLAKE2b and
signs with Ed25519 (docs/cryptographic-inventory.md). The object formats
that go with the profile, and the key registry, come with the node.

A component key is never used outside the composite (RFC 10073, sections
3.1 and 9.3). No function here signs with one component, and none returns
a component key or the composite private key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Iterable

from . import composite

SCHEME = 1                      # ML-DSA-65 with Ed25519, the combination of kern.composite
NETWORK_ID_BYTES = 32
SEED_BYTES = 32
HASH_BYTES = 48                 # every hash of the protocol is 384 bits

PUBLIC_KEY_BYTES = composite.PUBLIC_KEY_BYTES          # 1,984
SIGNATURE_BYTES = composite.SIGNATURE_BYTES            # 3,373


def _check_network_id(network_id: bytes) -> None:
    if not isinstance(network_id, bytes) or len(network_id) != NETWORK_ID_BYTES:
        raise ValueError("a network identifier is 32 bytes")


# --- Section 4.3: canonical JSON --------------------------------------------

_INT_MIN, _INT_MAX = -(2**63), 2**63 - 1

# Arrays and objects inside one another: 64 levels at most. The note sets no
# bound on nesting, and a decoder needs one of its own: how deep an
# interpreter follows changes with its version and with the state of the
# process, and bytes received must get the same answer everywhere. This is a
# limit of this implementation, far above what any object of the protocol
# holds, until the schemas give each object its bound. It is checked on the
# bytes before they are decoded, and on a value before it is encoded.
MAX_NESTING = 64

_STRING = re.compile(rb'"(?:[^"\\]|\\.)*(?:"|\\?\Z)', re.DOTALL)        # a string, closed or not
_NOT_BRACKETS = bytes(sorted(set(range(256)) - set(b"[]{}")))


def _check_nesting(data: bytes) -> None:
    """Refuse bytes whose arrays and objects are nested more than
    MAX_NESTING deep: the brackets outside strings are counted, in one
    pass over the bytes, before any decoder sees them."""
    if data.count(b"[") + data.count(b"{") <= MAX_NESTING:
        return
    depth = 0
    for byte in _STRING.sub(b"", data).translate(None, _NOT_BRACKETS):
        if byte in (0x5B, 0x7B):                      # [ and {
            depth += 1
            if depth > MAX_NESTING:
                raise ValueError(f"arrays and objects nested more than {MAX_NESTING} deep")
        else:
            depth -= 1


def _check_value(value: object, depth: int = 0) -> None:
    """Only objects, arrays, strings, integers of 64 bits and booleans,
    nested MAX_NESTING deep at most."""
    if isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise ValueError("an integer outside the signed 64-bit range has no canonical form")
        return
    if isinstance(value, (list, dict)):
        if depth >= MAX_NESTING:
            raise ValueError(f"arrays and objects nested more than {MAX_NESTING} deep")
        if isinstance(value, list):
            for item in value:
                _check_value(item, depth + 1)
            return
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("the keys of an object are strings")
            _check_value(item, depth + 1)
        return
    raise ValueError(f"{type(value).__name__} has no canonical form")     # null, a float, anything else


def canonical_json(value: object) -> bytes:
    """The one encoding of a value: UTF-8, no white space, the members of
    an object sorted by the UTF-8 bytes of their keys, integers in decimal,
    strings with the escapes of section 4.3 and no other.

    Raises ValueError on a value that has no canonical form: null, a
    float, an integer outside the signed 64-bit range, a string that is
    not valid Unicode, arrays and objects nested more than MAX_NESTING
    deep, anything that is not JSON.
    """
    _check_value(value)
    try:
        # Python compares strings by code point, which is the order of their UTF-8 bytes.
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except UnicodeEncodeError as exc:                 # a lone surrogate
        raise ValueError("a string that is not valid Unicode has no canonical form") from exc


def _refuse_number(literal: str) -> object:
    raise ValueError(f"{literal!r} is not an integer")


def decode_canonical(data: bytes) -> object:
    """Decode bytes that must be the canonical encoding of their value:
    they are decoded, encoded again and compared. Raises ValueError on
    anything else: white space, another key order, a repeated key, a
    float, an exponent, a leading zero, null, another spelling of a
    string, bytes that are not UTF-8, arrays and objects nested more than
    MAX_NESTING deep.

    This is the check of reception. Whether an object has the fields of
    its schema is another check, made by whoever knows the schema.
    """
    if not isinstance(data, bytes):
        raise ValueError("canonical JSON is a string of bytes")
    _check_nesting(data)
    try:
        value = json.loads(data.decode("utf-8"), parse_float=_refuse_number, parse_constant=_refuse_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("not JSON in UTF-8") from exc
    if canonical_json(value) != data:
        raise ValueError("not the canonical encoding of its value")
    return value


# --- Section 4.1: one hash function -----------------------------------------

# The domains whose data is a string of bytes laid out as section 4.1 says.
BYTE_DOMAINS = (
    "kern.merkle.empty", "kern.merkle.leaf", "kern.merkle.node", "kern.witness",
    "kern.addr", "kern.addr.contract", "kern.checksum", "kern.proposer",
    "kern.trie.key", "kern.trie.leaf", "kern.trie.branch", "kern.code", "kern.rollup.program",
    "kern.evm.code", "kern.evm.create", "kern.evm.create2", "kern.evm.signer",
)
# The domains whose data is the canonical JSON of an object.
OBJECT_DOMAINS = (
    "kern.tx", "kern.block", "kern.state", "kern.storage", "kern.batch", "kern.mailbox",
    "kern.gov.id", "kern.attestation.id", "kern.zk_claims.vk", "kern.evm",
)
DOMAINS = frozenset(BYTE_DOMAINS + OBJECT_DOMAINS)


def H(domain: str, network_id: bytes, data: bytes) -> bytes:
    """SHA3-384( len(domain) || domain || network_id || data ), 48 bytes.

    `domain` is one of the 27 names of section 4.1: a hash under another
    name is not a hash of the protocol, and raises ValueError. With the
    network identifier in every preimage, a hash of one network means
    nothing on another.
    """
    if not isinstance(domain, str) or domain not in DOMAINS:
        raise ValueError(f"not a hash domain of the protocol: {domain!r}")
    _check_network_id(network_id)
    if not isinstance(data, bytes):
        raise TypeError("what is hashed is a string of bytes")
    name = domain.encode("ascii")
    return hashlib.sha3_384(bytes([len(name)]) + name + network_id + data).digest()


# --- Section 4.4: Merkle trees ----------------------------------------------

def merkle_root(network_id: bytes, items: Iterable[bytes]) -> bytes:
    """The root of a list of items, each a string of bytes, with the
    structure of RFC 6962, section 2.1: the left subtree of `n` items holds
    the largest power of two strictly below `n`. The order counts, nothing
    is repeated to fill a level, and a leaf is never taken for a node."""
    leaves = list(items)
    for item in leaves:
        if not isinstance(item, bytes):
            raise TypeError("an item of a tree is a string of bytes")
    if not leaves:
        return H("kern.merkle.empty", network_id, b"")

    def root(start: int, end: int) -> bytes:
        n = end - start
        if n == 1:
            return H("kern.merkle.leaf", network_id, leaves[start])
        k = 1 << ((n - 1).bit_length() - 1)
        return H("kern.merkle.node", network_id, root(start, start + k) + root(start + k, end))

    return root(0, len(leaves))


# --- Section 6.2: signing contexts ------------------------------------------

PURPOSES = ("kern.tx", "kern.header", "kern.propose", "kern.preendorse",
            "kern.endorse", "kern.batch", "kern.rotate")


def signing_context(purpose: str, network_id: bytes) -> bytes:
    """The context a signature is made in: the purpose in ASCII, one zero
    byte, the network identifier. Raises ValueError on a purpose that is
    not one of the seven, or on a network identifier that is not 32 bytes."""
    if not isinstance(purpose, str) or purpose not in PURPOSES:
        raise ValueError(f"not a signing purpose: {purpose!r}")
    _check_network_id(network_id)
    return purpose.encode("ascii") + b"\x00" + network_id


# --- Section 5: text forms of public keys and signatures --------------------

PUBLIC_KEY_TEXT_PREFIX = "kpk1."
SIGNATURE_TEXT_PREFIX = "ksig1."
PUBLIC_KEY_TEXT_CHARACTERS = 2651
SIGNATURE_TEXT_CHARACTERS = 4504

_BASE64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _to_text(prefix: str, size: int, data: bytes) -> str:
    if not isinstance(data, bytes) or len(data) != size:
        raise ValueError(f"{size} bytes are written after {prefix}")
    return prefix + base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_text(prefix: str, size: int, characters: int, text: str) -> bytes:
    """One text per value: the exact prefix, the exact length, the 64
    characters of base64url and unused bits at zero. Everything else is
    refused: padding, another alphabet, white space, a last character
    whose unused bits are set."""
    if not isinstance(text, str) or len(text) != characters or not text.startswith(prefix):
        raise ValueError(f"not {characters} characters that begin with {prefix}")
    body = text[len(prefix):]
    if not _BASE64URL.issuperset(body):
        raise ValueError("a character that is not one of the 64 of base64url")
    data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if len(data) != size or _to_text(prefix, size, data) != text:
        raise ValueError("unused bits that are not zero")
    return data


def public_key_text(public_key: bytes) -> str:
    """`kpk1.` and the 1,984 bytes in base64url without padding: 2,651
    characters."""
    return _to_text(PUBLIC_KEY_TEXT_PREFIX, PUBLIC_KEY_BYTES, public_key)


def public_key_from_text(text: str) -> bytes:
    """The 1,984 bytes of a public key written as `kpk1.`. Raises
    ValueError on any other spelling. Whether the bytes are a key that can
    be recorded is another question: `public_key_is_valid`."""
    return _from_text(PUBLIC_KEY_TEXT_PREFIX, PUBLIC_KEY_BYTES, PUBLIC_KEY_TEXT_CHARACTERS, text)


def signature_text(signature: bytes) -> str:
    """`ksig1.` and the 3,373 bytes in base64url without padding: 4,504
    characters."""
    return _to_text(SIGNATURE_TEXT_PREFIX, SIGNATURE_BYTES, signature)


def signature_from_text(text: str) -> bytes:
    """The 3,373 bytes of a signature written as `ksig1.`. Raises
    ValueError on any other spelling."""
    return _from_text(SIGNATURE_TEXT_PREFIX, SIGNATURE_BYTES, SIGNATURE_TEXT_CHARACTERS, text)


# --- Section 5: addresses ---------------------------------------------------

ADDRESS_PREFIX = bytes.fromhex("7b0339")
ADDRESS_CHARACTERS = 75

_CHECKSUM_BYTES = 4
_ADDRESS_BYTES = len(ADDRESS_PREFIX) + HASH_BYTES + _CHECKSUM_BYTES     # 55
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_VALUES = {character: value for value, character in enumerate(_BASE58)}


def address_from_hash(network_id: bytes, digest: bytes) -> str:
    """prefix || hash || checksum in base 58: 75 characters that begin with
    `kn1`. The checksum is the first four bytes of H("kern.checksum",
    prefix || hash): Kern's own, not the one of Base58Check, and it is of
    one network."""
    if not isinstance(digest, bytes) or len(digest) != HASH_BYTES:
        raise ValueError("an address holds a hash of 48 bytes")
    body = ADDRESS_PREFIX + digest
    n = int.from_bytes(body + H("kern.checksum", network_id, body)[:_CHECKSUM_BYTES], "big")
    digits = []
    while n:
        n, remainder = divmod(n, 58)
        digits.append(_BASE58[remainder])
    return "".join(reversed(digits))                  # the prefix is not zero: no leading zero byte to write


def hash_from_address(network_id: bytes, address: str) -> bytes:
    """The 48-byte hash inside an address of this network. Raises
    ValueError on anything else: another length, a character outside the
    alphabet, another prefix, a checksum that is not the one of this
    network. An address does not say whether it is an account or a
    contract: the two are hashed under two domains (section 4.5)."""
    _check_network_id(network_id)
    if not isinstance(address, str) or len(address) != ADDRESS_CHARACTERS:
        raise ValueError("an address is 75 characters")
    n = 0
    for character in address:
        if character not in _BASE58_VALUES:
            raise ValueError("a character that is not in the alphabet of addresses")
        n = n * 58 + _BASE58_VALUES[character]
    try:
        raw = n.to_bytes(_ADDRESS_BYTES, "big")
    except OverflowError as exc:
        raise ValueError("not an address") from exc
    body, checksum = raw[:-_CHECKSUM_BYTES], raw[-_CHECKSUM_BYTES:]
    # 75 digits and this prefix leave one text per value: the number is at least 58^74,
    # so its first digit is not zero.
    if not body.startswith(ADDRESS_PREFIX):
        raise ValueError("not the prefix of an address")
    if H("kern.checksum", network_id, body)[:_CHECKSUM_BYTES] != checksum:
        raise ValueError("a damaged address, or the address of another network")
    return body[len(ADDRESS_PREFIX):]


def account_address(network_id: bytes, public_key: bytes) -> str:
    """The address of the account of a public key: the hash, under
    `kern.addr`, of the scheme number and the 1,984 bytes."""
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("a public key is 1,984 bytes")
    return address_from_hash(network_id, H("kern.addr", network_id, bytes([SCHEME]) + public_key))


def contract_address(network_id: bytes, transaction_id: bytes) -> str:
    """The address of a contract: the hash, under `kern.addr.contract`, of
    the identifier of the transaction that originates it."""
    if not isinstance(transaction_id, bytes) or len(transaction_id) != HASH_BYTES:
        raise ValueError("a transaction identifier is 48 bytes")
    return address_from_hash(network_id, H("kern.addr.contract", network_id, transaction_id))


def public_key_is_valid(public_key: bytes) -> bool:
    """What is checked before a key is recorded (section 4.5, rule 4): the
    right length, and an Ed25519 part that is a point of the subgroup of
    prime order (section 2.5, rule 2). Any 1,952 bytes are an ML-DSA-65
    public key, so that part has nothing more to check. Never raises."""
    return (isinstance(public_key, bytes) and len(public_key) == PUBLIC_KEY_BYTES
            and composite.ed25519_public_key_is_valid(public_key[composite.MLDSA_PUBLIC_KEY_BYTES:]))


# --- Section 3.2: key derivation --------------------------------------------
#
# HKDF (RFC 5869) over SHA-512, written out as the note writes it:
#
#   PRK    = HMAC-SHA-512(salt, seed)             salt: 64 zero bytes
#   info   = "KERN-KEY-DERIVATION-V1" || 0x01 || network_id || component
#   output = the first 32 bytes of HMAC-SHA-512(PRK, info || 0x01)
#
# The three outputs are three independent expansions of the same PRK. The
# first two are the seeds of the components of the account key; they never
# leave this module. The third is another secret, for contracts.

_DERIVATION_LABEL = b"KERN-KEY-DERIVATION-V1"
_COMPONENTS = ("mldsa65", "ed25519", "ed25519-standalone")


def _prk(seed: bytes) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
        raise ValueError("a seed is 32 bytes")
    return hmac.new(bytes(64), seed, hashlib.sha512).digest()


def _info(network_id: bytes, component: str) -> bytes:
    _check_network_id(network_id)
    if component not in _COMPONENTS:
        raise ValueError(f"not a component of the derivation: {component!r}")
    return _DERIVATION_LABEL + bytes([SCHEME]) + network_id + component.encode("ascii")


def _output(prk: bytes, info: bytes) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha512).digest()[:32]


class Keypair:
    """The account key of one seed on one network.

    A seed is 32 bytes drawn from the generator of the operating system by
    whoever creates the key, and kept by them: this object does not keep
    it. The same seed gives another key pair, and another address, for
    every network identifier.

    The object signs with both components, for one of the seven purposes,
    and gives no access to a component key.
    """

    __slots__ = ("_key", "_network_id", "_address")

    def __init__(self, seed: bytes, network_id: bytes) -> None:
        prk = _prk(seed)
        self._key = composite.CompositePrivateKey(
            _output(prk, _info(network_id, "mldsa65")) + _output(prk, _info(network_id, "ed25519")))
        self._network_id = network_id
        self._address = account_address(network_id, self._key.public_key)

    @property
    def network_id(self) -> bytes:
        return self._network_id

    @property
    def public_key(self) -> bytes:
        """The 1,984 bytes: ML-DSA public key, then Ed25519 public key."""
        return self._key.public_key

    @property
    def address(self) -> str:
        return self._address

    def sign(self, message: bytes, purpose: str) -> bytes:
        """A composite signature of `message` for `purpose` on the network
        of the key: 3,373 bytes. Raises ValueError on a purpose that is not
        one of the seven. Two calls return different bytes."""
        return self._key.sign(message, signing_context(purpose, self._network_id))

    def __repr__(self) -> str:
        return f"<Keypair {self._address}>"


def contract_key(seed: bytes, network_id: bytes) -> bytes:
    """The 32-byte Ed25519 private key (RFC 8032, section 5.1.5) that a
    seed gives, on one network, for contracts that verify Ed25519
    signatures. It is derived under `ed25519-standalone`: the same
    mechanism as the account key, another secret. It is never part of an
    account key, and an account key is never used in its place."""
    return _output(_prk(seed), _info(network_id, "ed25519-standalone"))


def verify(public_key: bytes, message: bytes, signature: bytes, purpose: str, network_id: bytes) -> bool:
    """True if `signature` is a composite signature of `message` under
    `public_key`, made for `purpose` on the network `network_id`. Both
    components must be valid.

    Never raises: a purpose that is not one of the seven, a network
    identifier that is not 32 bytes, a key or a signature of another
    length, all of it answers no, like any invalid signature.
    """
    try:
        context = signing_context(purpose, network_id)
    except ValueError:
        return False
    return composite.verify(public_key, message, signature, context)
