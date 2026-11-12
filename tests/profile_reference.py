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
the vectors:

    python tests/profile_reference.py                       profile.json
    python tests/profile_reference.py signatures [go.json]  composite_signatures.json

The second command needs the `cryptography` package, for ML-DSA: the node
does not depend on it yet. It makes new signatures, since signing is
randomized. The ones the Go program made are kept, or taken from the file
given, which is the output of `go run profile_check.go -sign`.
"""

from __future__ import annotations

import base64
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
# Sections 2.1 and 6.2: what the two components sign, and in which context
# ---------------------------------------------------------------------------

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"
MLDSA_PUBLIC_KEY_BYTES, MLDSA_SIGNATURE_BYTES = 1952, 3309
PUBLIC_KEY_BYTES, SIGNATURE_BYTES = 1984, 3373

PURPOSES = ("kern.tx", "kern.header", "kern.propose", "kern.preendorse",
            "kern.endorse", "kern.batch", "kern.rotate")


def signing_context(purpose: str, network_id: bytes) -> bytes:
    if purpose not in PURPOSES or len(network_id) != NETWORK_ID_BYTES:
        raise ValueError("unknown purpose, or network identifier that is not 32 bytes")
    return purpose.encode("ascii") + b"\x00" + network_id


def message_representative(message: bytes, context: bytes) -> bytes:
    """M' of RFC 10073, section 2.2: Prefix || Label || len(ctx) || ctx ||
    SHA-512(M). The ML-DSA component signs it with the Label as its own
    context, the Ed25519 component signs it as it is."""
    if len(context) > 255:
        raise ValueError("a context is at most 255 bytes")
    return PREFIX + LABEL + bytes([len(context)]) + context + hashlib.sha512(message).digest()


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


def key_text(public_key: bytes) -> str:
    """The text form of a public key: `kpk1.` and its 1,984 bytes in
    base64url without padding, 2,651 characters."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("public key of 1,984 bytes")
    return "kpk1." + base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii")


def contract_address(network_id: bytes, transaction_id: bytes) -> str:
    """The address of a contract: the hash of the identifier of the
    transaction that originates it, under a domain of its own."""
    if len(transaction_id) != HASH_BYTES:
        raise ValueError("a transaction identifier is 48 bytes")
    return address_from_hash(network_id, H("kern.addr.contract", network_id, transaction_id))


# ---------------------------------------------------------------------------
# Section 6.3: what a transaction carries besides what it signs
# ---------------------------------------------------------------------------

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
# Section 4.1: the other byte layouts. An integer is written big-endian on
# the stated number of bytes; a hash is its 48 bytes.
# ---------------------------------------------------------------------------

def proposer_draw(network_id: bytes, parent_hash: bytes, round_: int) -> int:
    """The public draw of the proposer of a round: the first 8 bytes of
    H("kern.proposer", network, parent hash || round on 4 bytes), read as
    an integer."""
    if len(parent_hash) != HASH_BYTES or not 0 <= round_ < 2**32:
        raise ValueError("parent hash of 48 bytes, round on 4 bytes")
    return int.from_bytes(H("kern.proposer", network_id, parent_hash + round_.to_bytes(4, "big"))[:8], "big")


def evm_create_address(network_id: bytes, creator: bytes, nonce: int) -> bytes:
    """CREATE in the Mini-EVM: the first 20 bytes of H("kern.evm.create",
    network, creator on 20 bytes || nonce on 8 bytes). Not the formula of
    Ethereum."""
    if len(creator) != 20 or not 0 <= nonce < 2**64:
        raise ValueError("creator of 20 bytes, nonce on 8 bytes")
    return H("kern.evm.create", network_id, creator + nonce.to_bytes(8, "big"))[:20]


def evm_create2_address(network_id: bytes, creator: bytes, salt: bytes, creation_code: bytes) -> bytes:
    """CREATE2 in the Mini-EVM: the first 20 bytes of H("kern.evm.create2",
    network, creator on 20 bytes || salt on 32 bytes || H("kern.evm.code",
    network, creation code))."""
    if len(creator) != 20 or len(salt) != 32:
        raise ValueError("creator of 20 bytes, salt of 32 bytes")
    return H("kern.evm.create2", network_id,
             creator + salt + H("kern.evm.code", network_id, creation_code))[:20]


def evm_signer_address(network_id: bytes, public_key: bytes) -> bytes:
    """What precompile 0x01 of the Mini-EVM returns, after 12 zero bytes,
    for the Ed25519 public key whose signature it has verified: the first
    20 bytes of H("kern.evm.signer", network, public key). Not the address
    of an account, whose key is composite."""
    if len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return H("kern.evm.signer", network_id, public_key)[:20]


# ---------------------------------------------------------------------------
# Section 4.6: the state root and the state trie
# ---------------------------------------------------------------------------

KEY_BITS = 8 * HASH_BYTES                             # 384
ACCOUNT_MAPS = ("balances", "nonces", "contracts")


def trie_key(network_id: bytes, address: str) -> bytes:
    """The position of an address in the trie: the hash of its text."""
    return H("kern.trie.key", network_id, address.encode("ascii"))


def _bit(key: bytes, i: int) -> int:
    return (key[i // 8] >> (7 - i % 8)) & 1           # bit 0 is the top bit of the first byte


def trie_leaf(network_id: bytes, key: bytes, depth: int, value: bytes) -> bytes:
    """A leaf at `depth`: it states how many bits of its key are left, then
    those bits (first bit in the top of the first byte, zeros to fill the
    last byte), then the length of its value on 4 bytes, then the value."""
    if len(key) != HASH_BYTES or not 0 <= depth <= KEY_BITS:
        raise ValueError("key of 48 bytes, depth from 0 to 384")
    count = KEY_BITS - depth
    packed = bytearray((count + 7) // 8)
    for i in range(count):
        packed[i // 8] |= _bit(key, depth + i) << (7 - i % 8)
    return H("kern.trie.leaf", network_id,
             count.to_bytes(2, "big") + bytes(packed) + len(value).to_bytes(4, "big") + value)


def trie_node(network_id: bytes, entries: list[tuple[bytes, bytes]], depth: int = 0) -> bytes:
    """The hash of the subtree that holds `entries`, pairs of a key and a
    value whose keys all share their first `depth` bits."""
    if not entries:
        return bytes(HASH_BYTES)                      # an empty subtree is 48 zero bytes
    if len(entries) == 1:
        return trie_leaf(network_id, entries[0][0], depth, entries[0][1])
    if depth == KEY_BITS:
        raise ValueError("two entries with the same key")
    left = [e for e in entries if _bit(e[0], depth) == 0]
    right = [e for e in entries if _bit(e[0], depth) == 1]
    return H("kern.trie.branch", network_id,
             trie_node(network_id, left, depth + 1) + trie_node(network_id, right, depth + 1))


def account_object(network_id: bytes, state: dict, address: str) -> dict:
    """What the trie holds for an address: its balance and its nonce, and
    for a contract the hash of its code and the hash of its storage."""
    out: dict = {"balance": state.get("balances", {}).get(address, 0),
                 "nonce": state.get("nonces", {}).get(address, 0)}
    contract = state.get("contracts", {}).get(address)
    if contract is not None:
        out["code_hash"] = H("kern.code", network_id, contract["code"].encode("utf-8")).hex()
        out["storage_root"] = H("kern.storage", network_id, canonical_json(contract["storage"])).hex()
    return out


def accounts_root(network_id: bytes, state: dict) -> bytes:
    addresses = sorted(set().union(*(state.get(name, {}) for name in ACCOUNT_MAPS)))
    return trie_node(network_id, [(trie_key(network_id, a), canonical_json(account_object(network_id, state, a)))
                                  for a in addresses])


def hashed_state(network_id: bytes, state: dict) -> dict:
    """The object that is hashed into the state root. With the function
    `json` it is the state. With the function `trie`, the three maps keyed
    by address are replaced by the root of their trie: every other field
    is hashed as it is, in both cases."""
    function = state.get("state_root_function")
    if function == "json":
        return state
    if function != "trie":
        raise ValueError("the state names its root function: json or trie")
    out = {name: value for name, value in state.items() if name not in ACCOUNT_MAPS}
    out["accounts_root"] = accounts_root(network_id, state).hex()
    return out


def state_root(network_id: bytes, state: dict) -> bytes:
    return H("kern.state", network_id, canonical_json(hashed_state(network_id, state)))


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------

def _with_mldsa(mldsa_seed: bytes, ed25519_public_key: bytes, network_id: bytes) -> dict:
    """The values that need ML-DSA.KeyGen_internal (FIPS 204, algorithm 6).
    They are computed with the `cryptography` package when the vectors are
    rebuilt, and by the Go program with its standard library: the node
    does not depend on that package yet."""
    from cryptography.hazmat.primitives.asymmetric import mldsa

    mldsa_public_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed).public_key().public_bytes_raw()
    public_key = mldsa_public_key + ed25519_public_key
    return {
        "mldsa65_public_key_sha3_384": hashlib.sha3_384(mldsa_public_key).hexdigest(),
        "composite_public_key_sha3_384": hashlib.sha3_384(public_key).hexdigest(),
        "address": account_address(network_id, public_key),
    }


VECTORS = Path(__file__).resolve().parent / "vectors" / "kern" / "profile.json"
SIGNATURES = VECTORS.with_name("composite_signatures.json")

CANONICAL_VALUES: list[object] = [
    {},
    [],
    {"b": 1, "a": 2},
    {"level": 7, "valid_round": -1, "block_hash": "ab", "kind": "propose"},
    {"a": [True, False, {"z": [], "y": {}}], "A": 0},
    {"min": INT_MIN, "max": INT_MAX, "zero": 0},
    {"text": "quote \" backslash \\ slash / tab \t newline \n"},
    {"text": "\b\f\r\u0000\u001f\u007f"},
    {"text": "café \u2028 \U0001f600 <&>"},            # U+2028 is written as it is, never escaped
    {"é": 1, "z": 2, "\ue000": 3, "\U0001f600": 4, "": 5},
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

# The depths at which a leaf is given: every way the bits that are left
# fill, or do not fill, a whole number of bytes.
LEAF_DEPTHS = (0, 1, 7, 8, 9, 375, 376, 377, 383, 384)


def _example_addresses(network: bytes) -> list[str]:
    """Four addresses for the trie: two ordinary ones, then the first pair,
    among the addresses whose hash is one byte repeated, whose keys share
    at least their first nine bits. Such a pair sits under a run of
    branches with one child, across the first byte of the key."""
    candidates = [address_from_hash(network, bytes([i]) * HASH_BYTES) for i in range(256)]
    keys = [trie_key(network, a) for a in candidates]
    for j in range(2, 256):
        for i in range(2, j):
            if keys[i][0] == keys[j][0] and keys[i][1] >> 7 == keys[j][1] >> 7:
                return [candidates[0], candidates[1], candidates[i], candidates[j]]
    raise AssertionError("no pair found")


def build_vectors() -> dict:
    import ed25519_reference                              # Ed25519 from RFC 8032, no library

    seed = bytes(range(32))
    network = bytes(range(0xA0, 0xC0))
    other_network = bytes(range(0xC0, 0xE0))
    key_bytes = bytes((7 * i + 3) % 256 for i in range(PUBLIC_KEY_BYTES))          # any 1,984 bytes
    signature = bytes((5 * i + 1) % 256 for i in range(SIGNATURE_BYTES))           # any 3,373 bytes
    second = bytes((3 * i + 2) % 256 for i in range(SIGNATURE_BYTES))
    transaction_id = H("kern.tx", network, b"a transaction")
    items = [bytes([i]) * HASH_BYTES for i in range(8)]

    def derivation(net: bytes) -> dict:
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

    # --- the byte layouts of section 4.1 ---
    parent_hash = H("kern.block", network, b"a parent block")
    creator, salt = bytes(range(1, 21)), bytes(range(0x40, 0x60))
    contract_key = ed25519_reference.public_key(derive(seed, network, "ed25519-standalone"))   # a key for contracts
    creation_code = bytes.fromhex("600a600c600039600a6000f3602a60005260206000f3")

    # --- objects hashed as canonical JSON ---
    a, b, c, d = _example_addresses(network)
    hex96 = lambda label: H("kern.tx", network, label.encode()).hex()           # any 48 bytes, as text
    objects = [
        ("kern.block", "a block header: the nine fields of section 6.3", {
            "version": 1, "level": 7, "payload_round": 0, "timestamp": 1794000000,
            "parent_hash": parent_hash.hex(), "state_root": hex96("state"), "txs_root": hex96("txs"),
            "witness_root": hex96("witnesses"), "proposer": a}),
        ("kern.tx", "what a transfer signs", {
            "kind": "transfer", "sender": a, "nonce": 1, "fee": 1000, "gas_limit": 10000,
            "recipient": b, "amount": 25, "chain_id": "kern-devnet"}),
        ("kern.storage", "the storage of a contract", {"count": 7, "owner": a, "paused": False}),
        ("kern.batch", "a rollup batch without its signature", {
            "rollup_id": "rollup-1", "batch_index": 3, "parent_state_root": hex96("before"),
            "state_root": hex96("after"), "tx_hashes": [hex96("l2 tx 0"), hex96("l2 tx 1")],
            "tx_data_hash": H("kern.rollup.program", network, creation_code).hex(),
            "timestamp": 1794000000, "sequencer": a}),
        ("kern.mailbox", "a forced inclusion request", {
            "rollup_id": "rollup-1", "sender": b, "l2_tx_payload": "deadbeef", "posted_at_l1_level": 120,
            "posted_at_l1_timestamp": 1794000120, "deadline_blocks": 21600}),
        ("kern.gov.id", "a governance proposal", {
            "submitter": a, "payload": {"swap": "state_root_function", "to": "trie"}, "salt": 0}),
        ("kern.attestation.id", "an attestation", {
            "issuer": a, "schema_id": "kyc.basic", "subject": b, "claim": {"level": 2, "country": "BE"},
            "attest_nonce": 4}),
        ("kern.zk_claims.vk", "a verifier key: coordinates as decimal strings (not points of a real key)", {
            "alpha1": ["1", "2"], "beta2": [["3", "4"], ["5", "6"]], "gamma2": [["7", "8"], ["9", "10"]],
            "delta2": [["11", "12"], ["13", "14"]],
            "ic": [["15", "16"],
                   ["21888242871839275222246405745257275088696311157297823662689037894645226208582", "18"]]}),
        ("kern.evm", "a state of the Mini-EVM", {
            "pc": 12, "stack": ["1", "115792089237316195423570985008687907853269984665640564039457584007913129639935"],
            "memory": "00" * 32, "gas": 99000, "halted": False, "output": "", "reverted": False,
            "storage": {"0": "7", "10": "1", "9": "2"},
            "context": {"address": str(int.from_bytes(creator, "big")), "caller": "1", "value": "0",
                        "calldata": "a9059cbb", "block_number": 7, "block_timestamp": 1794000000}}),
    ]

    # --- the state trie and the state root ---
    state = {
        "balances": {a: 1000, b: 0, c: 5},
        "nonces": {a: 3, d: 1},
        "contracts": {c: {"code": "contract Counter { storage { count: int } }", "storage": {"count": 7}}},
        "validators": [{"address": a, "stake": 100}],
        "total_supply": 1005,
        "state_root_function": "json",
    }
    in_trie = dict(state, state_root_function="trie")
    other_validators = dict(in_trie, validators=[{"address": a, "stake": 101}])
    # A key registry in the state: the first key of an account, then the key a rotation
    # gave it, current from level 121. Its shape is an example; that it is hashed is the rule.
    first_key, rotated_key, another_key = (
        key_text(bytes((m * i + c) % 256 for i in range(PUBLIC_KEY_BYTES))) for m, c in ((7, 3), (11, 5), (13, 7)))

    def registry(level: int, current: str) -> dict:
        return {a: [{"from": 0, "public_key": first_key}, {"from": level, "public_key": current}]}

    with_registry = [
        (f"the function {function}, {what}", dict(state, state_root_function=function, keys=keys))
        for function in ("json", "trie")
        for what, keys in (("with a key registry", registry(121, rotated_key)),
                           ("the rotated key current one level later: another root", registry(122, rotated_key)),
                           ("another key given by the rotation: another root", registry(121, another_key)))]
    accounts = [{"address": x, "position": trie_key(network, x).hex(), "object": account_object(network, state, x),
                 "value": canonical_json(account_object(network, state, x)).hex()} for x in sorted((a, b, c, d))]
    entries = [(bytes.fromhex(x["position"]), bytes.fromhex(x["value"])) for x in accounts]
    leaf_key, leaf_value = entries[0]

    return {
        "description": "Reference vectors of docs/hybrid-signatures.md. Bytes are in hexadecimal. "
                       "Rebuilt by tests/profile_reference.py; tests/vectors/kern/profile_check.go "
                       "computes the same values with the Go standard library. Three values of each "
                       "derivation need ML-DSA (mldsa65_public_key_sha3_384, composite_public_key_sha3_384, "
                       "address): they come from the `cryptography` package on one side and from crypto/mldsa "
                       "on the other.",
        "network_id": network.hex(),
        "canonical_json": [{"value": v, "encoding": canonical_json(v).hex()} for v in CANONICAL_VALUES],
        "not_canonical": [{"why": why, "bytes": data.hex()} for why, data in NOT_CANONICAL],
        "hash": [{"domain": dom, "data": x.hex(), "digest": H(dom, network, x).hex()}
                 for dom, x in (("kern.tx", b""), ("kern.block", b"abc"), ("kern.state", bytes(range(256))),
                                ("kern.merkle.empty", b""))]
                + [{"domain": "kern.tx", "network_id": other_network.hex(), "data": "",
                    "digest": H("kern.tx", other_network, b"").hex()}]
                + [{"domain": dom, "data": x.hex(), "digest": H(dom, network, x).hex()}
                   for dom, x in (("kern.code", "contract Counter { storage { count: int } }".encode()),
                                  ("kern.rollup.program", creation_code), ("kern.evm.code", creation_code))],
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
        "contract_address": {"transaction_id": transaction_id.hex(),
                             "hash": H("kern.addr.contract", network, transaction_id).hex(),
                             "address": contract_address(network, transaction_id)},
        "proposer": [{"parent_hash": parent_hash.hex(), "round": r,
                      "data": (parent_hash + r.to_bytes(4, "big")).hex(),
                      "draw": str(proposer_draw(network, parent_hash, r))} for r in (0, 1, 258, 2**32 - 1)],
        "evm": {"creator": creator.hex(), "nonce": 258, "salt": salt.hex(), "creation_code": creation_code.hex(),
                "code_hash": H("kern.evm.code", network, creation_code).hex(),
                "create": evm_create_address(network, creator, 258).hex(),
                "create2": evm_create2_address(network, creator, salt, creation_code).hex(),
                "signer_public_key": contract_key.hex(),
                "signer": evm_signer_address(network, contract_key).hex()},
        "objects": [{"domain": dom, "what": what, "object": obj, "encoding": canonical_json(obj).hex(),
                     "digest": H(dom, network, canonical_json(obj)).hex()} for dom, what, obj in objects],
        "trie": {
            "accounts": accounts,
            "leaves": [{"depth": depth, "digest": trie_leaf(network, leaf_key, depth, leaf_value).hex()}
                       for depth in LEAF_DEPTHS],
            "branch": {"left": entries[0][0].hex(), "right": bytes(HASH_BYTES).hex(),
                       "digest": H("kern.trie.branch", network, entries[0][0] + bytes(HASH_BYTES)).hex()},
            "roots": [{"accounts": n, "root": trie_node(network, entries[:n]).hex()} for n in range(5)],
        },
        "state": [{"what": what, "state": s, "hashed": canonical_json(hashed_state(network, s)).hex(),
                   "root": state_root(network, s).hex()}
                  for what, s in (("the function json: the state itself", state),
                                  ("the function trie: the accounts replaced by their root", in_trie),
                                  ("the function trie, another stake: another root", other_validators))]
                 + [{"what": what, "state": s, "root": state_root(network, s).hex()} for what, s in with_registry],
        "state_registry_rule": "In the states that hold `keys`, a public key is the text kpk1. of 1,984 bytes that "
                               "are not a real key: byte i is (7 * i + 3), (11 * i + 5) or (13 * i + 7) mod 256. "
                               "`from` is the level from which the key is current. The shape of the registry is "
                               "an example: its schema comes with the registry. What these vectors fix is that "
                               "it is hashed with the rest of the state, with both functions.",
    }


# ---------------------------------------------------------------------------
# Composite signatures, for the exchange with the Go program
# ---------------------------------------------------------------------------

SIGNED_MESSAGE = b'{"kind":"example","text":"a message signed by both programs"}'


def _composite_keys(seed: bytes, network: bytes):
    from cryptography.hazmat.primitives.asymmetric import mldsa

    import ed25519_reference

    mldsa_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(derive(seed, network, "mldsa65"))
    ed_seed = derive(seed, network, "ed25519")
    public_key = mldsa_key.public_key().public_bytes_raw() + ed25519_reference.public_key(ed_seed)
    return mldsa_key, ed_seed, public_key


def composite_sign(seed: bytes, network: bytes, message: bytes, context: bytes) -> bytes:
    """A composite signature made with the `cryptography` package for
    ML-DSA and with the arithmetic of ed25519_reference for Ed25519."""
    import ed25519_reference

    mldsa_key, ed_seed, _ = _composite_keys(seed, network)
    representative = message_representative(message, context)
    return mldsa_key.sign(representative, LABEL) + ed25519_reference.sign(ed_seed, representative)


def build_signature_vectors(go_signatures: list[dict] | None = None) -> dict:
    """Signatures in the seven contexts, made here, and what must be
    refused. The signatures made by the Go program are kept as they are:
    it rebuilds them itself, byte for byte."""
    import ed25519_reference

    seed, network, other_network = bytes(range(32)), bytes(range(0xA0, 0xC0)), bytes(range(0xC0, 0xE0))
    mldsa_key, ed_seed, public_key = _composite_keys(seed, network)
    message, other_message = SIGNED_MESSAGE, SIGNED_MESSAGE + b" "
    context = signing_context("kern.tx", network)
    good = composite_sign(seed, network, message, context)
    other = composite_sign(seed, network, other_message, context)
    representative = message_representative(message, context)
    cut = MLDSA_SIGNATURE_BYTES
    identity = (1).to_bytes(32, "little")                # the point of order 1

    def flipped(signature: bytes, position: int) -> bytes:
        return signature[:position] + bytes([signature[position] ^ 1]) + signature[position + 1:]

    invalid = [
        ("ML-DSA part of another message, Ed25519 part right", {"signature": other[:cut] + good[cut:]}),
        ("Ed25519 part of another message, ML-DSA part right", {"signature": good[:cut] + other[cut:]}),
        ("one bit changed in the ML-DSA part", {"signature": flipped(good, 100)}),
        ("one bit changed in the Ed25519 part", {"signature": flipped(good, cut + 40)}),
        ("the two parts in the other order", {"signature": good[cut:] + good[:cut]}),
        ("signature one byte short", {"signature": good[:-1]}),
        ("signature one byte long", {"signature": good + b"\x00"}),
        ("the Ed25519 part alone", {"signature": good[cut:]}),
        ("the ML-DSA part alone", {"signature": good[:cut]}),
        ("an Ed25519 signature of the message itself, alone",
         {"signature": ed25519_reference.sign(ed_seed, message)}),
        ("ML-DSA part signed with an empty ML-DSA context instead of the Label",
         {"signature": mldsa_key.sign(representative) + good[cut:]}),
        ("signature made for another purpose",
         {"signature": composite_sign(seed, network, message, signing_context("kern.header", network))}),
        ("signature made for another network",
         {"signature": composite_sign(seed, network, message, signing_context("kern.tx", other_network))}),
        ("signature of another message", {"signature": other}),
        ("public key one byte short", {"signature": good, "public_key": public_key[:-1]}),
        ("public key of another seed", {"signature": good, "public_key": _composite_keys(bytes(32), network)[2]}),
        ("Ed25519 public key of order 1, with the signature a lenient verifier accepts for it",
         {"signature": good[:cut] + identity + bytes(32),
          "public_key": public_key[:MLDSA_PUBLIC_KEY_BYTES] + identity}),
    ]
    return {
        "description": "Composite signatures (ML-DSA-65 with Ed25519, RFC 10073) made by two programs, and "
                       "what must be refused. Every signature is of `message`, by the key of `seed` on the "
                       "network `network_id`, in the context of its purpose. Those under `python` were made "
                       "by tests/profile_reference.py with the `cryptography` package and are randomized. "
                       "Those under `go` were made by profile_check.go with crypto/mldsa in its "
                       "deterministic mode, so that it rebuilds them byte for byte. Under `invalid`, a "
                       "field that is absent is the one given at the top, and every case is verified for "
                       "the purpose kern.tx.",
        "seed": seed.hex(), "network_id": network.hex(), "message": message.hex(),
        "public_key": public_key.hex(),
        "python": [{"purpose": p,
                    "signature": composite_sign(seed, network, message, signing_context(p, network)).hex()}
                   for p in PURPOSES],
        "go": go_signatures if go_signatures is not None else [],
        "invalid": [{"why": why, **{k: v.hex() for k, v in fields.items()}} for why, fields in invalid],
    }


def _write(path: Path, vectors: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    if sys.argv[1:2] == ["signatures"] and len(sys.argv) <= 3:
        if len(sys.argv) == 3:                            # the output of `go run profile_check.go -sign`
            kept = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        else:
            kept = json.loads(SIGNATURES.read_text(encoding="utf-8"))["go"] if SIGNATURES.exists() else None
        _write(SIGNATURES, build_signature_vectors(kept))
    elif not sys.argv[1:]:
        _write(VECTORS, build_vectors())
    else:
        sys.exit("usage: python tests/profile_reference.py [signatures [signatures made by the Go program]]")
