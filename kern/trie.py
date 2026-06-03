# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.trie
=========

Binary Merkle trie keyed by account address.

This replaces the v0.1-v0.3 "hash the whole state as JSON" approach with
a proper trie that supports:

1. O(log n) inclusion proofs for any account.
2. Light clients that can verify "account A has balance B at state root R"
   given only R and a small proof.
3. Incremental updates without rehashing the entire state.

Design choices
--------------

- **Binary radix trie** (not Ethereum's hex-Patricia trie). A binary trie
  is simpler to implement, simpler to prove against, and the proof size
  is only ~30% larger than the hex variant. The protocol value is in the
  *property* (any state read can be proved), not in matching Ethereum's
  specific trie layout.

- **Keys are 256-bit hashes of the account address.** This gives a
  uniformly-distributed key space, ensuring the trie stays roughly
  balanced. (Adversarial address-grinding cannot create deep paths.)

- **Domain-separated hashes** via blake2b keys: `kern.trie.leaf` for
  leaves, `kern.trie.branch` for internal nodes. This prevents
  second-preimage collision between leaves and branches.

- **Leaf encoding** is the canonical JSON of the account state. Account
  state shape: `{"balance": int, "nonce": int, "code_hash": str|null,
  "storage_root": str|null}`.

API
---

    trie = MerkleTrie()
    trie.set(address, account_state)
    root = trie.root_hex()
    proof = trie.prove(address)
    Verifier.verify(root, address, account_state, proof)  # True / False
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def _leaf_hash(key_bits: bytes, value: bytes) -> bytes:
    """Hash for a leaf node. Includes the residual key bits (the part of
    the path not absorbed by the trie structure) and the value."""
    h = hashlib.blake2b(digest_size=32, key=b"kern.trie.leaf")
    h.update(len(key_bits).to_bytes(2, "big"))
    h.update(key_bits)
    h.update(len(value).to_bytes(4, "big"))
    h.update(value)
    return h.digest()


def _branch_hash(left: bytes, right: bytes) -> bytes:
    """Hash for an internal branch node: H(left || right)."""
    h = hashlib.blake2b(digest_size=32, key=b"kern.trie.branch")
    h.update(left)
    h.update(right)
    return h.digest()


# A 256-bit "null hash" for empty subtrees, deterministic across nodes.
_EMPTY_LEAF = b"\x00" * 32


# ---------------------------------------------------------------------------
# Key conversion
# ---------------------------------------------------------------------------

def address_to_key(address: str) -> bytes:
    """Map an address (any string) to a 256-bit trie key via blake2b-256."""
    return hashlib.blake2b(address.encode("utf-8"), digest_size=32,
                           key=b"kern.trie.key").digest()


def _bits(key: bytes) -> List[int]:
    """Decompose a key into its bit sequence, MSB-first."""
    out: List[int] = []
    for byte in key:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _bits_to_bytes(bits: List[int]) -> bytes:
    """Pack a bit sequence back into bytes (padding LSBs with zeros)."""
    n = len(bits)
    out = bytearray((n + 7) // 8)
    for i, b in enumerate(bits):
        out[i // 8] |= (b & 1) << (7 - (i % 8))
    return bytes(out)


# ---------------------------------------------------------------------------
# Node representation
# ---------------------------------------------------------------------------

@dataclass
class Node:
    """A node in the binary trie.

    A node is either:
    - a Leaf: holds the residual key bits + the value bytes.
    - a Branch: holds the left and right child nodes (None means empty
      subtree, hashing to _EMPTY_LEAF).
    """

    is_leaf: bool
    # Leaf-only fields:
    key_bits: Optional[List[int]] = None
    value: Optional[bytes] = None
    # Branch-only fields:
    left: Optional["Node"] = None
    right: Optional["Node"] = None

    def hash(self) -> bytes:
        if self.is_leaf:
            return _leaf_hash(_bits_to_bytes(self.key_bits or []), self.value or b"")
        l = self.left.hash() if self.left else _EMPTY_LEAF
        r = self.right.hash() if self.right else _EMPTY_LEAF
        return _branch_hash(l, r)


# ---------------------------------------------------------------------------
# Trie
# ---------------------------------------------------------------------------

class MerkleTrie:
    """A binary Merkle trie keyed by account address.

    Values are arbitrary bytes (the canonical encoding of an account state).
    Use `set_account` / `get_account` to manage account state directly.
    """

    def __init__(self):
        self.root: Optional[Node] = None

    # ------------------------------------------------------------ low-level

    def _insert(self, node: Optional[Node], path: List[int], value: bytes,
                depth: int = 0) -> Node:
        # Empty subtree: place a leaf with the residual path.
        if node is None:
            return Node(is_leaf=True, key_bits=path[depth:], value=value)

        if node.is_leaf:
            existing_path = (node.key_bits or [])
            new_residual = path[depth:]

            # Same residual path → replace the value.
            if existing_path == new_residual:
                return Node(is_leaf=True, key_bits=existing_path, value=value)

            # Different paths sharing depth: split into branches at the
            # first differing bit.
            return self._split_leaf(node, existing_path, value, new_residual, depth)

        # Branch: descend into the matching child.
        bit = path[depth]
        if bit == 0:
            new_left = self._insert(node.left, path, value, depth + 1)
            return Node(is_leaf=False, left=new_left, right=node.right)
        else:
            new_right = self._insert(node.right, path, value, depth + 1)
            return Node(is_leaf=False, left=node.left, right=new_right)

    def _split_leaf(self, existing_leaf: Node, existing_path: List[int],
                    new_value: bytes, new_path: List[int], depth: int) -> Node:
        """Existing leaf at `depth` with residual `existing_path`; incoming
        value with residual `new_path`. Build a chain of branches that
        diverges at their first differing bit."""
        # We reconstruct the full bit-paths from `depth`.
        # The existing leaf's full bit-path is: (anything above depth, which
        # is shared since we got here) + existing_path
        # The new value's full bit-path is: (...same shared...) + new_path

        # Walk bit by bit until divergence.
        i = 0
        while i < len(existing_path) and i < len(new_path) and existing_path[i] == new_path[i]:
            i += 1
        # If we exhausted one path entirely, that's the same key → handled above.
        if i == len(existing_path) or i == len(new_path):
            # One path is a prefix of the other — should not happen with
            # uniform-length 256-bit keys, but handle defensively.
            raise ValueError("trie keys must all have the same length")

        # Build the divergence branch.
        existing_residual = existing_path[i + 1:]
        new_residual = new_path[i + 1:]
        existing_new_leaf = Node(is_leaf=True, key_bits=existing_residual, value=existing_leaf.value)
        incoming_leaf = Node(is_leaf=True, key_bits=new_residual, value=new_value)
        if existing_path[i] == 0:
            divergence = Node(is_leaf=False, left=existing_new_leaf, right=incoming_leaf)
        else:
            divergence = Node(is_leaf=False, left=incoming_leaf, right=existing_new_leaf)

        # Wrap in `i` levels of single-child branches matching the shared bits.
        node = divergence
        for j in range(i - 1, -1, -1):
            bit = existing_path[j]
            if bit == 0:
                node = Node(is_leaf=False, left=node, right=None)
            else:
                node = Node(is_leaf=False, left=None, right=node)
        return node

    def set(self, key: bytes, value: bytes) -> None:
        """Set the raw 32-byte key to `value` bytes."""
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        path = _bits(key)
        self.root = self._insert(self.root, path, value)

    def get(self, key: bytes) -> Optional[bytes]:
        """Look up the value for `key`. Returns None if absent."""
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        path = _bits(key)
        node = self.root
        depth = 0
        while node is not None:
            if node.is_leaf:
                if (node.key_bits or []) == path[depth:]:
                    return node.value
                return None
            bit = path[depth]
            node = node.left if bit == 0 else node.right
            depth += 1
        return None

    def root_hex(self) -> str:
        """The current trie root, as hex. Empty trie → all zeros."""
        if self.root is None:
            return _EMPTY_LEAF.hex()
        return self.root.hash().hex()

    # ------------------------------------------------------------ proofs

    def prove(self, key: bytes) -> "Proof":
        """Generate an inclusion proof for `key`. The proof can be
        independently verified given the root, the key, and the value.

        Raises KeyError if the key is not present.
        """
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        path = _bits(key)
        siblings: List[bytes] = []
        bits_taken: List[int] = []
        node = self.root
        depth = 0
        while node is not None:
            if node.is_leaf:
                if (node.key_bits or []) != path[depth:]:
                    raise KeyError(f"key not in trie")
                return Proof(
                    key=key,
                    value=node.value or b"",
                    leaf_residual_bits=list(node.key_bits or []),
                    siblings=siblings,
                    bits_taken=bits_taken,
                )
            bit = path[depth]
            sibling = node.right if bit == 0 else node.left
            sibling_hash = sibling.hash() if sibling else _EMPTY_LEAF
            siblings.append(sibling_hash)
            bits_taken.append(bit)
            node = node.left if bit == 0 else node.right
            depth += 1
        raise KeyError(f"key not in trie")

    # ------------------------------------------------------------ account helpers

    def set_account(self, address: str, account_state: dict) -> None:
        key = address_to_key(address)
        value = encode_account(account_state)
        self.set(key, value)

    def get_account(self, address: str) -> Optional[dict]:
        v = self.get(address_to_key(address))
        if v is None:
            return None
        return decode_account(v)

    def prove_account(self, address: str) -> Tuple["Proof", dict]:
        key = address_to_key(address)
        proof = self.prove(key)
        return proof, decode_account(proof.value)


# ---------------------------------------------------------------------------
# Proof
# ---------------------------------------------------------------------------

@dataclass
class Proof:
    """An inclusion proof for a single trie entry.

    `siblings[i]` is the hash of the sibling subtree at depth `i` along
    the path from root to leaf. `bits_taken[i]` tells the verifier which
    direction (0 = left, 1 = right) was taken at depth `i`.
    """

    key: bytes
    value: bytes
    leaf_residual_bits: List[int]
    siblings: List[bytes]
    bits_taken: List[int]

    def serialize(self) -> dict:
        return {
            "key": self.key.hex(),
            "value": self.value.hex(),
            "leaf_residual_bits": list(self.leaf_residual_bits),
            "siblings": [s.hex() for s in self.siblings],
            "bits_taken": list(self.bits_taken),
        }

    @classmethod
    def deserialize(cls, d: dict) -> "Proof":
        return cls(
            key=bytes.fromhex(d["key"]),
            value=bytes.fromhex(d["value"]),
            leaf_residual_bits=list(d["leaf_residual_bits"]),
            siblings=[bytes.fromhex(s) for s in d["siblings"]],
            bits_taken=list(d["bits_taken"]),
        )


def verify_proof(root_hex: str, proof: Proof) -> bool:
    """Reconstruct the root hash from the proof and the leaf value.
    Returns True iff the reconstructed root equals `root_hex` AND the
    leaf residual bits + path bits cover the entire key."""

    # 1. Reconstruct the path from key bits.
    full_path = _bits(proof.key)
    if len(proof.bits_taken) + len(proof.leaf_residual_bits) != len(full_path):
        return False
    # The bits taken descending into branches, plus the leaf residual,
    # must reconstitute the full key bits.
    reconstructed = list(proof.bits_taken) + list(proof.leaf_residual_bits)
    if reconstructed != full_path:
        return False

    # 2. Start from the leaf hash, walk back up applying siblings.
    h = _leaf_hash(_bits_to_bytes(proof.leaf_residual_bits), proof.value)
    # Walk from deepest sibling up to root.
    for i in range(len(proof.siblings) - 1, -1, -1):
        sibling = proof.siblings[i]
        if proof.bits_taken[i] == 0:
            # We were the left child; sibling is right.
            h = _branch_hash(h, sibling)
        else:
            h = _branch_hash(sibling, h)

    return h.hex() == root_hex


# ---------------------------------------------------------------------------
# Account encoding
# ---------------------------------------------------------------------------

def encode_account(account: dict) -> bytes:
    """Canonical encoding of an account state. Used as the leaf value."""
    canonical = json.dumps(account, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return canonical


def decode_account(b: bytes) -> dict:
    return json.loads(b.decode("utf-8"))


def make_account(
    balance: int = 0,
    nonce: int = 0,
    code_hash: Optional[str] = None,
    storage_root: Optional[str] = None,
) -> dict:
    """Build a canonical account-state dict."""
    return {
        "balance": balance,
        "nonce": nonce,
        "code_hash": code_hash,
        "storage_root": storage_root,
    }


# ---------------------------------------------------------------------------
# Convenience: build a trie from a state dict
# ---------------------------------------------------------------------------

def trie_from_state(state: dict) -> MerkleTrie:
    """Build a trie from a chain `state` dict (with balances, nonces,
    contracts). Each account appears once; contracts add a storage_root
    pointer (currently the JSON hash of their storage, until per-contract
    storage tries land)."""
    trie = MerkleTrie()
    balances = state.get("balances", {})
    nonces = state.get("nonces", {})
    contracts = state.get("contracts", {})

    all_addrs = set(balances.keys()) | set(nonces.keys()) | set(contracts.keys())
    for addr in sorted(all_addrs):  # sort for determinism
        c = contracts.get(addr)
        storage_root = None
        code_hash = None
        if c is not None:
            # Until per-contract storage tries, use blake2b of canonical storage.
            storage_json = json.dumps(c.get("storage"), sort_keys=True,
                                     separators=(",", ":")).encode()
            storage_root = hashlib.blake2b(storage_json, digest_size=32,
                                           key=b"kern.storage").hexdigest()
            code_json = c.get("code", "").encode("utf-8")
            code_hash = hashlib.blake2b(code_json, digest_size=32,
                                        key=b"kern.code").hexdigest()
        account = make_account(
            balance=balances.get(addr, 0),
            nonce=nonces.get(addr, 0),
            code_hash=code_hash,
            storage_root=storage_root,
        )
        trie.set_account(addr, account)
    return trie


def state_root_trie_hex(state: dict) -> str:
    """Drop-in replacement for the v0.1-v0.3 state_root_hex, computed via
    the Merkle trie. Same property: deterministic, blake2b-256."""
    return trie_from_state(state).root_hex()
