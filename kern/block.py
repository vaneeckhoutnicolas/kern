# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.block
----------

Block format for Kern.

A block has a header (signed by the proposer) and a body (the ordered list
of transactions plus consensus signatures from the validator set).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional

from .crypto import (
    KernKeypair,
    block_hash,
    pubkey_from_b58,
    signature_from_b58,
    verify,
    address_from_pubkey,
)
from .transaction import Transaction

# Rounds are encoded on 4 bytes in proposer selection
# (kern.consensus.select_proposer); larger values are refused at decoding.
MAX_ROUND = 2**32 - 1


@dataclass
class BlockHeader:
    """Block header — signed by the proposer.

    `level` is the block height (genesis = 0).
    `payload_round` is the round at which this payload was FIRST proposed
    (Phase E, docs/consensus-locking.md section 4.1). The header's
    `proposer` is the proposer selected for that round. A payload keeps
    its hash when it is proposed again in a later round; the round whose
    certificate finalized it is `Block.cert_round`, outside the hash.
    `state_root` commits to the post-block ledger state.
    """

    level: int
    payload_round: int
    timestamp: int                 # unix epoch seconds
    parent_hash: str               # hex
    state_root: str                # hex
    txs_root: str                  # hex (merkle root of tx hashes)
    proposer: str                  # kn1... address
    proposer_pubkey: str           # kpk... base58
    signature: Optional[str] = None

    def _signed_payload(self) -> bytes:
        d = {
            "level": self.level,
            "payload_round": self.payload_round,
            "timestamp": self.timestamp,
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "txs_root": self.txs_root,
            "proposer": self.proposer,
            "proposer_pubkey": self.proposer_pubkey,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> bytes:
        return block_hash(self._signed_payload())

    def hash_hex(self) -> str:
        return self.hash().hex()

    def sign(self, kp: KernKeypair) -> None:
        if kp.address != self.proposer:
            raise ValueError("keypair does not match proposer")
        self.signature = kp.sign_b58(self._signed_payload())

    def verify_signature(self) -> bool:
        if self.signature is None:
            return False
        try:
            pk = pubkey_from_b58(self.proposer_pubkey)
            if address_from_pubkey(pk) != self.proposer:
                return False
            sig = signature_from_b58(self.signature)
            return verify(pk, self._signed_payload(), sig)
        except Exception:
            return False

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "payload_round": self.payload_round,
            "timestamp": self.timestamp,
            "parent_hash": self.parent_hash,
            "state_root": self.state_root,
            "txs_root": self.txs_root,
            "proposer": self.proposer,
            "proposer_pubkey": self.proposer_pubkey,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BlockHeader":
        """Strictly typed decode; raises ValueError on malformed input.

        Like Transaction.from_dict, this is an ingress gate: gossiped
        blocks are decoded here before touching any consensus code."""
        if not isinstance(d, dict):
            raise ValueError("header: expected an object")

        def _uint(key: str) -> int:
            v = d.get(key)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError(f"header.{key}: expected a non-negative integer")
            return v

        def _round(key: str) -> int:
            v = _uint(key)
            if v > MAX_ROUND:
                raise ValueError(f"header.{key}: above the maximum round {MAX_ROUND}")
            return v

        def _hex32(key: str) -> str:
            v = d.get(key)
            if not isinstance(v, str) or len(v) != 64:
                raise ValueError(f"header.{key}: expected a 64-char hex string")
            try:
                bytes.fromhex(v)
            except ValueError:
                raise ValueError(f"header.{key}: expected a 64-char hex string")
            return v

        def _str(key: str) -> str:
            v = d.get(key)
            if not isinstance(v, str) or not v:
                raise ValueError(f"header.{key}: expected a non-empty string")
            return v

        sig = d.get("signature")
        if sig is not None and not isinstance(sig, str):
            raise ValueError("header.signature: expected a string or null")
        return cls(
            level=_uint("level"),
            payload_round=_round("payload_round"),
            timestamp=_uint("timestamp"),
            parent_hash=_hex32("parent_hash"),
            state_root=_hex32("state_root"),
            txs_root=_hex32("txs_root"),
            proposer=_str("proposer"),
            proposer_pubkey=_str("proposer_pubkey"),
            signature=sig,
        )


@dataclass
class Block:
    """A complete block — header, transactions, and validator commits."""

    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)
    # Endorse-schema signatures ("kn1addr:ksig...") that were known to the
    # proposer at proposal time and therefore feed reward accounting and
    # the state_root. In single-validator operation this is the proposer's
    # own self-endorsement.
    commits: List[str] = field(default_factory=list)
    # The endorsement quorum certificate gathered on the wire AFTER the
    # header was signed. Excluded from the header hash and from reward
    # accounting (both would be circular); counted, together with commits,
    # by validate_block's quorum check. Empty in single-validator blocks,
    # whose self-commit already satisfies the quorum on its own.
    endorsements: List[str] = field(default_factory=list)
    # Phase E: the round of the endorsement certificate carried in
    # `endorsements`. Not hashed (like `endorsements`); never lower than
    # header.payload_round. None means "same as payload_round" (blocks
    # built before finalization, and single-validator blocks whose quorum
    # is the proposer's self-commit). Two honest nodes may store different
    # cert_round values for the same block; nothing is derived from it.
    cert_round: Optional[int] = None

    def hash_hex(self) -> str:
        return self.header.hash_hex()

    def quorum_round(self) -> int:
        """The round the endorsement entries are signed for."""
        return self.header.payload_round if self.cert_round is None else self.cert_round

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "commits": self.commits,
            "endorsements": self.endorsements,
            "cert_round": self.quorum_round(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        if not isinstance(d, dict):
            raise ValueError("block: expected an object")
        txs = d.get("transactions")
        if not isinstance(txs, list):
            raise ValueError("block.transactions: expected a list")
        commits = d.get("commits", [])
        endorsements = d.get("endorsements", [])
        for name, lst in (("commits", commits), ("endorsements", endorsements)):
            if not isinstance(lst, list) or not all(isinstance(c, str) for c in lst):
                raise ValueError(f"block.{name}: expected a list of strings")
        cert_round = d.get("cert_round")
        if cert_round is not None and (not isinstance(cert_round, int) or isinstance(cert_round, bool)
                                       or cert_round < 0 or cert_round > MAX_ROUND):
            raise ValueError("block.cert_round: expected an integer between 0 and 2**32 - 1")
        return cls(
            header=BlockHeader.from_dict(d["header"]),
            transactions=[Transaction.from_dict(t) for t in txs],
            commits=list(commits),
            endorsements=list(endorsements),
            cert_round=cert_round,
        )


def merkle_root(hashes: List[bytes]) -> bytes:
    """Compute a simple merkle root of a list of byte hashes.

    Uses blake2b-256 with the 'kern.merkle' domain separator. If `hashes`
    is empty, returns 32 zero bytes. Odd levels duplicate the last hash.
    """
    import hashlib
    if not hashes:
        return b"\x00" * 32
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            h = hashlib.blake2b(level[i] + level[i + 1], digest_size=32, key=b"kern.merkle").digest()
            next_level.append(h)
        level = next_level
    return level[0]


def txs_merkle_root_hex(transactions: List[Transaction]) -> str:
    return merkle_root([tx.hash() for tx in transactions]).hex()
