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


@dataclass
class BlockHeader:
    """Block header — signed by the proposer.

    `level` is the block height (genesis = 0).
    `round` is the consensus round at which this block was finalized
    (used by the Tenderbake-lite logic in `consensus.py`).
    `state_root` commits to the post-block ledger state.
    """

    level: int
    round: int
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
            "round": self.round,
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
            "round": self.round,
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
        return cls(**d)


@dataclass
class Block:
    """A complete block — header, transactions, and validator commits."""

    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)
    commits: List[str] = field(default_factory=list)  # base58 sigs by validators

    def hash_hex(self) -> str:
        return self.header.hash_hex()

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "commits": self.commits,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            header=BlockHeader.from_dict(d["header"]),
            transactions=[Transaction.from_dict(t) for t in d["transactions"]],
            commits=d.get("commits", []),
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
