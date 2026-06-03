# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.bft
========

Multi-validator BFT consensus for Kern, implementing the three-phase
Tenderbake-style round protocol:

    1. PROPOSE      — the round's selected proposer broadcasts a candidate block.
    2. PRE-ENDORSE  — each validator signs a pre-endorsement over the block hash.
    3. ENDORSE      — once a validator sees pre-endorsements from > 2/3 of stake,
                       it signs an endorsement.

A block is committed once it has collected > 2/3 of stake in endorsements
(the "endorsement quorum certificate", or EQC). It is finalized once the
*next* block has been committed on top of it — i.e., 2 blocks after creation
under normal conditions.

This module implements the message types, the per-validator state machine,
the signature verification, and the quorum certificate logic. It is wired
into the node by `kern.node` (which exchanges messages over the P2P layer).

Key types
---------

ConsensusMessage : a signed message of one of three kinds.
ValidatorRound   : per-validator state for a single (level, round).
QuorumCertificate: a collection of signatures proving > 2/3 stake agreement.
BftEngine        : the per-node engine wiring all of this together.

Design notes
------------

- Messages are signed with the validator's Ed25519 key; signatures are
  verified against the registered public key in the validator set.
- Pre-endorsement and endorsement are over the *block hash* (the header
  hash), not the block contents. This keeps message size constant.
- A validator may pre-endorse at most one block per (level, round). A
  conflicting pre-endorsement is a slashable offense.
- Same for endorsement.
- The round timer advances rounds when a quorum is not reached in time.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .crypto import (
    KernKeypair,
    address_from_pubkey,
    pubkey_from_b58,
    signature_from_b58,
    verify,
)

LOG = logging.getLogger("kern.bft")


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

class MsgKind(str, Enum):
    PROPOSE = "propose"
    PREENDORSE = "preendorse"
    ENDORSE = "endorse"


@dataclass
class ConsensusMessage:
    """A signed consensus message.

    For PROPOSE messages, `block_hash` identifies the proposed block and the
    proposal payload (the actual block bytes) is exchanged out-of-band via
    the block-gossip channel.

    For PREENDORSE and ENDORSE, the signature covers (kind, level, round,
    block_hash, validator_pubkey).
    """

    kind: MsgKind
    level: int
    round: int
    block_hash: str          # hex
    validator: str           # kn1... address
    validator_pubkey: str    # kpk... base58
    signature: Optional[str] = None

    def _signed_payload(self) -> bytes:
        d = {
            "kind": self.kind.value,
            "level": self.level,
            "round": self.round,
            "block_hash": self.block_hash,
            "validator": self.validator,
            "validator_pubkey": self.validator_pubkey,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, kp: KernKeypair) -> None:
        if kp.address != self.validator:
            raise ValueError("keypair does not match validator address")
        self.signature = kp.sign_b58(self._signed_payload())

    def verify_signature(self) -> bool:
        if self.signature is None:
            return False
        try:
            pk = pubkey_from_b58(self.validator_pubkey)
            if address_from_pubkey(pk) != self.validator:
                return False
            sig = signature_from_b58(self.signature)
            return verify(pk, self._signed_payload(), sig)
        except Exception:
            return False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "level": self.level,
            "round": self.round,
            "block_hash": self.block_hash,
            "validator": self.validator,
            "validator_pubkey": self.validator_pubkey,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConsensusMessage":
        return cls(
            kind=MsgKind(d["kind"]),
            level=d["level"],
            round=d["round"],
            block_hash=d["block_hash"],
            validator=d["validator"],
            validator_pubkey=d["validator_pubkey"],
            signature=d.get("signature"),
        )


# ---------------------------------------------------------------------------
# Quorum certificates
# ---------------------------------------------------------------------------

@dataclass
class QuorumCertificate:
    """A collection of pre-endorsement or endorsement signatures proving that
    > 2/3 of stake has voted for a particular `block_hash` at a particular
    `(level, round)`. The QC is included in the block (or in the next block,
    for endorsement QCs) so that any verifier can check finality independently.
    """

    kind: MsgKind  # PREENDORSE or ENDORSE
    level: int
    round: int
    block_hash: str
    signatures: Dict[str, str]  # validator address -> signature b58

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "level": self.level,
            "round": self.round,
            "block_hash": self.block_hash,
            "signatures": dict(self.signatures),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "QuorumCertificate":
        return cls(
            kind=MsgKind(d["kind"]),
            level=d["level"],
            round=d["round"],
            block_hash=d["block_hash"],
            signatures=dict(d["signatures"]),
        )

    def verify(self, validator_set: List[dict]) -> Tuple[bool, str]:
        """Verify the QC against the validator set. Returns (ok, reason)."""
        total_stake = sum(v["stake"] for v in validator_set)
        if total_stake == 0:
            return False, "empty validator set"

        signed_stake = 0
        seen: Set[str] = set()

        for addr, sig_b58 in self.signatures.items():
            if addr in seen:
                continue
            v = next((v for v in validator_set if v["address"] == addr), None)
            if v is None:
                return False, f"validator {addr} not in set"
            # Reconstruct the signed payload for this validator.
            msg = ConsensusMessage(
                kind=self.kind,
                level=self.level,
                round=self.round,
                block_hash=self.block_hash,
                validator=addr,
                validator_pubkey=v["pubkey"],
                signature=sig_b58,
            )
            if not msg.verify_signature():
                return False, f"bad signature from {addr}"
            signed_stake += v["stake"]
            seen.add(addr)

        if signed_stake * 3 <= total_stake * 2:
            return False, f"insufficient stake: {signed_stake}/{total_stake} (need > 2/3)"

        return True, "ok"


# ---------------------------------------------------------------------------
# Per-(level, round) validator state
# ---------------------------------------------------------------------------

@dataclass
class RoundState:
    """The state a single validator maintains for a single (level, round)."""

    level: int
    round: int
    proposed_block_hash: Optional[str] = None
    preendorsements: Dict[str, ConsensusMessage] = field(default_factory=dict)
    endorsements: Dict[str, ConsensusMessage] = field(default_factory=dict)
    # Has this validator already pre-endorsed / endorsed this round?
    preendorsed: bool = False
    endorsed: bool = False
    # Cached locally-derived QCs.
    preendorse_qc: Optional[QuorumCertificate] = None
    endorse_qc: Optional[QuorumCertificate] = None


# ---------------------------------------------------------------------------
# BFT engine
# ---------------------------------------------------------------------------

@dataclass
class BftEngine:
    """The per-node consensus engine.

    Holds the validator's keypair, the validator set, and a window of
    recent (level, round) states. Processes inbound messages, decides
    when to emit outbound messages, and produces quorum certificates.

    Wiring:
    - `on_message(msg)` is called when a ConsensusMessage arrives from the
      network. Returns a list of outbound ConsensusMessages to broadcast.
    - `on_proposal(block)` is called when the local node observes (or
      itself proposes) a block. Returns outbound messages.
    - `try_finalize(level, round)` checks whether a block at that
      (level, round) has reached the endorsement quorum and returns the
      QC if so.
    """

    own_keypair: Optional[KernKeypair]
    own_pubkey_b58: Optional[str]
    validator_set: List[dict]  # mutable; updated each cycle
    # Window of recent states, keyed by (level, round).
    states: Dict[Tuple[int, int], RoundState] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers

    def _state(self, level: int, round_: int) -> RoundState:
        key = (level, round_)
        if key not in self.states:
            self.states[key] = RoundState(level=level, round=round_)
        return self.states[key]

    def _is_validator(self, addr: str) -> bool:
        return any(v["address"] == addr for v in self.validator_set)

    def _own_address(self) -> Optional[str]:
        if self.own_keypair is None:
            return None
        return self.own_keypair.address

    def _stake_of(self, addr: str) -> int:
        v = next((v for v in self.validator_set if v["address"] == addr), None)
        return v["stake"] if v else 0

    def _total_stake(self) -> int:
        return sum(v["stake"] for v in self.validator_set)

    def _has_quorum(self, sigs: Dict[str, "ConsensusMessage"]) -> bool:
        if self._total_stake() == 0:
            return False
        signed = sum(self._stake_of(addr) for addr in sigs.keys())
        return signed * 3 > self._total_stake() * 2

    # ---------------------------------------------------------------- inbound

    def on_proposal(self, level: int, round_: int, block_hash: str) -> List[ConsensusMessage]:
        """Called when this node observes a proposal (either received over
        the network or self-proposed). Emits a pre-endorsement if we haven't
        already pre-endorsed this round and we're an active validator."""
        state = self._state(level, round_)
        if state.proposed_block_hash is None:
            state.proposed_block_hash = block_hash
        elif state.proposed_block_hash != block_hash:
            LOG.warning(
                "conflicting proposal at L%d R%d: had %s, got %s — ignoring second",
                level, round_, state.proposed_block_hash[:12], block_hash[:12],
            )
            return []

        outbound: List[ConsensusMessage] = []
        own = self._own_address()
        if own is None or not self._is_validator(own) or state.preendorsed:
            return outbound

        # Emit pre-endorsement.
        msg = ConsensusMessage(
            kind=MsgKind.PREENDORSE,
            level=level,
            round=round_,
            block_hash=block_hash,
            validator=own,
            validator_pubkey=self.own_pubkey_b58 or "",
        )
        msg.sign(self.own_keypair)
        state.preendorsements[own] = msg
        state.preendorsed = True
        outbound.append(msg)
        LOG.debug("emitted PREENDORSE for L%d R%d hash=%s", level, round_, block_hash[:12])
        return outbound

    def on_message(self, msg: ConsensusMessage) -> List[ConsensusMessage]:
        """Process an incoming consensus message. Returns outbound messages
        to broadcast (typically: an endorsement once preendorse quorum is met)."""
        if not msg.verify_signature():
            LOG.warning("rejected unsigned/invalid consensus message from %s", msg.validator)
            return []
        if not self._is_validator(msg.validator):
            LOG.warning("rejected message from non-validator %s", msg.validator)
            return []

        state = self._state(msg.level, msg.round)
        outbound: List[ConsensusMessage] = []

        if msg.kind == MsgKind.PROPOSE:
            # PROPOSE messages are accepted by recording the block hash; the
            # actual block is delivered via the block-gossip channel.
            return self.on_proposal(msg.level, msg.round, msg.block_hash)

        if msg.kind == MsgKind.PREENDORSE:
            # Detect equivocation: same validator pre-endorsing a different block.
            existing = state.preendorsements.get(msg.validator)
            if existing and existing.block_hash != msg.block_hash:
                LOG.error(
                    "EQUIVOCATION: %s pre-endorsed both %s and %s at L%d R%d",
                    msg.validator, existing.block_hash[:12], msg.block_hash[:12],
                    msg.level, msg.round,
                )
                # In production, emit a slashing report.
                return outbound
            state.preendorsements[msg.validator] = msg

            # Have we reached pre-endorsement quorum? If so and we haven't
            # endorsed yet, emit our endorsement.
            if self._has_quorum(state.preendorsements):
                # Materialize the pre-endorsement QC.
                if state.preendorse_qc is None:
                    state.preendorse_qc = QuorumCertificate(
                        kind=MsgKind.PREENDORSE,
                        level=msg.level,
                        round=msg.round,
                        block_hash=state.proposed_block_hash or msg.block_hash,
                        signatures={
                            a: m.signature for a, m in state.preendorsements.items()
                            if m.signature is not None
                        },
                    )

                own = self._own_address()
                if (own is not None and self._is_validator(own)
                        and not state.endorsed and state.proposed_block_hash):
                    endorse = ConsensusMessage(
                        kind=MsgKind.ENDORSE,
                        level=msg.level,
                        round=msg.round,
                        block_hash=state.proposed_block_hash,
                        validator=own,
                        validator_pubkey=self.own_pubkey_b58 or "",
                    )
                    endorse.sign(self.own_keypair)
                    state.endorsements[own] = endorse
                    state.endorsed = True
                    outbound.append(endorse)
                    LOG.debug("emitted ENDORSE for L%d R%d hash=%s",
                              msg.level, msg.round, state.proposed_block_hash[:12])
            return outbound

        if msg.kind == MsgKind.ENDORSE:
            existing = state.endorsements.get(msg.validator)
            if existing and existing.block_hash != msg.block_hash:
                LOG.error(
                    "EQUIVOCATION: %s endorsed both %s and %s at L%d R%d",
                    msg.validator, existing.block_hash[:12], msg.block_hash[:12],
                    msg.level, msg.round,
                )
                return outbound
            state.endorsements[msg.validator] = msg

            if self._has_quorum(state.endorsements) and state.endorse_qc is None:
                state.endorse_qc = QuorumCertificate(
                    kind=MsgKind.ENDORSE,
                    level=msg.level,
                    round=msg.round,
                    block_hash=state.proposed_block_hash or msg.block_hash,
                    signatures={
                        a: m.signature for a, m in state.endorsements.items()
                        if m.signature is not None
                    },
                )
                LOG.info("ENDORSEMENT QUORUM reached at L%d R%d hash=%s",
                         msg.level, msg.round, state.endorse_qc.block_hash[:12])
            return outbound

        return outbound

    # ---------------------------------------------------------------- queries

    def get_endorse_qc(self, level: int, round_: int) -> Optional[QuorumCertificate]:
        state = self.states.get((level, round_))
        return state.endorse_qc if state else None

    def get_preendorse_qc(self, level: int, round_: int) -> Optional[QuorumCertificate]:
        state = self.states.get((level, round_))
        return state.preendorse_qc if state else None

    def prune_below(self, level: int) -> None:
        """Drop state for levels strictly below `level` (free memory)."""
        to_drop = [k for k in self.states if k[0] < level]
        for k in to_drop:
            del self.states[k]


# ---------------------------------------------------------------------------
# Slashing evidence
# ---------------------------------------------------------------------------

@dataclass
class SlashingEvidence:
    """Cryptographic proof that a validator equivocated.

    Two messages of the same (kind, level, round) from the same validator
    over distinct block_hashes constitute a slashable offense.
    """

    offender: str
    msg_a: ConsensusMessage
    msg_b: ConsensusMessage

    def verify(self) -> Tuple[bool, str]:
        if self.msg_a.validator != self.offender or self.msg_b.validator != self.offender:
            return False, "messages do not come from the named offender"
        if self.msg_a.kind != self.msg_b.kind:
            return False, "messages are of different kinds"
        if (self.msg_a.level, self.msg_a.round) != (self.msg_b.level, self.msg_b.round):
            return False, "messages are not at the same (level, round)"
        if self.msg_a.block_hash == self.msg_b.block_hash:
            return False, "messages are not in conflict"
        if not self.msg_a.verify_signature() or not self.msg_b.verify_signature():
            return False, "one or both signatures invalid"
        return True, "valid equivocation evidence"
