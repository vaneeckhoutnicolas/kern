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

Phase E (E1, docs/consensus-locking.md): locking and valid round.

- A validator votes only in the round its node is in (`current_round`).
  Votes for other rounds are still recorded and count toward
  certificates and evidence, but the engine never signs for them.
- On a pre-endorsement certificate for X in the current round, the
  validator endorses X and LOCKS on (round, X).
- A locked validator pre-endorses only its locked block, or a block X
  proposed with `valid_round > locked_round` and a pre-endorsement
  certificate for X at `valid_round` (this releases the lock).
- The engine tracks the most recent pre-endorsement certificate it has
  seen (`valid_round`, `valid_hash`); the proposer of a later round
  proposes that block again instead of a new one.
- Proposals are signed PROPOSE messages carrying `valid_round`. Two
  different proposals signed for one (level, round) are kept as evidence
  (not slashable yet).
- Every signature is first recorded in the persistent signing journal
  when the node has one (kern.signing_journal).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .block import MAX_ROUND
from .crypto import (
    KernKeypair,
    address_from_pubkey,
    pubkey_from_b58,
    signature_from_b58,
    verify,
)

LOG = logging.getLogger("kern.bft")

# Phase D: bounds on the consensus state an engine keeps. A signed message
# from a validator used to create a RoundState for ANY (level, round), so a
# faulty validator could grow memory without limit (external review,
# November 2026). Messages outside the window are dropped before any state
# is created.
MAX_LEVELS_AHEAD = 2        # accept levels min_level .. min_level + 2
MAX_ROUND_DISTANCE = 8      # accept rounds within +/- 8 of the node's round
MAX_ROUND_STATES = 256      # hard cap on RoundState objects kept


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

    Phase E: a PROPOSE message is signed by the proposer of `round` and
    also covers `valid_round`: -1 for a new payload, or the round of the
    pre-endorsement certificate that justifies proposing this block again.
    Votes have no valid_round (it is -1 and not part of their signature,
    so vote signatures are unchanged since Phase D).
    """

    kind: MsgKind
    level: int
    round: int
    block_hash: str          # hex
    validator: str           # kn1... address
    validator_pubkey: str    # kpk... base58
    signature: Optional[str] = None
    valid_round: int = -1

    def _signed_payload(self) -> bytes:
        d: Dict[str, object] = {
            "kind": self.kind.value,
            "level": self.level,
            "round": self.round,
            "block_hash": self.block_hash,
            "validator": self.validator,
            "validator_pubkey": self.validator_pubkey,
        }
        if self.kind == MsgKind.PROPOSE:
            d["valid_round"] = self.valid_round
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
        d = {
            "kind": self.kind.value,
            "level": self.level,
            "round": self.round,
            "block_hash": self.block_hash,
            "validator": self.validator,
            "validator_pubkey": self.validator_pubkey,
            "signature": self.signature,
        }
        if self.kind == MsgKind.PROPOSE:
            d["valid_round"] = self.valid_round
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ConsensusMessage":
        """Strictly typed decode; raises ValueError on malformed input."""
        if not isinstance(d, dict):
            raise ValueError("consensus: expected an object")

        def _uint(key: str) -> int:
            v = d.get(key)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError(f"consensus.{key}: expected a non-negative integer")
            return v

        def _str(key: str) -> str:
            v = d.get(key)
            if not isinstance(v, str) or not v:
                raise ValueError(f"consensus.{key}: expected a non-empty string")
            return v

        sig = d.get("signature")
        if sig is not None and not isinstance(sig, str):
            raise ValueError("consensus.signature: expected a string or null")
        kind = MsgKind(_str("kind"))
        round_ = _uint("round")
        if round_ > MAX_ROUND:
            raise ValueError("consensus.round: above the maximum round")
        vr = d.get("valid_round", -1)
        if not isinstance(vr, int) or isinstance(vr, bool) or vr < -1:
            raise ValueError("consensus.valid_round: expected an integer >= -1")
        if kind == MsgKind.PROPOSE:
            if vr >= round_:
                raise ValueError("consensus.valid_round: must be lower than round")
        elif vr != -1:
            raise ValueError("consensus.valid_round: only a PROPOSE message carries one")
        return cls(
            kind=kind,
            level=_uint("level"),
            round=round_,
            block_hash=_str("block_hash"),
            validator=_str("validator"),
            validator_pubkey=_str("validator_pubkey"),
            signature=sig,
            valid_round=vr,
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
        """Strictly typed decode (Phase E: certificates now travel on the
        wire as proofs of a valid round); raises ValueError."""
        if not isinstance(d, dict):
            raise ValueError("qc: expected an object")
        for k in ("level", "round"):
            v = d.get(k)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > MAX_ROUND:
                raise ValueError(f"qc.{k}: expected a non-negative integer")
        bh = d.get("block_hash")
        if not isinstance(bh, str) or not bh:
            raise ValueError("qc.block_hash: expected a non-empty string")
        sigs = d.get("signatures")
        if not isinstance(sigs, dict) or not all(
                isinstance(a, str) and isinstance(v, str) for a, v in sigs.items()):
            raise ValueError("qc.signatures: expected an object of strings")
        kind = d.get("kind")
        if not isinstance(kind, str):
            raise ValueError("qc.kind: expected a string")
        return cls(
            kind=MsgKind(kind),
            level=d["level"],
            round=d["round"],
            block_hash=bh,
            signatures=dict(sigs),
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
    # Phase E: the signed PROPOSE message (None when the proposal was
    # handed to the engine without one, as in library use), its
    # valid_round, and whether the valid round is proven (a verified
    # pre-endorsement certificate for the block at valid_round).
    proposal_msg: Optional[ConsensusMessage] = None
    proposal_valid_round: int = -1
    proposal_proof_ok: bool = False
    preendorsements: Dict[str, ConsensusMessage] = field(default_factory=dict)
    endorsements: Dict[str, ConsensusMessage] = field(default_factory=dict)
    # Has this validator already pre-endorsed / endorsed this round?
    preendorsed: bool = False
    endorsed: bool = False
    # Cached locally-derived QCs. Phase C: only ever set to a certificate
    # that (a) contains votes for `proposed_block_hash` exclusively and
    # (b) passed QuorumCertificate.verify against the validator set.
    preendorse_qc: Optional[QuorumCertificate] = None
    endorse_qc: Optional[QuorumCertificate] = None


@dataclass
class LevelState:
    """Phase E: lock and valid round of one level (Tendermint's
    lockedRound/lockedValue and validRound/validValue)."""

    locked_round: int = -1
    locked_hash: Optional[str] = None
    valid_round: int = -1
    valid_hash: Optional[str] = None


@dataclass
class ProposalEquivocation:
    """Two different PROPOSE messages signed by the same proposer for the
    same (level, round). Phase E keeps them as verifiable evidence; making
    them slashable is a later step (consensus-locking.md section 9.3)."""

    offender: str
    msg_a: ConsensusMessage
    msg_b: ConsensusMessage

    def verify(self) -> Tuple[bool, str]:
        a, b = self.msg_a, self.msg_b
        if a.kind != MsgKind.PROPOSE or b.kind != MsgKind.PROPOSE:
            return False, "not two proposals"
        if a.validator != self.offender or b.validator != self.offender:
            return False, "messages do not come from the named offender"
        if (a.level, a.round) != (b.level, b.round):
            return False, "proposals are not for the same (level, round)"
        if a.block_hash == b.block_hash and a.valid_round == b.valid_round:
            return False, "proposals are not in conflict"
        if not a.verify_signature() or not b.verify_signature():
            return False, "one or both signatures invalid"
        return True, "valid proposal equivocation evidence"


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
    - `on_proposal(level, round, hash, ...)` is called when the local node
      has validated a proposal (received, or its own). Returns outbound
      messages.
    - `enter_round(level, round)` is called by the node when its round
      changes (timeout, or a proposal for a later round).
    - `find_endorse_qc(level, hash)` returns an endorsement certificate
      for a block at any round, once one exists.

    `current_round` is the node's round. When it is None (library use
    without a driver), the engine votes in the round of each event, as
    before Phase E; the node and the simulator always set it.
    """

    own_keypair: Optional[KernKeypair]
    own_pubkey_b58: Optional[str]
    validator_set: List[dict]  # mutable; updated each cycle
    # Window of recent states, keyed by (level, round).
    states: Dict[Tuple[int, int], RoundState] = field(default_factory=dict)
    # Phase E: lock and valid state, per level.
    levels: Dict[int, LevelState] = field(default_factory=dict)
    # Phase C: equivocation evidence observed by this engine, not yet
    # handed to the node for on-chain submission (see take_evidence).
    pending_evidence: List["SlashingEvidence"] = field(default_factory=list)
    _evidence_keys: Set[Tuple[str, str, int, int]] = field(default_factory=set)
    # Phase E: proposal equivocations, kept (not slashable yet).
    proposal_evidence: List[ProposalEquivocation] = field(default_factory=list)
    # Phase D: acceptance window. min_level is raised by prune_below; the
    # node sets current_round each tick (None disables the round check,
    # for library use without a driver).
    min_level: int = 0
    current_round: Optional[int] = None
    # Phase E: persistent signing journal (kern.signing_journal), and a
    # level up to which this validator must not sign (journal missing or
    # unreadable after a restart).
    journal: Optional[object] = None
    no_signing_through_level: int = -1

    # ---------------------------------------------------------------- helpers

    def _state(self, level: int, round_: int) -> RoundState:
        key = (level, round_)
        if key not in self.states:
            self.states[key] = RoundState(level=level, round=round_)
        return self.states[key]

    def level_state(self, level: int) -> LevelState:
        if level not in self.levels:
            self.levels[level] = LevelState()
        return self.levels[level]

    def _is_validator(self, addr: str) -> bool:
        return any(v["address"] == addr for v in self.validator_set)

    def _own_address(self) -> Optional[str]:
        if self.own_keypair is None:
            return None
        return self.own_keypair.address

    def _can_vote(self) -> bool:
        own = self._own_address()
        return own is not None and self._is_validator(own)

    def _is_current(self, round_: int) -> bool:
        return self.current_round is None or round_ == self.current_round

    def _stake_of(self, addr: str) -> int:
        v = next((v for v in self.validator_set if v["address"] == addr), None)
        return v["stake"] if v else 0

    def _total_stake(self) -> int:
        return sum(v["stake"] for v in self.validator_set)

    def _has_quorum(self, sigs: Dict[str, "ConsensusMessage"],
                    block_hash: Optional[str] = None) -> bool:
        """> 2/3 of stake voted. When `block_hash` is given, only votes for
        that exact hash count (Phase C: a vote for another block is never
        weight towards this one)."""
        if self._total_stake() == 0:
            return False
        signed = sum(
            self._stake_of(addr) for addr, m in sigs.items()
            if block_hash is None or m.block_hash == block_hash
        )
        return signed * 3 > self._total_stake() * 2

    def _qc_for(self, kind: MsgKind, state: RoundState,
                target: Optional[str]) -> Optional[QuorumCertificate]:
        """Build a quorum certificate for `target` from the votes of `kind`
        that are for that exact hash, and return it only if it verifies
        against the validator set. Pure; never stores."""
        if target is None:
            return None
        votes = state.preendorsements if kind == MsgKind.PREENDORSE else state.endorsements
        if not self._has_quorum(votes, target):
            return None
        qc = QuorumCertificate(
            kind=kind, level=state.level, round=state.round, block_hash=target,
            signatures={a: m.signature for a, m in votes.items()
                        if m.block_hash == target and m.signature is not None},
        )
        ok, reason = qc.verify(self.validator_set)
        if not ok:
            LOG.warning("discarded %s QC at L%d R%d: %s",
                        kind.value, state.level, state.round, reason)
            return None
        return qc

    def _build_qc(self, kind: MsgKind, state: RoundState) -> Optional[QuorumCertificate]:
        """Certificate for the round's PROPOSED block (Phase C)."""
        return self._qc_for(kind, state, state.proposed_block_hash)

    def _polka(self, state: RoundState) -> Optional[QuorumCertificate]:
        """A pre-endorsement certificate for any block in this round."""
        for h in sorted({m.block_hash for m in state.preendorsements.values()}):
            qc = self._qc_for(MsgKind.PREENDORSE, state, h)
            if qc is not None:
                return qc
        return None

    def _record_vote(self, store: Dict[str, "ConsensusMessage"],
                     msg: "ConsensusMessage") -> bool:
        """Store the first vote of a validator for this (level, round, kind).
        A second vote for a DIFFERENT hash is equivocation: it is not
        stored (the first vote stands) and becomes slashing evidence.
        Returns True if the vote was newly stored."""
        existing = store.get(msg.validator)
        if existing is None:
            store[msg.validator] = msg
            return True
        if existing.block_hash != msg.block_hash:
            LOG.error("EQUIVOCATION: %s %s both %s and %s at L%d R%d",
                      msg.validator, msg.kind.value, existing.block_hash[:12],
                      msg.block_hash[:12], msg.level, msg.round)
            key = (msg.validator, msg.kind.value, msg.level, msg.round)
            if key not in self._evidence_keys:
                ev = SlashingEvidence(offender=msg.validator, msg_a=existing, msg_b=msg)
                if ev.verify()[0]:
                    self._evidence_keys.add(key)
                    self.pending_evidence.append(ev)
        return False

    def take_evidence(self) -> List["SlashingEvidence"]:
        """Hand over (and clear) the equivocation evidence gathered so far."""
        out, self.pending_evidence = self.pending_evidence, []
        return out

    # ---------------------------------------------------------------- signing

    def _sign(self, msg: ConsensusMessage, after: LevelState) -> bool:
        """Sign `msg` with the node's key, after recording it in the signing
        journal together with the level's lock and valid state `after` the
        step. Returns False (and leaves `msg` unsigned) when the journal
        refuses: same (kind, level, round) already signed for another
        block, journal not writable, or signing suspended after a restart
        without a readable journal."""
        assert self.own_keypair is not None
        if msg.level <= self.no_signing_through_level:
            LOG.warning("not signing %s at L%d R%d: waiting for the level to be "
                        "finalized by others (signing journal missing or unreadable)",
                        msg.kind.value, msg.level, msg.round)
            return False
        j = self.journal
        if j is not None:
            svr = msg.valid_round if msg.kind == MsgKind.PROPOSE else -1
            if j.conflicts(msg.kind.value, msg.level, msg.round, msg.block_hash,  # type: ignore[attr-defined]
                           svr):
                LOG.error("signing journal: refusing %s at L%d R%d for %s, another "
                          "message was signed there before", msg.kind.value, msg.level,
                          msg.round, msg.block_hash[:12])
                return False
            try:
                j.append(msg.kind.value, msg.level, msg.round, msg.block_hash,  # type: ignore[attr-defined]
                         locked_round=after.locked_round, locked_hash=after.locked_hash,
                         valid_round=after.valid_round, valid_hash=after.valid_hash,
                         signed_valid_round=svr)
            except OSError:
                LOG.exception("signing journal: write failed, not signing")
                return False
        msg.sign(self.own_keypair)
        return True

    def _vote(self, kind: MsgKind, state: RoundState, after: LevelState) -> Optional[ConsensusMessage]:
        own = self._own_address()
        assert own is not None and state.proposed_block_hash is not None
        msg = ConsensusMessage(
            kind=kind, level=state.level, round=state.round,
            block_hash=state.proposed_block_hash, validator=own,
            validator_pubkey=self.own_pubkey_b58 or "",
        )
        return msg if self._sign(msg, after) else None

    def restore_lock(self, level: int, locked_round: int, locked_hash: Optional[str],
                     valid_round: int, valid_hash: Optional[str]) -> None:
        """Restore a level's lock and valid state from the signing journal."""
        lv = self.level_state(level)
        lv.locked_round, lv.locked_hash = locked_round, locked_hash
        lv.valid_round, lv.valid_hash = valid_round, valid_hash

    # ---------------------------------------------------------------- rules

    def _proof_ok(self, state: RoundState) -> bool:
        """The proposal's valid_round is proven: by the certificate that
        came with it (checked in on_proposal), or by a pre-endorsement
        certificate for the block that this engine has itself seen."""
        vr = state.proposal_valid_round
        if vr < 0 or vr >= state.round:
            return False
        if state.proposal_proof_ok:
            return True
        seen = self.states.get((state.level, vr))
        return seen is not None and self._qc_for(
            MsgKind.PREENDORSE, seen, state.proposed_block_hash) is not None

    def _may_preendorse(self, state: RoundState) -> bool:
        """Rule 2: pre-endorse the proposal X of the current round if this
        validator is not locked, is locked on X, or the proposal proves a
        pre-endorsement certificate for X more recent than the lock."""
        x = state.proposed_block_hash
        lv = self.level_state(state.level)
        if lv.locked_round < 0 or lv.locked_hash == x:
            return True
        return state.proposal_valid_round > lv.locked_round and self._proof_ok(state)

    def _advance(self, state: RoundState) -> List[ConsensusMessage]:
        """Re-evaluate a round after any new vote, the proposal itself, or a
        change of the node's round. Certificates are only built for a
        definite block, and a round keeps trying until a VALID certificate
        exists, so a stray or hostile vote can delay nothing (Phase C,
        review point A). Phase E: votes are signed only in the current
        round, under the lock rules."""
        outbound: List[ConsensusMessage] = []
        lv = self.level_state(state.level)

        # Rule 4: track the most recent pre-endorsement certificate seen,
        # never above the node's round.
        if state.round > lv.valid_round and (
                self.current_round is None or state.round <= self.current_round):
            polka = (self._build_qc(MsgKind.PREENDORSE, state)
                     if state.proposed_block_hash is not None else None) or self._polka(state)
            if polka is not None:
                lv.valid_round, lv.valid_hash = state.round, polka.block_hash

        if state.proposed_block_hash is None:
            return outbound
        x = state.proposed_block_hash
        current = self._is_current(state.round)

        # Rule 2: pre-endorse.
        if current and self._can_vote() and not state.preendorsed and self._may_preendorse(state):
            msg = self._vote(MsgKind.PREENDORSE, state, lv)
            if msg is not None:
                assert msg.validator is not None
                state.preendorsements.setdefault(msg.validator, msg)
                state.preendorsed = True
                outbound.append(msg)
                LOG.debug("emitted PREENDORSE for L%d R%d hash=%s", state.level, state.round, x[:12])

        if state.preendorse_qc is None:
            state.preendorse_qc = self._build_qc(MsgKind.PREENDORSE, state)
            if state.preendorse_qc is not None and state.round > lv.valid_round and (
                    self.current_round is None or state.round <= self.current_round):
                lv.valid_round, lv.valid_hash = state.round, x

        # Rule 3: endorse and lock, once per round, in the current round.
        if state.preendorse_qc is not None and current and self._can_vote() and not state.endorsed:
            after = LevelState(locked_round=state.round, locked_hash=x,
                               valid_round=max(lv.valid_round, state.round),
                               valid_hash=x if state.round >= lv.valid_round else lv.valid_hash)
            msg = self._vote(MsgKind.ENDORSE, state, after)
            if msg is not None:
                lv.locked_round, lv.locked_hash = after.locked_round, after.locked_hash
                lv.valid_round, lv.valid_hash = after.valid_round, after.valid_hash
                state.endorsements.setdefault(msg.validator, msg)
                state.endorsed = True
                outbound.append(msg)
                LOG.debug("emitted ENDORSE for L%d R%d hash=%s", state.level, state.round, x[:12])

        if state.endorse_qc is None:
            state.endorse_qc = self._build_qc(MsgKind.ENDORSE, state)
            if state.endorse_qc is not None:
                LOG.info("ENDORSEMENT QUORUM reached at L%d R%d hash=%s",
                         state.level, state.round, state.endorse_qc.block_hash[:12])
        return outbound

    # ---------------------------------------------------------------- inbound

    def on_proposal(self, level: int, round_: int, block_hash: str, *,
                    valid_round: int = -1,
                    proof: Optional[QuorumCertificate] = None,
                    proposal_msg: Optional[ConsensusMessage] = None) -> List[ConsensusMessage]:
        """Called when this node has validated a proposal for (level, round)
        (received over the network, or its own). The node has already
        checked the block and the proposer; the engine checks the signed
        PROPOSE message when given (and keeps an equivocation as evidence)
        and the proof of `valid_round`."""
        if proposal_msg is not None:
            if (proposal_msg.kind != MsgKind.PROPOSE or proposal_msg.level != level
                    or proposal_msg.round != round_ or proposal_msg.block_hash != block_hash
                    or proposal_msg.valid_round != valid_round
                    or not proposal_msg.verify_signature()):
                LOG.warning("rejected proposal at L%d R%d: PROPOSE message does not match",
                            level, round_)
                return []
        state = self._state(level, round_)
        if (proposal_msg is not None and state.proposal_msg is not None
                and state.proposal_msg.validator == proposal_msg.validator
                and (state.proposal_msg.block_hash != proposal_msg.block_hash
                     or state.proposal_msg.valid_round != proposal_msg.valid_round)):
            ev = ProposalEquivocation(proposal_msg.validator, state.proposal_msg, proposal_msg)
            if ev.verify()[0] and not any(
                    (e.offender, e.msg_a.level, e.msg_a.round) == (ev.offender, level, round_)
                    for e in self.proposal_evidence):
                LOG.error("PROPOSAL EQUIVOCATION: %s at L%d R%d", ev.offender, level, round_)
                self.proposal_evidence.append(ev)
        if state.proposed_block_hash is None:
            state.proposed_block_hash = block_hash
            state.proposal_msg = proposal_msg
            state.proposal_valid_round = valid_round
            state.proposal_proof_ok = self._check_proof(level, round_, block_hash, valid_round, proof)
        elif state.proposed_block_hash != block_hash:
            LOG.warning(
                "conflicting proposal at L%d R%d: had %s, got %s — ignoring second",
                level, round_, state.proposed_block_hash[:12], block_hash[:12],
            )
            return []
        elif state.proposal_msg is None and proposal_msg is not None:
            state.proposal_msg = proposal_msg
        return self._advance(state)

    def _check_proof(self, level: int, round_: int, block_hash: str, valid_round: int,
                     proof: Optional[QuorumCertificate]) -> bool:
        if valid_round < 0 or proof is None:
            return False
        if (proof.kind != MsgKind.PREENDORSE or proof.level != level
                or proof.round != valid_round or valid_round >= round_
                or proof.block_hash != block_hash):
            return False
        return proof.verify(self.validator_set)[0]

    def enter_round(self, level: int, round_: int) -> List[ConsensusMessage]:
        """The node moved to `round_` at `level`: re-evaluate that round,
        whose proposal and votes may already have arrived."""
        self.current_round = round_
        state = self.states.get((level, round_))
        return self._advance(state) if state is not None else []

    def make_proposal(self, level: int, round_: int, block_hash: str,
                      valid_round: int) -> Optional[ConsensusMessage]:
        """Sign this node's PROPOSE message for (level, round), through the
        signing journal. None if the journal refuses (for instance a
        restarted proposer that already proposed another block there)."""
        own = self._own_address()
        if own is None:
            return None
        msg = ConsensusMessage(kind=MsgKind.PROPOSE, level=level, round=round_,
                               block_hash=block_hash, validator=own,
                               validator_pubkey=self.own_pubkey_b58 or "",
                               valid_round=valid_round)
        return msg if self._sign(msg, self.level_state(level)) else None

    def adopt_self_commit(self, msg: ConsensusMessage) -> bool:
        """A proposer that holds more than two thirds of the stake signs its
        own endorsement when it builds the block (kern.consensus
        propose_block). That signature is an endorsement like any other:
        record it in the journal, lock on the block, and count it. The
        caller must not publish the block if this returns False.

        The engine checks the rule itself (review of f24564b): the message
        must carry a valid signature by this validator's key, and this
        validator must hold strictly more than two thirds of the stake.
        Below that, an endorsement signed before any pre-endorsement
        certificate would bypass the lock rules."""
        own = self._own_address()
        if own is None or msg.validator != own or msg.kind != MsgKind.ENDORSE:
            return False
        if msg.validator_pubkey != (self.own_pubkey_b58 or "") or not msg.verify_signature():
            LOG.error("refusing a self-commit without a valid own signature")
            return False
        total = self._total_stake()
        if total <= 0 or self._stake_of(own) * 3 <= total * 2:
            LOG.error("refusing a self-commit: this validator does not hold more "
                      "than two thirds of the stake")
            return False
        if msg.level <= self.no_signing_through_level:
            return False
        lv = self.level_state(msg.level)
        if lv.locked_round >= 0 and lv.locked_hash != msg.block_hash:
            return False
        after = LevelState(msg.round, msg.block_hash, max(lv.valid_round, msg.round), msg.block_hash)
        j = self.journal
        if j is not None:
            if j.conflicts(msg.kind.value, msg.level, msg.round, msg.block_hash):  # type: ignore[attr-defined]
                return False
            try:
                j.append(msg.kind.value, msg.level, msg.round, msg.block_hash,  # type: ignore[attr-defined]
                         locked_round=after.locked_round, locked_hash=after.locked_hash,
                         valid_round=after.valid_round, valid_hash=after.valid_hash)
            except OSError:
                return False
        lv.locked_round, lv.locked_hash = after.locked_round, after.locked_hash
        lv.valid_round, lv.valid_hash = after.valid_round, after.valid_hash
        state = self._state(msg.level, msg.round)
        state.endorsements.setdefault(own, msg)
        state.endorsed = True
        return True

    def in_window(self, level: int, round_: int) -> bool:
        """True if (level, round) is close enough to the node's position to
        be worth keeping state for."""
        if level < self.min_level or level > self.min_level + MAX_LEVELS_AHEAD:
            return False
        if self.current_round is not None and abs(round_ - self.current_round) > MAX_ROUND_DISTANCE:
            return False
        if (level, round_) not in self.states and len(self.states) >= MAX_ROUND_STATES:
            return False
        return True

    def on_message(self, msg: ConsensusMessage) -> List[ConsensusMessage]:
        """Process an incoming consensus message. Returns outbound messages
        to broadcast (typically: an endorsement once preendorse quorum is met)."""
        if not self.in_window(msg.level, msg.round):
            LOG.debug("dropped out-of-window consensus message L%d R%d from %s",
                      msg.level, msg.round, msg.validator)
            return []
        if not msg.verify_signature():
            LOG.warning("rejected unsigned/invalid consensus message from %s", msg.validator)
            return []
        if not self._is_validator(msg.validator):
            LOG.warning("rejected message from non-validator %s", msg.validator)
            return []

        if msg.kind == MsgKind.PROPOSE:
            # A bare PROPOSE carries no block: the node only hands proposals
            # to the engine after validating the block (on_proposal).
            return []

        state = self._state(msg.level, msg.round)
        if msg.kind == MsgKind.PREENDORSE:
            self._record_vote(state.preendorsements, msg)
        elif msg.kind == MsgKind.ENDORSE:
            self._record_vote(state.endorsements, msg)
        else:
            return []
        out = self._advance(state)
        # A certificate in this round may complete a proof for a later
        # proposal in the current round (rule 2) or move the valid round.
        if self.current_round is not None and msg.round < self.current_round:
            cur = self.states.get((msg.level, self.current_round))
            if cur is not None:
                out += self._advance(cur)
        return out

    # ---------------------------------------------------------------- queries

    def get_endorse_qc(self, level: int, round_: int) -> Optional[QuorumCertificate]:
        state = self.states.get((level, round_))
        return state.endorse_qc if state else None

    def get_preendorse_qc(self, level: int, round_: int) -> Optional[QuorumCertificate]:
        state = self.states.get((level, round_))
        return state.preendorse_qc if state else None

    def find_preendorse_qc(self, level: int, round_: int,
                           block_hash: str) -> Optional[QuorumCertificate]:
        """Pre-endorsement certificate for `block_hash` at (level, round),
        whether or not it was that round's proposal (a proposer's proof)."""
        state = self.states.get((level, round_))
        return self._qc_for(MsgKind.PREENDORSE, state, block_hash) if state else None

    def find_endorse_qc(self, level: int, block_hash: str) -> Optional[QuorumCertificate]:
        """Endorsement certificate for `block_hash` at `level`, at the lowest
        round where one exists (rule 6: finalize at any round)."""
        for (lvl, _r), state in sorted(self.states.items()):
            if lvl != level:
                continue
            qc = (state.endorse_qc if state.endorse_qc is not None
                  and state.endorse_qc.block_hash == block_hash
                  else self._qc_for(MsgKind.ENDORSE, state, block_hash))
            if qc is not None:
                return qc
        return None

    def round_to_skip_to(self, level: int) -> Optional[int]:
        """Highest round above the current one in which validators holding
        more than one third of the stake have already voted (Tendermint's
        round skip). At least one honest validator is there, so the node
        can move to that round without waiting for its own timeouts, and a
        byzantine minority cannot make it jump."""
        if self.current_round is None:
            return None
        total = self._total_stake()
        best: Optional[int] = None
        for (lvl, r), st in self.states.items():
            if lvl != level or r <= self.current_round or (best is not None and r <= best):
                continue
            voters = set(st.preendorsements) | set(st.endorsements)
            if total > 0 and sum(self._stake_of(a) for a in voters) * 3 > total:
                best = r
        return best

    def prune_below(self, level: int) -> None:
        """Drop state for levels strictly below `level` (free memory)."""
        to_drop = [k for k in self.states if k[0] < level]
        for k in to_drop:
            del self.states[k]
        for lvl in [lvl for lvl in self.levels if lvl < level]:
            del self.levels[lvl]
        self.min_level = max(self.min_level, level)


# ---------------------------------------------------------------------------
# Commit verification (used by chain.validate_block)
# ---------------------------------------------------------------------------

def commit_entry(msg: "ConsensusMessage") -> str:
    """Canonical wire form of an endorsement inside a block:
    "<kn1 address>:<base58 signature>"."""
    return f"{msg.validator}:{msg.signature}"


def verify_commits(
    block_hash: str,
    level: int,
    round_: int,
    entries: List[str],
    validator_set: List[dict],
) -> Tuple[int, Optional[str]]:
    """Verify a list of "addr:sig" endorsement entries against the block.

    Each signature must be a valid ENDORSE ConsensusMessage signature by a
    validator in the set, over (endorse, level, round, block_hash, addr,
    pubkey). Returns (verified_stake, error). Any malformed or forged
    entry is a hard error — a block carrying junk in its quorum evidence
    is invalid, full stop. Duplicate addresses count once."""
    seen: Set[str] = set()
    stake = 0
    for entry in entries:
        if ":" not in entry:
            return 0, f"malformed commit entry: {entry[:32]!r}"
        addr, sig = entry.split(":", 1)
        if addr in seen:
            continue
        v = next((v for v in validator_set if v["address"] == addr), None)
        if v is None:
            return 0, f"commit from non-validator {addr}"
        msg = ConsensusMessage(
            kind=MsgKind.ENDORSE,
            level=level,
            round=round_,
            block_hash=block_hash,
            validator=addr,
            validator_pubkey=v["pubkey"],
            signature=sig,
        )
        if not msg.verify_signature():
            return 0, f"invalid commit signature from {addr}"
        seen.add(addr)
        stake += v["stake"]
    return stake, None


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
