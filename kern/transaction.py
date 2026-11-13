# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.transaction
----------------

Transaction types in Kern.

Three operation kinds are supported in the reference implementation:
1. TRANSFER  — move native KRN tokens from sender to recipient.
2. ORIGINATE — deploy a Skald contract; storage initialized from `params`.
3. CALL      — invoke an entry point of an originated contract.

Each transaction carries a nonce (per-sender, monotonically increasing),
a fee paid to the baker, and a gas limit. The transaction body is signed
by the sender; the signature covers a canonical serialization that does
NOT include the signature itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Callable, Optional

from .crypto import (
    KernKeypair,
    address_from_pubkey,
    pubkey_from_b58,
    signature_from_b58,
    tx_hash,
    verify,
)
from .nesting import nests_beyond

# A transaction, as JSON, nests 32 levels deep at most: itself, then what
# `params` and `initial_storage` hold. Every frame of the peer-to-peer
# protocol that carries a transaction then stays under the depth at which a
# frame is refused before it is decoded (kern.nesting.MAX_JSON_DEPTH): what
# a node admitted, it can pass on, and every node reads it.
MAX_TX_NESTING = 32



# ---------------------------------------------------------------------------
# Strict decoding helpers (ingress validation)
# ---------------------------------------------------------------------------

def _req_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"tx.{key}: expected a non-empty string")
    return v


def _opt_str(d: dict, key: str):
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"tx.{key}: expected a string or null")
    return v


def _req_uint(d: dict, key: str) -> int:
    v = d.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError(f"tx.{key}: expected a non-negative integer")
    return v


def _opt_uint(d: dict, key: str, default: int = 0) -> int:
    v = d.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError(f"tx.{key}: expected a non-negative integer")
    return v


class OpKind(str, Enum):
    TRANSFER = "transfer"
    ORIGINATE = "originate"
    CALL = "call"
    GOVERNANCE_PROPOSE = "governance_propose"
    GOVERNANCE_VOTE = "governance_vote"
    SLASH_EQUIVOCATION = "slash_equivocation"   # v1.0-rc
    DELEGATE_STAKE = "delegate_stake"           # v1.0-rc: stake delegation (bonded since Phase D)
    UNDELEGATE_STAKE = "undelegate_stake"       # v1.0-rc
    # v1.1-rc: slashable attestations — generalize the equivocation
    # detection-and-punishment pattern beyond governance to any
    # signed claim about the world. See kern/attestation.py.
    ATTEST = "attest"
    REVOKE_ATTESTATION = "revoke_attestation"
    SLASH_ATTESTATION_EQUIVOCATION = "slash_attestation_equivocation"
    # Phase C: slash a validator that signed two conflicting consensus
    # votes (PREENDORSE or ENDORSE) at the same (level, round).
    SLASH_CONSENSUS_EQUIVOCATION = "slash_consensus_equivocation"


@dataclass
class Transaction:
    """A signed Kern transaction.

    Signed bytes = canonical_json({kind, sender, sender_pubkey, nonce, fee,
    gas_limit, ...kind-specific fields}). Signature and tx hash are
    computed from those bytes.
    """

    kind: OpKind
    sender: str                  # kn1... address
    sender_pubkey: str           # kpk... base58 public key
    nonce: int
    fee: int                     # in mukrn (1 KRN = 1_000_000 mukrn)
    gas_limit: int

    # kind-specific fields
    recipient: Optional[str] = None      # TRANSFER, CALL
    amount: int = 0                      # TRANSFER, CALL (attached value)
    code: Optional[str] = None           # ORIGINATE: Skald source
    initial_storage: Any = None          # ORIGINATE
    entry: Optional[str] = None          # CALL: entry point name
    params: Any = None                   # CALL: parameter value

    signature: Optional[str] = None      # filled in by sign()

    # Optional chain_id for cross-network replay protection. If None,
    # the transaction is bound to the chain that originally signed it
    # (genesis hash-rooted identifier). See _signed_payload().
    chain_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Reject structurally invalid transactions at construction time.

        These checks close several CRITICAL vulnerabilities discovered
        during the v1.1-rc internal security review (S-CRIT-1, S-CRIT-2,
        S-MIN-1):

        - A negative `fee` would let an attacker DRAIN the baker's
          balance by crediting `-tx.fee` (which is a debit) to the
          baker while crediting `+tx.fee` (a credit) to the sender.
        - A negative `amount` in TRANSFER would let an attacker DRAIN
          the named "recipient"'s balance (the recipient is credited
          a negative amount and the sender is "debited" a negative
          amount — i.e. credited).
        - A negative `nonce` or `gas_limit` doesn't lead to direct
          theft but breaks accounting invariants downstream.

        We enforce non-negativity for all numeric fields HERE rather
        than at every consumer, so any consumer (mempool, RPC inject,
        block construction, replay) gets the same guarantee.

        Phase B (audit 1, finding 7): field TYPES are checked here as well,
        not only in from_dict, so that a Transaction built in-process (by a
        tool, a test or a future decoder) cannot carry a string fee or a
        list recipient into the state machine either."""
        if not isinstance(self.kind, OpKind):
            raise TypeError(f"tx.kind must be an OpKind, got {type(self.kind).__name__}")
        for name in ("sender", "sender_pubkey"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"tx.{name} must be a string")
        for name in ("nonce", "fee", "gas_limit", "amount"):
            v = getattr(self, name)
            # bool is a subclass of int in Python; reject it explicitly.
            if isinstance(v, bool) or not isinstance(v, int):
                raise TypeError(f"tx.{name} must be an integer, got {type(v).__name__}")
        for name in ("recipient", "code", "entry", "signature", "chain_id"):
            v = getattr(self, name)
            if v is not None and not isinstance(v, str):
                raise TypeError(f"tx.{name} must be a string or null")
        if self.fee < 0:
            raise ValueError(f"fee must be non-negative, got {self.fee}")
        if self.amount < 0:
            raise ValueError(f"amount must be non-negative, got {self.amount}")
        if self.gas_limit < 0:
            raise ValueError(f"gas_limit must be non-negative, got {self.gas_limit}")
        if self.nonce < 0:
            raise ValueError(f"nonce must be non-negative, got {self.nonce}")
        for name in ("initial_storage", "params"):
            if nests_beyond(getattr(self, name), MAX_TX_NESTING - 1):
                raise ValueError(f"tx.{name}: a transaction nested more than {MAX_TX_NESTING} deep")

    # ----- canonical encoding ------------------------------------------------

    def _signed_payload(self) -> bytes:
        d = {
            "kind": self.kind.value,
            "sender": self.sender,
            "sender_pubkey": self.sender_pubkey,
            "nonce": self.nonce,
            "fee": self.fee,
            "gas_limit": self.gas_limit,
            "recipient": self.recipient,
            "amount": self.amount,
            "code": self.code,
            "initial_storage": self.initial_storage,
            "entry": self.entry,
            "params": self.params,
            # chain_id binds the signature to a specific Kern network.
            # A transaction signed for devnet cannot be replayed on
            # mainnet (the canonical chain_id differs). Closes the
            # cross-network replay vulnerability S-MAJ-1 from the
            # v1.1-rc internal security review.
            "chain_id": self.chain_id,
        }
        # Canonical JSON: sorted keys, no whitespace, UTF-8.
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> bytes:
        return tx_hash(self._signed_payload())

    def encoded_size(self) -> int:
        """Deterministic encoded size of this transaction, in bytes.

        Uses the canonical signed payload (sorted-key, whitespace-free JSON),
        so every node computes the identical value. Used as the size proxy for
        the optional L1 fee floor and per-block size cap (see kern.chain)."""
        return len(self._signed_payload())

    def hash_hex(self) -> str:
        return self.hash().hex()

    def sign(self, keypair: KernKeypair) -> "Transaction":
        if keypair.address != self.sender:
            raise ValueError("keypair address does not match transaction sender")
        self.signature = keypair.sign_b58(self._signed_payload())
        return self

    def verify_signature(self) -> bool:
        if self.signature is None:
            return False
        try:
            pubkey = pubkey_from_b58(self.sender_pubkey)
            if address_from_pubkey(pubkey) != self.sender:
                return False
            sig = signature_from_b58(self.signature)
            return verify(pubkey, self._signed_payload(), sig)
        except Exception:
            return False

    # ----- (de)serialization -------------------------------------------------

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        """Decode a transaction dict with strict type and bounds checks.

        This is the ingress gate for every transaction that arrives from
        outside the process (P2P gossip and RPC injection both route
        through it), so it must reject malformed shapes *here* rather than
        letting them surface later inside consensus code. Raises
        ValueError with a field-specific message on any violation.
        Note: bool is a subclass of int in Python, so integer fields
        explicitly reject booleans."""
        if not isinstance(d, dict):
            raise ValueError("tx: expected an object")
        return cls(
            kind=OpKind(_req_str(d, "kind")),
            sender=_req_str(d, "sender"),
            sender_pubkey=_req_str(d, "sender_pubkey"),
            nonce=_req_uint(d, "nonce"),
            fee=_req_uint(d, "fee"),
            gas_limit=_req_uint(d, "gas_limit"),
            recipient=_opt_str(d, "recipient"),
            amount=_opt_uint(d, "amount", default=0),
            code=_opt_str(d, "code"),
            initial_storage=d.get("initial_storage"),
            entry=_opt_str(d, "entry"),
            params=d.get("params"),
            signature=_opt_str(d, "signature"),
            chain_id=_opt_str(d, "chain_id"),
        )


class Waiting:
    """A transaction as a mempool describes it: the four facts that tell
    whether the next block can charge it, and the transaction itself, which
    is read only when it is asked for.

    A proposer goes through everything that waits at every block. Sender,
    nonce, fee and size are enough to leave a transaction where it is or to
    remove it; decoding it is for those the block takes."""

    __slots__ = ("hash_hex", "sender", "nonce", "fee", "size", "_read")

    def __init__(self, hash_hex: str, sender: str, nonce: int, fee: int, size: int,
                 read: Callable[[], Optional[Transaction]]):
        self.hash_hex = hash_hex
        self.sender = sender
        self.nonce = nonce
        self.fee = fee
        self.size = size
        self._read = read

    @classmethod
    def of(cls, tx: Transaction) -> "Waiting":
        """The description of a transaction that is already at hand."""
        return cls(tx.hash_hex(), tx.sender, tx.nonce, tx.fee, tx.encoded_size(), lambda: tx)

    def transaction(self) -> Optional[Transaction]:
        """The transaction, or None when it is gone or cannot be read any more."""
        return self._read()


def make_transfer(
    sender_kp: KernKeypair,
    recipient: str,
    amount: int,
    nonce: int,
    fee: int = 1_000,
    gas_limit: int = 10_000,
) -> Transaction:
    tx = Transaction(
        kind=OpKind.TRANSFER,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        recipient=recipient,
        amount=amount,
    )
    tx.sign(sender_kp)
    return tx


def make_origination(
    sender_kp: KernKeypair,
    code: str,
    initial_storage: Any,
    nonce: int,
    fee: int = 10_000,
    gas_limit: int = 100_000,
) -> Transaction:
    tx = Transaction(
        kind=OpKind.ORIGINATE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        code=code,
        initial_storage=initial_storage,
    )
    tx.sign(sender_kp)
    return tx


def make_call(
    sender_kp: KernKeypair,
    contract: str,
    entry: str,
    params: Any,
    amount: int = 0,
    nonce: int = 0,
    fee: int = 5_000,
    gas_limit: int = 50_000,
) -> Transaction:
    tx = Transaction(
        kind=OpKind.CALL,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        recipient=contract,
        amount=amount,
        entry=entry,
        params=params,
    )
    tx.sign(sender_kp)
    return tx


def make_governance_propose(
    sender_kp: KernKeypair,
    track: str,              # "protocol" or "treasury"
    payload: dict,
    nonce: int,
    salt: int = 0,
    fee: int = 10_000,
    gas_limit: int = 50_000,
) -> Transaction:
    """Submit a governance proposal. The proposal lives in the chain state
    under `state["governance"][track]["proposals"]` until it terminates.

    For protocol proposals, the sender must be a registered validator.
    Treasury proposals are open to any sender."""
    if track not in ("protocol", "treasury"):
        raise ValueError("track must be 'protocol' or 'treasury'")
    tx = Transaction(
        kind=OpKind.GOVERNANCE_PROPOSE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"track": track, "payload": payload, "salt": salt},
    )
    tx.sign(sender_kp)
    return tx


def make_governance_vote(
    sender_kp: KernKeypair,
    track: str,
    proposal_id: str,
    vote: str,               # "yes" / "no" / "abstain"
    nonce: int,
    fee: int = 5_000,
    gas_limit: int = 20_000,
) -> Transaction:
    """Cast a vote on a governance proposal. Sender must be a registered
    validator. Votes are recorded on-chain; equivocation (different votes
    on the same proposal in the same phase from the same sender) is
    detectable from the block history and slashable."""
    if track not in ("protocol", "treasury"):
        raise ValueError("track must be 'protocol' or 'treasury'")
    if vote not in ("yes", "no", "abstain"):
        raise ValueError("vote must be 'yes', 'no', or 'abstain'")
    tx = Transaction(
        kind=OpKind.GOVERNANCE_VOTE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"track": track, "proposal_id": proposal_id, "vote": vote},
    )
    tx.sign(sender_kp)
    return tx


def make_slash_equivocation(
    sender_kp: KernKeypair,
    proposal_id: str,
    equivocator: str,        # the validator whose double-vote is the evidence
    nonce: int,
    fee: int = 1_000,        # tiny fee — slashing reports should be cheap
    gas_limit: int = 30_000,
) -> Transaction:
    """Submit slashing evidence: a proposal's `equivocations` list contains
    a record naming `equivocator`. Anyone can submit (it's a public good
    to report dishonest validators). On accept, the equivocator's stake
    is reduced and a portion is paid to the reporter (whistleblower
    reward); the rest is burned.

    The on-chain evidence is just the proposal_id + equivocator — the
    runtime looks up the actual equivocation record from the chain
    state, so the report is small and the verification is cheap."""
    tx = Transaction(
        kind=OpKind.SLASH_EQUIVOCATION,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"proposal_id": proposal_id, "equivocator": equivocator},
    )
    tx.sign(sender_kp)
    return tx


def make_slash_consensus_equivocation(
    sender_kp: KernKeypair,
    msg_a: dict,
    msg_b: dict,
    nonce: int,
    fee: int = 1_000,
    gas_limit: int = 30_000,
    chain_id: Optional[str] = None,
) -> Transaction:
    """Submit proof that a validator signed two conflicting consensus votes
    of the same kind at the same (level, round). `msg_a` and `msg_b` are
    ConsensusMessage.to_dict() payloads; the chain re-verifies both
    signatures against the offender's registered key. Phase C."""
    tx = Transaction(
        kind=OpKind.SLASH_CONSENSUS_EQUIVOCATION,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"msg_a": msg_a, "msg_b": msg_b},
        chain_id=chain_id,
    )
    tx.sign(sender_kp)
    return tx


def make_delegate_stake(
    sender_kp: KernKeypair,
    validator: str,           # kn1... address of the baker
    nonce: int,
    fee: int = 2_000,
    gas_limit: int = 20_000,
    amount: int = 0,
    chain_id: Optional[str] = None,
) -> Transaction:
    """Bond `amount` mukrn from the sender's balance to a validator.

    Phase D: delegation is bonded. The amount leaves the balance, counts
    in the validator's consensus weight and reward share, and is slashed
    with the validator for offences committed after it was bonded (Phase E:
    each top-up is a separate slice with its own level). It weighs in
    consensus from the next epoch boundary. Delegating again to the same
    validator adds to the bond; switching validator requires UNDELEGATE_STAKE first, after which
    the bond stays locked (and slashable) for the unbonding period before
    returning to the balance."""
    tx = Transaction(
        kind=OpKind.DELEGATE_STAKE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        amount=amount,
        params={"validator": validator},
        chain_id=chain_id,
    )
    tx.sign(sender_kp)
    return tx


def make_undelegate_stake(
    sender_kp: KernKeypair,
    nonce: int,
    fee: int = 2_000,
    gas_limit: int = 20_000,
) -> Transaction:
    """Stop delegating. The bond stops counting in the validator's
    consensus weight and reward share at once (Phase E), but stays locked
    for the unbonding period and is still slashed for offences the
    validator committed up to the level of this undelegation. It then
    returns to the sender's balance."""
    tx = Transaction(
        kind=OpKind.UNDELEGATE_STAKE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={},
    )
    tx.sign(sender_kp)
    return tx


# --- Slashable attestations (v1.1-rc) -------------------------------------

def make_attest(
    sender_kp: KernKeypair,
    schema_id: str,
    subject: str,
    claim: dict,
    nonce: int,
    bond: int = 0,
    fee: int = 2_000,
    gas_limit: int = 30_000,
) -> Transaction:
    """Issue an attestation: a signed claim about a subject under a schema.

    The attestation is recorded on-chain. If the same issuer later signs
    a CONTRADICTORY claim about the same (schema_id, subject) pair, anyone
    can submit a SLASH_ATTESTATION_EQUIVOCATION transaction to slash the
    issuer's bond and earn the whistleblower reward.

    Parameters:
        schema_id: Identifier of the attestation schema (e.g.,
            "price.usd-pair", "kyc.aml-screening", "energy.grid-frequency-hz",
            "telco.subscriber-count"). Schemas are open — anyone can use any
            string. Convention: dotted-namespace.
        subject: What the claim is about (e.g., "BTC", "kn1userAddress",
            "EU-grid-region-CWE", "FR-metro-orange").
        claim: The actual claim payload (any JSON-serializable dict).
        bond: Optional KRN amount locked alongside this attestation. Required
            for high-stakes attestations (oracles); zero is allowed but means
            no slashing-deterrent (the issuer's reputation is the only stake).

    On equivocation:
        - The issuer's bond is reduced by SLASHING_PERCENTAGE (30%)
        - 10% of the slash is paid to the whistleblower
        - The rest is burned"""
    tx = Transaction(
        kind=OpKind.ATTEST,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        amount=bond,                # bond travels in the amount field
        params={
            "schema_id": schema_id,
            "subject": subject,
            "claim": claim,
        },
    )
    tx.sign(sender_kp)
    return tx


def make_revoke_attestation(
    sender_kp: KernKeypair,
    attestation_id: str,
    nonce: int,
    fee: int = 2_000,
    gas_limit: int = 20_000,
) -> Transaction:
    """Revoke a previously issued attestation. The bond, if any, is
    returned to the issuer (less the revocation fee). Revocation does
    NOT prevent slashing for past equivocation — if you contradicted
    yourself before revoking, the evidence remains submittable.

    The attestation_id is the deterministic hash of the attestation
    transaction's (sender, schema_id, subject, attest_nonce)."""
    tx = Transaction(
        kind=OpKind.REVOKE_ATTESTATION,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"attestation_id": attestation_id},
    )
    tx.sign(sender_kp)
    return tx


def make_slash_attestation_equivocation(
    sender_kp: KernKeypair,
    attestation_id_1: str,
    attestation_id_2: str,
    nonce: int,
    fee: int = 1_000,
    gas_limit: int = 40_000,
) -> Transaction:
    """Submit slashing evidence: two contradicting attestations under the
    same (issuer, schema_id, subject) tuple with different claims.

    Anyone can submit. The runtime verifies that:
    - Both attestation_ids exist on-chain
    - Both have the same issuer (sender)
    - Both have the same schema_id and subject
    - The claims differ
    - The attestations have overlapping validity windows (i.e., they
      weren't a revoke-and-reissue pattern)
    - Neither has been used for slashing already (no double-slashing)

    On success:
    - Issuer's remaining bond on the LATER attestation is slashed 30%
    - Whistleblower (sender of this tx) receives 10% of the slashed amount
    - The rest is burned
    - Both attestations are marked "consumed_for_slashing" (idempotent)"""
    tx = Transaction(
        kind=OpKind.SLASH_ATTESTATION_EQUIVOCATION,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={
            "attestation_id_1": attestation_id_1,
            "attestation_id_2": attestation_id_2,
        },
    )
    tx.sign(sender_kp)
    return tx
