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
from typing import Any, Optional

from .crypto import (
    KernKeypair,
    address_from_pubkey,
    pubkey_from_b58,
    signature_from_b58,
    tx_hash,
    verify,
)


class OpKind(str, Enum):
    TRANSFER = "transfer"
    ORIGINATE = "originate"
    CALL = "call"
    GOVERNANCE_PROPOSE = "governance_propose"
    GOVERNANCE_VOTE = "governance_vote"
    SLASH_EQUIVOCATION = "slash_equivocation"   # v1.0-rc
    DELEGATE_STAKE = "delegate_stake"           # v1.0-rc: Liquid PoS baking delegation
    UNDELEGATE_STAKE = "undelegate_stake"       # v1.0-rc
    # v1.1-rc: slashable attestations — generalize the equivocation
    # detection-and-punishment pattern beyond governance to any
    # signed claim about the world. See kern/attestation.py.
    ATTEST = "attest"
    REVOKE_ATTESTATION = "revoke_attestation"
    SLASH_ATTESTATION_EQUIVOCATION = "slash_attestation_equivocation"


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
        block construction, replay) gets the same guarantee."""
        if self.fee < 0:
            raise ValueError(f"fee must be non-negative, got {self.fee}")
        if self.amount < 0:
            raise ValueError(f"amount must be non-negative, got {self.amount}")
        if self.gas_limit < 0:
            raise ValueError(f"gas_limit must be non-negative, got {self.gas_limit}")
        if self.nonce < 0:
            raise ValueError(f"nonce must be non-negative, got {self.nonce}")

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
        return cls(
            kind=OpKind(d["kind"]),
            sender=d["sender"],
            sender_pubkey=d["sender_pubkey"],
            nonce=d["nonce"],
            fee=d["fee"],
            gas_limit=d["gas_limit"],
            recipient=d.get("recipient"),
            amount=d.get("amount", 0),
            code=d.get("code"),
            initial_storage=d.get("initial_storage"),
            entry=d.get("entry"),
            params=d.get("params"),
            signature=d.get("signature"),
            chain_id=d.get("chain_id"),
        )


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


def make_delegate_stake(
    sender_kp: KernKeypair,
    validator: str,           # kn1... address of the baker
    nonce: int,
    fee: int = 2_000,
    gas_limit: int = 20_000,
) -> Transaction:
    """Delegate the sender's stake (their liquid KRN balance) to a validator
    for baking. Liquid PoS: no lock-up, no minimum, no transfer of custody.
    The balance stays in the sender's account and remains spendable; what
    changes is that the validator gets to count the balance toward their
    effective stake at reward-distribution time.

    A sender can delegate to exactly one validator at a time. Calling
    DELEGATE_STAKE again with a different validator switches the
    delegation. Use UNDELEGATE_STAKE to stop delegating.

    The validator must be in the active validator set; otherwise the
    transaction fails."""
    tx = Transaction(
        kind=OpKind.DELEGATE_STAKE,
        sender=sender_kp.address,
        sender_pubkey=sender_kp.public_key_b58,
        nonce=nonce,
        fee=fee,
        gas_limit=gas_limit,
        params={"validator": validator},
    )
    tx.sign(sender_kp)
    return tx


def make_undelegate_stake(
    sender_kp: KernKeypair,
    nonce: int,
    fee: int = 2_000,
    gas_limit: int = 20_000,
) -> Transaction:
    """Stop delegating. The sender's balance no longer counts toward any
    validator's effective stake. The sender stops earning baking yield
    but also stops being subject to validator slashing risk."""
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
