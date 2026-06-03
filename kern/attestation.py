# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.attestation
================

Slashable attestation primitive (v1.1-rc).

Generalizes the equivocation-detection-and-punishment pattern (already
used for governance equivocation in v1.0-rc) to any signed claim about
the world. An *attestation* is a signed claim by an issuer about a
subject under a schema. If the issuer later signs a CONTRADICTORY claim
about the same (schema_id, subject) pair, anyone can submit slashing
evidence to punish the issuer and earn a whistleblower reward.

Design rationale
----------------

Most oracle and attestation systems today (Chainlink, EAS, etc.) rely
on cryptoeconomic reputation off-chain: nodes that lie lose business
over time. This works at the limit but is:

- Slow (reputation takes months to update)
- Expensive (operators must be paid handsomely to maintain reputation)
- Coordinative-failure-prone (a coalition can attack short-term)

Kern's primitive moves the punishment on-chain and immediate:

1. Issuer posts a bond when attesting
2. Issuer signs a claim (price, KYC status, identity, energy
   measurement, telco subscriber count — anything)
3. If the issuer later contradicts itself for the same (schema, subject)
   pair, the contradiction is mathematically proven on-chain
4. Anyone can submit the proof; the issuer's bond is slashed; the
   prover earns 10% of the slashed amount

This makes equivocation **automatically expensive** in a way that
doesn't depend on social consensus or reputation systems.

State layout
------------

state["attestations"] = {
    attestation_id: {
        "issuer":        kn1 address of the issuer
        "schema_id":     dotted-namespace string
        "subject":       what the claim is about
        "claim":         the actual claim payload
        "bond":          mukrn locked alongside the attestation
        "issued_at_level": L1 block level at which the attestation was issued
        "revoked_at_level": L1 block level if revoked, else None
        "consumed_for_slashing": True if used as evidence already
    }
}

state["attestations_by_subject"] = {
    (issuer, schema_id, subject): [attestation_id, attestation_id, ...]
}

The second index lets the slashing handler find equivocating
attestations in O(1) on (issuer, schema_id, subject), rather than
scanning the entire attestation list.

Attestation ID derivation
-------------------------

Deterministic and unique:

    attestation_id = blake2b(
        domain="kern.attestation.id",
        message=canonical_json({
            "issuer": ...,
            "schema_id": ...,
            "subject": ...,
            "claim": ...,
            "attest_nonce": ...,
        })
    ).hex()[:32]

This means:
- Anyone can compute the ID without trusting the chain (deterministic)
- Two distinct attestations always have distinct IDs (issuer's nonce
  in the input ensures this even for identical claims)
- The ID is content-addressed (acts as the canonical key)
"""

from __future__ import annotations

import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Attestation ID derivation
# ---------------------------------------------------------------------------

def derive_attestation_id(
    issuer: str,
    schema_id: str,
    subject: str,
    claim: dict,
    attest_nonce: int,
) -> str:
    """Compute the deterministic attestation_id for a claim.

    This is content-addressed: the same inputs always produce the same ID.
    Two attestations with the same (issuer, schema_id, subject, claim)
    but different nonces have different IDs — this prevents an issuer
    from "rewriting history" by re-attesting the same claim.
    """
    payload = json.dumps(
        {
            "issuer": issuer,
            "schema_id": schema_id,
            "subject": subject,
            "claim": claim,
            "attest_nonce": attest_nonce,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.blake2b(
        payload,
        digest_size=16,
        key=b"kern.attestation.id",
    ).hexdigest()


# ---------------------------------------------------------------------------
# Equivocation detection
# ---------------------------------------------------------------------------

def claims_contradict(claim_a: Any, claim_b: Any) -> bool:
    """Return True iff two claims contradict each other.

    Two claims contradict iff they are deep-unequal. This is the
    conservative default — any difference at all is treated as a
    contradiction.

    Schemas may override this in their own logic (e.g., for prices,
    "10001" and "10000" might be both within an acceptable error
    band and not considered contradictory). The protocol-level check
    is strict equality; schema-specific tolerance is a layer above.
    """
    return claim_a != claim_b


def find_equivocation_pair(
    attestations: Dict[str, dict],
    issuer: str,
    schema_id: str,
    subject: str,
    id_1: str,
    id_2: str,
) -> Optional[Tuple[dict, dict, str]]:
    """Given two attestation IDs and the issuer's claimed identity,
    return the pair if it constitutes valid equivocation evidence,
    else None.

    Returns (att_1_record, att_2_record, reason_for_validity) on success.

    Validity criteria:
    - Both attestation IDs exist
    - Both have issuer == claimed_issuer
    - Both have the same schema_id and subject
    - The claims differ (via claims_contradict)
    - Neither has already been consumed for slashing
    - Their validity windows overlap (i.e., neither was revoked before
      the other was issued)
    - The IDs are distinct (no slashing yourself on the same record)
    """
    if id_1 == id_2:
        return None
    att_1 = attestations.get(id_1)
    att_2 = attestations.get(id_2)
    if not att_1 or not att_2:
        return None
    if att_1["issuer"] != issuer or att_2["issuer"] != issuer:
        return None
    if att_1["schema_id"] != schema_id or att_2["schema_id"] != schema_id:
        return None
    if att_1["subject"] != subject or att_2["subject"] != subject:
        return None
    if not claims_contradict(att_1["claim"], att_2["claim"]):
        return None
    if att_1.get("consumed_for_slashing") or att_2.get("consumed_for_slashing"):
        return None
    # Check overlapping validity: if one was revoked before the other
    # was issued, the issuer was not simultaneously committed to both.
    a_issued = att_1["issued_at_level"]
    a_revoked = att_1.get("revoked_at_level")
    b_issued = att_2["issued_at_level"]
    b_revoked = att_2.get("revoked_at_level")
    # a was revoked before b was even issued → no overlap, no equivocation
    if a_revoked is not None and a_revoked < b_issued:
        return None
    # b was revoked before a was even issued → no overlap, no equivocation
    if b_revoked is not None and b_revoked < a_issued:
        return None
    return (att_1, att_2, "valid_equivocation")


# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------

def attestations_for(
    state: dict,
    issuer: str,
    schema_id: str,
    subject: str,
) -> List[str]:
    """Return all attestation IDs by the given issuer for the given
    (schema_id, subject) tuple."""
    index = state.get("attestations_by_subject", {})
    key = _index_key(issuer, schema_id, subject)
    return list(index.get(key, []))


def latest_attestation(
    state: dict,
    issuer: str,
    schema_id: str,
    subject: str,
) -> Optional[dict]:
    """Return the most recent non-revoked attestation by the issuer for
    (schema_id, subject), or None if none exists.

    "Most recent" is by issued_at_level, with ties broken by attestation
    ID lexicographic order."""
    attestations = state.get("attestations", {})
    candidates = []
    for att_id in attestations_for(state, issuer, schema_id, subject):
        att = attestations.get(att_id)
        if att and att.get("revoked_at_level") is None:
            candidates.append((att["issued_at_level"], att_id, att))
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return candidates[0][2]


def _index_key(issuer: str, schema_id: str, subject: str) -> str:
    """The lookup key in state["attestations_by_subject"].

    Uses length-prefixed encoding to prevent collisions when one of the
    fields contains the separator character. Closes finding S-MED-1 from
    the v1.1-rc internal security review:

        Before (vulnerable): f"{issuer}|{schema_id}|{subject}"
            (issuer=A, schema=foo, subject=bar|baz)
                → key = "A|foo|bar|baz"
            (issuer=A, schema=foo|bar, subject=baz)
                → key = "A|foo|bar|baz"
            Same key — two distinct attestations collide.

        After (this implementation):
            (issuer=A, schema=foo, subject=bar|baz)
                → key = "1:A|3:foo|7:bar|baz"
            (issuer=A, schema=foo|bar, subject=baz)
                → key = "1:A|7:foo|bar|3:baz"
            Distinct keys — no collision possible.
    """
    return f"{len(issuer)}:{issuer}|{len(schema_id)}:{schema_id}|{len(subject)}:{subject}"


# ---------------------------------------------------------------------------
# Slashing math (mirrors kern.chain.SLASHING_PERCENTAGE)
# ---------------------------------------------------------------------------

ATTESTATION_SLASHING_PERCENTAGE = 30
ATTESTATION_WHISTLEBLOWER_REWARD_PCT = 10


def compute_attestation_slash(bond: int) -> Tuple[int, int, int]:
    """Given an attestation's bond, return (slash, reward, burn).

    slash = bond * 30 / 100
    reward = slash * 10 / 100  (paid to whistleblower)
    burn = slash - reward
    """
    slash = bond * ATTESTATION_SLASHING_PERCENTAGE // 100
    reward = slash * ATTESTATION_WHISTLEBLOWER_REWARD_PCT // 100
    burn = slash - reward
    return slash, reward, burn
