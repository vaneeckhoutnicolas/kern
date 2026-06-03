# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.zk_claims
==============

Privacy-preserving attestations using zk-SNARKs (v1.1-rc primitive).

The slashable attestation registry (kern.attestation) handles ANY claim
shape — but most attestations carry sensitive information that the
issuer should not publicly reveal:

  - KYC: "Alice's date of birth is 1990-03-12" → reveals DOB to anyone
  - Income: "Bob's annual income is €120 000" → reveals income
  - Identity: "Carol is the same person as account X" → links identities
  - Compliance: "This contract holds €500 000 of investor funds at
    custodian Z" → reveals counterparty balance

In each case, the consumer typically only needs a PROPERTY, not the raw
data:

  - "Alice is over 18" (not her exact DOB)
  - "Bob's income is above the qualified-investor threshold" (not exact)
  - "Carol owns account X" (without linking to her other accounts)
  - "Contract Y's funds are in regulator-approved custody" (without
    revealing balance or custodian identity)

zk-SNARKs let the issuer prove these properties without revealing the
underlying data. Kern already has BN254 (alt_bn128) precompiles (since
v0.7) which can verify Groth16 proofs on-chain — the same construction
used by Tornado Cash, zkSync v1, Aztec, and Zcash Sapling.

This module provides:

  1. Helper functions to construct ZK-backed claim payloads
  2. The canonical claim format for ZK attestations
  3. Verifier-key registry pattern (claims reference a registered
     verifier_key_hash so consumers know which proof system applies)

WHAT THIS MODULE DOES NOT DO
----------------------------

This module does NOT implement the prover. Building a zk-SNARK prover
for a specific predicate (e.g., "this DOB is > 18 years ago") requires:

  - A circuit (in Circom, Cairo, Noir, or similar)
  - A trusted setup (Powers of Tau + circuit-specific MPC ceremony)
  - A prover that runs the circuit on private inputs
  - A verification key derived from the trusted setup

Building those is application-specific work, beyond a "single Python
module that ships with the protocol." What this module provides:

  - The wire format for ZK-backed attestation CLAIMS
  - Helper to verify a Groth16 proof using Kern's BN254 precompile
  - The pattern for registering verifier keys via the schema marketplace
  - Two reference circuits described in spec (not implemented in
    Python — they'd be Circom or similar) for the most common
    predicates: "age threshold" and "value threshold"

In the v1.1-rc demonstration, the verification function is a STUB
that returns True for an empty proof (matching the empty-input case
of the underlying BN254 pairing). Production deployments substitute
a real proof verifier here once the application circuit is built.

CLAIM PAYLOAD FORMAT (canonical)
---------------------------------

A ZK-claim attestation has the following `claim` field structure:

    {
        "proof_system": "groth16-bn254",
        "verifier_key_hash": "<32-byte hex>",
        "public_inputs": [<list of int>],
        "proof": {
            "a": [<2 x int>],   # G1 point
            "b": [[<2 x int>], [<2 x int>]],   # G2 point
            "c": [<2 x int>],   # G1 point
        },
        "predicate_summary": "human-readable description of what is proved",
    }

The `predicate_summary` is for human auditors; the cryptographic check
uses `proof_system`, `verifier_key_hash`, `public_inputs`, and `proof`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Claim payload construction
# ---------------------------------------------------------------------------

def build_zk_claim(
    verifier_key_hash: str,
    public_inputs: List[int],
    proof_a: List[int],
    proof_b: List[List[int]],
    proof_c: List[int],
    predicate_summary: str,
    proof_system: str = "groth16-bn254",
) -> dict:
    """Build a canonical ZK-claim payload.

    Parameters:
        verifier_key_hash: 32-byte hex string identifying the circuit's
            verifier key (registered in the schema marketplace).
        public_inputs: integers that are public inputs to the circuit.
            The proof shows the prover knows witness values such that
            the circuit evaluates to true under these public inputs.
        proof_a: G1 point [x, y] from Groth16 proof.
        proof_b: G2 point [[x_r, x_i], [y_r, y_i]] from Groth16 proof.
        proof_c: G1 point [x, y] from Groth16 proof.
        predicate_summary: human-readable description.
        proof_system: defaults to "groth16-bn254"; other systems can be
            referenced as they're standardized (e.g., "plonk-bn254").

    Returns the claim dict ready for inclusion in a make_attest() call.
    """
    if len(proof_a) != 2:
        raise ValueError("proof_a must be a 2-element G1 point")
    if len(proof_b) != 2 or any(len(p) != 2 for p in proof_b):
        raise ValueError("proof_b must be a 2x2 G2 point")
    if len(proof_c) != 2:
        raise ValueError("proof_c must be a 2-element G1 point")
    return {
        "proof_system": proof_system,
        "verifier_key_hash": verifier_key_hash,
        "public_inputs": public_inputs,
        "proof": {
            "a": proof_a,
            "b": proof_b,
            "c": proof_c,
        },
        "predicate_summary": predicate_summary,
    }


def is_zk_claim(claim: Any) -> bool:
    """Detect whether a claim payload is a ZK-claim (has the canonical
    fields). Useful for consumers deciding how to verify."""
    if not isinstance(claim, dict):
        return False
    required = {"proof_system", "verifier_key_hash", "public_inputs", "proof"}
    if not required.issubset(claim.keys()):
        return False
    proof = claim.get("proof", {})
    if not isinstance(proof, dict):
        return False
    return {"a", "b", "c"}.issubset(proof.keys())


# ---------------------------------------------------------------------------
# Verifier-key registry
# ---------------------------------------------------------------------------

def derive_verifier_key_hash(verifier_key_bytes: bytes) -> str:
    """Compute the canonical hash of a Groth16 verifier key.

    The verifier key is the public output of the trusted-setup ceremony
    for a specific circuit. Hashing it gives a stable identifier that
    can be registered in the schema marketplace and referenced by
    individual attestations.
    """
    return hashlib.blake2b(
        verifier_key_bytes,
        digest_size=16,
        key=b"kern.zk_claims.vk",
    ).hexdigest()


# ---------------------------------------------------------------------------
# Verification (stub for v1.1-rc; real impl uses BN254 precompile)
# ---------------------------------------------------------------------------

def verify_zk_claim(
    claim: dict,
    verifier_key_registry: Optional[dict] = None,
) -> bool:
    """Verify a ZK-claim payload.

    In v1.1-rc this is a STUB: it does structural validation
    (well-formed claim, public inputs present, proof has the right
    shape) but does NOT perform the actual pairing check. To plug in
    real verification:

        1. Look up verifier_key_registry[claim["verifier_key_hash"]]
        2. Build the BN254 pairing inputs from the verifier key and
           the (a, b, c) proof points + public inputs
        3. Call kern.evm.bn254.pairing_check(...) with the inputs
        4. Return its boolean result

    For the v1.1-rc demonstration, we return True iff the claim is
    well-formed. Production deployments MUST replace this with the
    real verifier before relying on ZK attestations.

    Why a stub: a real verifier requires the specific circuit's
    verifier key, which is application-specific work (a real
    deployment generates these via a trusted setup ceremony). The
    primitive infrastructure here is what matters — applications
    plug in their own circuits.
    """
    if not is_zk_claim(claim):
        return False
    proof = claim["proof"]
    # Structural checks — closes S-MED-2 from the v1.1-rc internal
    # security review: previously, a malicious caller could submit a
    # claim with `proof_a = ["not_an_int", "neither"]` and the stub
    # would return True. Now we enforce that proof points are 2-element
    # lists of integers, G2 b is a 2x2 integer matrix, and public_inputs
    # are integers.
    a = proof.get("a")
    if not isinstance(a, list) or len(a) != 2 or not all(isinstance(x, int) for x in a):
        return False
    b = proof.get("b")
    if not isinstance(b, list) or len(b) != 2:
        return False
    for row in b:
        if not isinstance(row, list) or len(row) != 2 or not all(isinstance(x, int) for x in row):
            return False
    c = proof.get("c")
    if not isinstance(c, list) or len(c) != 2 or not all(isinstance(x, int) for x in c):
        return False
    public_inputs = claim.get("public_inputs")
    if not isinstance(public_inputs, list) or not all(isinstance(x, int) for x in public_inputs):
        return False

    # Verifier-key-registry lookup (placeholder)
    if verifier_key_registry is not None:
        vk_hash = claim["verifier_key_hash"]
        if vk_hash not in verifier_key_registry:
            return False
        # In production: load the verifier key and run the BN254 pairing
        # check via kern.evm.bn254.pairing_check(...).

    # v1.1-rc stub: structural validation passes
    return True


# ---------------------------------------------------------------------------
# Reference circuits (descriptive — actual Circom/Cairo not provided)
# ---------------------------------------------------------------------------

REFERENCE_CIRCUITS = {
    "age_threshold_v1": {
        "predicate": "the witness D satisfies D + min_age_seconds <= now_seconds",
        "private_inputs": ["date_of_birth_unix_seconds"],
        "public_inputs": ["now_seconds", "min_age_seconds"],
        "use_case": "prove a user is over 18 (or 21, 65, etc.) without revealing DOB",
        "implementation_notes": (
            "A Circom implementation can verify this in ~150 constraints. "
            "Trusted setup ceremony required (Foundation runs it once for the "
            "Kern ecosystem; the verifier key is registered in the schema "
            "marketplace as 'identity.age-over-threshold')."
        ),
    },
    "value_threshold_v1": {
        "predicate": "the witness V satisfies V >= public_threshold",
        "private_inputs": ["actual_value"],
        "public_inputs": ["public_threshold"],
        "use_case": (
            "prove an income, balance, or revenue exceeds a threshold "
            "(e.g., 'qualified investor' minimum) without revealing exact value"
        ),
        "implementation_notes": (
            "Comparable to age_threshold complexity. Same trusted setup, "
            "different circuit. Registered as 'compliance.value-over-threshold'."
        ),
    },
    "account_ownership_v1": {
        "predicate": (
            "the prover knows the private key sk such that "
            "pubkey(sk) == public_account_address, without revealing sk"
        ),
        "private_inputs": ["secret_key"],
        "public_inputs": ["public_account_address"],
        "use_case": "prove ownership of an account without re-signing or revealing the key",
    },
    "set_membership_v1": {
        "predicate": (
            "the prover knows a Merkle path proving public_leaf_hash is "
            "in the tree rooted at public_root, without revealing other leaves"
        ),
        "private_inputs": ["merkle_path"],
        "public_inputs": ["public_root", "public_leaf_hash"],
        "use_case": (
            "prove inclusion in a curated set (e.g., 'whitelisted KYC'd "
            "users') without revealing which leaf"
        ),
    },
}


def list_reference_circuits() -> List[str]:
    """Return the names of the reference circuits described in this module."""
    return list(REFERENCE_CIRCUITS.keys())


def describe_circuit(name: str) -> Optional[dict]:
    """Return the descriptive record for a reference circuit, or None."""
    return REFERENCE_CIRCUITS.get(name)
