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

Phase B (audit 2, point 3): `verify_zk_claim` now performs the real
Groth16 pairing check on BN254 against a registered verifier key. It
used to be a stub that returned True for any well-formed claim. The
structural check alone is still available as `check_zk_claim_shape`.
Without a verifier key for the claim's `verifier_key_hash`, a claim is
NOT verified (False): there is nothing to check it against.

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
# Verification: Groth16 over BN254
# ---------------------------------------------------------------------------

def check_zk_claim_shape(claim: Any) -> bool:
    """Structural validation only: canonical fields present, proof points
    are integer pairs, G2 `b` is a 2x2 integer matrix, public inputs are
    integers. This is what `verify_zk_claim` used to return as its final
    answer in v1.1-rc; it proves nothing cryptographically.

    Closes S-MED-2 from the v1.1-rc internal review (non-integer members
    used to pass)."""
    if not is_zk_claim(claim):
        return False
    proof = claim["proof"]

    def _ints(v: Any, n: int) -> bool:
        return (isinstance(v, list) and len(v) == n
                and all(isinstance(x, int) and not isinstance(x, bool) for x in v))

    if not _ints(proof.get("a"), 2) or not _ints(proof.get("c"), 2):
        return False
    b = proof.get("b")
    if not isinstance(b, list) or len(b) != 2 or not all(_ints(row, 2) for row in b):
        return False
    public_inputs = claim.get("public_inputs")
    if not isinstance(public_inputs, list) or not all(
        isinstance(x, int) and not isinstance(x, bool) for x in public_inputs
    ):
        return False
    return True


def verifier_key_bytes(vk: dict) -> bytes:
    """Canonical encoding of a Groth16 verifier key, used for its hash.

    vk = {"alpha1": [x, y], "beta2": [[x_r, x_i], [y_r, y_i]],
          "gamma2": G2, "delta2": G2, "ic": [[x, y], ...]}
    where len(ic) == number of public inputs + 1."""
    return json.dumps(vk, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_zk_claim(
    claim: dict,
    verifier_key_registry: Optional[dict] = None,
) -> bool:
    """Verify a ZK-claim payload cryptographically.

    Steps:
      1. Structural validation (`check_zk_claim_shape`).
      2. proof_system must be "groth16-bn254".
      3. The verifier key is looked up in `verifier_key_registry` by the
         claim's `verifier_key_hash`, and must hash to that value
         (`derive_verifier_key_hash(verifier_key_bytes(vk))`), so a
         registry entry cannot be swapped for another circuit's key.
      4. Groth16 check on BN254:
             e(A, B) == e(alpha1, beta2) * e(vk_x, gamma2) * e(C, delta2)
         with vk_x = ic[0] + sum(public_inputs[i] * ic[i + 1]),
         evaluated as a single product of Miller loops followed by one
         final exponentiation, compared with 1.

    Returns False on any failure, including a missing registry or key,
    points off the curve or outside the field, or public inputs outside
    the scalar field. Raises BN254BackendUnavailable if py_ecc is absent.

    Phase B (audit 2, point 3): this function used to return True after
    the structural check, without any pairing."""
    if not check_zk_claim_shape(claim):
        return False
    if claim.get("proof_system") != "groth16-bn254":
        return False
    if not verifier_key_registry:
        return False
    vk_hash = claim["verifier_key_hash"]
    vk = verifier_key_registry.get(vk_hash)
    if not isinstance(vk, dict):
        return False
    try:
        if derive_verifier_key_hash(verifier_key_bytes(vk)) != vk_hash:
            return False
    except (TypeError, ValueError):
        return False
    return _groth16_verify(vk, claim["public_inputs"], claim["proof"])


def _groth16_verify(vk: dict, public_inputs: List[int], proof: dict) -> bool:
    from .evm.bn254 import PY_ECC_AVAILABLE, BN254BackendUnavailable, N, P
    if not PY_ECC_AVAILABLE:
        raise BN254BackendUnavailable("Groth16 verification requires py_ecc")
    from py_ecc import optimized_bn128 as ob

    def g1(v: Any):
        if not (isinstance(v, list) and len(v) == 2
                and all(isinstance(t, int) and not isinstance(t, bool) and 0 <= t < P for t in v)):
            raise ValueError("bad G1")
        if v == [0, 0]:
            return ob.Z1  # point at infinity
        pt = (ob.FQ(v[0]), ob.FQ(v[1]), ob.FQ.one())
        if not ob.is_on_curve(pt, ob.b):
            raise ValueError("G1 off curve")
        return pt

    def g2(v: Any):
        if not (isinstance(v, list) and len(v) == 2 and all(
                isinstance(r, list) and len(r) == 2
                and all(isinstance(t, int) and not isinstance(t, bool) and 0 <= t < P for t in r)
                for r in v)):
            raise ValueError("bad G2")
        (xr, xi), (yr, yi) = v
        pt = (ob.FQ2([xr, xi]), ob.FQ2([yr, yi]), ob.FQ2.one())
        if not ob.is_on_curve(pt, ob.b2):
            raise ValueError("G2 off curve")
        # Subgroup check: G2 on BN254 has a non-trivial cofactor.
        if not ob.is_inf(ob.multiply(pt, N)):
            raise ValueError("G2 not in subgroup")
        return pt

    try:
        ic = vk.get("ic")
        if not isinstance(ic, list) or len(ic) != len(public_inputs) + 1:
            return False
        if any(not (0 <= x < N) for x in public_inputs):
            return False
        a = g1(proof["a"])
        b = g2(proof["b"])
        c = g1(proof["c"])
        alpha1 = g1(vk.get("alpha1"))
        beta2 = g2(vk.get("beta2"))
        gamma2 = g2(vk.get("gamma2"))
        delta2 = g2(vk.get("delta2"))
        vk_x = g1(ic[0])
        for x, point in zip(public_inputs, ic[1:]):
            vk_x = ob.add(vk_x, ob.multiply(g1(point), x))
    except (ValueError, TypeError, KeyError):
        return False

    def miller(q, p):
        if ob.is_inf(q) or ob.is_inf(p):
            return ob.FQ12.one()
        return ob.pairing(q, p, final_exponentiate=False)

    neg_a = ob.neg(a)
    acc = (miller(b, neg_a) * miller(beta2, alpha1)
           * miller(gamma2, vk_x) * miller(delta2, c))
    return ob.final_exponentiate(acc) == ob.FQ12.one()


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
