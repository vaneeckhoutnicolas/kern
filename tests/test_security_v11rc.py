# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Regression tests for vulnerabilities found in the v1.1-rc internal
security review. Each test corresponds to a specific finding (S-*); see
docs/security-review-v11rc.md for the full review.

These tests MUST stay green. If any breaks in a future change, the
corresponding vulnerability has been reintroduced and the fix is gone."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.attestation import _index_key, derive_attestation_id
from kern.chain import apply_transaction, empty_state
from kern.crypto import KernKeypair
from kern.transaction import OpKind, Transaction, make_transfer, make_attest
from kern.zk_claims import build_zk_claim, verify_zk_claim


# ===========================================================================
# S-CRIT-1 — Negative fee enables baker theft
# ===========================================================================

def test_s_crit_1_negative_fee_rejected_at_construction():
    """A negative fee must be rejected at Transaction construction time,
    preventing the negative-fee baker-drain exploit."""
    attacker = KernKeypair.from_seed(bytes([0x55]) * 32)
    with pytest.raises(ValueError, match="fee must be non-negative"):
        Transaction(
            kind=OpKind.TRANSFER,
            sender=attacker.address,
            sender_pubkey=attacker.public_key_b58,
            nonce=0,
            fee=-1,           # the exploit
            gas_limit=10_000,
            recipient=attacker.address,
            amount=0,
        )


def test_s_crit_1_negative_fee_rejected_via_from_dict():
    """The same rejection must apply when a transaction arrives over RPC
    (constructed via from_dict)."""
    with pytest.raises(ValueError, match="fee must be non-negative"):
        Transaction.from_dict({
            "kind": "transfer",
            "sender": "kn1xxx",
            "sender_pubkey": "9Xxxx",
            "nonce": 0,
            "fee": -1,
            "gas_limit": 10_000,
            "recipient": "kn1xxx",
            "amount": 0,
        })


# ===========================================================================
# S-CRIT-2 — Negative amount enables theft from "recipient"
# ===========================================================================

def test_s_crit_2_negative_amount_rejected_at_construction():
    """A negative amount must be rejected at Transaction construction,
    preventing the reverse-transfer exploit."""
    attacker = KernKeypair.from_seed(bytes([0x55]) * 32)
    with pytest.raises(ValueError, match="amount must be non-negative"):
        Transaction(
            kind=OpKind.TRANSFER,
            sender=attacker.address,
            sender_pubkey=attacker.public_key_b58,
            nonce=0,
            fee=1000,
            gas_limit=10_000,
            recipient="kn1victim",
            amount=-500_000,    # the exploit
        )


def test_s_crit_2_negative_amount_rejected_via_from_dict():
    """Same protection over RPC."""
    with pytest.raises(ValueError, match="amount must be non-negative"):
        Transaction.from_dict({
            "kind": "transfer",
            "sender": "kn1xxx",
            "sender_pubkey": "9Xxxx",
            "nonce": 0,
            "fee": 1000,
            "gas_limit": 10_000,
            "recipient": "kn1victim",
            "amount": -500_000,
        })


# ===========================================================================
# S-MAJ-1 — chain_id replay protection
# ===========================================================================

def test_s_maj_1_chain_id_changes_signature():
    """Two transactions identical except for chain_id produce DIFFERENT
    signed payloads — so a signature for one network cannot be replayed
    on another."""
    kp = KernKeypair.from_seed(bytes([0x42]) * 32)
    tx_devnet = Transaction(
        kind=OpKind.TRANSFER, sender=kp.address, sender_pubkey=kp.public_key_b58,
        nonce=0, fee=1000, gas_limit=10_000,
        recipient=kp.address, amount=100,
        chain_id="kern-devnet",
    )
    tx_mainnet = Transaction(
        kind=OpKind.TRANSFER, sender=kp.address, sender_pubkey=kp.public_key_b58,
        nonce=0, fee=1000, gas_limit=10_000,
        recipient=kp.address, amount=100,
        chain_id="kern-midgard",
    )
    assert tx_devnet._signed_payload() != tx_mainnet._signed_payload()


def test_s_maj_1_chain_id_signature_does_not_verify_cross_network():
    """A signature for chain_id A does not verify when the tx is presented
    with chain_id B."""
    kp = KernKeypair.from_seed(bytes([0x42]) * 32)
    tx_devnet = Transaction(
        kind=OpKind.TRANSFER, sender=kp.address, sender_pubkey=kp.public_key_b58,
        nonce=0, fee=1000, gas_limit=10_000,
        recipient=kp.address, amount=100,
        chain_id="kern-devnet",
    )
    tx_devnet.sign(kp)

    # An attacker takes the same signed tx and tries to inject it on mainnet
    # by changing chain_id locally before submission.
    tx_replayed = Transaction.from_dict({**tx_devnet.to_dict(), "chain_id": "kern-midgard"})
    assert not tx_replayed.verify_signature(), "cross-network replay must fail"


def test_s_maj_1_chain_id_none_is_self_consistent():
    """Transactions with chain_id=None still verify correctly (backwards
    compatibility for code that does not set chain_id)."""
    kp = KernKeypair.from_seed(bytes([0x42]) * 32)
    tx = make_transfer(kp, kp.address, 100, nonce=0)
    assert tx.verify_signature()


# ===========================================================================
# S-MAJ-2 — Slash handler must refund unslashed portion
# ===========================================================================

def test_s_maj_2_slash_refunds_unslashed_portion_to_issuer():
    """After slashing, the unslashed portion of the bond (70%) is REFUNDED
    to the issuer. Before this fix, those funds were permanently locked,
    causing total_supply-vs-balances inconsistency and over-punishment."""
    issuer = KernKeypair.from_seed(bytes([0xAA]) * 32)
    snitch = KernKeypair.from_seed(bytes([0xBB]) * 32)
    state = empty_state()
    state["balances"] = {issuer.address: 10_000_000, snitch.address: 100_000}
    state["nonces"] = {issuer.address: 0, snitch.address: 0}
    state["total_supply"] = 10_100_000
    state["_current_level"] = 100

    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=1_000_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=1_000_000)
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    pre_issuer = state["balances"][issuer.address]
    pre_supply = state["total_supply"]
    pre_snitch = state["balances"][snitch.address]

    from kern.transaction import make_slash_attestation_equivocation
    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    r = apply_transaction(state, slash_tx, baker=issuer.address)
    assert r.ok

    # Slashed 300k, of which 30k → snitch and 270k → burned.
    # The unslashed remainder (700k) MUST be returned to the issuer.
    # Note: the slash target is whichever attestation has bond=1M;
    # the OTHER attestation still holds the second 1M bond.
    assert r.extra["slashed"] == 300_000
    assert r.extra["refunded_to_issuer"] == 700_000

    # Total economic loss to issuer = 300_000 (= the slash).
    # Issuer balance change from pre-slash to post-slash:
    #   + refunded_to_issuer (700k) + fee returned from baker (issuer pays fee
    #     but baker == issuer here, so net zero on fee)
    # Note: tx fee 1000 from snitch goes to baker=issuer = +1000
    #   so the net change is +700_000 + 1000.
    assert state["balances"][issuer.address] == pre_issuer + 700_000 + 1000

    # The snitch got their reward, less the fee.
    assert state["balances"][snitch.address] == pre_snitch - 1000 + 30_000


def test_s_maj_2_supply_consistency_after_slash():
    """After slashing, total_supply must equal sum_of_balances + locked_bonds.

    Before the fix, the unslashed portion was 'locked' in attestation.bond
    but not accessible to anyone, breaking the conservation invariant."""
    issuer = KernKeypair.from_seed(bytes([0xCC]) * 32)
    snitch = KernKeypair.from_seed(bytes([0xDD]) * 32)
    state = empty_state()
    state["balances"] = {issuer.address: 10_000_000, snitch.address: 100_000}
    state["nonces"] = {issuer.address: 0, snitch.address: 0}
    state["total_supply"] = 10_100_000
    state["_current_level"] = 100

    tx1 = make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=1_000_000)
    id_1 = apply_transaction(state, tx1, baker=issuer.address).extra["attestation_id"]
    tx2 = make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=1_000_000)
    id_2 = apply_transaction(state, tx2, baker=issuer.address).extra["attestation_id"]

    from kern.transaction import make_slash_attestation_equivocation
    slash_tx = make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0)
    apply_transaction(state, slash_tx, baker=issuer.address)

    # Invariant: total_supply = sum_of_balances + sum_of_locked_bonds
    sum_balances = sum(state["balances"].values())
    sum_bonds = sum(att["bond"] for att in state["attestations"].values())
    assert state["total_supply"] == sum_balances + sum_bonds, (
        f"supply invariant violated: total={state['total_supply']}, "
        f"balances={sum_balances}, bonds={sum_bonds}"
    )


# ===========================================================================
# S-MED-1 — _index_key collisions
# ===========================================================================

def test_s_med_1_index_key_no_collision_with_separator_in_subject():
    """Two distinct (schema, subject) pairs must map to distinct keys
    even if one of them contains the legacy '|' separator."""
    # Before the fix:
    #   _index_key("A", "foo", "bar|baz") == "A|foo|bar|baz"
    #   _index_key("A", "foo|bar", "baz") == "A|foo|bar|baz"  ← COLLISION
    # After the fix: length-prefixed encoding distinguishes them.
    key_1 = _index_key("A", "foo", "bar|baz")
    key_2 = _index_key("A", "foo|bar", "baz")
    assert key_1 != key_2


def test_s_med_1_index_key_collision_with_separator_in_schema():
    """Similarly for schema_id containing the separator."""
    key_1 = _index_key("A", "x|y", "z")
    key_2 = _index_key("A", "x", "y|z")
    assert key_1 != key_2


def test_s_med_1_index_key_collision_with_separator_in_issuer():
    """And for issuer containing the separator (defense in depth — issuers
    are addresses so this shouldn't happen, but defense)."""
    key_1 = _index_key("A|B", "schema", "subject")
    key_2 = _index_key("A", "B|schema", "subject")
    assert key_1 != key_2


# ===========================================================================
# S-MED-2 — verify_zk_claim type checks
# ===========================================================================

def test_s_med_2_verify_rejects_non_int_proof_a():
    """A claim with non-int values in proof_a must be rejected."""
    bad_claim = {
        "proof_system": "groth16-bn254",
        "verifier_key_hash": "ab" * 16,
        "public_inputs": [1, 2],
        "proof": {
            "a": ["not_an_int", "neither"],   # MALICIOUS
            "b": [[1, 2], [3, 4]],
            "c": [5, 6],
        },
        "predicate_summary": "fake",
    }
    assert not verify_zk_claim(bad_claim)


def test_s_med_2_verify_rejects_non_int_proof_b():
    bad_claim = {
        "proof_system": "groth16-bn254",
        "verifier_key_hash": "ab" * 16,
        "public_inputs": [1],
        "proof": {
            "a": [1, 2],
            "b": [["bogus", 2], [3, 4]],   # MALICIOUS
            "c": [5, 6],
        },
        "predicate_summary": "fake",
    }
    assert not verify_zk_claim(bad_claim)


def test_s_med_2_verify_rejects_non_int_proof_c():
    bad_claim = {
        "proof_system": "groth16-bn254",
        "verifier_key_hash": "ab" * 16,
        "public_inputs": [1],
        "proof": {
            "a": [1, 2],
            "b": [[1, 2], [3, 4]],
            "c": [None, "bogus"],   # MALICIOUS
        },
        "predicate_summary": "fake",
    }
    assert not verify_zk_claim(bad_claim)


def test_s_med_2_verify_rejects_non_int_public_inputs():
    bad_claim = {
        "proof_system": "groth16-bn254",
        "verifier_key_hash": "ab" * 16,
        "public_inputs": ["string", "in", "place", "of", "int"],   # MALICIOUS
        "proof": {
            "a": [1, 2],
            "b": [[1, 2], [3, 4]],
            "c": [5, 6],
        },
        "predicate_summary": "fake",
    }
    assert not verify_zk_claim(bad_claim)


def test_s_med_2_verify_accepts_well_formed():
    """The accepted-input path still works (regression check on the fix)."""
    good_claim = build_zk_claim(
        verifier_key_hash="ab" * 16,
        public_inputs=[1, 2, 3],
        proof_a=[10, 20],
        proof_b=[[30, 40], [50, 60]],
        proof_c=[70, 80],
        predicate_summary="ok",
    )
    assert verify_zk_claim(good_claim)


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    for name, obj in inspect.getmembers(me):
        if name.startswith("test_") and callable(obj):
            try:
                obj()
                print(f"  ✓ {name}")
            except Exception as e:
                print(f"  ✗ {name}: {e}")
