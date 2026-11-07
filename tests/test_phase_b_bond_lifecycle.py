# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 3: one economic owner per attestation bond.

Audit 1, findings 1, 2 and 10:
  1. a revoked attestation returned its bond immediately, yet stayed
     slashable;
  2. the slash then paid out of a bond that no longer existed, so the sum
     of balances exceeded total_supply;
  10. after a slash, the smaller of the two bonds stayed locked forever.

These tests pin the conservation invariant

    sum(balances) + sum(attestation bonds) == total_supply

across attest, revoke, slash and release, including the exact attack
sequence from the audit (revoke both halves, then get slashed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.attestation import attestation_unbonding_blocks
from kern.chain import _release_matured_attestation_bonds, apply_transaction, empty_state
from kern.crypto import KernKeypair
from kern.transaction import (
    make_attest,
    make_revoke_attestation,
    make_slash_attestation_equivocation,
)

BOND = 1_000_000


def _supply_gap(state: dict) -> int:
    """total_supply minus every mukrn that exists somewhere. Must be 0."""
    held = sum(state["balances"].values())
    locked = sum(a.get("bond", 0) for a in state.get("attestations", {}).values())
    return state["total_supply"] - held - locked


def _setup():
    issuer = KernKeypair.from_seed(bytes([0x31]) * 32)
    snitch = KernKeypair.from_seed(bytes([0x32]) * 32)
    baker = KernKeypair.from_seed(bytes([0x33]) * 32)
    state = empty_state()
    state["balances"] = {issuer.address: 10_000_000, snitch.address: 100_000}
    state["nonces"] = {}
    state["total_supply"] = 10_100_000
    state["_current_level"] = 100
    return state, issuer, snitch, baker


def _contradiction(state, issuer, baker):
    r1 = apply_transaction(state, make_attest(issuer, "s", "subj", {"v": 1}, nonce=0, bond=BOND),
                           baker=baker.address)
    r2 = apply_transaction(state, make_attest(issuer, "s", "subj", {"v": 2}, nonce=1, bond=BOND),
                           baker=baker.address)
    assert r1.ok and r2.ok
    return r1.extra["attestation_id"], r2.extra["attestation_id"]


def test_audit_attack_revoke_both_then_slash_conserves_supply():
    """The exact sequence from audit 1: the issuer revokes both halves of
    a contradiction, then a whistleblower slashes the pair. Before Phase B
    the issuer kept both bonds AND the slash paid out of thin air."""
    state, issuer, snitch, baker = _setup()
    id_1, id_2 = _contradiction(state, issuer, baker)
    assert _supply_gap(state) == 0

    assert apply_transaction(state, make_revoke_attestation(issuer, id_1, nonce=2),
                             baker=baker.address).ok
    assert apply_transaction(state, make_revoke_attestation(issuer, id_2, nonce=3),
                             baker=baker.address).ok
    assert _supply_gap(state) == 0

    issuer_before = state["balances"][issuer.address]
    r = apply_transaction(state, make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0),
                          baker=baker.address)
    assert r.ok, r.error
    assert _supply_gap(state) == 0
    # The issuer recovers exactly 2 bonds minus the slash.
    assert state["balances"][issuer.address] - issuer_before == 2 * BOND - r.extra["slashed"]

    # Nothing left to release later: no double payment at maturity.
    end = 100 + attestation_unbonding_blocks(state)
    issuer_after_slash = state["balances"][issuer.address]
    _release_matured_attestation_bonds(state, end)
    assert state["balances"][issuer.address] == issuer_after_slash
    assert _supply_gap(state) == 0


def test_revoked_bond_stays_slashable_during_unbonding():
    state, issuer, snitch, baker = _setup()
    id_1, id_2 = _contradiction(state, issuer, baker)
    apply_transaction(state, make_revoke_attestation(issuer, id_1, nonce=2), baker=baker.address)
    assert state["attestations"][id_1]["bond"] == BOND
    r = apply_transaction(state, make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0),
                          baker=baker.address)
    assert r.ok
    assert r.extra["slashed"] == BOND * 30 // 100


def test_second_bond_is_released_by_the_slash():
    """Audit 1, finding 10."""
    state, issuer, snitch, baker = _setup()
    id_1, id_2 = _contradiction(state, issuer, baker)
    r = apply_transaction(state, make_slash_attestation_equivocation(snitch, id_1, id_2, nonce=0),
                          baker=baker.address)
    assert r.ok
    assert state["attestations"][id_1]["bond"] == 0
    assert state["attestations"][id_2]["bond"] == 0
    assert _supply_gap(state) == 0


def test_release_after_unbonding_without_slash():
    state, issuer, _snitch, baker = _setup()
    r = apply_transaction(state, make_attest(issuer, "s", "x", {"v": 1}, nonce=0, bond=BOND),
                          baker=baker.address)
    att_id = r.extra["attestation_id"]
    apply_transaction(state, make_revoke_attestation(issuer, att_id, nonce=1), baker=baker.address)
    bal = state["balances"][issuer.address]
    release = state["attestations"][att_id]["bond_release_level"]
    _release_matured_attestation_bonds(state, release)
    assert state["balances"][issuer.address] == bal + BOND
    assert state["attestations"][att_id]["bond"] == 0
    assert state.get("attestation_unbonding") == {}
    assert _supply_gap(state) == 0


def test_genesis_can_shorten_unbonding_period():
    state, issuer, _snitch, baker = _setup()
    state["attestation_unbonding_blocks"] = 10
    r = apply_transaction(state, make_attest(issuer, "s", "x", {"v": 1}, nonce=0, bond=BOND),
                          baker=baker.address)
    att_id = r.extra["attestation_id"]
    apply_transaction(state, make_revoke_attestation(issuer, att_id, nonce=1), baker=baker.address)
    assert state["attestations"][att_id]["bond_release_level"] == 110
