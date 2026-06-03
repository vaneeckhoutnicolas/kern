# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for the optional L1 fee floor + per-block size cap.

The feature is a CONSENSUS rule gated by a protocol parameter
(`fee_floor_enabled` in state["issuance_params"]). It is OFF by default, so the
absence of the flag must leave behaviour identical to prior releases. These
tests cover the pure check functions, the validate_block integration (the
consensus gate), and the governance whitelist that allows turning it on."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    DEFAULT_FEE_FLOOR_BASE,
    DEFAULT_FEE_FLOOR_PER_BYTE,
    check_fee_rules,
    fee_params,
    state_root_hex,
    tx_min_fee,
    validate_block,
)
from kern.crypto import KernKeypair
from kern.transaction import make_transfer


def _genesis(baker_kp, balances, fee_cfg=None):
    state = {
        "balances": dict(balances),
        "nonces": {},
        "contracts": {},
        "validators": [{
            "address": baker_kp.address,
            "pubkey": baker_kp.public_key_b58,
            "stake": 1_000_000_000,
        }],
    }
    if fee_cfg is not None:
        state["fee_params"] = dict(fee_cfg)
    header = BlockHeader(
        level=0, round=0, timestamp=int(time.time()),
        parent_hash="0" * 64,
        state_root=state_root_hex(state),
        txs_root=txs_merkle_root_hex([]),
        proposer=baker_kp.address,
        proposer_pubkey=baker_kp.public_key_b58,
    )
    header.sign(baker_kp)
    return Block(header=header, transactions=[], commits=[]), state


ON = {
    "fee_floor_enabled": True,
    "fee_floor_base": 100,
    "fee_floor_per_byte": 2,
    "max_block_bytes": 1_048_576,
}


# --- Pure functions ---------------------------------------------------------

def test_disabled_by_default():
    """No issuance_params -> feature off -> even a zero-fee tx passes the check."""
    p = fee_params({})
    assert p["enabled"] is False
    a, b = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(a, recipient=b.address, amount=1, nonce=0, fee=0)
    assert check_fee_rules([tx], p) is None


def test_defaults_resolved_when_unset():
    p = fee_params({"fee_params": {"fee_floor_enabled": True}})
    assert p["enabled"] is True
    assert p["base"] == DEFAULT_FEE_FLOOR_BASE
    assert p["per_byte"] == DEFAULT_FEE_FLOOR_PER_BYTE


def test_tx_min_fee_math():
    a, b = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(a, recipient=b.address, amount=1, nonce=0, fee=0)
    p = fee_params({"fee_params": ON})
    assert tx_min_fee(tx, p) == 100 + 2 * tx.encoded_size()


def test_underpaying_tx_rejected_when_enabled():
    a, b = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(a, recipient=b.address, amount=1, nonce=0, fee=10)  # << floor
    err = check_fee_rules([tx], fee_params({"fee_params": ON}))
    assert err is not None and "fee floor" in err


def test_adequate_fee_accepted_when_enabled():
    a, b = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(a, recipient=b.address, amount=1, nonce=0, fee=5_000)  # >> floor
    assert check_fee_rules([tx], fee_params({"fee_params": ON})) is None


def test_legitimate_default_fee_passes_floor():
    """A normal transfer paying the 1000-mukrn default fee must clear the floor
    (the floor is deliberately calibrated below typical legitimate fees)."""
    a, b = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(a, recipient=b.address, amount=1, nonce=0, fee=1_000)
    assert tx.fee >= tx_min_fee(tx, fee_params({"fee_params": ON}))
    assert check_fee_rules([tx], fee_params({"fee_params": ON})) is None


def test_block_size_cap_rejected():
    a, b = KernKeypair.generate(), KernKeypair.generate()
    # Tiny cap so a handful of well-paid txs already exceed it.
    params = fee_params({"fee_params": {**ON, "max_block_bytes": 500}})
    txs = [make_transfer(a, recipient=b.address, amount=1, nonce=i, fee=5_000)
           for i in range(3)]
    err = check_fee_rules(txs, params)
    assert err is not None and "max_block_bytes" in err


# --- validate_block integration (the consensus gate) ------------------------

def test_validate_block_enforces_fee_floor():
    from kern.consensus import propose_block

    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()

    # Flag-ON network.
    genesis, state = _genesis(baker, {alice.address: 1_000_000}, fee_cfg=ON)

    # An underpaying transfer (fee 10 << floor). propose_block still includes it
    # because it applies fine; the floor is a *validity* rule, not an apply rule.
    tx = make_transfer(alice, recipient=bob.address, amount=1, nonce=0, fee=10)
    block = propose_block(
        parent=genesis, mempool=[tx], proposer_keypair=baker,
        proposer_pubkey_b58=baker.public_key_b58, state_before=state, round_=1,
    )
    err = validate_block(block, genesis.header, state, state["validators"],
                         require_quorum=False)
    assert err is not None and "fee floor" in err


def test_validate_block_ok_when_feature_off():
    """Same underpaying transfer is accepted on a network that has not enabled
    the floor — proving the flag is what gates the rule."""
    from kern.consensus import propose_block

    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    genesis, state = _genesis(baker, {alice.address: 1_000_000})  # no issuance_params

    tx = make_transfer(alice, recipient=bob.address, amount=1, nonce=0, fee=10)
    block = propose_block(
        parent=genesis, mempool=[tx], proposer_keypair=baker,
        proposer_pubkey_b58=baker.public_key_b58, state_before=state, round_=1,
    )
    err = validate_block(block, genesis.header, state, state["validators"],
                         require_quorum=False)
    assert err is None, err


# --- Governance can turn it on ----------------------------------------------

def test_fee_params_in_governance_whitelist():
    from kern.governance import ALLOWED_PARAMS, validate_protocol_payload
    for name in ("fee_floor_enabled", "fee_floor_base", "fee_floor_per_byte",
                 "max_block_bytes"):
        assert name in ALLOWED_PARAMS
    payload = {"params": {"fee_floor_enabled": True, "fee_floor_base": 100,
                          "fee_floor_per_byte": 2, "max_block_bytes": 1_048_576}}
    assert validate_protocol_payload(payload) is None


def test_governance_activation_routes_fee_params():
    """An activated amendment must route fee-floor keys into state['fee_params']
    and ordinary issuance keys into state['issuance_params'], with no leakage
    between buckets (so IssuanceParams construction stays valid)."""
    from kern.chain import _apply_activated_change
    state = {"issuance_params": {"i_max": 0.05}}
    _apply_activated_change(state, {"params": {"fee_floor_enabled": True,
                                               "fee_floor_per_byte": 3,
                                               "i_min": 0.01}})
    assert state["fee_params"]["fee_floor_enabled"] is True
    assert state["fee_params"]["fee_floor_per_byte"] == 3
    assert state["issuance_params"]["i_min"] == 0.01
    assert state["issuance_params"]["i_max"] == 0.05
    # No fee key leaked into issuance_params (would break IssuanceParams(**...)).
    assert "fee_floor_enabled" not in state["issuance_params"]


if __name__ == "__main__":
    test_disabled_by_default()
    test_defaults_resolved_when_unset()
    test_tx_min_fee_math()
    test_underpaying_tx_rejected_when_enabled()
    test_adequate_fee_accepted_when_enabled()
    test_legitimate_default_fee_passes_floor()
    test_block_size_cap_rejected()
    test_validate_block_enforces_fee_floor()
    test_validate_block_ok_when_feature_off()
    test_fee_params_in_governance_whitelist()
    test_governance_activation_routes_fee_params()
    print("All fee-floor tests passed.")
