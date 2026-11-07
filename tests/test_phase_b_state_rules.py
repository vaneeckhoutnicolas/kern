# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 4: current level, one delegation truth, genesis and
chain_id (audit 1 findings 3, 4, 5, 6, 8, 9; audit 2 point 5)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    _compute_staked,
    _governance_validator_set,
    apply_block,
    apply_transaction,
    empty_state,
    initial_state_from_genesis,
)
from kern.crypto import KernKeypair
from kern.governance import _tally
from kern.node import check_genesis_safety
from kern.transaction import make_attest, make_transfer

ROOT = Path(__file__).resolve().parent.parent


# --- Finding 3: transactions observe their own block level ---------------------

def test_transactions_see_the_level_of_their_block():
    baker = KernKeypair.from_seed(bytes([0x41]) * 32)
    issuer = KernKeypair.from_seed(bytes([0x42]) * 32)
    state = empty_state()
    state["validators"] = [{"address": baker.address, "pubkey": baker.public_key_b58, "stake": 1}]
    state["balances"] = {issuer.address: 10_000_000}
    state["total_supply"] = 10_000_000
    state["_current_level"] = 6          # left by the previous block
    tx = make_attest(issuer, "s", "x", {"v": 1}, nonce=0, bond=0)
    header = BlockHeader(level=7, payload_round=0, timestamp=0, parent_hash="0" * 64, state_root="",
                         txs_root=txs_merkle_root_hex([tx]), proposer=baker.address,
                         proposer_pubkey=baker.public_key_b58)
    new_state, results = apply_block(state, Block(header=header, transactions=[tx], commits=[]))
    assert results[0].ok, results[0].error
    att = next(iter(new_state["attestations"].values()))
    assert att["issued_at_level"] == 7


# --- Findings 4, 5, 6: one delegation truth ------------------------------------

def _delegated_state():
    v = KernKeypair.from_seed(bytes([0x51]) * 32)
    d = KernKeypair.from_seed(bytes([0x52]) * 32)
    state = empty_state()
    state["validators"] = [{"address": v.address, "pubkey": v.public_key_b58, "stake": 100}]
    state["balances"] = {v.address: 0, d.address: 0}
    # Phase D: delegation is bonded; 900 is held in the delegation record.
    state["delegations"] = {d.address: {"validator": v.address, "amount": 900}}
    return state, v, d


def test_emission_ratio_counts_delegated_bonds():
    state, _v, _d = _delegated_state()
    assert _compute_staked(state) == 1_000


def test_governance_weighs_delegated_bonds_on_both_tracks():
    state, v, d = _delegated_state()
    eff = _governance_validator_set(state)
    assert eff == [{"address": v.address, "pubkey": v.public_key_b58, "stake": 1_000}]
    # The state's own validator record is untouched.
    assert state["validators"][0]["stake"] == 100
    yes, _no, _abs, total = _tally({v.address: "yes"}, eff)
    assert yes == total == 1_000


def test_treasury_no_longer_keeps_a_private_delegation_copy():
    from kern.chain import _load_treasury, _save_treasury
    state, _v, _d = _delegated_state()
    gov_state = state["governance"]
    gov_state["treasury"]["delegations"] = {"kn1legacy": "kn1other"}
    tgov = _load_treasury(gov_state, state, 0)
    assert tgov.delegations == {}
    _save_treasury(gov_state, tgov)
    assert "delegations" not in gov_state["treasury"]


# --- Finding 8: declared genesis supply is checked -----------------------------

def test_genesis_with_inconsistent_total_supply_is_refused():
    with pytest.raises(ValueError, match="total_supply"):
        initial_state_from_genesis({"balances": {"kn1a": 5}, "total_supply": 6})


def test_repository_genesis_is_consistent():
    genesis = json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))
    state = initial_state_from_genesis(genesis)
    assert state["total_supply"] == genesis["total_supply"]


# --- Finding 9: chain_id is enforced --------------------------------------------

def _chain_state(chain_id):
    alice = KernKeypair.from_seed(bytes([0x61]) * 32)
    state = initial_state_from_genesis({"chain_id": chain_id,
                                        "balances": {alice.address: 1_000_000}})
    return state, alice


def test_transaction_for_another_network_is_rejected():
    state, alice = _chain_state("kern-devnet-a")
    tx = make_transfer(alice, alice.address, 1, nonce=0)
    tx.chain_id = "kern-devnet-b"
    tx.sign(alice)
    r = apply_transaction(state, tx, baker=alice.address)
    assert not r.ok and "chain_id" in r.error
    assert state["nonces"].get(alice.address, 0) == 0     # rejected before any mutation


def test_unbound_transaction_is_rejected_on_a_named_chain():
    state, alice = _chain_state("kern-devnet-a")
    r = apply_transaction(state, make_transfer(alice, alice.address, 1, nonce=0), baker=alice.address)
    assert not r.ok and "chain_id" in r.error


def test_matching_chain_id_is_accepted():
    state, alice = _chain_state("kern-devnet-a")
    tx = make_transfer(alice, alice.address, 1, nonce=0)
    tx.chain_id = "kern-devnet-a"
    tx.sign(alice)
    assert apply_transaction(state, tx, baker=alice.address).ok


def test_test_chains_without_chain_id_still_accept_null():
    state, alice = _chain_state(None)
    assert apply_transaction(state, make_transfer(alice, alice.address, 1, nonce=0),
                             baker=alice.address).ok


# --- Audit 2, point 5: no mainnet label on public keys ---------------------------

def test_repository_genesis_is_labelled_devnet_with_placeholder_keys():
    genesis = json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))
    assert "mainnet" not in genesis["chain_id"]
    assert genesis["placeholder_keys"] is True
    check_genesis_safety(genesis)        # a devnet genesis is allowed


def test_mainnet_genesis_with_placeholder_addresses_is_refused():
    genesis = json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))
    genesis["chain_id"] = "kern-mainnet-midgard"
    with pytest.raises(ValueError, match="placeholder"):
        check_genesis_safety(genesis)
    genesis.pop("placeholder_keys")
    with pytest.raises(ValueError, match="public placeholder seeds"):
        check_genesis_safety(genesis)


def test_genesis_builder_refuses_mainnet_label():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_v1_genesis
    with pytest.raises(ValueError):
        build_v1_genesis.build_genesis("kern-mainnet-midgard")
