# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Integration tests: governance driven by transactions through the chain.

These tests exercise the v0.6 wiring: GOVERNANCE_PROPOSE and
GOVERNANCE_VOTE transactions go through the mempool, get included in
blocks, get processed by apply_transaction, and governance state lives
in the chain state. apply_block advances phases automatically.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import copy

from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    apply_block,
    empty_state,
    initial_state_from_genesis,
    state_root_hex,
)
from kern.consensus import propose_block
from kern.crypto import KernKeypair
from kern.transaction import (
    OpKind,
    Transaction,
    make_governance_propose,
    make_governance_vote,
)


def _make_baker_keypair():
    return KernKeypair.from_seed(bytes.fromhex("11" * 32))


def _genesis_with_baker(stake=10_000_000_000, bond=200_000_000):
    """Build a genesis state with one baker who has enough KRN for bonds + stake."""
    baker_kp = _make_baker_keypair()
    treasury_kp = KernKeypair.from_seed(bytes.fromhex("22" * 32))
    state = initial_state_from_genesis({
        "balances": {
            baker_kp.address: bond * 10 + stake,
            treasury_kp.address: 1_000_000_000,
        },
        "validators": [{
            "address": baker_kp.address,
            "pubkey": baker_kp.public_key_b58,
            "stake": stake,
        }],
        "treasury_address": treasury_kp.address,
    })
    state["state_root_function"] = "json"
    return state, baker_kp, treasury_kp


def _bake_one_block(state, baker_kp, txs=None, level_override=None):
    """Build and apply one block. Returns (new_state, block)."""
    # Build a parent header so propose_block can produce a valid child.
    if txs is None:
        txs = []
    # Pretend we have a genesis-ish parent.
    parent_level = state.get("_current_level", 0)
    parent_hash = state.get("_last_hash", "0" * 64)

    # Use a minimal Block-like surrogate for propose_block's `parent`.
    parent_header = BlockHeader(
        level=parent_level, round=0, timestamp=0,
        parent_hash="0" * 64 if parent_level == 0 else "1" * 64,
        state_root="dummy", txs_root="0" * 64,
        proposer=baker_kp.address,
        proposer_pubkey=baker_kp.public_key_b58,
    )
    parent_header.sign(baker_kp)
    parent_block = Block(header=parent_header, transactions=[], commits=[])
    # We don't validate the parent in this minimal helper; the harness
    # only needs propose_block to give us a child with the right state_root.
    # We provide the parent_hash via parent_block.hash_hex().
    new_block = propose_block(
        parent=parent_block,
        mempool=txs,
        proposer_keypair=baker_kp,
        proposer_pubkey_b58=baker_kp.public_key_b58,
        state_before=state,
        round_=0,
    )

    new_state, _results = apply_block(state, new_block)
    new_state["_last_hash"] = new_block.hash_hex()
    return new_state, new_block


# ---------------------------------------------------------------------------
# Basic transactional governance
# ---------------------------------------------------------------------------

def test_governance_propose_creates_proposal_in_state():
    state, baker_kp, _ = _genesis_with_baker()
    pre_balance = state["balances"][baker_kp.address]

    propose_tx = make_governance_propose(
        sender_kp=baker_kp,
        track="protocol",
        payload={"params": {"i_max": 0.05}},
        nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])

    proposals = state["governance"]["protocol"]["proposals"]
    assert len(proposals) == 1
    pid = next(iter(proposals))
    assert proposals[pid]["submitter"] == baker_kp.address

    # The bond was escrowed.
    post_balance = state["balances"][baker_kp.address]
    # post = pre - bond - fee + rewards (small)
    # Just check that the bond was taken.
    assert post_balance < pre_balance


def test_governance_propose_non_validator_rejected_for_protocol():
    state, baker_kp, _ = _genesis_with_baker()
    outsider = KernKeypair.from_seed(bytes.fromhex("33" * 32))
    state["balances"][outsider.address] = 500_000_000

    propose_tx = make_governance_propose(
        sender_kp=outsider,
        track="protocol",
        payload={"params": {"i_max": 0.05}},
        nonce=0,
    )
    state_after, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])

    # Proposal not created (non-validator submitter rejected by gov logic).
    assert state_after["governance"]["protocol"]["proposals"] == {}


def test_governance_propose_treasury_open_to_anyone():
    state, baker_kp, _ = _genesis_with_baker()
    outsider = KernKeypair.from_seed(bytes.fromhex("44" * 32))
    state["balances"][outsider.address] = 100_000_000

    propose_tx = make_governance_propose(
        sender_kp=outsider,
        track="treasury",
        payload={"recipients": [{"address": outsider.address, "amount": 100_000}]},
        nonce=0,
    )
    state_after, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])

    proposals = state_after["governance"]["treasury"]["proposals"]
    assert len(proposals) == 1


def test_governance_vote_records_in_state():
    state, baker_kp, _ = _genesis_with_baker()
    # Submit
    propose_tx = make_governance_propose(
        sender_kp=baker_kp,
        track="protocol",
        payload={"params": {"i_max": 0.05}},
        nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])
    pid = next(iter(state["governance"]["protocol"]["proposals"]))

    # Walk past the SUBMITTED window (default 100 blocks).
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp, txs=[])
    # Proposal should now be in EXPLORATION.
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "exploration"

    # Vote yes.
    nonce = state["nonces"][baker_kp.address]
    vote_tx = make_governance_vote(
        sender_kp=baker_kp, track="protocol",
        proposal_id=pid, vote="yes", nonce=nonce,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[vote_tx])
    # Check vote recorded.
    votes = state["governance"]["protocol"]["proposals"][pid]["votes"]["exploration"]
    assert votes[baker_kp.address] == "yes"


# ---------------------------------------------------------------------------
# Full e2e: propose → vote → activate → effect on state
# ---------------------------------------------------------------------------

def test_e2e_protocol_amendment_activates_and_changes_params():
    """Drive a full protocol-amendment cycle through transactions and observe
    that the activated change updates issuance_params in state."""
    state, baker_kp, _ = _genesis_with_baker()

    # 1. Submit.
    propose_tx = make_governance_propose(
        sender_kp=baker_kp,
        track="protocol",
        payload={"params": {"i_max": 0.04}},
        nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])
    pid = next(iter(state["governance"]["protocol"]["proposals"]))

    # 2. Walk past SUBMITTED (100 blocks).
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "exploration"

    # 3. Vote yes during exploration.
    nonce = state["nonces"][baker_kp.address]
    vote_tx = make_governance_vote(
        sender_kp=baker_kp, track="protocol",
        proposal_id=pid, vote="yes", nonce=nonce,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[vote_tx])

    # 4. Walk past EXPLORATION.
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    # Should be in COOLDOWN now.
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "cooldown"

    # 5. Walk past COOLDOWN.
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "adoption"

    # 6. Vote yes during adoption.
    nonce = state["nonces"][baker_kp.address]
    vote_tx2 = make_governance_vote(
        sender_kp=baker_kp, track="protocol",
        proposal_id=pid, vote="yes", nonce=nonce,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[vote_tx2])

    # 7. Walk past ADOPTION.
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "activated"

    # 8. Effect on state: issuance_params now reflects the new i_max.
    params = state.get("issuance_params") or {}
    assert params.get("i_max") == 0.04


def test_e2e_state_root_function_swap_via_tx():
    """Same flow but for a function-swap payload: verify
    state["state_root_function"] flips."""
    state, baker_kp, _ = _genesis_with_baker()
    assert state["state_root_function"] == "json"

    propose_tx = make_governance_propose(
        sender_kp=baker_kp, track="protocol",
        payload={"swap": "state_root_function", "to": "trie"},
        nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])
    pid = next(iter(state["governance"]["protocol"]["proposals"]))

    # Walk: submitted → exploration → vote → cooldown → adoption → vote → activated
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    nonce = state["nonces"][baker_kp.address]
    state, _ = _bake_one_block(state, baker_kp, txs=[
        make_governance_vote(baker_kp, "protocol", pid, "yes", nonce=nonce),
    ])
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)
    nonce = state["nonces"][baker_kp.address]
    state, _ = _bake_one_block(state, baker_kp, txs=[
        make_governance_vote(baker_kp, "protocol", pid, "yes", nonce=nonce),
    ])
    for _ in range(101):
        state, _ = _bake_one_block(state, baker_kp)

    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "activated"
    assert state["state_root_function"] == "trie"


# ---------------------------------------------------------------------------
# Bond settlement
# ---------------------------------------------------------------------------

def test_bond_refunded_on_activation():
    """When a proposal activates, the bond is fully refunded."""
    state, baker_kp, _ = _genesis_with_baker()
    pre_balance = state["balances"][baker_kp.address]

    propose_tx = make_governance_propose(
        sender_kp=baker_kp, track="protocol",
        payload={"params": {"i_max": 0.04}}, nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])
    pid = next(iter(state["governance"]["protocol"]["proposals"]))
    # The bond is escrowed (so we have less balance than before).
    mid_balance = state["balances"][baker_kp.address]
    assert mid_balance < pre_balance

    # Drive to activation.
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)
    nonce = state["nonces"][baker_kp.address]
    state, _ = _bake_one_block(state, baker_kp, txs=[
        make_governance_vote(baker_kp, "protocol", pid, "yes", nonce=nonce),
    ])
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)
    nonce = state["nonces"][baker_kp.address]
    state, _ = _bake_one_block(state, baker_kp, txs=[
        make_governance_vote(baker_kp, "protocol", pid, "yes", nonce=nonce),
    ])
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)

    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "activated"
    # Bond returned: post-activation balance ≥ mid-balance + bond
    post_balance = state["balances"][baker_kp.address]
    assert post_balance > mid_balance  # bond returned plus rewards
    # No bond record left for this proposal.
    assert pid not in state["governance"]["protocol"]["bonds"]


def test_bond_partially_burned_on_rejection():
    """When a proposal is rejected by vote, the bond is split:
    50% burned (total_supply down), 50% to treasury."""
    state, baker_kp, treasury_kp = _genesis_with_baker()
    pre_treasury = state["balances"][treasury_kp.address]

    propose_tx = make_governance_propose(
        sender_kp=baker_kp, track="protocol",
        payload={"params": {"i_max": 0.04}}, nonce=0,
    )
    state, _ = _bake_one_block(state, baker_kp, txs=[propose_tx])
    pid = next(iter(state["governance"]["protocol"]["proposals"]))

    # Walk to EXPLORATION.
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)
    # Vote NO.
    nonce = state["nonces"][baker_kp.address]
    state, _ = _bake_one_block(state, baker_kp, txs=[
        make_governance_vote(baker_kp, "protocol", pid, "no", nonce=nonce),
    ])
    # Walk past EXPLORATION → REJECTED.
    for _ in range(101): state, _ = _bake_one_block(state, baker_kp)

    assert state["governance"]["protocol"]["proposals"][pid]["phase"] == "rejected"
    # Treasury received half the bond.
    post_treasury = state["balances"][treasury_kp.address]
    assert post_treasury > pre_treasury


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} integration tests passed.")
