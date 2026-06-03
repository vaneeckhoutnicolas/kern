# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.chain — block application, validation, state transitions."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    Chain,
    apply_block,
    apply_transaction,
    initial_state_from_genesis,
    state_root_hex,
)
from kern.crypto import KernKeypair
from kern.transaction import make_transfer


def _make_genesis(baker_kp, balances):
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


def test_initial_state_has_balances():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    genesis_block, state = _make_genesis(baker, {alice.address: 5_000_000_000})

    chain = Chain(
        genesis_block,
        state["validators"],
        initial_state=state,
    )
    assert chain.state["balances"][alice.address] == 5_000_000_000


def test_apply_transfer_updates_balances():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 10_000_000_000})

    tx = make_transfer(alice, recipient=bob.address, amount=3_000_000, nonce=0, fee=1_000)
    result = apply_transaction(state, tx, baker=baker.address)
    assert result.ok, result.error
    assert state["balances"][alice.address] == 10_000_000_000 - 3_000_000 - 1_000
    assert state["balances"][bob.address] == 3_000_000
    assert state["balances"][baker.address] == 1_000  # fee
    assert state["nonces"][alice.address] == 1


def test_bad_nonce_rejected():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 10_000_000_000})

    tx = make_transfer(alice, recipient=bob.address, amount=1, nonce=99, fee=1_000)
    result = apply_transaction(state, tx, baker=baker.address)
    assert not result.ok
    assert "nonce" in result.error.lower()


def test_insufficient_balance_rejected():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 500})

    tx = make_transfer(alice, recipient=bob.address, amount=10_000_000, nonce=0, fee=1_000)
    # Alice has 500 but the fee alone is 1_000.
    result = apply_transaction(state, tx, baker=baker.address)
    assert not result.ok
    assert "insufficient" in result.error.lower()


def test_state_root_changes_with_state():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 100})
    root_before = state_root_hex(state)
    state["balances"][alice.address] = 200
    root_after = state_root_hex(state)
    assert root_before != root_after


def test_chain_append_advances_height():
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    genesis_block, state = _make_genesis(baker, {alice.address: 10_000_000_000})
    chain = Chain(genesis_block, state["validators"], initial_state=state)
    assert chain.height == 0

    tx = make_transfer(alice, recipient=bob.address, amount=1_000_000, nonce=0, fee=1_000)
    # Build a block containing it.
    from kern.consensus import propose_block
    block = propose_block(
        parent=chain.head,
        mempool=[tx],
        proposer_keypair=baker,
        proposer_pubkey_b58=baker.public_key_b58,
        state_before=chain.state,
        round_=1,
    )
    chain.append(block)
    assert chain.height == 1
    assert chain.state["balances"][bob.address] == 1_000_000


# --- Rollback / atomicity (locks in the apply_transaction snapshot strategy) --

_REVERT_CONTRACT = """
contract Revert {
    storage { x: int }
    entry boom() { require false with "always reverts"; }
}
"""


def test_failed_transfer_charges_fee_and_bumps_nonce():
    """A transfer whose amount exceeds the balance (but whose fee is
    affordable) must still debit the fee and bump the nonce, and must not
    move any value. This is the no-snapshot hot path."""
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 10_000})

    # Fee 1_000 is affordable; amount 50_000 is not (balance after fee = 9_000).
    tx = make_transfer(alice, recipient=bob.address, amount=50_000, nonce=0, fee=1_000)
    result = apply_transaction(state, tx, baker=baker.address)

    assert not result.ok
    assert "insufficient" in result.error.lower()
    # Fee was charged, nonce bumped, no value moved to bob.
    assert state["balances"][alice.address] == 9_000
    assert state["balances"].get(bob.address, 0) == 0
    assert state["balances"][baker.address] >= 1_000  # baker got the fee
    assert state["nonces"][alice.address] == 1


def test_reverting_call_rolls_back_value_but_keeps_fee():
    """A CALL that attaches value and then reverts must undo the value
    transfer (atomic rollback via snapshot) while still charging the fee and
    bumping the nonce. This exercises the snapshotted (non-hot) path."""
    from kern.chain import derive_contract_address
    from kern.transaction import make_call, make_origination

    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 1_000_000})

    # 1) Originate the reverting contract.
    orig = make_origination(alice, _REVERT_CONTRACT, {"x": 0}, nonce=0, fee=10_000)
    r1 = apply_transaction(state, orig, baker=baker.address)
    assert r1.ok, r1.error
    contract_addr = r1.new_contract
    assert contract_addr is not None

    bal_alice_before = state["balances"][alice.address]
    nonce_before = state["nonces"][alice.address]

    # 2) Call the reverting entry, attaching 100_000 of value.
    call = make_call(alice, contract_addr, "boom", params={}, amount=100_000,
                     nonce=nonce_before, fee=5_000)
    r2 = apply_transaction(state, call, baker=baker.address)

    assert not r2.ok
    assert "revert" in r2.error.lower()
    # Value (100_000) must NOT have moved to the contract.
    assert state["balances"].get(contract_addr, 0) == 0
    # Alice paid only the fee (5_000); the 100_000 value was rolled back.
    assert state["balances"][alice.address] == bal_alice_before - 5_000
    # Nonce advanced exactly once.
    assert state["nonces"][alice.address] == nonce_before + 1


def test_l1_fee_is_flat_and_independent_of_gas_limit():
    """Characterization test (documents current behaviour, not an endorsement):
    the L1 charges exactly `tx.fee`, and `tx.gas_limit` is NOT metered at L1 —
    two otherwise-identical transfers whose gas_limit differs by 1000x cost the
    same. The optional, governance-gated fee floor (off by default) is in
    docs/fee-floor.md; if it or a gas market is enabled, pricing changes and
    this test should be updated accordingly."""
    baker = KernKeypair.generate()
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    _, state = _make_genesis(baker, {alice.address: 1_000_000})

    tx_low = make_transfer(alice, recipient=bob.address, amount=10, nonce=0,
                           fee=500, gas_limit=21_000)
    assert apply_transaction(state, tx_low, baker=baker.address).ok
    after_low = state["balances"][alice.address]

    tx_high = make_transfer(alice, recipient=bob.address, amount=10, nonce=1,
                            fee=500, gas_limit=21_000_000)  # 1000x the gas limit
    assert apply_transaction(state, tx_high, baker=baker.address).ok
    after_high = state["balances"][alice.address]

    # Each transfer cost exactly fee (500) + amount (10) = 510; gas_limit irrelevant.
    assert after_low == 1_000_000 - 510
    assert after_high == after_low - 510


if __name__ == "__main__":
    test_initial_state_has_balances()
    test_apply_transfer_updates_balances()
    test_bad_nonce_rejected()
    test_insufficient_balance_rejected()
    test_state_root_changes_with_state()
    test_chain_append_advances_height()
    test_failed_transfer_charges_fee_and_bumps_nonce()
    test_reverting_call_rolls_back_value_but_keeps_fee()
    test_l1_fee_is_flat_and_independent_of_gas_limit()
    print("All chain tests passed.")
