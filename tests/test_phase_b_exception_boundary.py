# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase B, lot 1: the exception boundary of the state machine.

Audit 1, finding 7: a correctly signed transaction with malformed fields
used to raise a Python exception (AssertionError, TypeError,
AttributeError) inside apply_transaction. The exception escaped
propose_block, and because the transaction stays in the mempool and is
gossiped to every baker, block production stopped network wide.

Each test below reproduces one variant of that attack and pins the fix:
the transaction is rejected deterministically, its fee is retained, and
block production continues."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, apply_block, apply_transaction, state_root_hex
from kern.consensus import propose_block
from kern.crypto import KernKeypair
from kern.transaction import OpKind, Transaction, make_transfer

FUNDS = 10_000_000_000
FEE = 1_000


def _genesis(baker, balances):
    state = {
        "balances": dict(balances),
        "nonces": {},
        "contracts": {},
        "validators": [{
            "address": baker.address,
            "pubkey": baker.public_key_b58,
            "stake": 1_000_000_000,
        }],
    }
    header = BlockHeader(
        level=0, round=0, timestamp=int(time.time()),
        parent_hash="0" * 64,
        state_root=state_root_hex(state),
        txs_root=txs_merkle_root_hex([]),
        proposer=baker.address,
        proposer_pubkey=baker.public_key_b58,
    )
    header.sign(baker)
    return Block(header=header, transactions=[], commits=[]), state


def _signed(kp, kind, nonce=0, **fields):
    tx = Transaction(
        kind=kind,
        sender=kp.address,
        sender_pubkey=kp.public_key_b58,
        nonce=nonce,
        fee=FEE,
        gas_limit=10_000,
        **fields,
    )
    tx.sign(kp)
    return tx


@pytest.fixture
def actors():
    return KernKeypair.generate(), KernKeypair.generate(), KernKeypair.generate()


# --- The poison transactions -------------------------------------------------

def _poison_txs(attacker, nonce_start=0):
    """Correctly signed transactions that used to crash the state machine."""
    n = nonce_start
    out = []
    # Transfer without a recipient: the original reproduction (assert).
    out.append(_signed(attacker, OpKind.TRANSFER, nonce=n, amount=5)); n += 1
    # Call without an entry point (assert).
    out.append(_signed(attacker, OpKind.CALL, nonce=n, recipient=attacker.address)); n += 1
    # Originate without code (assert).
    out.append(_signed(attacker, OpKind.ORIGINATE, nonce=n)); n += 1
    # Governance with params as a list (AttributeError on .get).
    out.append(_signed(attacker, OpKind.GOVERNANCE_PROPOSE, nonce=n, params=[1, 2])); n += 1
    # Attestation with an unhashable schema id inside a dict (TypeError path).
    out.append(_signed(attacker, OpKind.REVOKE_ATTESTATION, nonce=n,
                       params={"attestation_id": ["not", "a", "string"]})); n += 1
    # Delegation with a dict as validator address (TypeError on comparison).
    out.append(_signed(attacker, OpKind.DELEGATE_STAKE, nonce=n,
                       params={"validator": {"x": 1}})); n += 1
    return out


def test_every_poison_tx_is_rejected_not_raised(actors):
    baker, attacker, _ = actors
    state = {"balances": {attacker.address: FUNDS}, "nonces": {}, "contracts": {},
             "validators": []}
    for tx in _poison_txs(attacker):
        before_bal = state["balances"][attacker.address]
        result = apply_transaction(state, tx, baker=baker.address)
        assert result.ok is False, tx.kind
        assert result.error
        # Fee retained and nonce consumed: the attack is not free to replay.
        assert state["balances"][attacker.address] == before_bal - FEE
        assert state["nonces"][attacker.address] == tx.nonce + 1


def test_poison_tx_does_not_stop_block_production(actors):
    """The original liveness attack: the baker must keep producing blocks
    and must still include honest transactions queued behind the poison."""
    baker, attacker, alice = actors
    genesis, state = _genesis(baker, {attacker.address: FUNDS, alice.address: FUNDS})
    chain = Chain(genesis, state["validators"], initial_state=state)

    honest = make_transfer(alice, attacker.address, 7, nonce=0)
    mempool = _poison_txs(attacker) + [honest]

    block = propose_block(
        parent=chain.head,
        mempool=mempool,
        proposer_keypair=baker,
        proposer_pubkey_b58=baker.public_key_b58,
        state_before=chain.state,
    )
    chain.append(block)
    assert chain.height == 1
    assert honest.hash_hex() in [t.hash_hex() for t in block.transactions]


def test_block_containing_poison_tx_validates_deterministically(actors):
    """A proposer may legitimately include a failing transaction (it pays
    its fee). Every validator must reach the same state root."""
    baker, attacker, _ = actors
    genesis, state = _genesis(baker, {attacker.address: FUNDS})
    poison = _poison_txs(attacker)
    header = BlockHeader(
        level=1, round=0, timestamp=int(time.time()),
        parent_hash=genesis.hash_hex(), state_root="",
        txs_root=txs_merkle_root_hex(poison),
        proposer=baker.address, proposer_pubkey=baker.public_key_b58,
    )
    block = Block(header=header, transactions=poison, commits=[])
    s1, r1 = apply_block(state, block)
    s2, r2 = apply_block(state, block)
    assert state_root_hex(s1) == state_root_hex(s2)
    assert all(not r.ok for r in r1)


def test_never_valid_txs_are_reported_for_eviction(actors):
    baker, attacker, alice = actors
    genesis, state = _genesis(baker, {alice.address: FUNDS})
    state["nonces"][alice.address] = 3
    stale = make_transfer(alice, attacker.address, 1, nonce=1)       # consumed nonce
    future = make_transfer(alice, attacker.address, 1, nonce=9)      # may become valid
    forged = make_transfer(alice, attacker.address, 1, nonce=3)
    forged.amount = 2                                                # signature now invalid
    evicted: list = []
    propose_block(
        parent=genesis, mempool=[stale, future, forged],
        proposer_keypair=baker, proposer_pubkey_b58=baker.public_key_b58,
        state_before=state, evict_out=evicted,
    )
    assert stale.hash_hex() in evicted
    assert forged.hash_hex() in evicted
    assert future.hash_hex() not in evicted


# --- Strict types at ingress ---------------------------------------------------

BASE = {
    "kind": "transfer", "sender": "kn1x", "sender_pubkey": "kpk",
    "nonce": 0, "fee": 1, "gas_limit": 1, "recipient": "kn1y", "amount": 1,
}


@pytest.mark.parametrize("field,value", [
    ("fee", "1000"),
    ("fee", 1.5),
    ("nonce", True),
    ("amount", None),
    ("gas_limit", [1]),
    ("recipient", ["kn1y"]),
    ("sender", 42),
    ("chain_id", 7),
    ("entry", {"a": 1}),
])
def test_from_dict_rejects_wrong_types(field, value):
    d = dict(BASE)
    d[field] = value
    with pytest.raises((TypeError, ValueError)):
        Transaction.from_dict(d)


def test_from_dict_rejects_non_object():
    with pytest.raises((TypeError, ValueError)):
        Transaction.from_dict(["transfer"])  # type: ignore[arg-type]


# --- Rewards cannot be steered through unverified commit entries -------------

def test_extra_commit_entries_do_not_change_rewards(actors):
    """Audit 2, point 4: reward accounting must not read unverified commit
    addresses. A relay that appends a bogus commit naming another
    validator must not alter the post-block state."""
    baker, other, alice = actors
    genesis, state = _genesis(baker, {alice.address: FUNDS})
    state["validators"].append({
        "address": other.address, "pubkey": other.public_key_b58, "stake": 1_000_000_000,
    })
    # A realistic supply so that the block actually mints rewards.
    state["total_supply"] = 100_000_000 * 1_000_000
    block = propose_block(
        parent=genesis, mempool=[], proposer_keypair=baker,
        proposer_pubkey_b58=baker.public_key_b58, state_before=state,
    )
    honest_state, _ = apply_block(state, block)
    tampered = Block(header=block.header, transactions=block.transactions,
                     commits=list(block.commits) + [f"{other.address}:forged"])
    tampered_state, _ = apply_block(state, tampered)
    assert state_root_hex(honest_state) == state_root_hex(tampered_state)
    assert state_root_hex(honest_state) == block.header.state_root
    assert honest_state["balances"].get(baker.address, 0) > 0     # rewards were minted
    assert honest_state["balances"].get(other.address, 0) == 0    # and not steered
