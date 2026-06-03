# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout and Kern contributors
"""Tests for v1.0-rc Liquid PoS baking delegation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.chain import (
    DEFAULT_COMMISSION_PCT,
    SLASHING_PERCENTAGE,
    apply_transaction,
    commission_rate_of,
    delegators_of,
    effective_stake,
    empty_state,
)
from kern.crypto import KernKeypair
from kern.issuance import split_validator_reward
from kern.transaction import (
    OpKind,
    Transaction,
    make_delegate_stake,
    make_slash_equivocation,
    make_undelegate_stake,
)


# ---------------------------------------------------------------------------
# split_validator_reward — pure math
# ---------------------------------------------------------------------------

def test_split_no_delegators_validator_keeps_all():
    val, dels = split_validator_reward(
        reward=1000, own_stake=100, delegators=[], commission_pct=10,
    )
    assert val == 1000
    assert dels == {}


def test_split_one_delegator_commission_then_prorata():
    # validator stake 100, delegator A stake 900, commission 10%
    # commission = 100
    # remaining = 900
    # effective = 1000
    # val prorata = 900 * 100/1000 = 90
    # A's share = 900 * 900/1000 = 810
    # val total = 100 + 90 = 190
    val, dels = split_validator_reward(
        reward=1000, own_stake=100,
        delegators=[("A", 900)], commission_pct=10,
    )
    assert val == 190
    assert dels == {"A": 810}
    assert val + sum(dels.values()) == 1000


def test_split_multiple_delegators():
    val, dels = split_validator_reward(
        reward=1000, own_stake=100,
        delegators=[("A", 300), ("B", 600)], commission_pct=10,
    )
    # commission=100, remaining=900, effective=1000
    # val prorata = 900*100/1000 = 90
    # A = 900*300/1000 = 270
    # B = 900*600/1000 = 540
    # val total = 100 + 90 = 190
    assert val == 190
    assert dels == {"A": 270, "B": 540}
    assert val + sum(dels.values()) == 1000


def test_split_zero_commission():
    val, dels = split_validator_reward(
        reward=1000, own_stake=500,
        delegators=[("A", 500)], commission_pct=0,
    )
    # No commission. Effective 1000. Each side gets 500.
    assert val == 500
    assert dels == {"A": 500}


def test_split_100pct_commission_validator_takes_all():
    val, dels = split_validator_reward(
        reward=1000, own_stake=100,
        delegators=[("A", 900)], commission_pct=100,
    )
    assert val == 1000
    assert dels == {}


def test_split_rounding_goes_to_validator():
    # Reward 7, own_stake=1, delegator=1, commission_pct=0
    # remaining=7, effective=2, val_prorata=7*1/2=3, A=7*1/2=3
    # leftover = 7 - 3 - 3 = 1 → validator
    # val total = 0 + 3 + 1 = 4
    val, dels = split_validator_reward(
        reward=7, own_stake=1,
        delegators=[("A", 1)], commission_pct=0,
    )
    assert val == 4
    assert dels == {"A": 3}
    assert val + sum(dels.values()) == 7


# ---------------------------------------------------------------------------
# Delegation state helpers
# ---------------------------------------------------------------------------

def test_effective_stake_no_delegators_equals_own():
    state = empty_state()
    state["validators"] = [{"address": "kn1v1", "pubkey": "pk", "stake": 1000}]
    assert effective_stake(state, "kn1v1") == 1000


def test_effective_stake_counts_delegated_balances():
    state = empty_state()
    state["validators"] = [{"address": "kn1v1", "pubkey": "pk", "stake": 1000}]
    state["balances"] = {"kn1alice": 5000, "kn1bob": 3000}
    state["delegations"] = {"kn1alice": "kn1v1", "kn1bob": "kn1v1"}
    assert effective_stake(state, "kn1v1") == 1000 + 5000 + 3000


def test_effective_stake_ignores_other_validators_delegators():
    state = empty_state()
    state["validators"] = [
        {"address": "kn1v1", "pubkey": "pk", "stake": 1000},
        {"address": "kn1v2", "pubkey": "pk", "stake": 2000},
    ]
    state["balances"] = {"kn1alice": 5000, "kn1bob": 3000}
    state["delegations"] = {"kn1alice": "kn1v1", "kn1bob": "kn1v2"}
    assert effective_stake(state, "kn1v1") == 1000 + 5000
    assert effective_stake(state, "kn1v2") == 2000 + 3000


def test_delegators_of_returns_pairs():
    state = empty_state()
    state["validators"] = [{"address": "kn1v1", "pubkey": "pk", "stake": 1000}]
    state["balances"] = {"kn1alice": 5000, "kn1bob": 3000, "kn1carol": 0}
    state["delegations"] = {
        "kn1alice": "kn1v1", "kn1bob": "kn1v1",
        "kn1carol": "kn1v1",  # zero balance → excluded
    }
    dels = delegators_of(state, "kn1v1")
    assert sorted(dels) == [("kn1alice", 5000), ("kn1bob", 3000)]


def test_commission_rate_defaults():
    state = empty_state()
    assert commission_rate_of(state, "kn1anyone") == DEFAULT_COMMISSION_PCT


def test_commission_rate_custom():
    state = empty_state()
    state["commission_rates"] = {"kn1v1": 5}
    assert commission_rate_of(state, "kn1v1") == 5
    assert commission_rate_of(state, "kn1v2") == DEFAULT_COMMISSION_PCT


# ---------------------------------------------------------------------------
# DELEGATE_STAKE / UNDELEGATE_STAKE transactions
# ---------------------------------------------------------------------------

def _state_with_validator_and_delegator():
    """Helper: build a state with one validator (stake 1B) and one
    pre-funded delegator (balance 1M, plenty for fees)."""
    val_kp = KernKeypair.from_seed(bytes([0x11]) * 32)
    del_kp = KernKeypair.from_seed(bytes([0x22]) * 32)
    state = empty_state()
    state["validators"] = [{
        "address": val_kp.address,
        "pubkey": val_kp.public_key_b58,
        "stake": 1_000_000_000,
    }]
    state["balances"] = {
        val_kp.address: 100_000_000,
        del_kp.address: 1_000_000,
    }
    state["total_supply"] = 1_100_000_000
    return state, val_kp, del_kp


def test_delegate_records_in_state():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    tx = make_delegate_stake(del_kp, validator=val_kp.address, nonce=0)
    result = apply_transaction(state, tx, baker=val_kp.address)
    assert result.ok, result.error
    assert state["delegations"][del_kp.address] == val_kp.address


def test_delegate_to_non_validator_fails():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    tx = make_delegate_stake(del_kp, validator="kn1notavalidator", nonce=0)
    result = apply_transaction(state, tx, baker=val_kp.address)
    assert not result.ok
    assert "not in active set" in (result.error or "")


def test_delegate_to_self_fails():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    # del_kp tries to delegate to itself.
    tx = make_delegate_stake(del_kp, validator=del_kp.address, nonce=0)
    result = apply_transaction(state, tx, baker=val_kp.address)
    assert not result.ok
    assert "cannot delegate to self" in (result.error or "")


def test_delegate_switches_validator():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    # Add a second validator.
    val2_kp = KernKeypair.from_seed(bytes([0x33]) * 32)
    state["validators"].append({
        "address": val2_kp.address,
        "pubkey": val2_kp.public_key_b58,
        "stake": 500_000_000,
    })
    # First delegate to val1.
    apply_transaction(state, make_delegate_stake(del_kp, val_kp.address, nonce=0), baker=val_kp.address)
    # Then switch to val2.
    result = apply_transaction(state, make_delegate_stake(del_kp, val2_kp.address, nonce=1), baker=val_kp.address)
    assert result.ok
    assert state["delegations"][del_kp.address] == val2_kp.address


def test_undelegate_removes_delegation():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    apply_transaction(state, make_delegate_stake(del_kp, val_kp.address, nonce=0), baker=val_kp.address)
    assert del_kp.address in state["delegations"]
    result = apply_transaction(state, make_undelegate_stake(del_kp, nonce=1), baker=val_kp.address)
    assert result.ok
    assert del_kp.address not in state["delegations"]


def test_undelegate_when_not_delegating_is_noop():
    state, val_kp, del_kp = _state_with_validator_and_delegator()
    result = apply_transaction(state, make_undelegate_stake(del_kp, nonce=0), baker=val_kp.address)
    assert result.ok  # no error, just nothing to undo


# ---------------------------------------------------------------------------
# End-to-end: delegator earns yield from block rewards
# ---------------------------------------------------------------------------

def test_delegator_receives_share_of_block_rewards():
    """Build a state with a baker who has a delegator, then bake a block
    and verify the delegator received a proportional share of the reward."""
    from kern.block import Block, BlockHeader, txs_merkle_root_hex
    from kern.consensus import propose_block

    baker_kp = KernKeypair.from_seed(bytes([0xee]) * 32)
    del_kp = KernKeypair.from_seed(bytes([0xdd]) * 32)
    state = empty_state()
    state["validators"] = [{
        "address": baker_kp.address,
        "pubkey": baker_kp.public_key_b58,
        "stake": 1_000_000_000,
    }]
    # Delegator has 9_000_000_000 — so total effective stake = 10B,
    # delegator owns 90% of effective stake.
    state["balances"] = {
        baker_kp.address: 200_000_000,
        del_kp.address: 9_000_000_000,
    }
    state["total_supply"] = 10_200_000_000
    state["delegations"] = {del_kp.address: baker_kp.address}

    pre_del_balance = state["balances"][del_kp.address]
    pre_baker_balance = state["balances"][baker_kp.address]

    # Bake a block. propose_block computes the state_root and gets rewards.
    parent_header = BlockHeader(
        level=0, round=0, timestamp=0, parent_hash="0" * 64,
        state_root="dummy", txs_root="0" * 64,
        proposer=baker_kp.address, proposer_pubkey=baker_kp.public_key_b58,
    )
    parent_header.sign(baker_kp)
    parent_block = Block(header=parent_header, transactions=[], commits=[])
    new_block = propose_block(
        parent=parent_block, mempool=[], proposer_keypair=baker_kp,
        proposer_pubkey_b58=baker_kp.public_key_b58, state_before=state, round_=0,
    )
    from kern.chain import apply_block
    new_state, _ = apply_block(state, new_block)

    post_del_balance = new_state["balances"][del_kp.address]
    post_baker_balance = new_state["balances"][baker_kp.address]

    # Both received something.
    assert post_del_balance > pre_del_balance, "delegator did not receive a reward share"
    assert post_baker_balance > pre_baker_balance, "baker did not receive anything"

    # Delegator earned LESS than the baker per unit of stake (because of
    # the 10% commission off the top), but on absolute terms the
    # delegator earned ~9x more than the baker (because they have 9x the
    # stake).
    del_gain = post_del_balance - pre_del_balance
    baker_gain = post_baker_balance - pre_baker_balance
    # Delegator should have ~9x baker's gain minus the commission
    # (rough check: del_gain should be > 4x baker_gain on small rewards).
    assert del_gain > baker_gain * 4, (
        f"delegator share too low: del_gain={del_gain}, baker_gain={baker_gain}"
    )


def test_proportional_slashing_of_delegators():
    """When a validator equivocates and is slashed, their delegators are
    also slashed proportional to their delegated balance."""
    baker_kp = KernKeypair.from_seed(bytes([0xee]) * 32)
    del_kp = KernKeypair.from_seed(bytes([0xdd]) * 32)
    snitch_kp = KernKeypair.from_seed(bytes([0xff]) * 32)
    state = empty_state()
    state["validators"] = [{
        "address": baker_kp.address,
        "pubkey": baker_kp.public_key_b58,
        "stake": 1_000_000_000,
    }]
    state["balances"] = {
        baker_kp.address: 100_000_000,
        del_kp.address:   500_000_000,
        snitch_kp.address: 10_000_000,
    }
    state["nonces"] = {snitch_kp.address: 0}
    state["total_supply"] = 1_610_000_000
    state["delegations"] = {del_kp.address: baker_kp.address}

    # Plant an equivocation record.
    state["governance"]["protocol"]["proposals"]["pid"] = {
        "proposal_id": "pid", "submitter": baker_kp.address,
        "payload": {}, "submitted_at_level": 0, "phase": "exploration",
        "votes": {"exploration": {}, "adoption": {}}, "phase_transitions": [],
        "equivocations": [{"voter": baker_kp.address, "phase": "exploration",
                           "first_vote": "yes", "second_vote": "no",
                           "second_at_level": 5}],
    }

    pre_del_balance = state["balances"][del_kp.address]

    tx = make_slash_equivocation(snitch_kp, "pid", baker_kp.address, nonce=0)
    result = apply_transaction(state, tx, baker=baker_kp.address)
    assert result.ok, result.error

    # Delegator was slashed by SLASHING_PERCENTAGE (30%) of their balance.
    post_del_balance = state["balances"][del_kp.address]
    expected_del_slash = pre_del_balance * SLASHING_PERCENTAGE // 100
    assert post_del_balance == pre_del_balance - expected_del_slash


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} delegation tests passed.")
