# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E (E2, E3): when a bond starts and stops backing a validator.

External review of Phase D (November 2026):

E2. UNDELEGATE_STAKE removed the bond from effective_stake but left the
    epoch snapshot (state["consensus_set"]) untouched, so the bond kept
    weighing in consensus until the next epoch boundary.

E3. _slash_validator cut every bond present when the evidence landed,
    including bonds created after the offence. Tezos and CometBFT slash
    the stake that was exposed at the offence.

Rule after Phase E: a bond (or a slice of a bond) is exposed to an offence
at level L when it was bonded at or before L and had not started
unbonding before L."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.bft import ConsensusMessage, MsgKind
from kern.chain import (
    _epoch_tick,
    _release_matured_delegation_bonds,
    apply_transaction,
    consensus_validator_set,
    effective_stake,
    initial_state_from_genesis,
)
from kern.crypto import KernKeypair
from kern.transaction import (
    make_delegate_stake,
    make_slash_consensus_equivocation,
    make_undelegate_stake,
)

KRN = 1_000_000
STAKE = 1_000 * KRN


def _keys(n, base):
    return [KernKeypair.from_seed(bytes([base + i]) * 32) for i in range(n)]


def _genesis(validators, balances, **extra):
    g = {"balances": dict(balances),
         "validators": [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                        for k, s in validators]}
    g.update(extra)
    return initial_state_from_genesis(g)


def _locked(state):
    stakes = sum(v.get("stake", 0) for v in state["validators"])
    bonds = sum(e["amount"] for e in state.get("delegations", {}).values())
    unbonding = sum(e["amount"] for es in state.get("delegation_unbonding", {}).values() for e in es)
    return stakes + bonds + unbonding


def _gap(state):
    return state["total_supply"] - sum(state["balances"].values()) - _locked(state)


def _vote(kp, h, level):
    m = ConsensusMessage(kind=MsgKind.ENDORSE, level=level, round=0, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def _evidence(reporter, offender, level, nonce):
    return make_slash_consensus_equivocation(
        reporter, _vote(offender, "aa" * 32, level).to_dict(),
        _vote(offender, "bb" * 32, level).to_dict(), nonce=nonce)


def _weight(state, addr):
    return next(e["stake"] for e in consensus_validator_set(state) if e["address"] == addr)


def _setup(base):
    v0, v1, reporter, d1, d2 = _keys(5, base)
    st = _genesis([(v0, STAKE), (v1, STAKE)],
                  {v0.address: STAKE, v1.address: STAKE, reporter.address: KRN,
                   d1.address: 10 * STAKE, d2.address: 10 * STAKE},
                  epoch_blocks=10, delegation_unbonding_blocks=50)
    return st, v0, v1, reporter, d1, d2


# --- E2 ------------------------------------------------------------------------------

def test_undelegation_lowers_consensus_weight_at_once():
    st, _, v1, _, d1, _ = _setup(0x30)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=0, amount=4 * STAKE), "x").ok
    _epoch_tick(st, 10)
    assert _weight(st, v1.address) == 5 * STAKE
    st["_current_level"] = 12
    assert apply_transaction(st, make_undelegate_stake(d1, nonce=1), "x").ok
    assert _weight(st, v1.address) == STAKE          # not at the next boundary: now
    assert effective_stake(st, v1.address) == STAKE


def test_delegation_never_raises_weight_inside_an_epoch():
    st, _, v1, _, d1, d2 = _setup(0x38)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=0, amount=4 * STAKE), "x").ok
    _epoch_tick(st, 10)
    st["_current_level"] = 12
    assert apply_transaction(st, make_delegate_stake(d2, v1.address, nonce=0, amount=3 * STAKE), "x").ok
    assert apply_transaction(st, make_undelegate_stake(d1, nonce=1), "x").ok
    # Effective stake is now 1 + 3; the snapshot may only go down, so 4 is
    # the right answer here and the new bond weighs from the next boundary.
    assert _weight(st, v1.address) == 4 * STAKE
    _epoch_tick(st, 20)
    assert _weight(st, v1.address) == 4 * STAKE


# --- E3 ------------------------------------------------------------------------------

def test_bond_created_after_the_offence_is_not_slashed():
    st, _, v1, reporter, d1, d2 = _setup(0x40)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=0, amount=4 * STAKE), "x").ok
    # Offence at level 7; d2 delegates at level 9, evidence lands at 20.
    st["_current_level"] = 9
    assert apply_transaction(st, make_delegate_stake(d2, v1.address, nonce=0, amount=3 * STAKE), "x").ok
    st["_current_level"] = 20
    r = apply_transaction(st, _evidence(reporter, v1, 7, 0), "x")
    assert r.ok, r.error
    assert st["delegations"][d1.address]["amount"] == 4 * STAKE * 70 // 100
    assert st["delegations"][d2.address]["amount"] == 3 * STAKE      # untouched
    assert _gap(st) == 0


def test_only_the_exposed_slice_of_a_topped_up_bond_is_slashed():
    st, _, v1, reporter, d1, _ = _setup(0x48)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=0, amount=4 * STAKE), "x").ok
    st["_current_level"] = 9
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=1, amount=2 * STAKE), "x").ok
    st["_current_level"] = 20
    assert apply_transaction(st, _evidence(reporter, v1, 7, 0), "x").ok
    assert st["delegations"][d1.address]["amount"] == 4 * STAKE * 70 // 100 + 2 * STAKE
    assert _gap(st) == 0


def test_bond_unbonding_before_the_offence_is_not_slashed():
    st, _, v1, reporter, d1, d2 = _setup(0x50)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d1, v1.address, nonce=0, amount=4 * STAKE), "x").ok
    assert apply_transaction(st, make_delegate_stake(d2, v1.address, nonce=0, amount=3 * STAKE), "x").ok
    st["_current_level"] = 6                                   # d1 leaves before the offence
    assert apply_transaction(st, make_undelegate_stake(d1, nonce=1), "x").ok
    st["_current_level"] = 20                                  # d2 leaves after it
    assert apply_transaction(st, make_undelegate_stake(d2, nonce=1), "x").ok
    assert apply_transaction(st, _evidence(reporter, v1, 7, 0), "x").ok
    by = {e["delegator"]: e["amount"]
          for es in st["delegation_unbonding"].values() for e in es}
    assert by[d1.address] == 4 * STAKE                          # was not backing level 7
    assert by[d2.address] == 3 * STAKE * 70 // 100              # was, and still is locked
    assert _gap(st) == 0
    _release_matured_delegation_bonds(st, 10_000)
    assert _gap(st) == 0


def test_offence_with_nothing_exposed_but_own_stake_still_slashes_own_stake():
    st, _, v1, reporter, _, d2 = _setup(0x58)
    st["_current_level"] = 9
    assert apply_transaction(st, make_delegate_stake(d2, v1.address, nonce=0, amount=3 * STAKE), "x").ok
    st["_current_level"] = 20
    assert apply_transaction(st, _evidence(reporter, v1, 7, 0), "x").ok
    v = next(v for v in st["validators"] if v["address"] == v1.address)
    assert v["stake"] == STAKE * 70 // 100
    assert st["delegations"][d2.address]["amount"] == 3 * STAKE
    assert _gap(st) == 0


def test_governance_equivocation_uses_the_level_of_the_second_vote():
    from kern.chain import empty_state
    from kern.transaction import make_slash_equivocation
    baker, early, late, snitch = _keys(4, 0x60)
    st = empty_state()
    st["validators"] = [{"address": baker.address, "pubkey": baker.public_key_b58,
                         "stake": STAKE}]
    st["balances"] = {snitch.address: KRN}
    st["total_supply"] = STAKE + KRN + 7 * STAKE
    st["delegations"] = {
        early.address: {"validator": baker.address, "amount": 4 * STAKE,
                        "tranches": [{"level": 3, "amount": 4 * STAKE}]},
        late.address: {"validator": baker.address, "amount": 3 * STAKE,
                       "tranches": [{"level": 8, "amount": 3 * STAKE}]},
    }
    st["governance"]["protocol"]["proposals"]["pid"] = {
        "proposal_id": "pid", "submitter": baker.address, "payload": {},
        "submitted_at_level": 0, "phase": "exploration",
        "votes": {"exploration": {}, "adoption": {}}, "phase_transitions": [],
        "equivocations": [{"voter": baker.address, "phase": "exploration",
                           "first_vote": "yes", "second_vote": "no",
                           "second_at_level": 5}],
    }
    st["_current_level"] = 12
    r = apply_transaction(st, make_slash_equivocation(snitch, "pid", baker.address, nonce=0), "x")
    assert r.ok, r.error
    assert st["delegations"][early.address]["amount"] == 4 * STAKE * 70 // 100
    assert st["delegations"][late.address]["amount"] == 3 * STAKE
