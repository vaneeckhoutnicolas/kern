# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase D: consensus weight is backed by locked, slashable funds.

External review (November 2026): after Phase C a delegation weighed in the
consensus snapshot while the delegator's KRN stayed liquid. A holder could
delegate just before an epoch boundary, move the funds away the next block,
and leave a validator with weight that no collateral covered; the slash
then hit current balances, not the funds behind the weight. A validator
with no own stake could not be slashed at all.

Phase D bonds own stake and delegations, keeps undelegated funds locked
and slashable for the unbonding period, and accepts slashing evidence for
that period. Also covered: BFT memory window and report nonces."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern import bft as bftmod
from kern.bft import BftEngine, ConsensusMessage, MsgKind
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    Chain,
    _epoch_tick,
    _release_matured_delegation_bonds,
    apply_transaction,
    consensus_validator_set,
    effective_stake,
    initial_state_from_genesis,
    state_root_hex,
)
from kern.consensus import BakerConfig
from kern.crypto import KernKeypair
from kern.transaction import (
    make_delegate_stake,
    make_slash_consensus_equivocation,
    make_transfer,
    make_undelegate_stake,
)

KRN = 1_000_000
STAKE = 1_000 * KRN


def _keys(n, base=0xA0):
    return [KernKeypair.from_seed(bytes([base + i]) * 32) for i in range(n)]


def _genesis(validators, balances, **extra):
    g = {"balances": dict(balances),
         "validators": [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                        for k, s in validators]}
    g.update(extra)
    return initial_state_from_genesis(g)


def _locked(state):
    """Every mukrn that is not a liquid balance."""
    stakes = sum(v.get("stake", 0) for v in state["validators"])
    bonds = sum(e["amount"] for e in state.get("delegations", {}).values())
    unbonding = sum(e["amount"] for es in state.get("delegation_unbonding", {}).values() for e in es)
    att = sum(a.get("bond", 0) for a in state.get("attestations", {}).values())
    return stakes + bonds + unbonding + att


def _gap(state):
    return state["total_supply"] - sum(state["balances"].values()) - _locked(state)


def _vote(kp, h, level, round_=0, kind=MsgKind.ENDORSE):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


# --- genesis ---------------------------------------------------------------------

def test_genesis_stake_is_bonded_out_of_the_balance():
    v, = _keys(1)
    st = _genesis([(v, STAKE)], {v.address: STAKE + 5})
    assert st["balances"][v.address] == 5
    assert st["total_supply"] == STAKE + 5
    assert _gap(st) == 0


def test_genesis_stake_without_balance_is_refused():
    v, = _keys(1)
    with pytest.raises(ValueError, match="bond"):
        _genesis([(v, STAKE)], {v.address: STAKE - 1})


def test_unbonding_shorter_than_an_epoch_is_refused():
    v, = _keys(1)
    with pytest.raises(ValueError, match="epoch"):
        _genesis([(v, STAKE)], {v.address: STAKE}, epoch_blocks=100,
                 delegation_unbonding_blocks=99)


# --- the reviewer's attack ---------------------------------------------------------

def test_delegate_then_flee_leaves_funds_slashable():
    v0, v1, reporter = _keys(3)
    whale = KernKeypair.from_seed(bytes([0xAF]) * 32)
    st = _genesis([(v0, STAKE), (v1, STAKE)],
                  {v0.address: STAKE, v1.address: STAKE, reporter.address: KRN,
                   whale.address: 100 * STAKE + KRN},
                  epoch_blocks=10, delegation_unbonding_blocks=50)
    st["_current_level"] = 9
    # 1. Delegate just before the boundary.
    r = apply_transaction(st, make_delegate_stake(whale, v1.address, nonce=0, amount=100 * STAKE), "x")
    assert r.ok, r.error
    _epoch_tick(st, 10)                                    # 2. snapshot taken at level 10
    weight = next(e["stake"] for e in consensus_validator_set(st) if e["address"] == v1.address)
    assert weight == 101 * STAKE
    # 3. Undelegate and try to move the money away the next block.
    st["_current_level"] = 11
    assert apply_transaction(st, make_undelegate_stake(whale, nonce=1), "x").ok
    flee = apply_transaction(st, make_transfer(whale, reporter.address, 100 * STAKE, nonce=2), "x")
    assert not flee.ok                                      # the funds are not liquid
    # 4. The validator equivocates at level 11, while those funds still backed it
    #    (Phase E: the undelegation lowers the weight at once, but the bond was
    #    still exposed at the offence level).
    ev = make_slash_consensus_equivocation(reporter, _vote(v1, "aa" * 32, 11).to_dict(),
                                           _vote(v1, "bb" * 32, 11).to_dict(), nonce=0)
    assert apply_transaction(st, ev, "x").ok
    unbonding = [e for es in st["delegation_unbonding"].values() for e in es]
    assert unbonding[0]["amount"] == 70 * STAKE             # 30% of the fleeing funds burned
    assert _gap(st) == 0


def test_validator_without_own_stake_is_still_slashable():
    v0, v1, reporter, d = _keys(4, base=0xB0)
    st = _genesis([(v0, STAKE), (v1, 0)],
                  {v0.address: STAKE, reporter.address: KRN, d.address: 10 * STAKE},
                  epoch_blocks=10, delegation_unbonding_blocks=50)
    st["_current_level"] = 5
    assert apply_transaction(st, make_delegate_stake(d, v1.address, nonce=0, amount=9 * STAKE), "x").ok
    ev = make_slash_consensus_equivocation(reporter, _vote(v1, "aa" * 32, 5).to_dict(),
                                           _vote(v1, "bb" * 32, 5).to_dict(), nonce=0)
    r = apply_transaction(st, ev, "x")
    assert r.ok, r.error
    assert st["delegations"][d.address]["amount"] == 9 * STAKE * 70 // 100
    assert _gap(st) == 0


def test_liquid_balance_gives_no_weight():
    v, d = _keys(2, base=0xC0)
    st = _genesis([(v, STAKE)], {v.address: STAKE, d.address: 50 * STAKE})
    st["delegations"] = {d.address: v.address}              # pre-Phase D record: no bond
    assert effective_stake(st, v.address) == STAKE


def test_evidence_expires_with_the_unbonding_period():
    v0, v1, reporter = _keys(3, base=0xD0)
    st = _genesis([(v0, STAKE), (v1, STAKE)],
                  {v0.address: STAKE, v1.address: STAKE, reporter.address: KRN},
                  epoch_blocks=10, delegation_unbonding_blocks=50)
    st["_current_level"] = 100
    old = make_slash_consensus_equivocation(reporter, _vote(v1, "aa" * 32, 40).to_dict(),
                                            _vote(v1, "bb" * 32, 40).to_dict(), nonce=0)
    r = apply_transaction(st, old, "x")
    assert not r.ok and "expired" in r.error
    fresh = make_slash_consensus_equivocation(reporter, _vote(v1, "aa" * 32, 50).to_dict(),
                                              _vote(v1, "bb" * 32, 50).to_dict(), nonce=1)
    assert apply_transaction(st, fresh, "x").ok


def test_supply_is_conserved_through_bond_unbond_release():
    v, d = _keys(2, base=0xE0)
    st = _genesis([(v, STAKE)], {v.address: STAKE, d.address: 10 * STAKE},
                  epoch_blocks=10, delegation_unbonding_blocks=20)
    st["_current_level"] = 1
    assert apply_transaction(st, make_delegate_stake(d, v.address, nonce=0, amount=5 * STAKE), v.address).ok
    assert _gap(st) == 0
    r = apply_transaction(st, make_undelegate_stake(d, nonce=1), v.address)
    assert _gap(st) == 0
    _release_matured_delegation_bonds(st, r.extra["release_level"])
    assert _gap(st) == 0 and not st["delegation_unbonding"]


# --- BFT memory window -----------------------------------------------------------------

def test_far_future_messages_create_no_state():
    keys = _keys(4, base=0xF0)
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": 1} for k in keys]
    eng = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                    validator_set=vs, min_level=10, current_round=50)
    for level, rnd in [(10_000, 50), (11, 10_000), (11, 0), (5, 50)]:
        eng.on_message(_vote(keys[1], "aa" * 32, level, rnd))
    assert eng.states == {}
    eng.on_message(_vote(keys[1], "aa" * 32, 11, 51))       # inside the window
    assert list(eng.states) == [(11, 51)]


def test_state_count_is_capped(monkeypatch):
    monkeypatch.setattr(bftmod, "MAX_ROUND_STATES", 3)
    keys = _keys(2, base=0x70)
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": 1} for k in keys]
    eng = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58, validator_set=vs)
    for rnd in range(6):
        eng.on_message(_vote(keys[1], "aa" * 32, 1, rnd))
    assert len(eng.states) == 3


# --- report nonces ---------------------------------------------------------------------------

def test_several_reports_get_consecutive_nonces(tmp_path):
    from kern.node import Node
    from kern.storage import Storage

    keys = _keys(4, base=0x60)
    me = keys[0]
    st = _genesis([(k, STAKE) for k in keys], {k.address: 2 * STAKE for k in keys})
    header = BlockHeader(level=0, payload_round=0, timestamp=int(time.time()), parent_hash="0" * 64,
                         state_root=state_root_hex(st), txs_root=txs_merkle_root_hex([]),
                         proposer=me.address, proposer_pubkey=me.public_key_b58)
    header.sign(me)
    chain = Chain(Block(header=header, transactions=[], commits=[]), st["validators"],
                  initial_state=st)
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), chain, storage, BakerConfig(me, me.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)

    async def feed():
        for evil in keys[2:]:
            await node._ingest_consensus(_vote(evil, "aa" * 32, 1), from_wire=True)
            await node._ingest_consensus(_vote(evil, "bb" * 32, 1), from_wire=True)

    asyncio.run(feed())
    nonces = sorted(tx.nonce for tx in storage.drain_mempool(max_n=10))
    assert nonces == [0, 1]
    storage.close()
