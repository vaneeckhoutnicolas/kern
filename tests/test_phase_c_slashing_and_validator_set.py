# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase C, C2 and C3.

C2 (external review, point C): consensus equivocation is detected by the
node, turned into evidence, and slashed on chain through
SLASH_CONSENSUS_EQUIVOCATION.

C3 (external review, point B): consensus reads ONE validator set, the
effective one (own stake after slashing plus delegated balances), taken
from chain state and refreshed at epoch boundaries."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.bft import BftEngine, ConsensusMessage, MsgKind
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    Chain,
    apply_transaction,
    consensus_validator_set,
    initial_state_from_genesis,
    state_root_hex,
)
from kern.consensus import BakerConfig, propose_block
from kern.crypto import KernKeypair
from kern.transaction import make_delegate_stake, make_slash_consensus_equivocation

STAKE = 1_000_000_000
A = "aa" * 32
B = "bb" * 32


def _keys(n):
    return [KernKeypair.from_seed(bytes([0x90 + i]) * 32) for i in range(n)]


def _state(keys, epoch_blocks=None, extra_balances=None):
    genesis = {
        "balances": {k.address: 10 * STAKE for k in keys} | (extra_balances or {}),
        "validators": [{"address": k.address, "pubkey": k.public_key_b58, "stake": STAKE}
                       for k in keys],
    }
    if epoch_blocks:
        genesis["epoch_blocks"] = epoch_blocks
    st = initial_state_from_genesis(genesis)
    st["_current_level"] = 10
    return st


def _vote(kp, block_hash, kind=MsgKind.ENDORSE, level=5, round_=0):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=block_hash,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def _stake(state, addr):
    return next(v["stake"] for v in state["validators"] if v["address"] == addr)


# --- C2: on-chain slashing of consensus equivocation ---------------------------

def test_double_endorsement_is_slashed_once():
    keys = _keys(4)
    reporter, evil = keys[0], keys[3]
    st = _state(keys)
    supply = st["total_supply"]
    tx = make_slash_consensus_equivocation(reporter, _vote(evil, A).to_dict(),
                                           _vote(evil, B).to_dict(), nonce=0)
    r = apply_transaction(st, tx, baker=keys[1].address)
    assert r.ok, r.error
    assert _stake(st, evil.address) == STAKE * 70 // 100
    # Consensus weight drops at once, before the next epoch boundary.
    assert next(v["stake"] for v in consensus_validator_set(st)
                if v["address"] == evil.address) <= STAKE * 70 // 100
    assert st["total_supply"] < supply

    again = make_slash_consensus_equivocation(reporter, _vote(evil, A).to_dict(),
                                              _vote(evil, "cc" * 32).to_dict(), nonce=1)
    r2 = apply_transaction(st, again, baker=keys[1].address)
    assert not r2.ok and "already slashed" in r2.error


def test_non_conflicting_or_forged_evidence_is_rejected():
    keys = _keys(4)
    reporter, evil, other = keys[0], keys[3], keys[2]
    st = _state(keys)
    same = make_slash_consensus_equivocation(reporter, _vote(evil, A).to_dict(),
                                             _vote(evil, A).to_dict(), nonce=0)
    assert not apply_transaction(st, same, baker=reporter.address).ok

    forged = _vote(evil, B).to_dict()
    forged["signature"] = _vote(other, B).signature
    bad = make_slash_consensus_equivocation(reporter, _vote(evil, A).to_dict(), forged, nonce=1)
    assert not apply_transaction(st, bad, baker=reporter.address).ok

    future = make_slash_consensus_equivocation(reporter, _vote(evil, A, level=99).to_dict(),
                                               _vote(evil, B, level=99).to_dict(), nonce=2)
    r = apply_transaction(st, future, baker=reporter.address)
    assert not r.ok and "future" in r.error

    garbage = make_slash_consensus_equivocation(reporter, {"kind": "endorse"}, {}, nonce=3)
    assert not apply_transaction(st, garbage, baker=reporter.address).ok
    assert _stake(st, evil.address) == STAKE


def test_node_no_longer_drops_the_conflicting_vote(tmp_path):
    """The node used to dedup on (kind, level, round, validator): the second,
    conflicting vote never reached the engine. It now reaches it, and the
    node files a slashing transaction in its own mempool."""
    from kern.node import Node
    from kern.storage import Storage

    keys = _keys(4)
    me, evil = keys[0], keys[3]
    st = _state(keys)
    header = BlockHeader(level=0, round=0, timestamp=int(time.time()), parent_hash="0" * 64,
                         state_root=state_root_hex(st), txs_root=txs_merkle_root_hex([]),
                         proposer=me.address, proposer_pubkey=me.public_key_b58)
    header.sign(me)
    chain = Chain(Block(header=header, transactions=[], commits=[]), st["validators"],
                  initial_state=st)
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), chain, storage, BakerConfig(me, me.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)

    async def feed():
        await node._ingest_consensus(_vote(evil, A, level=1), from_wire=True)
        await node._ingest_consensus(_vote(evil, B, level=1), from_wire=True)

    asyncio.run(feed())
    pending = storage.drain_mempool(max_n=10)
    assert len(pending) == 1
    tx = pending[0]
    assert tx.kind.value == "slash_consensus_equivocation" and tx.sender == me.address
    storage.close()


# --- C3: one effective validator set, refreshed per epoch ----------------------

def test_chain_validators_follow_state_and_delegation_waits_for_the_epoch():
    keys = _keys(2)
    v0, v1 = keys
    delegator = KernKeypair.from_seed(bytes([0x99]) * 32)
    st = _state(keys, epoch_blocks=3, extra_balances={delegator.address: 5 * STAKE})
    st["_current_level"] = 0
    header = BlockHeader(level=0, round=0, timestamp=0, parent_hash="0" * 64,
                         state_root=state_root_hex(st), txs_root=txs_merkle_root_hex([]),
                         proposer=v0.address, proposer_pubkey=v0.public_key_b58)
    header.sign(v0)
    chain = Chain(Block(header=header, transactions=[], commits=[]), st["validators"],
                  initial_state=st)

    def weight(addr):
        return next(v["stake"] for v in chain.validators if v["address"] == addr)

    assert weight(v1.address) == STAKE
    deleg = make_delegate_stake(delegator, v1.address, nonce=0, amount=5 * STAKE - 10_000)
    # Blocks 1 and 2: the delegation is recorded but consensus weight is unchanged.
    for lvl in (1, 2):
        txs = [deleg] if lvl == 1 else []
        blk = propose_block(parent=chain.head, mempool=txs, proposer_keypair=v0,
                            proposer_pubkey_b58=v0.public_key_b58, state_before=chain.state,
                            round_=chain.head.header.round + 1)
        chain.append(blk)
        assert weight(v1.address) == STAKE
    # Block 3 is an epoch boundary: the delegated balance now counts.
    blk = propose_block(parent=chain.head, mempool=[], proposer_keypair=v0,
                        proposer_pubkey_b58=v0.public_key_b58, state_before=chain.state,
                        round_=chain.head.header.round + 1)
    chain.append(blk)
    assert weight(v1.address) > STAKE + 4 * STAKE


def test_engine_weights_come_from_the_chain_set():
    """The BFT engine must weigh votes with the same set the chain uses."""
    keys = _keys(4)
    st = _state(keys)
    st["consensus_set"][3]["stake"] = 0          # e.g. fully slashed
    eng = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                    validator_set=consensus_validator_set(st))
    eng.on_proposal(1, 0, A)
    for kp in keys[1:3]:
        m = ConsensusMessage(kind=MsgKind.PREENDORSE, level=1, round=0, block_hash=A,
                             validator=kp.address, validator_pubkey=kp.public_key_b58)
        m.sign(kp)
        eng.on_message(m)
    # 3 of 3 remaining weight -> quorum, the zero-weight validator is irrelevant.
    assert eng.get_preendorse_qc(1, 0) is not None
