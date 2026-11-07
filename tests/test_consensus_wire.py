# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Consensus-on-the-wire tests: strict quorum on the live path.

These tests pin the Phase A hardening contract:

1. Blocks appended with require_quorum=True carry cryptographically
   verified endorse-schema signatures worth > 2/3 of stake — a solo
   proposer's self-commit satisfies this with 100% of stake, a forged
   signature is a hard rejection, and 2-of-3 equal-stake is not enough.
2. The BftEngine round trip (propose → pre-endorse → endorse → QC)
   produces endorsements that validate_block accepts.
3. The Network layer transports consensus messages and serves catch-up
   sync (get_blocks/blocks).
4. load_chain restores the exact head state from a periodic snapshot
   plus deterministic replay.
"""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import BftEngine, ConsensusMessage, MsgKind, commit_entry, verify_commits
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, apply_block, state_root_hex, validate_and_apply, validate_block
from kern.consensus import propose_block
from kern.crypto import KernKeypair
from kern.network import Network
from kern.node import load_chain
from kern.storage import Storage
from kern.transaction import make_transfer


def _genesis_with_validators(keypairs, stake_each=1_000_000_000, balances=None):
    validators = [{
        "address": kp.address,
        "pubkey": kp.public_key_b58,
        "stake": stake_each,
    } for kp in keypairs]
    state = {
        "balances": dict(balances or {}),
        "nonces": {},
        "contracts": {},
        "validators": validators,
    }
    proposer = keypairs[0]
    header = BlockHeader(
        level=0, round=0, timestamp=int(time.time()),
        parent_hash="0" * 64,
        state_root=state_root_hex(state),
        txs_root=txs_merkle_root_hex([]),
        proposer=proposer.address,
        proposer_pubkey=proposer.public_key_b58,
    )
    header.sign(proposer)
    return Block(header=header, transactions=[], commits=[]), state


def _propose_next(parent, state, kp, txs=None, round_=1):
    return propose_block(
        parent=parent,
        mempool=txs or [],
        proposer_keypair=kp,
        proposer_pubkey_b58=kp.public_key_b58,
        state_before=state,
        round_=round_,
    )


# ---------------------------------------------------------------------------
# 1. Solo mode passes strict quorum; forgeries fail it
# ---------------------------------------------------------------------------

def test_solo_block_passes_strict_quorum():
    kp = KernKeypair.generate()
    genesis, state = _genesis_with_validators([kp])
    chain = Chain(genesis, state["validators"], initial_state=state)
    block = _propose_next(genesis, chain.state, kp)
    # The self-commit is an ENDORSE-schema signature worth 100% of stake.
    chain.append(block, require_quorum=True)
    assert chain.height == 1


def test_forged_commit_is_hard_rejected():
    kp = KernKeypair.generate()
    stranger = KernKeypair.generate()
    genesis, state = _genesis_with_validators([kp])
    chain = Chain(genesis, state["validators"], initial_state=state)
    block = _propose_next(genesis, chain.state, kp)

    # Replace the valid self-commit with a signature by the right address
    # but produced by the wrong key (forgery), keeping the entry shape.
    forged = ConsensusMessage(
        kind=MsgKind.ENDORSE, level=1, round=1,
        block_hash=block.hash_hex(),
        validator=stranger.address,
        validator_pubkey=stranger.public_key_b58,
    )
    forged.sign(stranger)
    block.commits = [f"{kp.address}:{forged.signature}"]
    with pytest.raises(ValueError, match="invalid commit signature"):
        chain.append(block, require_quorum=True)


def test_commit_from_non_validator_rejected():
    kp = KernKeypair.generate()
    outsider = KernKeypair.generate()
    genesis, state = _genesis_with_validators([kp])
    chain = Chain(genesis, state["validators"], initial_state=state)
    block = _propose_next(genesis, chain.state, kp)
    block.endorsements = [f"{outsider.address}:{'k' * 60}"]
    with pytest.raises(ValueError, match="non-validator"):
        chain.append(block, require_quorum=True)


def test_quorum_not_required_path_still_works():
    kp = KernKeypair.generate()
    genesis, state = _genesis_with_validators([kp])
    chain = Chain(genesis, state["validators"], initial_state=state)
    block = _propose_next(genesis, chain.state, kp)
    block.commits = []  # no quorum evidence at all
    chain.append(block)  # default require_quorum=False (library use)
    assert chain.height == 1


# ---------------------------------------------------------------------------
# 2. Multi-validator: engine round trip produces a QC that chains accept
# ---------------------------------------------------------------------------

def _drive_engines_to_qc(engines, level, round_, block_hash):
    """Deliver the proposal to every engine, then flood all outbound
    messages to all engines until quiescence. Returns the first endorse QC."""
    inbox = []
    for eng in engines:
        inbox.extend(eng.on_proposal(level, round_, block_hash))
    while inbox:
        msg, inbox = inbox[0], inbox[1:]
        for eng in engines:
            inbox.extend(eng.on_message(msg))
    for eng in engines:
        qc = eng.get_endorse_qc(level, round_)
        if qc is not None:
            return qc
    return None


def test_three_validator_qc_finalizes_block():
    kps = [KernKeypair.generate() for _ in range(3)]
    genesis, state = _genesis_with_validators(kps)
    validators = state["validators"]
    # Proposer for round 1 is deterministic; find it and propose with it.
    from kern.consensus import select_proposer
    sel = select_proposer(genesis.hash_hex(), validators, round_=1)
    proposer_kp = next(kp for kp in kps if kp.address == sel["address"])
    chain = Chain(genesis, validators, initial_state=state)
    block = _propose_next(genesis, chain.state, proposer_kp)

    engines = [BftEngine(own_keypair=kp, own_pubkey_b58=kp.public_key_b58,
                         validator_set=validators) for kp in kps]
    qc = _drive_engines_to_qc(engines, 1, 1, block.hash_hex())
    assert qc is not None
    ok, reason = qc.verify(validators)
    assert ok, reason

    block.endorsements = sorted(f"{a}:{s}" for a, s in qc.signatures.items())
    chain.append(block, require_quorum=True)
    assert chain.height == 1
    # All three validators are in the verified entries.
    stake, err = verify_commits(block.hash_hex(), 1, 1,
                                block.commits + block.endorsements, validators)
    assert err is None
    assert stake == 3_000_000_000


def test_two_of_three_equal_stake_is_insufficient():
    kps = [KernKeypair.generate() for _ in range(3)]
    genesis, state = _genesis_with_validators(kps)
    validators = state["validators"]
    from kern.consensus import select_proposer
    sel = select_proposer(genesis.hash_hex(), validators, round_=1)
    proposer_kp = next(kp for kp in kps if kp.address == sel["address"])
    other_kp = next(kp for kp in kps if kp.address != sel["address"])
    chain = Chain(genesis, validators, initial_state=state)
    block = _propose_next(genesis, chain.state, proposer_kp)

    # Exactly 2 of 3 equal-stake endorse-schema signatures: proposer's
    # self-commit + one other validator. 2/3 is NOT strictly greater than
    # 2/3, so the block must be rejected.
    endorse = ConsensusMessage(
        kind=MsgKind.ENDORSE, level=1, round=1,
        block_hash=block.hash_hex(),
        validator=other_kp.address,
        validator_pubkey=other_kp.public_key_b58,
    )
    endorse.sign(other_kp)
    block.endorsements = [commit_entry(endorse)]
    with pytest.raises(ValueError, match="insufficient commit stake"):
        chain.append(block, require_quorum=True)


def test_duplicate_endorsements_count_once():
    kps = [KernKeypair.generate() for _ in range(3)]
    genesis, state = _genesis_with_validators(kps)
    validators = state["validators"]
    from kern.consensus import select_proposer
    sel = select_proposer(genesis.hash_hex(), validators, round_=1)
    proposer_kp = next(kp for kp in kps if kp.address == sel["address"])
    chain = Chain(genesis, validators, initial_state=state)
    block = _propose_next(genesis, chain.state, proposer_kp)
    # Repeat the proposer's own valid commit three times as endorsements:
    # dedup by address must keep counted stake at 1/3 → insufficient.
    block.endorsements = list(block.commits) * 3
    with pytest.raises(ValueError, match="insufficient commit stake"):
        chain.append(block, require_quorum=True)


# ---------------------------------------------------------------------------
# 3. Network transport: consensus relay + catch-up sync
# ---------------------------------------------------------------------------

def test_network_consensus_and_sync_roundtrip():
    async def main():
        received_cons = []
        received_blocks_b = []
        served = [{"header": {"level": i}} for i in range(1, 4)]

        async def a_on_block(d): pass
        async def a_on_tx(d): pass
        async def b_on_tx(d): pass

        async def b_on_block(d):
            received_blocks_b.append(d)

        async def a_on_consensus(d):
            received_cons.append(d)

        def a_get_blocks(lo, hi):
            return [b for b in served if lo <= b["header"]["level"] <= hi]

        # A: serves blocks, receives consensus. Head level 3.
        net_a = Network(host="127.0.0.1", port=19801,
                        on_block=a_on_block, on_tx=a_on_tx,
                        get_head_level=lambda: 3,
                        on_consensus=a_on_consensus,
                        get_blocks_fn=a_get_blocks)
        # B: behind at level 0; on hello from A it requests 1..3.
        def b_on_peer_level(level):
            return (1, level) if level > 0 else None
        net_b = Network(host="127.0.0.1", port=19802,
                        on_block=b_on_block, on_tx=b_on_tx,
                        get_head_level=lambda: 0,
                        on_peer_level=b_on_peer_level)
        await net_a.start()
        await net_b.start()
        await net_b.connect("127.0.0.1", 19801)
        await asyncio.sleep(0.3)

        # Catch-up sync: B asked for 1..3 after A's hello and got them.
        assert [b["header"]["level"] for b in received_blocks_b] == [1, 2, 3]

        # Consensus relay: B broadcasts a consensus message; A receives it.
        await net_b.broadcast_consensus({"kind": "endorse", "level": 1})
        await asyncio.sleep(0.2)
        assert received_cons == [{"kind": "endorse", "level": 1}]

        await net_a.stop()
        await net_b.stop()

    asyncio.run(asyncio.wait_for(main(), timeout=10))


# ---------------------------------------------------------------------------
# 4. Snapshot + replay restores the exact head state
# ---------------------------------------------------------------------------

def test_load_chain_replays_from_periodic_snapshot(tmp_path):
    kp = KernKeypair.generate()
    alice = KernKeypair.generate()
    genesis, state = _genesis_with_validators(
        [kp], balances={kp.address: 10_000_000_000})
    chain = Chain(genesis, state["validators"], initial_state=state)

    storage = Storage(str(tmp_path), snapshot_interval=4)
    storage.save_block(genesis)
    storage.save_state(chain.state, 0)

    # Build 10 blocks with a transfer each; snapshot only every 4 levels,
    # so levels 9 and 10 exist only as blocks, not in the snapshot.
    for level in range(1, 11):
        tx = make_transfer(kp, recipient=alice.address, amount=1000,
                           nonce=level - 1, fee=0)
        block = _propose_next(chain.head, chain.state, kp,
                              txs=[tx], round_=chain.head.header.round + 1)
        chain.append(block, require_quorum=True)
        storage.save_block(block)
        storage.maybe_save_state(chain.state, level)
    assert storage.load_state_level() == 8  # last periodic snapshot
    live_root = state_root_hex(chain.state)
    storage.close()

    reloaded = load_chain(Storage(str(tmp_path), snapshot_interval=4))
    assert reloaded.height == 10
    assert state_root_hex(reloaded.state) == live_root
    assert reloaded.state["balances"][alice.address] == 10_000


def test_load_chain_legacy_snapshot_no_replay(tmp_path):
    """A database written by a pre-snapshot node has no head_level row:
    the snapshot is the head state and must load as-is."""
    kp = KernKeypair.generate()
    genesis, state = _genesis_with_validators([kp])
    chain = Chain(genesis, state["validators"], initial_state=state)
    storage = Storage(str(tmp_path))
    storage.save_block(genesis)
    block = _propose_next(genesis, chain.state, kp)
    chain.append(block, require_quorum=True)
    storage.save_block(block)
    # Legacy write: no level tag.
    storage.conn.execute(
        "INSERT OR REPLACE INTO state(key, json) VALUES ('head', ?)",
        (__import__("json").dumps(chain.state),),
    )
    storage.conn.execute("DELETE FROM state WHERE key = 'head_level'")
    storage.close()

    reloaded = load_chain(Storage(str(tmp_path)))
    assert reloaded.height == 1
    assert state_root_hex(reloaded.state) == state_root_hex(chain.state)
