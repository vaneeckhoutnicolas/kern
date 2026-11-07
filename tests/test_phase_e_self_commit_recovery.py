# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of part 2 (f24564b): self-commit crash recovery and
journal hardening.

P1. A proposer holding more than two thirds of the stake signs its own
endorsement (the self-commit) and writes its lock to the signing journal.
If it crashed before the block was safely kept, it restarted locked on a
hash whose block it no longer had: it could not propose that block again,
it refused any other, and nobody else could finalize without it. The
block body is now written to disk before the lock, restored at start, and
the self-commit is counted again, so the same payload is finalized.
Validators that receive a proposal also count the endorsements it carries
in `commits`, so they can finalize it even if the proposer never comes
back.

P2. The journal compared only the block hash; a PROPOSE also signs its
valid_round. The journal now refuses a second PROPOSE with another
valid_round.

P2. `BftEngine.adopt_self_commit` now checks the signature and the two
thirds threshold itself instead of trusting its caller."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import BftEngine, ConsensusMessage, MsgKind
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, state_root_hex
from kern.consensus import BakerConfig, select_proposer
from kern.crypto import KernKeypair
from kern.signing_journal import JOURNAL_FILE, SigningJournal

A = "aa" * 32


class Crash(Exception):
    """Stands for the process dying at this point."""


def _keys():
    return [KernKeypair.from_seed(bytes([0x90 + i]) * 32) for i in range(2)]


def _chain(keys, stakes=(90, 10)):
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
          for k, s in zip(keys, stakes)]
    state = {"balances": {}, "nonces": {}, "contracts": {}, "validators": vs}
    h = BlockHeader(level=0, payload_round=0, timestamp=1_700_000_000, parent_hash="0" * 64,
                    state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                    proposer=keys[0].address, proposer_pubkey=keys[0].public_key_b58)
    h.sign(keys[0])
    return Chain(Block(header=h), vs, initial_state=state)


def _node(path, kp, keys):
    from kern.node import Node
    from kern.storage import Storage
    path.mkdir(parents=True, exist_ok=True)
    storage = Storage(str(path))
    node = Node(str(path), _chain(keys), storage, BakerConfig(kp, kp.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)
    return node, storage


def _proposer_round(node, kp):
    """First round whose proposer is `kp`; the node moves there."""
    r = next(r for r in range(64) if select_proposer(
        node.chain.head.hash_hex(), node.chain.validators, r)["address"] == kp.address)
    node._round = r
    node._refresh_engine()
    return r


class _Net:
    """Network stub: records what is broadcast, optionally dies on the
    first proposal broadcast."""

    def __init__(self, crash_on_proposal=False):
        self.crash_on_proposal = crash_on_proposal
        self.proposals = []

    async def broadcast_proposal(self, env):
        self.proposals.append(env)
        if self.crash_on_proposal:
            raise Crash()

    async def broadcast_consensus(self, msg):
        pass

    async def broadcast_block(self, block):
        pass


def _crash_proposer(tmp_path, monkeypatch, where):
    keys = _keys()
    big = keys[0]
    node, storage = _node(tmp_path / "a", big, keys)
    _proposer_round(node, big)
    net = _Net(crash_on_proposal=(where == "broadcast"))
    node.network = net
    if where == "journal":
        # Dies right after the self-commit and the lock are synced to disk.
        monkeypatch.setattr(BftEngine, "make_proposal",
                            lambda self, *a, **k: (_ for _ in ()).throw(Crash()))
    with pytest.raises(Crash):
        asyncio.run(node._propose(node.chain.head))
    monkeypatch.undo()
    # A real restart takes more than a second: a block rebuilt afterwards
    # has another timestamp, hence another hash.
    import kern.consensus as kc
    real = time.time
    monkeypatch.setattr(kc.time, "time", lambda: real() + 60)
    locked = node.journal.restore(1).locked_hash
    assert locked is not None and node.chain.height == 0
    storage.close()
    return keys, locked, net


@pytest.mark.parametrize("where", ["journal", "broadcast"])
def test_restarted_proposer_finalizes_the_same_payload(tmp_path, monkeypatch, where):
    keys, locked, _ = _crash_proposer(tmp_path, monkeypatch, where)
    node, storage = _node(tmp_path / "a", keys[0], keys)       # restart, same data dir
    assert node.bft.level_state(1).locked_hash == locked
    asyncio.run(node._recover())
    assert node.chain.height == 1
    assert node.chain.head.hash_hex() == locked                 # no new payload
    storage.close()


def test_restarted_proposer_never_signs_a_conflicting_payload(tmp_path, monkeypatch):
    keys, locked, _ = _crash_proposer(tmp_path, monkeypatch, "journal")
    node, storage = _node(tmp_path / "a", keys[0], keys)
    _proposer_round(node, keys[0])
    asyncio.run(node._propose(node.chain.head))
    asyncio.run(node._recover())
    ends = [r for r in node.journal.records if r["kind"] == "endorse" and r["level"] == 1]
    assert {r["block_hash"] for r in ends} == {locked}
    assert node.chain.head.hash_hex() == locked
    storage.close()


def test_receiver_finalizes_from_the_self_commit_when_the_proposer_dies(tmp_path, monkeypatch):
    """The proposal left the machine, then the proposer died before the
    finalized block was gossiped. The 10% validator finalizes the block
    from the self-commit it carries, and verifies it independently."""
    keys, locked, net = _crash_proposer(tmp_path, monkeypatch, "broadcast")
    small, storage = _node(tmp_path / "b", keys[1], keys)
    asyncio.run(small._on_proposal_msg(net.proposals[0]))
    assert small.chain.height == 1 and small.chain.head.hash_hex() == locked
    head = small.chain.head
    assert head.quorum_round() == head.header.payload_round
    fresh = _chain(keys)
    fresh.append(Block.from_dict(head.to_dict()), require_quorum=True)
    storage.close()

    big, storage_a = _node(tmp_path / "a", keys[0], keys)     # and the proposer comes back
    asyncio.run(big._recover())
    assert big.chain.head.hash_hex() == locked
    storage_a.close()


def test_journal_refuses_a_second_proposal_with_another_valid_round(tmp_path):
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    j.append("propose", 10, 2, A, locked_round=-1, locked_hash=None, valid_round=-1,
             valid_hash=None, signed_valid_round=0)
    assert not j.conflicts("propose", 10, 2, A, signed_valid_round=0)
    assert j.conflicts("propose", 10, 2, A, signed_valid_round=1)
    reopened = SigningJournal(str(tmp_path / JOURNAL_FILE))
    assert reopened.conflicts("propose", 10, 2, A, signed_valid_round=1)


def test_engine_refuses_to_sign_a_second_proposal_with_another_valid_round(tmp_path):
    keys = _keys()
    e = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                  validator_set=[{"address": k.address, "pubkey": k.public_key_b58, "stake": 50}
                                 for k in keys], current_round=2)
    e.journal = SigningJournal(str(tmp_path / JOURNAL_FILE))
    assert e.make_proposal(10, 2, A, 0) is not None
    assert e.make_proposal(10, 2, A, 0) is not None            # same message again
    assert e.make_proposal(10, 2, A, 1) is None


def _engine(keys, stakes):
    return BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                     validator_set=[{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                                    for k, s in zip(keys, stakes)], current_round=0)


def _endorse(kp, h=A):
    m = ConsensusMessage(kind=MsgKind.ENDORSE, level=1, round=0, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def test_adopt_self_commit_checks_the_two_thirds_threshold_itself():
    keys = _keys()
    assert not _engine(keys, (60, 40)).adopt_self_commit(_endorse(keys[0]))
    assert not _engine(keys, (2, 1)).adopt_self_commit(_endorse(keys[0]))   # exactly two thirds
    assert _engine(keys, (90, 10)).adopt_self_commit(_endorse(keys[0]))


def test_adopt_self_commit_checks_the_signature():
    keys = _keys()
    forged = _endorse(keys[0])
    forged.signature = _endorse(keys[0], "bb" * 32).signature
    assert not _engine(keys, (90, 10)).adopt_self_commit(forged)
    unsigned = ConsensusMessage(kind=MsgKind.ENDORSE, level=1, round=0, block_hash=A,
                                validator=keys[0].address, validator_pubkey=keys[0].public_key_b58)
    assert not _engine(keys, (90, 10)).adopt_self_commit(unsigned)
