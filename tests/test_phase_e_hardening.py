# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of 84cbbcc.

P1. The block file of the signing journal (signing_journal.blocks.jsonl)
skipped a final line cut by a crash but left it in the file. The next
block was appended right after the fragment, on the same line, so it was
lost at the following restart although the node had treated it as kept on
disk before signing. The cut line is now dropped at start, and every
append starts on a fresh line.

P2. A proposer could sign many different valid blocks for its round: the
node validated each one in full, kept it in memory and wrote it to disk
before the engine saw the conflict. Only the first block of a (level,
round) is now validated and kept; a later, different one is checked for
its signature, kept as proposal equivocation evidence, and dropped.

P2. Vote evidence keys were never pruned, and proposal equivocation
evidence grew without bound."""

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import kern.bft as bft
from kern.bft import BftEngine, ConsensusMessage, MsgKind, ProposalEquivocation
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, state_root_hex
from kern.consensus import BakerConfig, propose_block, select_proposer
from kern.crypto import KernKeypair
from kern.signing_journal import BLOCKS_FILE, JOURNAL_FILE, SigningJournal

A = "aa" * 32


# ------------------------------------------------------------------- P1

def test_a_cut_block_line_does_not_swallow_the_next_block(tmp_path):
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    j.record_block(1, "11" * 32, {"n": 1})
    with open(tmp_path / BLOCKS_FILE, "a", encoding="utf-8") as f:
        f.write('{"level": 1, "block_hash": "22')            # crash during the write
    j2 = SigningJournal(str(tmp_path / JOURNAL_FILE))       # restart
    assert j2.has_block(1, "11" * 32) and not j2.has_block(1, "22" * 32)
    j2.record_block(1, "33" * 32, {"n": 3})                  # kept "on disk" before signing
    j3 = SigningJournal(str(tmp_path / JOURNAL_FILE))       # next restart
    assert j3.has_block(1, "33" * 32)
    assert j3.has_block(1, "11" * 32)
    assert (tmp_path / BLOCKS_FILE).read_text(encoding="utf-8").endswith("\n")


def test_an_append_always_starts_on_a_fresh_line(tmp_path):
    """Even if the fragment appears after the journal was opened."""
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    j.record_block(1, "11" * 32, {"n": 1})
    with open(tmp_path / BLOCKS_FILE, "a", encoding="utf-8") as f:
        f.write('{"level": 1, "blo')
    j.record_block(1, "33" * 32, {"n": 3})
    assert SigningJournal(str(tmp_path / JOURNAL_FILE)).has_block(1, "33" * 32)


# ------------------------------------------------------------------- P2, proposals

def _keys(n=4):
    return [KernKeypair.from_seed(bytes([0xB0 + i]) * 32) for i in range(n)]


def _chain(keys):
    vs = [{"address": k.address, "pubkey": k.public_key_b58, "stake": 100} for k in keys]
    state = {"balances": {}, "nonces": {}, "contracts": {}, "validators": vs}
    h = BlockHeader(level=0, payload_round=0, timestamp=1_700_000_000, parent_hash="0" * 64,
                    state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                    proposer=keys[0].address, proposer_pubkey=keys[0].public_key_b58)
    h.sign(keys[0])
    return Chain(Block(header=h), vs, initial_state=state)


def test_conflicting_proposals_are_not_validated_or_kept(tmp_path, monkeypatch):
    from kern import node as node_mod
    from kern.node import Node
    from kern.storage import Storage

    keys = _keys()
    chain = _chain(keys)
    proposer = next(k for k in keys if k.address == select_proposer(
        chain.head.hash_hex(), chain.validators, 0)["address"])
    me = next(k for k in keys if k.address != proposer.address)
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), chain, storage, BakerConfig(me, me.public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0)

    import kern.consensus as consensus_mod
    envelopes = []
    for i in range(20):                                   # twenty different valid blocks
        with monkeypatch.context() as mp:
            mp.setattr(consensus_mod.time, "time", lambda i=i: 1_700_000_100 + i)
            block = propose_block(parent=chain.head, mempool=[], proposer_keypair=proposer,
                                  proposer_pubkey_b58=proposer.public_key_b58,
                                  state_before=chain.state, round_=0)
        m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=0, block_hash=block.hash_hex(),
                             validator=proposer.address, validator_pubkey=proposer.public_key_b58)
        m.sign(proposer)
        envelopes.append(Node._envelope(block, m, None))

    calls = []
    real_validate = node_mod.validate_and_apply
    monkeypatch.setattr(node_mod, "validate_and_apply",
                        lambda *a, **k: calls.append(1) or real_validate(*a, **k))
    assert len({e["proposal"]["block_hash"] for e in envelopes}) == 20

    async def flood():
        for e in envelopes:
            await node._on_proposal_msg(e)
    asyncio.run(flood())

    assert len(calls) == 1                                 # only the first block is validated
    assert len([k for k in node._pending if k[0] == 1]) == 1
    assert len(node.journal.blocks(1)) == 1                # and kept on disk
    ev = node.bft.proposal_evidence
    assert ev and all(e.offender == proposer.address and e.verify()[0] for e in ev)
    storage.close()


# ------------------------------------------------------------------- P2, evidence

def _vote(kp, h, level, round_=0, kind=MsgKind.ENDORSE):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def test_vote_evidence_keys_are_pruned_with_their_level():
    keys = _keys()
    e = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                  validator_set=[{"address": k.address, "pubkey": k.public_key_b58, "stake": 100}
                                 for k in keys])
    for level in (1, 2, 3):
        e.min_level = level
        e.on_message(_vote(keys[3], "aa" * 32, level))
        e.on_message(_vote(keys[3], "bb" * 32, level))
    assert len(e.take_evidence()) == 3 and len(e._evidence_keys) == 3
    e.prune_below(3)
    assert {k[2] for k in e._evidence_keys} == {3}


def test_proposal_evidence_is_bounded():
    keys = _keys()
    p = keys[1]
    e = BftEngine(own_keypair=keys[0], own_pubkey_b58=keys[0].public_key_b58,
                  validator_set=[{"address": k.address, "pubkey": k.public_key_b58, "stake": 100}
                                 for k in keys])

    def prop(level, h):
        m = ConsensusMessage(kind=MsgKind.PROPOSE, level=level, round=0, block_hash=h,
                             validator=p.address, validator_pubkey=p.public_key_b58)
        m.sign(p)
        return m

    for level in range(1, bft.MAX_PROPOSAL_EVIDENCE + 50):
        e.min_level = level
        e.on_proposal(level, 0, "aa" * 32, proposal_msg=prop(level, "aa" * 32))
        e.on_proposal(level, 0, "bb" * 32, proposal_msg=prop(level, "bb" * 32))
        e.prune_below(level)
    assert len(e.proposal_evidence) == bft.MAX_PROPOSAL_EVIDENCE
    assert e.proposal_evidence[-1].msg_a.level == bft.MAX_PROPOSAL_EVIDENCE + 49   # newest kept
