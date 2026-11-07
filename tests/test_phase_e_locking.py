# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, E1 step 3: unit tests of the locking design.

docs/consensus-locking.md, sections 4 and 9: block identity independent of
the finalization round, signed proposals with a valid round, lock and
valid round in the engine, votes only in the current round, persistent
signing journal, proposer of the payload round checked by the chain,
cert_round in quorum verification. The network-level behaviour is in
tests/test_phase_e_consensus_harness.py."""

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import (BftEngine, ConsensusMessage, MsgKind, ProposalEquivocation,
                      QuorumCertificate, commit_entry)
from kern.block import MAX_ROUND, Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, state_root_hex
from kern.consensus import (BakerConfig, holds_quorum_alone, propose_block, round_timeout,
                            select_proposer)
from kern.crypto import KernKeypair
from kern.signing_journal import JOURNAL_FILE, JournalError, SigningJournal

A, B, C = "aa" * 32, "bb" * 32, "cc" * 32


def _keys(n=4, base=0x40):
    return [KernKeypair.from_seed(bytes([base + i]) * 32) for i in range(n)]


def _vs(keys, stakes=None):
    stakes = stakes or [100] * len(keys)
    return [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
            for k, s in zip(keys, stakes)]


def _vote(kp, kind, h, level=1, round_=0):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def _engine(keys, me=0, current_round=0, journal=None):
    e = BftEngine(own_keypair=keys[me], own_pubkey_b58=keys[me].public_key_b58,
                  validator_set=_vs(keys), current_round=current_round)
    e.min_level = 1
    if journal is not None:
        e.journal = journal
    return e


def _polka(keys, h, level=1, round_=0, who=(0, 1, 2)):
    sigs = {}
    for i in who:
        sigs[keys[i].address] = _vote(keys[i], MsgKind.PREENDORSE, h, level, round_).signature
    return QuorumCertificate(kind=MsgKind.PREENDORSE, level=level, round=round_,
                             block_hash=h, signatures=sigs)


def _own(out, kind):
    return [m for m in out if m.kind == kind]


# ------------------------------------------------------------ block format

def _header(kp, payload_round=0):
    h = BlockHeader(level=1, payload_round=payload_round, timestamp=1_700_000_000,
                    parent_hash="ab" * 32, state_root="cd" * 32, txs_root="ef" * 32,
                    proposer=kp.address, proposer_pubkey=kp.public_key_b58)
    h.sign(kp)
    return h


def test_payload_round_is_hashed_cert_round_is_not():
    kp = _keys(1)[0]
    b = Block(header=_header(kp, 3))
    h = b.hash_hex()
    b.cert_round = 9
    b.endorsements = ["x:y"]
    assert b.hash_hex() == h
    assert Block(header=_header(kp, 4)).hash_hex() != h


def test_block_roundtrip_and_strict_cert_round():
    kp = _keys(1)[0]
    b = Block(header=_header(kp, 2), cert_round=5)
    d = b.to_dict()
    assert d["cert_round"] == 5 and d["header"]["payload_round"] == 2
    assert Block.from_dict(d).cert_round == 5
    assert Block(header=_header(kp, 2)).to_dict()["cert_round"] == 2   # default: payload round
    for bad in (-1, True, "3", MAX_ROUND + 1):
        d["cert_round"] = bad
        with pytest.raises(ValueError, match="cert_round"):
            Block.from_dict(d)


def test_old_header_field_round_is_refused():
    kp = _keys(1)[0]
    d = _header(kp).to_dict()
    d["round"] = d.pop("payload_round")
    with pytest.raises(ValueError, match="payload_round"):
        BlockHeader.from_dict(d)


# --------------------------------------------------------- proposal message

def test_propose_message_signs_its_valid_round():
    kp = _keys(1)[0]
    m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=3, block_hash=A,
                         validator=kp.address, validator_pubkey=kp.public_key_b58,
                         valid_round=1)
    m.sign(kp)
    assert m.verify_signature()
    d = m.to_dict()
    assert d["valid_round"] == 1
    assert ConsensusMessage.from_dict(d).verify_signature()
    d["valid_round"] = 0                                   # tampered
    assert not ConsensusMessage.from_dict(d).verify_signature()


def test_vote_signatures_are_unchanged_and_carry_no_valid_round():
    kp = _keys(1)[0]
    v = _vote(kp, MsgKind.ENDORSE, A)
    assert "valid_round" not in v.to_dict()
    bad = v.to_dict()
    bad["valid_round"] = 0
    with pytest.raises(ValueError, match="valid_round"):
        ConsensusMessage.from_dict(bad)


def test_propose_valid_round_must_be_below_its_round():
    kp = _keys(1)[0]
    d = {"kind": "propose", "level": 1, "round": 2, "block_hash": A,
         "validator": kp.address, "validator_pubkey": kp.public_key_b58,
         "signature": None, "valid_round": 2}
    with pytest.raises(ValueError, match="valid_round"):
        ConsensusMessage.from_dict(d)
    d["round"] = MAX_ROUND + 1
    with pytest.raises(ValueError, match="round"):
        ConsensusMessage.from_dict(d)


def test_certificate_decoding_is_strict():
    keys = _keys()
    qc = _polka(keys, A)
    assert QuorumCertificate.from_dict(qc.to_dict()).verify(_vs(keys))[0]
    for field, bad in (("level", -1), ("round", "0"), ("block_hash", 3), ("signatures", [])):
        d = qc.to_dict()
        d[field] = bad
        with pytest.raises(ValueError):
            QuorumCertificate.from_dict(d)


# ------------------------------------------------------------- engine rules

def test_lock_on_endorse_and_refuse_another_block_later():
    keys = _keys()
    e = _engine(keys)
    e.on_proposal(1, 0, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A))
    lv = e.level_state(1)
    assert (lv.locked_round, lv.locked_hash) == (0, A)
    assert (lv.valid_round, lv.valid_hash) == (0, A)
    e.enter_round(1, 1)
    out = e.on_proposal(1, 1, B)                          # new payload, no proof
    assert _own(out, MsgKind.PREENDORSE) == []


def test_locked_validator_accepts_its_locked_block_again():
    keys = _keys()
    e = _engine(keys)
    e.on_proposal(1, 0, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A))
    e.enter_round(1, 1)
    out = e.on_proposal(1, 1, A, valid_round=0, proof=_polka(keys, A))
    assert [m.block_hash for m in _own(out, MsgKind.PREENDORSE)] == [A]


def test_a_more_recent_certificate_releases_the_lock():
    keys = _keys()
    e = _engine(keys)
    e.on_proposal(1, 0, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A))     # locked on A at round 0
    e.enter_round(1, 2)
    # B gathered a certificate at round 1 (this node missed round 1).
    out = e.on_proposal(1, 2, B, valid_round=1, proof=_polka(keys, B, round_=1, who=(1, 2, 3)))
    assert [m.block_hash for m in _own(out, MsgKind.PREENDORSE)] == [B]


def test_a_proof_not_more_recent_than_the_lock_does_not_release_it():
    keys = _keys()
    e = _engine(keys)
    e.enter_round(1, 1)
    e.on_proposal(1, 1, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A, round_=1))   # locked on A at round 1
    e.enter_round(1, 2)
    out = e.on_proposal(1, 2, B, valid_round=0, proof=_polka(keys, B, round_=0, who=(1, 2, 3)))
    assert _own(out, MsgKind.PREENDORSE) == []


def test_an_invalid_proof_does_not_release_the_lock():
    keys = _keys()
    e = _engine(keys)
    e.on_proposal(1, 0, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A))
    e.enter_round(1, 2)
    weak = _polka(keys, B, round_=1, who=(1, 2))           # two thirds exactly: no quorum
    out = e.on_proposal(1, 2, B, valid_round=1, proof=weak)
    assert _own(out, MsgKind.PREENDORSE) == []


def test_no_vote_in_a_round_the_node_has_left():
    """Rule 1: a late certificate for round 0 does not make a node that is
    already in round 1 endorse in round 0. The votes still count."""
    keys = _keys()
    e = _engine(keys)
    e.on_proposal(1, 0, A)                                 # own pre-endorsement in round 0
    e.enter_round(1, 1)
    out = []
    for k in keys[1:3]:
        out += e.on_message(_vote(k, MsgKind.PREENDORSE, A))
    assert _own(out, MsgKind.ENDORSE) == []
    assert e.get_preendorse_qc(1, 0) is not None           # recorded and counted
    assert e.level_state(1).locked_round == -1
    assert e.level_state(1).valid_round == 0               # the valid round is tracked


def test_no_vote_for_a_proposal_of_a_future_round_before_entering_it():
    keys = _keys()
    e = _engine(keys)
    out = e.on_proposal(1, 3, A)
    assert out == []
    out = e.enter_round(1, 3)
    assert [m.round for m in _own(out, MsgKind.PREENDORSE)] == [3]


def test_valid_round_is_not_tracked_above_the_current_round():
    keys = _keys()
    e = _engine(keys)
    for k in keys[1:4]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, B, round_=2))
    assert e.level_state(1).valid_round == -1


def test_round_skip_needs_more_than_a_third_of_the_stake():
    keys = _keys()
    e = _engine(keys)
    e.on_message(_vote(keys[1], MsgKind.PREENDORSE, A, round_=4))
    assert e.round_to_skip_to(1) is None                   # one quarter
    e.on_message(_vote(keys[2], MsgKind.ENDORSE, A, round_=4))
    assert e.round_to_skip_to(1) == 4                      # one half


def test_finalize_at_any_round():
    keys = _keys()
    e = _engine(keys)
    for k in keys[1:4]:
        e.on_message(_vote(k, MsgKind.ENDORSE, A, round_=3))
    qc = e.find_endorse_qc(1, A)
    assert qc is not None and qc.round == 3 and e.find_endorse_qc(1, B) is None


def test_proposal_equivocation_is_kept_not_slashed():
    keys = _keys()
    e = _engine(keys, me=1)
    p = keys[0]

    def prop(h):
        m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=0, block_hash=h,
                             validator=p.address, validator_pubkey=p.public_key_b58)
        m.sign(p)
        return m

    e.on_proposal(1, 0, A, proposal_msg=prop(A))
    assert e.on_proposal(1, 0, B, proposal_msg=prop(B)) == []
    assert len(e.proposal_evidence) == 1
    ev = e.proposal_evidence[0]
    assert isinstance(ev, ProposalEquivocation) and ev.verify()[0]
    assert e.take_evidence() == []                          # not handed over for slashing


def test_a_mismatching_propose_message_is_refused():
    keys = _keys()
    e = _engine(keys, me=1)
    m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=0, block_hash=A,
                         validator=keys[0].address, validator_pubkey=keys[0].public_key_b58)
    m.sign(keys[0])
    assert e.on_proposal(1, 0, B, proposal_msg=m) == []
    assert (1, 0) not in e.states


# ------------------------------------------------------------ signing journal

def test_journal_records_before_signing_and_restores(tmp_path):
    keys = _keys()
    j = SigningJournal(str(tmp_path / JOURNAL_FILE), "devnet")
    e = _engine(keys, journal=j)
    e.on_proposal(1, 0, A)
    for k in keys[1:3]:
        e.on_message(_vote(k, MsgKind.PREENDORSE, A))
    kinds = [(r["kind"], r["round"], r["block_hash"]) for r in j.records]
    assert kinds == [("preendorse", 0, A), ("endorse", 0, A)]
    assert j.records[-1]["locked_round"] == 0 and j.records[-1]["locked_hash"] == A
    reopened = SigningJournal(str(tmp_path / JOURNAL_FILE), "devnet")
    rec = reopened.restore(1)
    assert (rec.locked_round, rec.locked_hash, rec.valid_round, rec.max_round) == (0, A, 0, 0)


def test_journal_refuses_a_conflicting_signature_after_restart(tmp_path):
    keys = _keys()
    path = str(tmp_path / JOURNAL_FILE)
    e = _engine(keys, journal=SigningJournal(path))
    e.on_proposal(1, 0, A)                                 # pre-endorsed A at round 0
    fresh = _engine(keys, journal=SigningJournal(path))    # restart, lock not restored
    out = fresh.on_proposal(1, 0, B)
    assert _own(out, MsgKind.PREENDORSE) == []
    again = _engine(keys, journal=SigningJournal(path))
    assert [m.block_hash for m in _own(again.on_proposal(1, 0, A), MsgKind.PREENDORSE)] == [A]


def test_journal_ignores_a_cut_final_record_and_rejects_corruption(tmp_path):
    path = tmp_path / JOURNAL_FILE
    j = SigningJournal(str(path))
    j.append("preendorse", 1, 0, A, locked_round=-1, locked_hash=None,
             valid_round=-1, valid_hash=None)
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"kind": "endorse", "lev')                 # crash during the write
    j2 = SigningJournal(str(path))
    assert len(j2.records) == 1
    assert path.read_text(encoding="utf-8").endswith("\n")
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n")
    with pytest.raises(JournalError):
        SigningJournal(str(path))


def test_journal_compaction(tmp_path):
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    for lvl in (1, 2, 3):
        j.append("endorse", lvl, 0, A, locked_round=0, locked_hash=A, valid_round=0, valid_hash=A)
    j.compact(3)
    assert [r["level"] for r in SigningJournal(str(tmp_path / JOURNAL_FILE)).records] == [3]


def test_signing_suspended_until_the_level_is_final():
    keys = _keys()
    e = _engine(keys)
    e.no_signing_through_level = 1
    assert e.on_proposal(1, 0, A) == []
    assert e.make_proposal(1, 0, A, -1) is None


# ------------------------------------------------------ proposer self-commit

def _genesis(keys, stakes):
    vs = _vs(keys, stakes)
    state = {"balances": {}, "nonces": {}, "contracts": {}, "validators": vs}
    h = BlockHeader(level=0, payload_round=0, timestamp=int(time.time()), parent_hash="0" * 64,
                    state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                    proposer=keys[0].address, proposer_pubkey=keys[0].public_key_b58)
    h.sign(keys[0])
    return Chain(Block(header=h), vs, initial_state=state)


def _selected(chain, round_, keys):
    sel = select_proposer(chain.head.hash_hex(), chain.validators, round_)["address"]
    return next(k for k in keys if k.address == sel)


def test_no_self_commit_without_the_quorum_alone():
    """A proposer with 40 % of the stake signs no endorsement when it builds
    its block: with a byzantine 30 %, that signature alone would finalize a
    block nobody honest is locked on."""
    keys = _keys(4)
    chain = _genesis(keys, [40, 30, 15, 15])
    kp = _selected(chain, 0, keys)
    b = propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                      proposer_pubkey_b58=kp.public_key_b58, state_before=chain.state, round_=0)
    assert b.commits == []
    assert not holds_quorum_alone(keys[0].address, chain.validators)


def test_self_commit_of_a_proposer_holding_the_quorum_alone():
    keys = _keys(2)
    chain = _genesis(keys, [90, 10])
    kp = _selected(chain, 0, keys)
    b = propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                      proposer_pubkey_b58=kp.public_key_b58, state_before=chain.state, round_=0)
    assert (len(b.commits) == 1) == holds_quorum_alone(kp.address, chain.validators)


def test_adopted_self_commit_locks_and_is_journaled(tmp_path):
    keys = _keys(1)
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    e = _engine(keys, journal=j)
    m = _vote(keys[0], MsgKind.ENDORSE, A, round_=0)
    assert e.adopt_self_commit(m)
    assert e.level_state(1).locked_hash == A and j.records[-1]["kind"] == "endorse"
    assert not e.adopt_self_commit(_vote(keys[0], MsgKind.ENDORSE, B, round_=0))


# ---------------------------------------------------------- chain validation

def _endorse_all(keys, block, round_, who=None):
    who = range(len(keys)) if who is None else who
    return sorted(commit_entry(_vote(keys[i], MsgKind.ENDORSE, block.hash_hex(),
                                     level=block.header.level, round_=round_)) for i in who)


def test_block_from_a_proposer_not_selected_for_its_payload_round_is_invalid():
    keys = _keys(4)
    chain = _genesis(keys, [100] * 4)
    selected = _selected(chain, 0, keys)
    other = next(k for k in keys if k.address != selected.address)
    b = propose_block(parent=chain.head, mempool=[], proposer_keypair=other,
                      proposer_pubkey_b58=other.public_key_b58, state_before=chain.state, round_=0)
    with pytest.raises(ValueError, match="selected proposer"):
        chain.append(b)                                     # even without a quorum check


def test_quorum_is_verified_at_cert_round():
    keys = _keys(4)
    chain = _genesis(keys, [100] * 4)
    kp = _selected(chain, 0, keys)
    b = propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                      proposer_pubkey_b58=kp.public_key_b58, state_before=chain.state, round_=0)
    b.endorsements = _endorse_all(keys, b, round_=2)
    b.cert_round = 3                                         # wrong round
    c = Chain(chain.blocks[0], chain.validators, initial_state=chain.state)
    with pytest.raises(ValueError, match="invalid commit signature"):
        c.append(Block.from_dict(b.to_dict()), require_quorum=True)
    b.cert_round = 2
    c.append(Block.from_dict(b.to_dict()), require_quorum=True)
    assert c.height == 1


def test_cert_round_below_the_payload_round_is_invalid():
    keys = _keys(4)
    chain = _genesis(keys, [100] * 4)
    kp = _selected(chain, 2, keys)
    b = propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                      proposer_pubkey_b58=kp.public_key_b58, state_before=chain.state, round_=2)
    b.endorsements = _endorse_all(keys, b, round_=1)
    b.cert_round = 1
    with pytest.raises(ValueError, match="cert_round"):
        chain.append(b, require_quorum=True)


def test_new_node_verifies_finality_of_every_block_on_its_own():
    """Five blocks, finalized at various rounds (re-proposals included);
    a node that starts from genesis checks every quorum from the blocks
    alone and reaches the same head. A tampered cert_round is refused."""
    keys = _keys(4)
    source = _genesis(keys, [100] * 4)
    genesis = source.blocks[0]
    wire = []
    for level, (payload_round, cert_round) in enumerate([(0, 0), (0, 2), (1, 1), (3, 5), (0, 0)], 1):
        kp = _selected(source, payload_round, keys)
        b = propose_block(parent=source.head, mempool=[], proposer_keypair=kp,
                          proposer_pubkey_b58=kp.public_key_b58, state_before=source.state,
                          round_=payload_round)
        b.endorsements = _endorse_all(keys, b, cert_round, who=(0, 1, 3))
        b.cert_round = cert_round
        source.append(b, require_quorum=True)
        wire.append(json.loads(json.dumps(b.to_dict())))

    fresh = Chain(genesis, _vs(keys), initial_state=_genesis(keys, [100] * 4).state)
    for d in wire:
        fresh.append(Block.from_dict(d), require_quorum=True)
    assert fresh.head.hash_hex() == source.head.hash_hex()
    assert state_root_hex(fresh.state) == state_root_hex(source.state)

    tampered = Chain(genesis, _vs(keys), initial_state=_genesis(keys, [100] * 4).state)
    tampered.append(Block.from_dict(wire[0]), require_quorum=True)
    bad = dict(wire[1])
    bad["cert_round"] = 0
    with pytest.raises(ValueError):
        tampered.append(Block.from_dict(bad), require_quorum=True)


# ---------------------------------------------------------- node integration

def _node(tmp_path, keys, me=0, chain=None):
    from kern.node import Node
    from kern.storage import Storage
    chain = chain or _genesis(keys, [100] * len(keys))
    storage = Storage(str(tmp_path))
    return Node(str(tmp_path), chain, storage, BakerConfig(keys[me], keys[me].public_key_b58),
                rpc_port=0, p2p_port=0, peers=[], block_time=1.0), storage


def test_node_restores_lock_and_round_from_its_journal(tmp_path):
    keys = _keys(4)
    j = SigningJournal(str(tmp_path / JOURNAL_FILE))
    j.append("endorse", 1, 2, A, locked_round=2, locked_hash=A, valid_round=2, valid_hash=A)
    node, storage = _node(tmp_path, keys)
    lv = node.bft.level_state(1)
    assert (lv.locked_round, lv.locked_hash) == (2, A)
    assert node._round == 2 and node.bft.no_signing_through_level == -1
    storage.close()


def test_node_with_an_unreadable_journal_does_not_sign_the_level(tmp_path):
    keys = _keys(4)
    (tmp_path / JOURNAL_FILE).write_text("garbage\n", encoding="utf-8")
    node, storage = _node(tmp_path, keys)
    assert node.bft.no_signing_through_level == 1
    assert any(p.name.startswith(JOURNAL_FILE + ".unreadable-") for p in tmp_path.iterdir())
    storage.close()


def _envelope(chain, keys, round_, *, valid_round=-1, proof=None, block=None, signer=None):
    from kern.node import Node
    kp = signer or _selected(chain, round_, keys)
    if block is None:
        block = propose_block(parent=chain.head, mempool=[], proposer_keypair=kp,
                              proposer_pubkey_b58=kp.public_key_b58, state_before=chain.state,
                              round_=round_)
    m = ConsensusMessage(kind=MsgKind.PROPOSE, level=1, round=round_, block_hash=block.hash_hex(),
                         validator=kp.address, validator_pubkey=kp.public_key_b58,
                         valid_round=valid_round)
    m.sign(kp)
    return Node._envelope(block, m, proof), block


def test_node_accepts_a_signed_proposal_and_pre_endorses(tmp_path):
    keys = _keys(4)
    chain = _genesis(keys, [100] * 4)
    proposer = _selected(chain, 0, keys)
    me = next(i for i, k in enumerate(keys) if k.address != proposer.address)
    node, storage = _node(tmp_path, keys, me=me, chain=chain)
    env, block = _envelope(chain, keys, 0)
    sent = []

    async def capture(msgs):
        sent.extend(msgs)
    node._emit_consensus = capture
    asyncio.run(node._on_proposal_msg(env))
    assert (1, block.hash_hex()) in node._pending
    assert [m.kind for m in sent] == [MsgKind.PREENDORSE]
    assert [r["kind"] for r in node.journal.records] == ["preendorse"]
    storage.close()


@pytest.mark.parametrize("case", ["wrong_signer", "reproposal_without_proof",
                                  "payload_round_mismatch"])
def test_node_rejects_bad_proposals(tmp_path, case):
    keys = _keys(4)
    chain = _genesis(keys, [100] * 4)
    p0 = _selected(chain, 0, keys)
    me = next(i for i, k in enumerate(keys) if k.address != p0.address)
    node, storage = _node(tmp_path, keys, me=me, chain=chain)
    if case == "wrong_signer":
        env, block = _envelope(chain, keys, 0, signer=keys[me])
    elif case == "reproposal_without_proof":
        _, block = _envelope(chain, keys, 0)
        r = 1
        env, _ = _envelope(chain, keys, r, valid_round=0, block=block)
    else:
        _, block = _envelope(chain, keys, 0)
        r = 1
        env, _ = _envelope(chain, keys, r, block=block)       # new payload claimed, old round
    asyncio.run(node._on_proposal_msg(env))
    assert node._pending == {}
    assert node.journal.records == []
    storage.close()


def test_round_timeout_grows_and_restarts():
    assert round_timeout(2.0, 0) == 2.0
    assert round_timeout(2.0, 4) == 6.0
