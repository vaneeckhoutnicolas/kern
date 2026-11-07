# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, review of 3f2b200.

P1. The signing journal restored a validator's lock, valid round and the
blocks it signed for, but not the pre-endorsement certificate that proves
the valid round. If every validator endorsed block B and the whole
cluster stopped before B was final, no process kept that certificate:
after the restart all were locked on B, a new payload could not gather a
certificate, and B could not be proposed again with its proof. The level
stayed stuck (reproduced with four real processes in
tests/test_phase_e_multiprocess.py). Every journal record now carries the
certificate of its valid round, synced with the signature that depends on
it, and the engine checks it and puts it back at start.

P2. The journal is a security boundary and now fails closed: a format
version, the chain id and every field are required and checked; a journal
in the older format, for another chain, or with a malformed record is
unreadable, and the node does not sign at the level in progress."""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import BftEngine, ConsensusMessage, MsgKind, QuorumCertificate
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import Chain, state_root_hex
from kern.consensus import BakerConfig
from kern.crypto import KernKeypair
from kern.signing_journal import JOURNAL_FILE, JOURNAL_VERSION, JournalError, SigningJournal

B, C = "bb" * 32, "cc" * 32


def _keys(n=4):
    return [KernKeypair.from_seed(bytes([0xA0 + i]) * 32) for i in range(n)]


def _vs(keys):
    return [{"address": k.address, "pubkey": k.public_key_b58, "stake": 100} for k in keys]


def _vote(kp, kind, h, level=1, round_=0):
    m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=h,
                         validator=kp.address, validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    return m


def _engine(keys, me, journal=None, current_round=0):
    e = BftEngine(own_keypair=keys[me], own_pubkey_b58=keys[me].public_key_b58,
                  validator_set=_vs(keys), current_round=current_round)
    e.min_level = 1
    e.journal = journal
    return e


def _polka(keys, h=B, level=1, round_=0, who=(0, 1, 2, 3)):
    return QuorumCertificate(kind=MsgKind.PREENDORSE, level=level, round=round_, block_hash=h,
                             signatures={keys[i].address: _vote(keys[i], MsgKind.PREENDORSE, h,
                                                                level, round_).signature
                                         for i in who})


def _endorse_then_crash(tmp_path, keys):
    """Every validator pre-endorses B at round 0, sees the certificate and
    endorses; no endorsement is delivered. Returns the journal paths."""
    paths = [str(tmp_path / f"v{i}.jsonl") for i in range(len(keys))]
    engines = [_engine(keys, i, SigningJournal(p)) for i, p in enumerate(paths)]
    pre = []
    for e in engines:
        pre += [m for m in e.on_proposal(1, 0, B) if m.kind == MsgKind.PREENDORSE]
    endorsed = []
    for e in engines:
        for m in pre:
            if m.validator != e.own_keypair.address:
                endorsed += [x for x in e.on_message(m) if x.kind == MsgKind.ENDORSE]
    assert len(endorsed) == len(keys)                       # all signed, none delivered
    return paths


def _restart(keys, i, path):
    j = SigningJournal(path)
    e = _engine(keys, i, j, current_round=0)
    rec = j.restore(1)
    restored = e.restore_lock(1, rec.locked_round, rec.locked_hash, rec.valid_round,
                              rec.valid_hash, rec.valid_qc)
    e.current_round = max(0, rec.max_round)
    return e, restored


# ------------------------------------------------------------------- P1

def test_endorse_record_carries_a_valid_certificate(tmp_path):
    keys = _keys()
    paths = _endorse_then_crash(tmp_path, keys)
    rec = [r for r in SigningJournal(paths[0]).records if r["kind"] == "endorse"][0]
    qc = QuorumCertificate.from_dict(rec["valid_qc"])
    assert (qc.kind, qc.level, qc.round, qc.block_hash) == (MsgKind.PREENDORSE, 1, 0, B)
    assert qc.verify(_vs(keys))[0]


def test_whole_cluster_restart_can_propose_the_locked_block_again(tmp_path):
    keys = _keys()
    paths = _endorse_then_crash(tmp_path, keys)
    restarted = [_restart(keys, i, p) for i, p in enumerate(paths)]
    assert all(ok for _, ok in restarted)
    engines = [e for e, _ in restarted]
    for e in engines:
        lv = e.level_state(1)
        assert (lv.locked_round, lv.locked_hash, lv.valid_round) == (0, B, 0)
        proof = e.find_preendorse_qc(1, 0, B)
        assert proof is not None and proof.verify(_vs(keys))[0]
    # Round 1: the proposer offers B again with its proof; every locked
    # validator pre-endorses it, then endorses: B becomes final.
    for e in engines:
        e.enter_round(1, 1)
    proof = engines[0].find_preendorse_qc(1, 0, B)
    out = []
    for e in engines:
        out += e.on_proposal(1, 1, B, valid_round=0, proof=proof)
    while out:
        m, out = out[0], out[1:]
        for e in engines:
            if m.validator != e.own_keypair.address:
                out += e.on_message(m)
    for e in engines:
        qc = e.find_endorse_qc(1, B)
        assert qc is not None and qc.round == 1


def test_without_the_certificate_the_locked_cluster_cannot_propose_it(tmp_path):
    """Control: the same restart, ignoring the journalled certificate,
    leaves every validator locked on B with no proof to propose it."""
    keys = _keys()
    paths = _endorse_then_crash(tmp_path, keys)
    for i, p in enumerate(paths):
        j = SigningJournal(p)
        e = _engine(keys, i, j)
        rec = j.restore(1)
        e.restore_lock(1, rec.locked_round, rec.locked_hash, rec.valid_round, rec.valid_hash)
        assert e.level_state(1).locked_hash == B
        assert e.find_preendorse_qc(1, 0, B) is None
        e.enter_round(1, 1)
        assert [m for m in e.on_proposal(1, 1, C) if m.kind == MsgKind.PREENDORSE] == []


@pytest.mark.parametrize("case", ["weak", "wrong_round", "wrong_block", "forged", "malformed"])
def test_a_bad_certificate_is_ignored_and_the_lock_kept(case):
    keys = _keys()
    e = _engine(keys, 0)
    qc = _polka(keys)
    if case == "weak":
        qc = _polka(keys, who=(0, 1))                       # half of the stake
    elif case == "wrong_round":
        qc = _polka(keys, round_=1)
    elif case == "wrong_block":
        qc = _polka(keys, h=C)
    elif case == "forged":
        qc.signatures[keys[3].address] = qc.signatures[keys[2].address]
    d = qc.to_dict()
    if case == "malformed":
        d = {"kind": "preendorse", "level": "1"}
    assert not e.restore_lock(1, 0, B, 0, B, d)
    assert e.level_state(1).locked_hash == B
    assert e.find_preendorse_qc(1, 0, B) is None


# ------------------------------------------------------------------- P2

def _rec(**over):
    r = {"v": JOURNAL_VERSION, "chain_id": "devnet", "kind": "endorse", "level": 1, "round": 0,
         "block_hash": B, "signed_valid_round": -1, "locked_round": 0, "locked_hash": B,
         "valid_round": 0, "valid_hash": B, "valid_qc": None}
    r.update(over)
    return r


def _write(path, *records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def test_a_well_formed_journal_loads(tmp_path):
    p = tmp_path / JOURNAL_FILE
    _write(p, _rec(), _rec(kind="propose", round=2, signed_valid_round=1, locked_round=0))
    assert len(SigningJournal(str(p), "devnet").records) == 2


@pytest.mark.parametrize("record,why", [
    ({k: v for k, v in _rec().items() if k != "v"}, "format"),          # older format
    ({k: v for k, v in _rec().items() if k not in ("v", "signed_valid_round")}, "format"),
    (_rec(v=3), "format"),
    (_rec(chain_id="mainnet"), "chain"),
    ({k: v for k, v in _rec().items() if k != "chain_id"}, "without chain_id"),
    ({k: v for k, v in _rec().items() if k != "signed_valid_round"}, "signed_valid_round"),
    (_rec(signed_valid_round=0), "vote with"),
    (_rec(kind="propose", round=1, signed_valid_round=1), "below its round"),
    (_rec(signed_valid_round=True), "signed_valid_round"),
    (_rec(kind="vote"), "unknown"),
    (_rec(locked_hash=None), "locked_hash"),
    (_rec(valid_round=-1), "valid_hash"),
    (_rec(valid_qc=[]), "valid_qc"),
])
def test_journal_fails_closed(tmp_path, record, why):
    p = tmp_path / JOURNAL_FILE
    _write(p, record)
    with pytest.raises(JournalError, match=why):
        SigningJournal(str(p), "devnet")


def test_append_refuses_a_record_that_would_not_reload(tmp_path):
    j = SigningJournal(str(tmp_path / JOURNAL_FILE), "devnet")
    with pytest.raises(ValueError):
        j.append("endorse", 1, 0, B, locked_round=0, locked_hash=None,
                 valid_round=-1, valid_hash=None)
    assert not (tmp_path / JOURNAL_FILE).exists()


def _node(tmp_path):
    from kern.node import Node
    from kern.storage import Storage
    keys = _keys()
    vs = _vs(keys)
    state = {"balances": {}, "nonces": {}, "contracts": {}, "validators": vs, "chain_id": "devnet"}
    h = BlockHeader(level=0, payload_round=0, timestamp=int(time.time()), parent_hash="0" * 64,
                    state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                    proposer=keys[0].address, proposer_pubkey=keys[0].public_key_b58)
    h.sign(keys[0])
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), Chain(Block(header=h), vs, initial_state=state), storage,
                BakerConfig(keys[0], keys[0].public_key_b58), rpc_port=0, p2p_port=0,
                peers=[], block_time=1.0)
    return node, storage


@pytest.mark.parametrize("record", [
    {k: v for k, v in _rec().items() if k != "v"},          # journal of an older node
    _rec(chain_id="another-chain"),
])
def test_node_does_not_sign_with_an_untrusted_journal(tmp_path, record):
    _write(tmp_path / JOURNAL_FILE, record)
    node, storage = _node(tmp_path)
    assert node.bft.no_signing_through_level == 1
    assert any(p.name.startswith(JOURNAL_FILE + ".unreadable-") for p in tmp_path.iterdir())
    assert node.bft.on_proposal(1, 0, B) == []
    storage.close()


def test_node_restores_the_certificate_at_start(tmp_path):
    keys = _keys()
    _write(tmp_path / JOURNAL_FILE, _rec(valid_qc=_polka(keys).to_dict()))
    node, storage = _node(tmp_path)
    assert node.bft.no_signing_through_level == -1
    assert node.bft.find_preendorse_qc(1, 0, B) is not None
    storage.close()
