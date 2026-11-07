# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Ingress decoding hardening: every dict that crosses the process
boundary (P2P gossip, RPC) must be strictly typed at the door.

A gossiped transaction whose fields are wrong-typed (a string amount, a
boolean nonce, a float fee) must be rejected in from_dict with a
field-specific ValueError, never allowed to reach consensus code. bool is
a subclass of int in Python, so these tests explicitly pin bool
rejection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.bft import ConsensusMessage
from kern.block import Block, BlockHeader
from kern.crypto import KernKeypair
from kern.transaction import Transaction, make_transfer


def _valid_tx_dict():
    kp = KernKeypair.generate()
    dst = KernKeypair.generate().address
    return make_transfer(kp, recipient=dst, amount=1000, nonce=0).to_dict()


def test_valid_tx_roundtrips():
    d = _valid_tx_dict()
    tx = Transaction.from_dict(d)
    assert tx.to_dict() == d
    assert tx.verify_signature()


@pytest.mark.parametrize("field,bad", [
    ("nonce", "0"), ("nonce", -1), ("nonce", 1.5), ("nonce", True), ("nonce", None),
    ("fee", "1000"), ("fee", -1), ("fee", 2.0), ("fee", False),
    ("gas_limit", "10000"), ("gas_limit", -5), ("gas_limit", True),
    ("amount", "1000"), ("amount", -1), ("amount", 1.0), ("amount", True),
])
def test_bad_integer_fields_rejected(field, bad):
    d = _valid_tx_dict()
    d[field] = bad
    with pytest.raises(ValueError, match=rf"tx\.{field}"):
        Transaction.from_dict(d)


@pytest.mark.parametrize("field", ["kind", "sender", "sender_pubkey"])
@pytest.mark.parametrize("bad", [None, 42, "", ["x"]])
def test_bad_required_string_fields_rejected(field, bad):
    d = _valid_tx_dict()
    d[field] = bad
    with pytest.raises(ValueError):
        Transaction.from_dict(d)


def test_unknown_kind_rejected():
    d = _valid_tx_dict()
    d["kind"] = "mint_infinite_money"
    with pytest.raises(ValueError):
        Transaction.from_dict(d)


def test_non_dict_rejected():
    with pytest.raises(ValueError):
        Transaction.from_dict(["not", "a", "dict"])


def test_poisoned_tx_never_reaches_mempool_shape():
    """The exact poison scenario: a self-consistent tx whose amount is a
    *string*. Its signature can be valid over the string bytes, but the
    decode gate rejects it before signature checking even matters."""
    d = _valid_tx_dict()
    d["amount"] = "999999999"
    with pytest.raises(ValueError, match=r"tx\.amount"):
        Transaction.from_dict(d)


# ---------------------------------------------------------------------------
# BlockHeader / Block
# ---------------------------------------------------------------------------

def _valid_header_dict():
    kp = KernKeypair.generate()
    h = BlockHeader(
        level=1, payload_round=0, timestamp=1_700_000_000,
        parent_hash="ab" * 32, state_root="cd" * 32, txs_root="ef" * 32,
        proposer=kp.address, proposer_pubkey=kp.public_key_b58,
    )
    h.sign(kp)
    return h.to_dict()


def test_valid_header_roundtrips():
    d = _valid_header_dict()
    assert BlockHeader.from_dict(d).to_dict() == d


@pytest.mark.parametrize("field,bad", [
    ("level", "1"), ("level", -1), ("level", True),
    ("payload_round", 1.0), ("payload_round", 2**32), ("timestamp", -5),
    ("parent_hash", "zz" * 32), ("parent_hash", "ab" * 31), ("parent_hash", 12),
    ("state_root", None), ("txs_root", "ab"),
    ("proposer", ""), ("proposer_pubkey", 7),
])
def test_bad_header_fields_rejected(field, bad):
    d = _valid_header_dict()
    d[field] = bad
    with pytest.raises(ValueError, match=rf"header\.{field}"):
        BlockHeader.from_dict(d)


def test_block_commits_must_be_string_list():
    d = {"header": _valid_header_dict(), "transactions": [], "commits": [42]}
    with pytest.raises(ValueError, match=r"block\.commits"):
        Block.from_dict(d)


def test_block_endorsements_roundtrip():
    d = {"header": _valid_header_dict(), "transactions": [],
         "commits": ["kn1a:sig"], "endorsements": ["kn1b:sig"]}
    b = Block.from_dict(d)
    assert b.endorsements == ["kn1b:sig"]
    assert Block.from_dict(b.to_dict()).endorsements == ["kn1b:sig"]


# ---------------------------------------------------------------------------
# ConsensusMessage
# ---------------------------------------------------------------------------

def test_consensus_message_strict():
    kp = KernKeypair.generate()
    from kern.bft import MsgKind
    m = ConsensusMessage(kind=MsgKind.ENDORSE, level=1, round=0,
                         block_hash="ab" * 32, validator=kp.address,
                         validator_pubkey=kp.public_key_b58)
    m.sign(kp)
    d = m.to_dict()
    assert ConsensusMessage.from_dict(d).verify_signature()
    for field, bad in [("level", "1"), ("round", True), ("block_hash", ""),
                       ("validator", None), ("kind", "bribe")]:
        dd = dict(d); dd[field] = bad
        with pytest.raises(ValueError):
            ConsensusMessage.from_dict(dd)
