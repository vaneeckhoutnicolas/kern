# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""What a node remembers and compares is what was signed, not the bytes of
a signature.

Review of 12 November 2026 (docs/consensus-locking.md, section 10.11).
Two places in the node depended on signature bytes.

1. Two signed PROPOSE messages of a (level, round) were compared through
`to_dict()`, which includes the signature. The same statement signed a
second time, under other signature bytes, was taken for a conflicting
proposal and never validated nor voted on. With Ed25519 only the proposer
can do that, by signing with another nonce; with a randomized scheme such
as ML-DSA every new signature of a statement has other bytes.

2. The identifier of a transaction leaves its signature out, and a
gossiped transaction was remembered under that identifier before its
signature was checked. A copy with a damaged signature, received first,
made the node ignore the real transaction when it arrived.

The tests sign the same PROPOSE twice with Ed25519, using RFC 8032 with
another nonce than the deterministic one. They fail on 1c94114, except
the one marked as a control.
"""

import asyncio
import hashlib
import sys
from pathlib import Path

import nacl.bindings as sodium
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kern.bft import ConsensusMessage, MsgKind, ProposalEquivocation
from kern.crypto import PREFIX_SIGNATURE, KernKeypair, b58check_encode
from kern.node import Node
from kern.transaction import make_transfer

from test_phase_e_invalid_first_proposal import _own_votes, _run, _setup
from test_phase_e_review_0695a80 import _reproposal_setup


def _second_signature(seed: bytes, message: bytes) -> bytes:
    """Another valid Ed25519 signature of `message` under the key of
    `seed`: RFC 8032, section 5.1.6, with a nonce of our own."""
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    a = sodium.crypto_core_ed25519_scalar_reduce(bytes(scalar) + bytes(32))
    public = sodium.crypto_scalarmult_ed25519_base_noclamp(a)
    r = sodium.crypto_core_ed25519_scalar_reduce(
        hashlib.sha512(b"another nonce" + digest[32:] + message).digest())
    big_r = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
    k = sodium.crypto_core_ed25519_scalar_reduce(hashlib.sha512(big_r + public + message).digest())
    return big_r + sodium.crypto_core_ed25519_scalar_add(r, sodium.crypto_core_ed25519_scalar_mul(k, a))


def _signed_again(kp, message: ConsensusMessage) -> ConsensusMessage:
    """The same statement as `message`, under other signature bytes."""
    again = ConsensusMessage.from_dict(message.to_dict())
    again.signature = b58check_encode(PREFIX_SIGNATURE, _second_signature(kp.seed, message._signed_payload()))
    return again


# ------------------------------------------------------------- proposals

def test_control_the_second_signature_is_valid_and_different(tmp_path, monkeypatch):
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    again = _signed_again(p1, pmsg)
    assert again.signature != pmsg.signature
    assert again.verify_signature() and pmsg.verify_signature()
    assert again._signed_payload() == pmsg._signed_payload()
    # Evidence was already judged on what is signed: no conflict here.
    assert not ProposalEquivocation(p1.address, pmsg, again).verify()[0]
    storage.close()


def test_same_statement_looks_at_what_is_signed_and_at_nothing_else(tmp_path, monkeypatch):
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    assert pmsg.same_statement(_signed_again(p1, pmsg))
    for field, value in (("valid_round", -1), ("block_hash", "ab" * 32), ("round", 2), ("level", 2),
                         ("kind", "preendorse"), ("validator", me.address),
                         ("validator_pubkey", me.public_key_b58)):
        changed = {**pmsg.to_dict(), field: value}
        if field == "kind":
            del changed["valid_round"]                   # only a PROPOSE carries one
        assert not pmsg.same_statement(ConsensusMessage.from_dict(changed)), field
    storage.close()


@pytest.mark.parametrize("damage", ["missing", "weak"])
def test_a_proposal_signed_again_still_goes_through_after_a_damaged_proof(tmp_path, monkeypatch, damage):
    """The first copy arrives with a proof a relay stripped or damaged, and
    occupies the round without being validated. The proposer sends the
    same statement again, signed again, with its valid proof: it is the
    proposal of the round, and it is pre-endorsed."""
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    damaged = Node._envelope(x, pmsg, None if damage == "missing" else weak)
    genuine = Node._envelope(x, _signed_again(p1, pmsg), good)
    _run(node, damaged, genuine)
    assert [(m.kind, m.round, m.block_hash) for m in _own_votes(node, me)] == [
        (MsgKind.PREENDORSE, 1, x.hash_hex())]
    assert node.bft.proposal_evidence == []
    storage.close()


def test_a_proposal_signed_again_is_not_relayed_as_a_conflict(tmp_path, monkeypatch):
    keys, chain, p1, me, node, storage, x, pmsg, good, weak = _reproposal_setup(tmp_path, monkeypatch)
    damaged = Node._envelope(x, pmsg, weak)
    genuine = Node._envelope(x, _signed_again(p1, pmsg), good)
    _run(node, damaged, genuine)
    assert node._relayed_conflicts == set()
    assert node.network.proposals == [genuine]            # relayed once, as a valid proposal
    storage.close()


# ---------------------------------------------------------- transactions

def _gossip(node, *transactions):
    relayed = []

    async def broadcast_tx(tx_dict):
        relayed.append(tx_dict)

    node.network.broadcast_tx = broadcast_tx

    async def go():
        for tx_dict in transactions:
            await node._on_tx_msg(tx_dict)
        await asyncio.sleep(0)                # let the relay run
    asyncio.run(go())
    return relayed


def _transfer_and_damaged_copy():
    alice, bob = KernKeypair.from_seed(b"\xA1" * 32), KernKeypair.from_seed(b"\xB0" * 32)
    tx = make_transfer(alice, recipient=bob.address, amount=1_000_000, nonce=0, fee=1_000)
    damaged = dict(tx.to_dict(), signature=alice.sign_b58(b"not this transaction"))
    assert tx.verify_signature() and damaged["signature"] != tx.signature
    return tx, damaged


def test_a_damaged_copy_of_a_transaction_does_not_hide_the_real_one(tmp_path):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    tx, damaged = _transfer_and_damaged_copy()
    chain.state["balances"][tx.sender] = 10_000_000     # a node takes a transaction whose sender can pay its fee
    relayed = _gossip(node, damaged, tx.to_dict(), tx.to_dict())
    assert [t.to_dict() for t in storage.drain_mempool()] == [tx.to_dict()]
    assert relayed == [tx.to_dict()]                    # the real one, once
    storage.close()


def test_control_a_damaged_transaction_alone_is_neither_kept_nor_relayed(tmp_path):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    tx, damaged = _transfer_and_damaged_copy()
    chain.state["balances"][tx.sender] = 10_000_000
    assert _gossip(node, damaged, damaged) == []
    assert storage.mempool_size() == 0
    storage.close()
