# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.consensus
--------------

Kern's consensus is a simplified Tenderbake-style BFT protocol. The
production design (described in `docs/consensus.md`) has three message
types per round — Propose, Preendorse, Endorse — and reaches finality
in 2*delta_block_time after a successful round.

This reference implementation collapses the protocol to its essentials:

1. The round leader is selected deterministically from the validator
   set, weighted by stake, using the parent block hash as a seed.
2. The leader proposes a block.
3. Each validator emits a commit signature over the block hash.
4. A block with > 2/3 stake committing it is final.

In a single-validator local network (the default), step 3 collapses to
the proposer self-committing, and finality is achieved in one block time.

`target_block_time` is configurable; the default is 1 second. Block
production sleeps to maintain a steady cadence even when the mempool is
empty.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Union

from .block import Block, BlockHeader, txs_merkle_root_hex
from .chain import apply_block, state_root_hex
from .crypto import KernKeypair
from .transaction import Transaction, Waiting


DEFAULT_BLOCK_TIME_S = 1.0
DEFAULT_MAX_TXS_PER_BLOCK = 5_000


def round_timeout(base: float, round_: int) -> float:
    """Phase E (consensus-locking.md, rule 7): the duration of round r grows
    linearly, base + r * base / 2, so that after the network stabilizes a
    round eventually lasts long enough for a full exchange. Every level
    restarts at round 0, so a slow level does not slow down the next."""
    return base + round_ * base / 2


def holds_quorum_alone(address: str, validators: List[dict]) -> bool:
    """True when `address` holds strictly more than two thirds of the
    consensus stake on its own (single-validator operation)."""
    total = sum(v["stake"] for v in validators)
    own = sum(v["stake"] for v in validators if v["address"] == address)
    return total > 0 and own * 3 > total * 2


def select_proposer(
    parent_hash_hex: str,
    validators: List[dict],
    round_: int,
) -> dict:
    """Deterministically select the proposer for a given round.

    Phase E: every level restarts at round 0, and the round is the round
    of the PROPOSAL. A block proposed again in a later round keeps the
    header proposer of its payload round; the PROPOSE message is signed by
    the proposer of the current round.

    Stake-weighted: each validator's chance of being selected is
    proportional to its stake. The selection is seeded by
    blake2b(parent_hash || round) for verifiability.
    """
    if not validators:
        raise ValueError("empty validator set")
    seed_bytes = parent_hash_hex.encode() + round_.to_bytes(4, "big")
    digest = hashlib.blake2b(seed_bytes, digest_size=8).digest()
    rnd = int.from_bytes(digest, "big")
    total_stake = sum(v["stake"] for v in validators)
    if total_stake <= 0:
        return validators[round_ % len(validators)]
    pick = rnd % total_stake
    acc = 0
    for v in validators:
        acc += v["stake"]
        if pick < acc:
            return v
    return validators[-1]


def propose_block(
    *,
    parent: Block,
    mempool: Iterable[Union[Transaction, Waiting]],
    proposer_keypair: KernKeypair,
    proposer_pubkey_b58: str,
    state_before: dict,
    round_: int = 0,
    max_txs: int = DEFAULT_MAX_TXS_PER_BLOCK,
    evict_out: Optional[List[str]] = None,
) -> Block:
    """Construct, fill, and sign a new block proposing it as the next
    head.

    The mempool is read in its order, until the block is full: `max_txs`
    transactions, or the bytes that `chain.proposed_block_bytes` allows. A
    transaction is looked at through four facts first, its sender, nonce,
    fee and size (`chain.mempool_verdict`), on the state as the block has
    made it so far:

    - the block takes what it can charge. A transaction that is charged is
      in the block whether its operation then succeeds or fails: it paid
      its fee and consumed its nonce, which is what `apply_block` does with
      it on every validator;
    - a transaction whose nonce is ahead of its account waits in the
      mempool, at no cost;
    - a transaction no block will charge stays out, and its hash goes to
      `evict_out`, when it is given, so that the caller removes it from
      the mempool: a nonce that is consumed or too far ahead, a sender that
      cannot pay the fee, a fee under the floor, a size beyond what a node
      takes, a signature or a chain that `apply_transaction` refuses.

    The state is copied once. Until this rule the proposer copied it before
    each of the 5,000 oldest transactions, left out those whose operation
    failed although the block would have charged them, and never looked at
    the fee floor: transactions that could only fail stayed in the mempool
    for ever and hid the others, and with the floor on the block was one
    that every validator refused.

    `round_` becomes the header's payload_round. Phase E: the proposer's
    self-commit (an ENDORSE signature over the block) is only produced
    when the proposer holds more than two thirds of the consensus stake on
    its own, so that the signature is a complete quorum and no lock rule
    is bypassed. With several validators, an endorsement signed before a
    pre-endorsement certificate exists would let a large proposer plus a
    byzantine minority finalize a block no honest validator is locked on.

    Block rewards are applied to working_state BEFORE computing the
    state_root, so that the published state_root commits to the
    post-reward state — matching what apply_block will produce on
    validation.

    Phase B (audit 1, finding 7): a transaction can never stop block
    production. `apply_transaction` turns every handler exception into a
    rejection, and this loop additionally guards the call so that a defect
    anywhere in the application path discards the transaction instead of
    propagating out of the baker loop."""
    import copy
    from . import chain
    from .chain import DROP, TAKE, _apply_block_rewards

    level = parent.header.level + 1
    baker = proposer_keypair.address
    fees = chain.fee_params(state_before)
    room = chain.proposed_block_bytes(fees)
    selected: List[Transaction] = []

    def fresh_state() -> dict:
        working = copy.deepcopy(state_before)
        # Same rule as apply_block: transactions observe the block's own level.
        working["_current_level"] = level
        return working

    def evict(waiting: Waiting) -> None:
        if evict_out is not None:
            evict_out.append(waiting.hash_hex)

    working_state = fresh_state()
    for candidate in mempool:
        if len(selected) >= max_txs:
            break
        waiting = candidate if isinstance(candidate, Waiting) else Waiting.of(candidate)
        verdict, _why = chain.mempool_verdict(waiting.sender, waiting.nonce, waiting.fee, waiting.size,
                                              working_state, fees)
        if verdict == DROP:
            evict(waiting)
            continue
        if verdict != TAKE:
            continue                              # its nonce is ahead: it waits
        if waiting.size > room:
            break                                 # the block is full
        tx = waiting.transaction()
        if tx is None:
            evict(waiting)
            continue
        try:
            chain.apply_transaction(working_state, tx, baker=baker)
        except Exception:  # defensive: apply_transaction should not raise
            # The transaction is removed, and the state, which may be half
            # changed, is rebuilt from what the block holds so far.
            evict(waiting)
            working_state = fresh_state()
            for taken in selected:
                chain.apply_transaction(working_state, taken, baker=baker)
            continue
        if working_state["nonces"].get(tx.sender, 0) != tx.nonce + 1:
            # Not charged: its signature or its chain was refused before
            # anything changed. No block will take it.
            evict(waiting)
            continue
        selected.append(tx)
        room -= waiting.size

    # Build a draft header so we can call _apply_block_rewards against the
    # block (it uses block.header.level and block.header.proposer + commits).
    draft_header = BlockHeader(
        level=parent.header.level + 1,
        payload_round=round_,
        timestamp=int(time.time()),
        parent_hash=parent.hash_hex(),
        state_root="",   # placeholder, filled after reward application
        txs_root=txs_merkle_root_hex(selected),
        proposer=proposer_keypair.address,
        proposer_pubkey=proposer_pubkey_b58,
    )
    draft_block = Block(header=draft_header, transactions=selected, commits=[])
    # Self-commit: the proposer's own endorse-schema signature. It is
    # populated (with a placeholder signature) before computing rewards so
    # that the endorser set feeding _apply_block_rewards is known, then
    # re-signed over the final block hash below. In multi-validator
    # operation, additional endorsements gathered on the wire go into
    # block.endorsements (see docs/consensus-wire.md) — they arrive after
    # the header is signed and therefore cannot feed the state_root.
    draft_block.commits.append(f"{proposer_keypair.address}:placeholder")

    # Apply block rewards to working_state now that commits are known.
    _apply_block_rewards(working_state, draft_block)

    # Apply per-block governance tick (advance phases, settle bonds, apply
    # activations). This must run BEFORE state_root computation so that
    # the proposed state_root matches what apply_block will produce on
    # validation.
    from .chain import _apply_governance_tick, _release_matured_attestation_bonds
    _release_matured_attestation_bonds(working_state, draft_block.header.level)
    from .chain import _release_matured_delegation_bonds
    _release_matured_delegation_bonds(working_state, draft_block.header.level)
    _apply_governance_tick(working_state, draft_block.header.level)
    from .chain import _epoch_tick
    _epoch_tick(working_state, draft_block.header.level)

    # Now compute the final state_root over the post-reward state.
    draft_header.state_root = state_root_hex(working_state)
    draft_header.sign(proposer_keypair)
    # Sign the self-commit over the now-final block hash, using the same
    # ENDORSE message schema that wire endorsements use, so that a solo
    # proposer's block passes strict quorum verification identically to a
    # multi-validator block (one schema, one verifier: bft.verify_commits).
    # Phase E: only when the proposer alone holds the quorum (see above).
    from .bft import ConsensusMessage, MsgKind, commit_entry
    from .chain import consensus_validator_set
    vs = consensus_validator_set(state_before)
    if vs and not holds_quorum_alone(proposer_keypair.address, vs):
        draft_block.commits = []
        return draft_block
    self_endorse = ConsensusMessage(
        kind=MsgKind.ENDORSE,
        level=draft_header.level,
        round=draft_header.payload_round,
        block_hash=draft_header.hash_hex(),
        validator=proposer_keypair.address,
        validator_pubkey=proposer_pubkey_b58,
    )
    self_endorse.sign(proposer_keypair)
    draft_block.commits = [commit_entry(self_endorse)]
    return draft_block


@dataclass
class BakerConfig:
    keypair: KernKeypair
    pubkey_b58: str
    block_time: float = DEFAULT_BLOCK_TIME_S
    max_txs_per_block: int = DEFAULT_MAX_TXS_PER_BLOCK
