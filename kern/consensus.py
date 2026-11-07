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
from typing import List, Optional

from .block import Block, BlockHeader, txs_merkle_root_hex
from .chain import apply_block, state_root_hex
from .crypto import KernKeypair
from .transaction import Transaction


DEFAULT_BLOCK_TIME_S = 1.0
DEFAULT_MAX_TXS_PER_BLOCK = 5_000


def select_proposer(
    parent_hash_hex: str,
    validators: List[dict],
    round_: int,
) -> dict:
    """Deterministically select the proposer for a given round.

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
    mempool: List[Transaction],
    proposer_keypair: KernKeypair,
    proposer_pubkey_b58: str,
    state_before: dict,
    round_: int = 0,
    max_txs: int = DEFAULT_MAX_TXS_PER_BLOCK,
    evict_out: Optional[List[str]] = None,
) -> Block:
    """Construct, fill, and sign a new block proposing it as the next
    head. Transactions are taken in mempool order; ones that fail to
    apply are skipped (kept in the mempool for next round).

    Block rewards are applied to working_state BEFORE computing the
    state_root, so that the published state_root commits to the
    post-reward state — matching what apply_block will produce on
    validation.

    Phase B (audit 1, finding 7): a transaction can never stop block
    production. `apply_transaction` turns every handler exception into a
    rejection, and this loop additionally guards the call so that a defect
    anywhere in the application path discards the transaction instead of
    propagating out of the baker loop.

    If `evict_out` is given, the hashes of transactions that can NEVER
    become valid (bad signature, nonce already consumed) are appended to
    it so the caller can drop them from the mempool. Transactions that
    may become valid later (future nonce, insufficient balance) stay."""
    selected: List[Transaction] = []
    # Trial-apply candidate transactions; build a working state.
    import copy
    working_state = copy.deepcopy(state_before)
    # Same rule as apply_block: transactions observe the block's own level.
    working_state["_current_level"] = parent.header.level + 1
    from .chain import apply_transaction, _apply_block_rewards

    for tx in mempool[:max_txs]:
        before = copy.deepcopy(working_state)
        try:
            result = apply_transaction(working_state, tx, baker=proposer_keypair.address)
        except Exception:  # defensive: apply_transaction should not raise
            working_state = before
            if evict_out is not None:
                evict_out.append(tx.hash_hex())
            continue
        if not result.ok:
            # Discard this tx for this proposal; restore state.
            working_state = before
            if evict_out is not None and _never_valid(tx, before):
                evict_out.append(tx.hash_hex())
            continue
        selected.append(tx)

    # Build a draft header so we can call _apply_block_rewards against the
    # block (it uses block.header.level and block.header.proposer + commits).
    draft_header = BlockHeader(
        level=parent.header.level + 1,
        round=round_,
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
    from .bft import ConsensusMessage, MsgKind, commit_entry
    self_endorse = ConsensusMessage(
        kind=MsgKind.ENDORSE,
        level=draft_header.level,
        round=draft_header.round,
        block_hash=draft_header.hash_hex(),
        validator=proposer_keypair.address,
        validator_pubkey=proposer_pubkey_b58,
    )
    self_endorse.sign(proposer_keypair)
    draft_block.commits = [commit_entry(self_endorse)]
    return draft_block


def _never_valid(tx: Transaction, state: dict) -> bool:
    """True when `tx` cannot become valid in any later block: its signature
    is invalid, or its nonce is already consumed. Pure."""
    if not tx.verify_signature():
        return True
    return tx.nonce < state.get("nonces", {}).get(tx.sender, 0)


@dataclass
class BakerConfig:
    keypair: KernKeypair
    pubkey_b58: str
    block_time: float = DEFAULT_BLOCK_TIME_S
    max_txs_per_block: int = DEFAULT_MAX_TXS_PER_BLOCK
