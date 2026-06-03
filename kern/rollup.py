# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.rollup
===========

Optimistic Smart Rollup framework for Kern.

This module provides:

1. A `Rollup` data model — a separately-tracked EVM-compatible execution
   layer whose state commitments are posted to Kern.
2. A `Batch` type — a sequence of L2 transactions plus a state-root
   commitment, signed by the sequencer and posted to L1.
3. A fraud-proof framework — challengers can submit `FraudProof` objects
   that point to a specific batch and provide evidence that its committed
   state root does not result from honest execution.
4. A `Bridge` Skald contract template — implements deposit/withdraw
   semantics with declared invariants.
5. The challenge window — a configurable period (default 7 days) during
   which a posted batch can be challenged before its withdrawals become
   spendable on L1.

The reference implementation here is the *data model and control plane*.
The actual EVM execution layer would be a separate process (e.g., a
Reth/Geth-derived node) that consumes L2 transactions and produces the
state roots that the sequencer posts. This module provides the L1-side
view of that L2 — what Kern itself sees, validates, and settles.

Key design points
-----------------

- **Single sequencer per rollup, governance-rotatable.** Each rollup
  has a designated sequencer at any given time. The sequencer's role
  is to order L2 transactions and post batches. Sequencer rotation is
  a governance-amendable operation on the rollup's L1 contract.

- **Permissionless challengers.** Anyone can submit a fraud proof
  against any posted batch within the challenge window. A successful
  challenge slashes the sequencer's bond and reverts the disputed
  batch (and all batches built on top of it).

- **Optimistic by default.** A batch posted at time T becomes final
  at time T + challenge_window. Withdrawals through the bridge are
  only credited to L1 once the batch carrying them is final.

- **State roots, not full state.** Kern stores only the L2 state root,
  the batch metadata, and the L2 transaction hash list. Full L2 state
  reconstruction is the rollup operator's responsibility.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .crypto import (
    KernKeypair,
    blake2b256,
    pubkey_from_b58,
    signature_from_b58,
    verify,
    address_from_pubkey,
)


# ---------------------------------------------------------------------------
# Rollup descriptor
# ---------------------------------------------------------------------------

@dataclass
class Rollup:
    """Static descriptor of a registered rollup."""

    rollup_id: str                       # human-readable identifier (e.g. "kern-evm-1")
    bridge_address: str                  # kn1... address of the bridge contract on L1
    sequencer_address: str               # kn1... address authorized to post batches
    sequencer_pubkey: str                # kpk... pubkey for signature verification
    sequencer_bond: int                  # mukrn locked as fraud-proof collateral
    challenge_window_seconds: int = 7 * 24 * 3600  # 7 days
    genesis_state_root: str = "0" * 64
    # Versioning: which L2 protocol version this rollup runs (EVM-Shanghai,
    # EVM-Cancun, custom-WASM, etc.). Future amendments may upgrade this.
    l2_protocol: str = "evm-shanghai"

    def to_dict(self) -> dict:
        return {
            "rollup_id": self.rollup_id,
            "bridge_address": self.bridge_address,
            "sequencer_address": self.sequencer_address,
            "sequencer_pubkey": self.sequencer_pubkey,
            "sequencer_bond": self.sequencer_bond,
            "challenge_window_seconds": self.challenge_window_seconds,
            "genesis_state_root": self.genesis_state_root,
            "l2_protocol": self.l2_protocol,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Rollup":
        return cls(**d)


# ---------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------

class BatchStatus(str, Enum):
    PENDING = "pending"      # posted, within challenge window
    FINAL = "final"          # challenge window elapsed without successful challenge
    CHALLENGED = "challenged" # under active challenge
    REVERTED = "reverted"    # successfully challenged, removed from rollup history


@dataclass
class Batch:
    """A batch of L2 transactions, with the resulting state-root commitment."""

    rollup_id: str
    batch_index: int                          # 0, 1, 2, ...
    parent_state_root: str                    # state root before this batch
    state_root: str                           # state root after applying this batch
    tx_hashes: List[str]                      # hashes of the L2 transactions, in order
    tx_data_hash: str                         # blake2b of the concatenated raw tx data
    timestamp: int                            # unix epoch at which this was posted
    sequencer: str                            # kn1...
    sequencer_pubkey: str
    signature: Optional[str] = None
    # L1-side bookkeeping (set by the bridge contract on posting):
    posted_at_level: Optional[int] = None     # Kern level at which this was accepted
    status: BatchStatus = BatchStatus.PENDING

    def _signed_payload(self) -> bytes:
        d = {
            "rollup_id": self.rollup_id,
            "batch_index": self.batch_index,
            "parent_state_root": self.parent_state_root,
            "state_root": self.state_root,
            "tx_hashes": list(self.tx_hashes),
            "tx_data_hash": self.tx_data_hash,
            "timestamp": self.timestamp,
            "sequencer": self.sequencer,
            "sequencer_pubkey": self.sequencer_pubkey,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, kp: KernKeypair) -> None:
        if kp.address != self.sequencer:
            raise ValueError("keypair does not match sequencer")
        self.signature = kp.sign_b58(self._signed_payload())

    def verify_signature(self) -> bool:
        if self.signature is None:
            return False
        try:
            pk = pubkey_from_b58(self.sequencer_pubkey)
            if address_from_pubkey(pk) != self.sequencer:
                return False
            sig = signature_from_b58(self.signature)
            return verify(pk, self._signed_payload(), sig)
        except Exception:
            return False

    def hash(self) -> bytes:
        return blake2b256(self._signed_payload(), key=b"kern.batch")

    def hash_hex(self) -> str:
        return self.hash().hex()

    def to_dict(self) -> dict:
        return {
            "rollup_id": self.rollup_id,
            "batch_index": self.batch_index,
            "parent_state_root": self.parent_state_root,
            "state_root": self.state_root,
            "tx_hashes": list(self.tx_hashes),
            "tx_data_hash": self.tx_data_hash,
            "timestamp": self.timestamp,
            "sequencer": self.sequencer,
            "sequencer_pubkey": self.sequencer_pubkey,
            "signature": self.signature,
            "posted_at_level": self.posted_at_level,
            "status": self.status.value,
        }


# ---------------------------------------------------------------------------
# Fraud proofs
# ---------------------------------------------------------------------------

@dataclass
class FraudProof:
    """Evidence that a posted batch's state root is incorrect.

    A fraud proof identifies a specific batch and provides a witness that
    re-executing its transactions from `parent_state_root` does not yield
    the claimed `state_root`.

    The witness format depends on the L2 protocol. For EVM rollups, it is
    typically an interactive bisection over execution steps (à la
    Arbitrum / Optimism) — the challenger and the rollup operator narrow
    down to a single VM step that can be verified on L1.

    In this reference implementation, we model only the L1-side state
    machine of the challenge process. A real implementation would call
    out to an EVM single-step verifier as part of `verify()`.
    """

    rollup_id: str
    batch_index: int
    challenger: str                            # kn1...
    expected_state_root: str                   # what the correct execution would produce
    claimed_state_root: str                    # what the batch claimed
    witness_data: dict                         # protocol-specific evidence
    # For demonstration, the witness here includes a `step_proof` field that
    # a real verifier would consume. We treat the proof as valid if it
    # asserts an expected_state_root different from claimed_state_root.

    def verify_shape(self) -> Tuple[bool, str]:
        if self.expected_state_root == self.claimed_state_root:
            return False, "expected and claimed state roots agree — not a fraud"
        if "step_proof" not in self.witness_data:
            return False, "witness missing step_proof field"
        return True, "ok"


# ---------------------------------------------------------------------------
# Rollup state machine
# ---------------------------------------------------------------------------

@dataclass
class RollupState:
    """L1-side state of one rollup."""

    rollup: Rollup
    batches: List[Batch] = field(default_factory=list)
    # Active challenge per batch index (only one challenge in flight per batch).
    active_challenges: Dict[int, FraudProof] = field(default_factory=dict)
    # Pending withdrawals: each withdrawal references the batch that authorized
    # it; once that batch is final, the withdrawal can be claimed on L1.
    pending_withdrawals: Dict[int, List[dict]] = field(default_factory=dict)

    # ------------------------------------------------------------ posting

    def post_batch(self, batch: Batch, current_level: int, now: int) -> Tuple[bool, str]:
        """Accept a new batch from the sequencer."""
        if batch.rollup_id != self.rollup.rollup_id:
            return False, "rollup_id mismatch"
        if batch.sequencer != self.rollup.sequencer_address:
            return False, "batch not signed by current sequencer"
        if not batch.verify_signature():
            return False, "invalid sequencer signature"
        if batch.batch_index != self.next_batch_index():
            return False, f"out-of-order batch: expected {self.next_batch_index()}"
        if batch.parent_state_root != self.current_state_root():
            return False, "parent_state_root does not match current head"
        if batch.timestamp > now + 300 or batch.timestamp < now - 300:
            return False, "batch timestamp outside acceptable window"

        batch.posted_at_level = current_level
        batch.status = BatchStatus.PENDING
        self.batches.append(batch)
        return True, "ok"

    def next_batch_index(self) -> int:
        # Skip reverted batches when computing next index.
        for i in range(len(self.batches) - 1, -1, -1):
            if self.batches[i].status != BatchStatus.REVERTED:
                return self.batches[i].batch_index + 1
        return 0

    def current_state_root(self) -> str:
        for b in reversed(self.batches):
            if b.status != BatchStatus.REVERTED:
                return b.state_root
        return self.rollup.genesis_state_root

    # ------------------------------------------------------------ challenges

    def open_challenge(self, proof: FraudProof, now: int) -> Tuple[bool, str]:
        if proof.rollup_id != self.rollup.rollup_id:
            return False, "rollup_id mismatch"
        if proof.batch_index >= len(self.batches):
            return False, "no such batch"
        batch = self.batches[proof.batch_index]
        if batch.status not in (BatchStatus.PENDING,):
            return False, f"batch is not challengeable (status={batch.status.value})"
        if now > batch.timestamp + self.rollup.challenge_window_seconds:
            return False, "challenge window expired"
        ok, reason = proof.verify_shape()
        if not ok:
            return False, f"proof rejected: {reason}"
        if proof.claimed_state_root != batch.state_root:
            return False, "claimed state root in proof does not match batch"
        self.active_challenges[proof.batch_index] = proof
        batch.status = BatchStatus.CHALLENGED
        return True, "ok"

    def resolve_challenge_for_challenger(self, batch_index: int) -> Tuple[bool, str]:
        """The challenger wins. Revert this batch and every batch on top of it.

        In a real implementation, `verify()` would run a single-step EVM
        execution to decide the winner. Here we assume the result has been
        determined by an external verifier."""
        if batch_index not in self.active_challenges:
            return False, "no active challenge"
        # Revert this batch and all subsequent ones.
        for b in self.batches[batch_index:]:
            if b.status != BatchStatus.REVERTED:
                b.status = BatchStatus.REVERTED
                self.pending_withdrawals.pop(b.batch_index, None)
        del self.active_challenges[batch_index]
        return True, "ok"

    def resolve_challenge_for_sequencer(self, batch_index: int) -> Tuple[bool, str]:
        """The sequencer wins the challenge: batch returns to pending status
        and the challenger's bond is slashed."""
        if batch_index not in self.active_challenges:
            return False, "no active challenge"
        self.batches[batch_index].status = BatchStatus.PENDING
        del self.active_challenges[batch_index]
        return True, "ok"

    # ------------------------------------------------------------ finality

    def finalize_pending(self, now: int) -> List[int]:
        """Mark as final all pending batches whose challenge window has
        elapsed without a successful challenge. Returns the indices of
        newly-finalized batches."""
        finalized: List[int] = []
        for b in self.batches:
            if b.status == BatchStatus.PENDING and now > b.timestamp + self.rollup.challenge_window_seconds:
                b.status = BatchStatus.FINAL
                finalized.append(b.batch_index)
        return finalized

    # ------------------------------------------------------------ withdrawals

    def queue_withdrawal(self, batch_index: int, recipient: str, amount: int) -> None:
        """Called when an L2 batch includes a withdrawal-to-L1 operation."""
        self.pending_withdrawals.setdefault(batch_index, []).append({
            "recipient": recipient,
            "amount": amount,
        })

    def claimable_withdrawals(self) -> List[dict]:
        """Return all withdrawals associated with finalized batches."""
        out: List[dict] = []
        for b in self.batches:
            if b.status == BatchStatus.FINAL:
                out.extend(self.pending_withdrawals.get(b.batch_index, []))
        return out


# ---------------------------------------------------------------------------
# Bridge Skald contract template
# ---------------------------------------------------------------------------

BRIDGE_SKALD = """
// bridge.skald — L1-side bridge contract for an EVM rollup.
//
// Manages the locked-on-L1 collateral that backs the rollup's L2 supply.
// Deposits credit the rollup's account. Withdrawals are honored only
// for batches that have been marked final by the rollup state machine.

contract Bridge {
    storage {
        rollup_id: string,
        sequencer: address,
        total_deposited: int,
        total_withdrawn: int,
        challenge_window: int,
    }

    // Invariant: the bridge cannot pay out more than was deposited.
    invariant solvent {
        total_deposited >= total_withdrawn
    }

    // Anyone can deposit value into the rollup; it will be credited on L2
    // by the sequencer at the next batch.
    entry deposit() {
        require amount > 0 with "must attach value";
        total_deposited = total_deposited + amount;
    }

    // Withdrawal is invoked by the rollup state machine on behalf of a user
    // once their L2 withdrawal batch has finalized.
    // `n` is the amount to release; the actual outbound transfer is emitted
    // as a side effect by the runtime.
    entry release(n: int) {
        require sender == sequencer with "only sequencer can release";
        require n > 0 with "amount must be positive";
        require total_deposited - total_withdrawn >= n with "insufficient collateral";
        total_withdrawn = total_withdrawn + n;
    }

    view solvency_margin() -> int {
        total_deposited - total_withdrawn
    }
}
"""


def get_bridge_skald_source() -> str:
    """Return the source code of the standard bridge contract."""
    return BRIDGE_SKALD
