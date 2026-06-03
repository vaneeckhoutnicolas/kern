# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.forced_inclusion
=====================

Censorship-resistance for Kern rollups.

The threat
----------

A rollup sequencer chooses which L2 transactions to include in batches.
A malicious or compromised sequencer could refuse to include transactions
from a particular user or set of users, effectively censoring them off
the rollup.

The mechanism
-------------

Kern's L1 hosts a **Forced Inclusion Mailbox** for each rollup. Any user
can post a transaction directly to L1, addressed to the rollup. Once
posted:

1. The sequencer has a fixed window (default: 6 L1 hours, i.e., ~21 600
   blocks at 1 s/block) to include the transaction in a batch.
2. If the sequencer fails to include it by the deadline, anyone can:
   (a) call `prove_omission` on L1 with the offending mailbox entry, OR
   (b) submit a "self-include" batch that consists solely of the omitted
       forced-inclusion entries, which the rollup must accept.

The sequencer's bond is slashed for each unjustified omission.

What this guarantees
--------------------

- **Any user can transact eventually.** A sequencer can delay your tx
  for up to the deadline, but no longer. After that, you (or anyone else)
  can force its inclusion.
- **Eventual fairness.** The forced inclusion path is permissionless to
  trigger — it doesn't require coordination with the sequencer or anyone
  else.
- **Economic deterrence.** Repeated forced inclusions slash the
  sequencer's bond; long-running censorship is unprofitable.

What this doesn't guarantee
---------------------------

- **Real-time fairness.** Forced inclusion has a delay (the deadline
  window). Time-sensitive operations may still be censored within that
  window.
- **Order fairness.** The sequencer can still order transactions
  adversarially within a batch.
- **Inclusion of malformed transactions.** Forced-include transactions
  must still be syntactically valid; the rollup will discard invalid
  ones (but the sequencer is not slashed for those).

Data model
----------

A `MailboxEntry` is a posted transaction awaiting inclusion. It carries
the L1 timestamp / level of posting, which is what the deadline is
measured against. Each entry is identified by its hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# Default deadline: 6 L1 hours at 1s block time.
DEFAULT_INCLUSION_DEADLINE_BLOCKS = 6 * 3600  # 21 600 L1 blocks


class MailboxStatus(str, Enum):
    PENDING = "pending"     # awaiting inclusion in a batch
    INCLUDED = "included"   # sequencer included it before the deadline
    OMITTED = "omitted"     # deadline passed without inclusion
    FORCE_INCLUDED = "force_included"  # self-included via the forced path


@dataclass
class MailboxEntry:
    """A single L2 transaction posted to the L1 mailbox awaiting inclusion."""

    rollup_id: str
    sender: str                          # kn1... address that posted
    l2_tx_payload: str                   # opaque hex (the L2 transaction bytes)
    posted_at_l1_level: int              # L1 level at which it was posted
    posted_at_l1_timestamp: int
    deadline_blocks: int = DEFAULT_INCLUSION_DEADLINE_BLOCKS
    status: MailboxStatus = MailboxStatus.PENDING
    included_in_batch: Optional[int] = None  # batch index, if INCLUDED

    def hash(self) -> bytes:
        d = {
            "rollup_id": self.rollup_id,
            "sender": self.sender,
            "l2_tx_payload": self.l2_tx_payload,
            "posted_at_l1_level": self.posted_at_l1_level,
            "posted_at_l1_timestamp": self.posted_at_l1_timestamp,
            "deadline_blocks": self.deadline_blocks,
        }
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.blake2b(canonical, digest_size=32, key=b"kern.mailbox").digest()

    def hash_hex(self) -> str:
        return self.hash().hex()

    def deadline_level(self) -> int:
        return self.posted_at_l1_level + self.deadline_blocks

    def is_overdue(self, current_l1_level: int) -> bool:
        return current_l1_level > self.deadline_level()

    def to_dict(self) -> dict:
        return {
            "rollup_id": self.rollup_id,
            "sender": self.sender,
            "l2_tx_payload": self.l2_tx_payload,
            "posted_at_l1_level": self.posted_at_l1_level,
            "posted_at_l1_timestamp": self.posted_at_l1_timestamp,
            "deadline_blocks": self.deadline_blocks,
            "status": self.status.value,
            "included_in_batch": self.included_in_batch,
            "hash": self.hash_hex(),
        }


@dataclass
class Mailbox:
    """The per-rollup forced-inclusion mailbox, held on L1.

    The mailbox is a Skald contract conceptually; this class is the
    Python state-machine model of it. In the running node, the mailbox
    state is part of the rollup's L1 account.
    """

    rollup_id: str
    entries: Dict[str, MailboxEntry] = field(default_factory=dict)
    # Total slashings inflicted (in mukrn) for record-keeping.
    total_slashed: int = 0

    # ------------------------------------------------------------ public ops

    def post(self, entry: MailboxEntry) -> Tuple[bool, str]:
        """Anyone can post a transaction to the mailbox."""
        if entry.rollup_id != self.rollup_id:
            return False, "rollup_id mismatch"
        h = entry.hash_hex()
        if h in self.entries:
            return False, "duplicate entry"
        self.entries[h] = entry
        return True, "ok"

    def mark_included(self, entry_hash: str, batch_index: int) -> Tuple[bool, str]:
        """The sequencer or the L1-side rollup state machine calls this when
        an L2 batch includes the corresponding transaction."""
        e = self.entries.get(entry_hash)
        if e is None:
            return False, "no such mailbox entry"
        if e.status != MailboxStatus.PENDING:
            return False, f"entry not pending (status={e.status.value})"
        e.status = MailboxStatus.INCLUDED
        e.included_in_batch = batch_index
        return True, "ok"

    def overdue_entries(self, current_l1_level: int) -> List[MailboxEntry]:
        """All entries that are PENDING and past their deadline."""
        return [e for e in self.entries.values()
                if e.status == MailboxStatus.PENDING and e.is_overdue(current_l1_level)]

    def prove_omission(
        self,
        entry_hash: str,
        current_l1_level: int,
        sequencer_bond: int,
        slash_pct: int = 10,
    ) -> Tuple[bool, str, int]:
        """Mark an overdue entry as OMITTED and slash the sequencer.

        Returns (ok, reason, slashed_amount). Anyone can call this; the
        caller becomes the bounty recipient (handled by the rollup state
        machine; this function only computes the amount).
        """
        e = self.entries.get(entry_hash)
        if e is None:
            return False, "no such mailbox entry", 0
        if e.status != MailboxStatus.PENDING:
            return False, f"entry not pending (status={e.status.value})", 0
        if not e.is_overdue(current_l1_level):
            return False, "deadline not yet reached", 0

        e.status = MailboxStatus.OMITTED
        slashed = max(1, sequencer_bond * slash_pct // 100)
        self.total_slashed += slashed
        return True, "ok", slashed

    def force_include(
        self,
        entry_hashes: List[str],
        current_l1_level: int,
    ) -> Tuple[bool, str, List[MailboxEntry]]:
        """Build a self-include batch containing the listed overdue entries.

        The rollup state machine accepts this batch unconditionally
        (no sequencer signature required), and the L2 execution layer
        re-executes the included transactions in order.

        Returns (ok, reason, accepted_entries).
        """
        accepted: List[MailboxEntry] = []
        for h in entry_hashes:
            e = self.entries.get(h)
            if e is None:
                return False, f"unknown entry {h[:12]}", []
            if e.status != MailboxStatus.PENDING:
                return False, f"entry {h[:12]} not pending ({e.status.value})", []
            if not e.is_overdue(current_l1_level):
                return False, f"entry {h[:12]} not yet overdue", []
            accepted.append(e)

        # Mark them all as force-included.
        for e in accepted:
            e.status = MailboxStatus.FORCE_INCLUDED

        return True, "ok", accepted

    # ------------------------------------------------------------ queries

    def pending(self) -> List[MailboxEntry]:
        return [e for e in self.entries.values() if e.status == MailboxStatus.PENDING]

    def included(self) -> List[MailboxEntry]:
        return [e for e in self.entries.values() if e.status == MailboxStatus.INCLUDED]

    def omitted(self) -> List[MailboxEntry]:
        return [e for e in self.entries.values() if e.status == MailboxStatus.OMITTED]


# ---------------------------------------------------------------------------
# Skald contract template for the mailbox
# ---------------------------------------------------------------------------

MAILBOX_SKALD = """
// mailbox.skald — L1-side forced-inclusion mailbox for a rollup.
//
// Tracks total bond posted by the sequencer, the inclusion deadline
// parameters, and the count of slashed omissions. The actual entry
// records are managed by the L1 runtime (see kern.forced_inclusion).

contract Mailbox {
    storage {
        rollup_id: string,
        sequencer: address,
        sequencer_bond: int,
        deadline_blocks: int,
        slash_pct: int,
        total_slashed: int,
        omission_count: int,
    }

    // Bond must be strictly positive and not exceeded by cumulative slashes.
    invariant solvent_bond {
        sequencer_bond >= total_slashed
    }

    invariant valid_slash_pct {
        slash_pct >= 1
    }

    entry post_bond(n: int) {
        require sender == sequencer with "only sequencer";
        require n > 0 with "bond must be positive";
        sequencer_bond = sequencer_bond + n;
    }

    entry record_omission(amount: int) {
        require amount > 0 with "amount must be positive";
        require sequencer_bond - total_slashed >= amount with "insufficient bond";
        total_slashed = total_slashed + amount;
        omission_count = omission_count + 1;
    }

    view remaining_bond() -> int {
        sequencer_bond - total_slashed
    }
}
"""


def get_mailbox_skald_source() -> str:
    return MAILBOX_SKALD
