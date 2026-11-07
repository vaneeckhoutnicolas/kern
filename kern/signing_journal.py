# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.signing_journal
--------------------

Persistent signing journal of a validator (Phase E, E1; design in
docs/consensus-locking.md section 9.2).

Before Phase E the whole consensus state of a validator lived in memory:
a validator that endorsed block B, crashed before B was final and
restarted had lost its lock and its record of what it had signed. It
could then sign a conflicting vote, which reintroduces exactly what the
lock prevents.

The journal is an append-only file of JSON lines, one record per
consensus message the node is ABOUT to sign:

    {"chain_id", "kind", "level", "round", "block_hash",
     "locked_round", "locked_hash", "valid_round", "valid_hash"}

The lock and valid fields are the engine's state for that level after the
step. Rules:

- The record is written, flushed and synced to disk (fsync) BEFORE the
  signature is produced, so no signature can exist without its record.
- At start the node replays the journal before signing anything: it
  restores the lock and valid state of the level it is working on, and
  the journal refuses any (kind, level, round) already recorded for a
  different block.
- A final line without its newline is a record whose write was cut by a
  crash; its signature was never produced, so the line is ignored. Any
  other unreadable line makes the whole journal unreadable.
- Records below the finalized height can be compacted away.

The journal only protects against a crash. It is not a substitute for
running one signing process per validator key.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger("kern.signing_journal")

JOURNAL_FILE = "signing_journal.jsonl"

_FIELDS = ("kind", "level", "round", "block_hash",
           "locked_round", "locked_hash", "valid_round", "valid_hash")


@dataclass
class LockRecord:
    """Lock and valid state of one level, as restored from the journal."""

    locked_round: int = -1
    locked_hash: Optional[str] = None
    valid_round: int = -1
    valid_hash: Optional[str] = None
    max_round: int = -1     # highest round in which this node signed anything


class JournalError(Exception):
    """The journal exists but cannot be read."""


class SigningJournal:
    def __init__(self, path: str, chain_id: Optional[str] = None):
        self.path = path
        self.chain_id = chain_id
        self.records: List[dict] = []
        # (kind, level, round) -> block_hash already signed
        self._signed: Dict[Tuple[str, int, int], str] = {}
        self._load()

    # ------------------------------------------------------------- loading

    @classmethod
    def open_in(cls, data_dir: str, chain_id: Optional[str] = None) -> "SigningJournal":
        return cls(os.path.join(data_dir, JOURNAL_FILE), chain_id)

    @property
    def existed(self) -> bool:
        return os.path.exists(self.path)

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
        except OSError as e:
            raise JournalError(f"cannot read {self.path}: {e}") from e
        lines = raw.split(b"\n")
        # The last element is b"" when the file ends with a newline; any
        # other value is a record cut by a crash before its signature.
        complete, tail = lines[:-1], lines[-1]
        if tail:
            LOG.warning("signing journal: ignoring an incomplete final record")
        for n, line in enumerate(complete, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line.decode("utf-8"))
                self._check_record(rec)
            except (ValueError, UnicodeDecodeError) as e:
                raise JournalError(f"{self.path}, line {n}: {e}") from e
            self._index(rec)
        if tail:
            # Drop the cut record from the file, so later appends start on
            # a fresh line.
            self._rewrite(self.records)

    @staticmethod
    def _check_record(rec: object) -> None:
        if not isinstance(rec, dict):
            raise ValueError("record is not an object")
        for k in _FIELDS:
            if k not in rec:
                raise ValueError(f"record without {k}")
        for k in ("level", "round", "locked_round", "valid_round"):
            v = rec[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < -1:
                raise ValueError(f"record field {k} is not an integer")
        if not isinstance(rec["kind"], str) or not isinstance(rec["block_hash"], str):
            raise ValueError("record kind or block_hash is not a string")

    def _index(self, rec: dict) -> None:
        self.records.append(rec)
        self._signed[(rec["kind"], rec["level"], rec["round"])] = rec["block_hash"]

    # ------------------------------------------------------------- queries

    def conflicts(self, kind: str, level: int, round_: int, block_hash: str) -> bool:
        """True if this node already signed (kind, level, round) for another
        block. Signing the same message again is allowed: it reproduces the
        same signature."""
        prev = self._signed.get((kind, level, round_))
        return prev is not None and prev != block_hash

    def restore(self, level: int) -> LockRecord:
        """Lock and valid state of `level` after the last recorded step."""
        out = LockRecord()
        for rec in self.records:
            if rec["level"] != level:
                continue
            out.locked_round = rec["locked_round"]
            out.locked_hash = rec["locked_hash"]
            out.valid_round = rec["valid_round"]
            out.valid_hash = rec["valid_hash"]
            out.max_round = max(out.max_round, rec["round"])
        return out

    # ------------------------------------------------------------- writing

    def append(self, kind: str, level: int, round_: int, block_hash: str, *,
               locked_round: int, locked_hash: Optional[str],
               valid_round: int, valid_hash: Optional[str]) -> None:
        """Write one record and sync it to disk. Raises OSError on failure;
        the caller must then not sign."""
        rec = {
            "chain_id": self.chain_id,
            "kind": kind, "level": level, "round": round_, "block_hash": block_hash,
            "locked_round": locked_round, "locked_hash": locked_hash,
            "valid_round": valid_round, "valid_hash": valid_hash,
        }
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self._index(rec)

    def compact(self, below_level: int) -> None:
        """Drop the records of levels strictly below `below_level` (already
        finalized). The new file replaces the old one atomically."""
        keep = [r for r in self.records if r["level"] >= below_level]
        if len(keep) == len(self.records):
            return
        self._rewrite(keep)
        self.records = []
        self._signed = {}
        for r in keep:
            self._index(r)

    def _rewrite(self, records: List[dict]) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
