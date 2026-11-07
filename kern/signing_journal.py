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

    {"v": 2, "chain_id", "kind", "level", "round", "block_hash",
     "signed_valid_round", "locked_round", "locked_hash",
     "valid_round", "valid_hash", "valid_qc"}

The lock and valid fields are the engine's state for that level after the
step. `signed_valid_round` is the valid_round a PROPOSE message signs (-1
for votes): two proposals for one (level, round) that differ only there
are still two different signed messages. `valid_qc` is the
pre-endorsement certificate for (valid_round, valid_hash), or null
(review of 3f2b200, P1): without it, validators that all restart locked
on a block could no longer propose that block again with its proof, and
the level would stay stuck. It is written in the same synced record as
the ENDORSE that depends on it.

Format (review of 3f2b200, P2): the journal is a security boundary and
fails closed. Every record must carry the format version `v`, the chain's
`chain_id` and every field above with its type, and `signed_valid_round`
must be -1 for votes and lower than `round` for proposals. A journal
written in an older format, for another chain, or with any malformed
record is unreadable: the node moves it aside and does not sign at the
level in progress. There is no automatic migration, because the old
format did not record what a proposal signed.

Rules:

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

Block bodies (review of f24564b, P1). A lock names a block hash; after a
crash the node must still have that block, or a validator holding more
than two thirds of the stake would stay locked on a block it can neither
propose nor finalize. Every block the node is about to sign for (its own
proposal, or a validated proposal from another validator) is therefore
appended to a second file, `signing_journal.blocks.jsonl`, and synced to
disk BEFORE any signature over it. The node restores these blocks at
start. The block file only helps liveness: a missing or damaged line is
skipped, never trusted. Review of 84cbbcc: a final line cut by a crash is
removed at start, and every append starts on a fresh line, so a cut
record can never swallow the next block.

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
BLOCKS_FILE = "signing_journal.blocks.jsonl"

JOURNAL_VERSION = 2

_FIELDS = ("v", "chain_id", "kind", "level", "round", "block_hash", "signed_valid_round",
           "locked_round", "locked_hash", "valid_round", "valid_hash", "valid_qc")
_KINDS = ("propose", "preendorse", "endorse")


@dataclass
class LockRecord:
    """Lock and valid state of one level, as restored from the journal."""

    locked_round: int = -1
    locked_hash: Optional[str] = None
    valid_round: int = -1
    valid_hash: Optional[str] = None
    valid_qc: Optional[dict] = None   # pre-endorsement certificate for the valid round
    max_round: int = -1     # highest round in which this node signed anything


class JournalError(Exception):
    """The journal exists but cannot be read."""


class SigningJournal:
    def __init__(self, path: str, chain_id: Optional[str] = None):
        self.path = path
        self.chain_id = chain_id
        self.records: List[dict] = []
        # (kind, level, round) -> (block_hash, signed_valid_round) already signed
        self._signed: Dict[Tuple[str, int, int], Tuple[str, int]] = {}
        self._load()
        self.blocks_path = os.path.join(os.path.dirname(path) or ".", BLOCKS_FILE)
        self.block_records: List[dict] = []
        self._load_blocks()

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

    def _check_record(self, rec: object) -> None:
        if not isinstance(rec, dict):
            raise ValueError("record is not an object")
        if rec.get("v") != JOURNAL_VERSION:
            raise ValueError(f"journal format {rec.get('v', 1)!r}, expected {JOURNAL_VERSION}: "
                             "written by an older node, not trusted")
        for k in _FIELDS:
            if k not in rec:
                raise ValueError(f"record without {k}")
        if rec["chain_id"] != self.chain_id:
            raise ValueError(f"record for chain {rec['chain_id']!r}, not {self.chain_id!r}")

        def _int(k: str, low: int) -> int:
            v = rec[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < low:
                raise ValueError(f"record field {k} is not an integer >= {low}")
            return v

        _int("level", 0)
        round_ = _int("round", 0)
        svr = _int("signed_valid_round", -1)
        lr, vr = _int("locked_round", -1), _int("valid_round", -1)
        if rec["kind"] not in _KINDS:
            raise ValueError(f"record kind {rec['kind']!r} unknown")
        if not isinstance(rec["block_hash"], str) or not rec["block_hash"]:
            raise ValueError("record block_hash is not a string")
        if rec["kind"] == "propose" and svr >= round_:
            raise ValueError("proposal signed_valid_round not below its round")
        if rec["kind"] != "propose" and svr != -1:
            raise ValueError("vote with a signed_valid_round")
        for k, r in (("locked_hash", lr), ("valid_hash", vr)):
            h = rec[k]
            if (r < 0) != (h is None) or (h is not None and (not isinstance(h, str) or not h)):
                raise ValueError(f"record field {k} does not match its round")
        if rec["valid_qc"] is not None and not isinstance(rec["valid_qc"], dict):
            raise ValueError("record field valid_qc is not an object")

    def _index(self, rec: dict) -> None:
        self.records.append(rec)
        self._signed[(rec["kind"], rec["level"], rec["round"])] = (
            rec["block_hash"], rec["signed_valid_round"])

    # ------------------------------------------------------------- queries

    def conflicts(self, kind: str, level: int, round_: int, block_hash: str,
                  signed_valid_round: int = -1) -> bool:
        """True if this node already signed (kind, level, round) for another
        block, or (for PROPOSE) with another valid_round. Signing the same
        message again is allowed: it reproduces the same signature."""
        prev = self._signed.get((kind, level, round_))
        return prev is not None and prev != (block_hash, signed_valid_round)

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
            out.valid_qc = rec["valid_qc"]
            out.max_round = max(out.max_round, rec["round"])
        return out

    # ------------------------------------------------------------- writing

    def append(self, kind: str, level: int, round_: int, block_hash: str, *,
               locked_round: int, locked_hash: Optional[str],
               valid_round: int, valid_hash: Optional[str],
               signed_valid_round: int = -1,
               valid_qc: Optional[dict] = None) -> None:
        """Write one record and sync it to disk. Raises OSError on failure,
        ValueError if the record would not pass the format check; the
        caller must then not sign."""
        rec = {
            "v": JOURNAL_VERSION,
            "chain_id": self.chain_id,
            "kind": kind, "level": level, "round": round_, "block_hash": block_hash,
            "signed_valid_round": signed_valid_round,
            "locked_round": locked_round, "locked_hash": locked_hash,
            "valid_round": valid_round, "valid_hash": valid_hash,
            "valid_qc": valid_qc,
        }
        self._check_record(rec)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self._index(rec)

    # ------------------------------------------------------------- blocks

    def _load_blocks(self) -> None:
        if not os.path.exists(self.blocks_path):
            return
        try:
            with open(self.blocks_path, "rb") as f:
                raw = f.read()
        except OSError as e:
            LOG.warning("signing journal: cannot read kept blocks (%s)", e)
            return
        lines = raw.split(b"\n")
        cut = bool(lines and lines[-1])     # no final newline: a write cut by a crash
        for line in lines:
            if not line.strip():
                continue
            try:
                rec = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                LOG.warning("signing journal: skipping a damaged kept block")
                continue
            if (isinstance(rec, dict) and isinstance(rec.get("level"), int)
                    and isinstance(rec.get("block_hash"), str)
                    and isinstance(rec.get("block"), dict)):
                self.block_records.append(rec)
        if cut:
            LOG.warning("signing journal: dropping a kept block cut by a crash")
            self._rewrite(self.block_records, self.blocks_path)

    def _ends_cleanly(self, path: str) -> bool:
        """True if `path` is empty or ends with a newline."""
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() == 0:
                    return True
                f.seek(-1, os.SEEK_END)
                return f.read(1) == b"\n"
        except FileNotFoundError:
            return True

    def has_block(self, level: int, block_hash: str) -> bool:
        return any(r["level"] == level and r["block_hash"] == block_hash
                   for r in self.block_records)

    def record_block(self, level: int, block_hash: str, block: dict) -> None:
        """Keep a block body on disk (synced) before any signature over it.
        Raises OSError on failure; the caller must then not sign."""
        if self.has_block(level, block_hash):
            return
        rec = {"level": level, "block_hash": block_hash, "block": block}
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        if not self._ends_cleanly(self.blocks_path):
            line = "\n" + line             # never glue a record to a cut fragment
        with open(self.blocks_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self.block_records.append(rec)

    def blocks(self, level: int) -> List[dict]:
        """Kept block bodies of `level` (dicts, still to be validated)."""
        return [r["block"] for r in self.block_records if r["level"] == level]

    # ------------------------------------------------------------- compaction

    def compact(self, below_level: int) -> None:
        """Drop the records and kept blocks of levels strictly below
        `below_level` (already finalized). Each new file replaces the old
        one atomically."""
        keep_blocks = [r for r in self.block_records if r["level"] >= below_level]
        if len(keep_blocks) != len(self.block_records):
            self._rewrite(keep_blocks, self.blocks_path)
            self.block_records = keep_blocks
        keep = [r for r in self.records if r["level"] >= below_level]
        if len(keep) == len(self.records):
            return
        self._rewrite(keep)
        self.records = []
        self._signed = {}
        for r in keep:
            self._index(r)

    def _rewrite(self, records: List[dict], path: Optional[str] = None) -> None:
        path = path or self.path
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
