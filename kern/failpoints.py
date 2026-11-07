# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.failpoints
---------------

Crash injection for tests (review of f24564b, P1). A failpoint is a named
place in the node where a test can make the process die at once, with no
cleanup, exactly as a power cut or a kill -9 would.

Disabled unless the environment variable KERN_FAILPOINT names the point.
KERN_FAILPOINT_SKIP (default 0) lets that many hits pass first, so a test
can crash in the middle of a running chain. KERN_FAILPOINT_LEVEL, when set,
limits the point to hits at that block level, so that several processes
can be made to die at the same level. The process exits with code
FAILPOINT_EXIT_CODE through os._exit: no finally blocks, no snapshot, no
buffered write that was not already synced.

Points used by the node:
    after_self_commit         own self-commit and lock synced to the journal
    after_proposal_signed     PROPOSE signed, not yet broadcast
    after_proposal_broadcast  proposal broadcast, block not yet finalized
    before_endorse_broadcast  own ENDORSE signed and journaled, not yet sent
"""

from __future__ import annotations

import os
import sys
from typing import Optional

FAILPOINT_EXIT_CODE = 99

_hits: dict = {}


def hit(name: str, level: Optional[int] = None) -> None:
    if os.environ.get("KERN_FAILPOINT") != name:
        return
    want = os.environ.get("KERN_FAILPOINT_LEVEL")
    if want is not None and (level is None or str(level) != want):
        return
    seen = _hits.get(name, 0)
    _hits[name] = seen + 1
    try:
        skip = int(os.environ.get("KERN_FAILPOINT_SKIP", "0"))
    except ValueError:
        skip = 0
    if seen >= skip:
        sys.stderr.write(f"failpoint {name}: exiting\n")
        sys.stderr.flush()
        os._exit(FAILPOINT_EXIT_CODE)
