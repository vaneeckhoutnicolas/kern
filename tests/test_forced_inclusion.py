# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.forced_inclusion — mailbox, deadlines, slashing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.forced_inclusion import (
    DEFAULT_INCLUSION_DEADLINE_BLOCKS,
    MAILBOX_SKALD,
    Mailbox,
    MailboxEntry,
    MailboxStatus,
    get_mailbox_skald_source,
)


def _entry(rollup_id="kern-evm-1", sender="kn1aaa", posted_at=100, deadline=10):
    return MailboxEntry(
        rollup_id=rollup_id,
        sender=sender,
        l2_tx_payload="deadbeef",
        posted_at_l1_level=posted_at,
        posted_at_l1_timestamp=1779394000,
        deadline_blocks=deadline,
    )


def test_post_entry_to_mailbox():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry()
    ok, _ = mb.post(e)
    assert ok
    assert len(mb.pending()) == 1


def test_post_duplicate_rejected():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry()
    mb.post(e)
    ok, reason = mb.post(e)
    assert not ok
    assert "duplicate" in reason


def test_post_wrong_rollup_rejected():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(rollup_id="kern-evm-2")
    ok, reason = mb.post(e)
    assert not ok
    assert "rollup_id mismatch" in reason


def test_sequencer_includes_before_deadline():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry()
    mb.post(e)
    h = e.hash_hex()
    ok, _ = mb.mark_included(h, batch_index=5)
    assert ok
    assert e.status == MailboxStatus.INCLUDED
    assert e.included_in_batch == 5
    assert len(mb.included()) == 1
    assert len(mb.pending()) == 0


def test_overdue_detection():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(posted_at=100, deadline=10)  # deadline at level 110
    mb.post(e)
    # Not overdue yet at level 105
    assert mb.overdue_entries(current_l1_level=105) == []
    # Overdue at level 111 (level > 110)
    overdue = mb.overdue_entries(current_l1_level=111)
    assert len(overdue) == 1


def test_prove_omission_slashes_sequencer():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(posted_at=100, deadline=10)
    mb.post(e)
    ok, reason, slashed = mb.prove_omission(
        entry_hash=e.hash_hex(),
        current_l1_level=200,           # well past deadline
        sequencer_bond=1_000_000_000,
        slash_pct=10,
    )
    assert ok, reason
    assert slashed == 100_000_000  # 10% of bond
    assert e.status == MailboxStatus.OMITTED
    assert mb.total_slashed == slashed


def test_cannot_prove_omission_before_deadline():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(posted_at=100, deadline=10)
    mb.post(e)
    ok, reason, _ = mb.prove_omission(
        entry_hash=e.hash_hex(),
        current_l1_level=105,           # still within deadline
        sequencer_bond=1_000_000_000,
    )
    assert not ok
    assert "deadline not yet reached" in reason
    assert e.status == MailboxStatus.PENDING


def test_cannot_prove_omission_of_included_entry():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(posted_at=100, deadline=10)
    mb.post(e)
    mb.mark_included(e.hash_hex(), batch_index=1)
    ok, reason, _ = mb.prove_omission(
        entry_hash=e.hash_hex(),
        current_l1_level=200,
        sequencer_bond=1_000_000_000,
    )
    assert not ok
    assert "not pending" in reason


def test_force_include_overdue_entries():
    mb = Mailbox(rollup_id="kern-evm-1")
    e1 = _entry(posted_at=100, deadline=10, sender="kn1aaa")
    e2 = _entry(posted_at=101, deadline=10, sender="kn1bbb")
    mb.post(e1)
    mb.post(e2)

    ok, reason, accepted = mb.force_include(
        entry_hashes=[e1.hash_hex(), e2.hash_hex()],
        current_l1_level=200,
    )
    assert ok, reason
    assert len(accepted) == 2
    assert e1.status == MailboxStatus.FORCE_INCLUDED
    assert e2.status == MailboxStatus.FORCE_INCLUDED


def test_force_include_rejects_not_yet_overdue():
    mb = Mailbox(rollup_id="kern-evm-1")
    e = _entry(posted_at=100, deadline=10)
    mb.post(e)
    ok, reason, _ = mb.force_include(
        entry_hashes=[e.hash_hex()],
        current_l1_level=105,           # not overdue
    )
    assert not ok
    assert "not yet overdue" in reason


def test_force_include_rejects_unknown_hash():
    mb = Mailbox(rollup_id="kern-evm-1")
    ok, reason, _ = mb.force_include(
        entry_hashes=["00" * 32],
        current_l1_level=200,
    )
    assert not ok
    assert "unknown entry" in reason


def test_mailbox_skald_typechecks():
    """The mailbox Skald template must itself type-check."""
    from kern.skald.typecheck import type_check
    errors = type_check(get_mailbox_skald_source())
    assert errors == [], f"Mailbox contract has type errors: {errors}"


def test_mailbox_skald_originates():
    """The mailbox Skald template must originate cleanly with sensible initial state."""
    from kern.skald import interpret_origination
    storage = interpret_origination(get_mailbox_skald_source(), {
        "rollup_id": "kern-evm-1",
        "sequencer": "kn1" + "a" * 33,
        "sequencer_bond": 1_000_000_000,
        "deadline_blocks": DEFAULT_INCLUSION_DEADLINE_BLOCKS,
        "slash_pct": 10,
        "total_slashed": 0,
        "omission_count": 0,
    })
    assert storage["sequencer_bond"] == 1_000_000_000
    assert storage["slash_pct"] == 10


def test_mailbox_slash_invariant_enforced():
    """Trying to record_omission beyond available bond is rejected."""
    from kern.skald import interpret_call, interpret_origination, SkaldError
    src = get_mailbox_skald_source()
    storage = interpret_origination(src, {
        "rollup_id": "r1",
        "sequencer": "kn1" + "s" * 33,
        "sequencer_bond": 100,
        "deadline_blocks": 10,
        "slash_pct": 10,
        "total_slashed": 0,
        "omission_count": 0,
    })

    # Slash 50 → ok
    storage = interpret_call(
        src, storage, "record_omission", {"amount": 50},
        sender="kn1" + "x" * 33, amount=0, self_addr="kn1" + "c" * 33,
    )
    assert storage["total_slashed"] == 50

    # Slash 60 more → would exceed bond, require fails
    with pytest.raises(SkaldError, match="insufficient bond"):
        interpret_call(
            src, storage, "record_omission", {"amount": 60},
            sender="kn1" + "x" * 33, amount=0, self_addr="kn1" + "c" * 33,
        )


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} forced-inclusion tests passed.")
