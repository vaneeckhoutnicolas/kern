# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for mempool admission bounds and RPC rate limiting.

These cover the post-v1.1-rc hardening of the two transaction intake
surfaces that an external review flagged as unbounded: the mempool
(per-sender and global caps) and the write-facing RPC endpoint
(`/chain/inject_transaction`, a per-client rate limiter).
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.rpc import RateLimiter
from kern.storage import Storage
from kern.transaction import make_transfer


def _storage(**kw) -> Storage:
    return Storage(tempfile.mkdtemp(), **kw)


def test_per_sender_cap_rejects_flood():
    alice = KernKeypair.generate()
    bob = KernKeypair.generate()
    st = _storage(max_mempool_per_sender=3)

    admitted = [
        st.add_to_mempool(make_transfer(alice, recipient=bob.address, amount=1, nonce=i))
        for i in range(5)
    ]
    # First three from alice admitted, the rest rejected.
    assert admitted == [True, True, True, False, False]
    assert st._mempool_count_for_sender(alice.address) == 3

    # A different sender is unaffected by alice's flood.
    assert st.add_to_mempool(
        make_transfer(bob, recipient=alice.address, amount=1, nonce=0)
    ) is True


def test_global_cap_rejects_when_full():
    st = _storage(max_mempool_size=2)
    senders = [KernKeypair.generate() for _ in range(3)]
    dest = KernKeypair.generate().address
    results = [
        st.add_to_mempool(make_transfer(s, recipient=dest, amount=1, nonce=0))
        for s in senders
    ]
    assert results == [True, True, False]
    assert st.mempool_size() == 2


def test_resubmitting_same_tx_does_not_consume_budget():
    alice = KernKeypair.generate()
    dest = KernKeypair.generate().address
    st = _storage(max_mempool_per_sender=1)
    tx = make_transfer(alice, recipient=dest, amount=1, nonce=0)

    assert st.add_to_mempool(tx) is True
    # Same hash again: a re-insert, not a new slot -> still allowed.
    assert st.add_to_mempool(tx) is True
    assert st.mempool_size() == 1
    # But a genuinely new tx from alice now exceeds her cap.
    other = make_transfer(alice, recipient=dest, amount=1, nonce=1)
    assert st.add_to_mempool(other) is False


def test_rate_limiter_window():
    rl = RateLimiter(max_events=3, window_s=10.0)
    # Manual clock via the `now` parameter keeps the test deterministic.
    assert rl.allow("1.2.3.4", now=0.0) is True
    assert rl.allow("1.2.3.4", now=1.0) is True
    assert rl.allow("1.2.3.4", now=2.0) is True
    assert rl.allow("1.2.3.4", now=3.0) is False  # 4th within window
    # A different client has its own budget.
    assert rl.allow("5.6.7.8", now=3.0) is True
    # Once the window slides past the early hits, capacity returns.
    assert rl.allow("1.2.3.4", now=11.0) is True


def test_sender_column_migration_on_legacy_db():
    """A pre-hardening DB (mempool without `sender`) opens and gains the column."""
    import sqlite3

    d = tempfile.mkdtemp()
    path = Path(d) / "kern.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE mempool (hash TEXT PRIMARY KEY, json TEXT NOT NULL, "
        "received_at INTEGER NOT NULL)"
    )
    conn.commit()
    conn.close()

    st = Storage(d)  # must not raise; migration adds the sender column
    alice = KernKeypair.generate()
    dest = KernKeypair.generate().address
    assert st.add_to_mempool(
        make_transfer(alice, recipient=dest, amount=1, nonce=0)
    ) is True
    assert st._mempool_count_for_sender(alice.address) == 1
