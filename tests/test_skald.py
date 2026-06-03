# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.skald — parse, execute, invariants, errors."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.skald import (
    SkaldError,
    interpret_call,
    interpret_origination,
    interpret_view,
    parse,
)


COUNTER = """
contract Counter {
    storage {
        count: int,
        owner: address,
    }
    invariant nonneg { count >= 0 }
    entry increment() { count = count + 1; }
    entry add(n: int) {
        require n > 0 with "delta must be positive";
        count = count + n;
    }
    entry reset() {
        require sender == owner with "only owner";
        count = 0;
    }
    view current() -> int { count }
}
"""


def test_parse_counter():
    c = parse(COUNTER)
    assert "increment" in c.functions
    assert "add" in c.functions
    assert "current" in c.functions
    assert c.functions["current"].kind == "view"
    assert len(c.invariants) == 1


def test_origination_with_initial_storage():
    s = interpret_origination(COUNTER, {"count": 0, "owner": "kn1" + "a" * 33})
    assert s["count"] == 0
    assert s["owner"].startswith("kn1")


def test_increment():
    s = interpret_origination(COUNTER, {"count": 0, "owner": "kn1" + "a" * 33})
    s = interpret_call(COUNTER, s, "increment", {},
                      sender="kn1" + "b" * 33, amount=0, self_addr="kn1" + "c" * 33)
    assert s["count"] == 1


def test_add_positive():
    s = interpret_origination(COUNTER, {"count": 5, "owner": "kn1" + "a" * 33})
    s = interpret_call(COUNTER, s, "add", {"n": 7},
                      sender="kn1" + "b" * 33, amount=0, self_addr="kn1" + "c" * 33)
    assert s["count"] == 12


def test_require_rejects():
    s = interpret_origination(COUNTER, {"count": 5, "owner": "kn1" + "a" * 33})
    with pytest.raises(SkaldError, match="delta must be positive"):
        interpret_call(COUNTER, s, "add", {"n": -1},
                      sender="kn1" + "b" * 33, amount=0, self_addr="kn1" + "c" * 33)


def test_only_owner():
    owner = "kn1" + "a" * 33
    other = "kn1" + "b" * 33
    s = interpret_origination(COUNTER, {"count": 5, "owner": owner})
    # Owner can reset
    s = interpret_call(COUNTER, s, "reset", {},
                      sender=owner, amount=0, self_addr="kn1" + "c" * 33)
    assert s["count"] == 0
    # Stranger cannot
    s = interpret_origination(COUNTER, {"count": 5, "owner": owner})
    with pytest.raises(SkaldError, match="only owner"):
        interpret_call(COUNTER, s, "reset", {},
                      sender=other, amount=0, self_addr="kn1" + "c" * 33)


def test_view_does_not_mutate():
    s = interpret_origination(COUNTER, {"count": 5, "owner": "kn1" + "a" * 33})
    v = interpret_view(COUNTER, s, "current", {})
    assert v == 5
    assert s["count"] == 5


def test_invariant_enforced_on_origination():
    # Trying to originate with count = -1 violates the invariant.
    with pytest.raises(SkaldError, match="invariant"):
        interpret_origination(COUNTER, {"count": -1, "owner": "kn1" + "a" * 33})


VAULT = """
contract Vault {
    storage {
        owner: address,
        deposited: int,
        withdrawn: int,
    }
    invariant accounting { deposited >= withdrawn }
    entry deposit() {
        require amount > 0 with "must attach value";
        deposited = deposited + amount;
    }
    entry withdraw(n: int) {
        require sender == owner with "not owner";
        require n > 0 with "amount must be positive";
        require deposited - withdrawn >= n with "insufficient escrow";
        withdrawn = withdrawn + n;
    }
    view available() -> int { deposited - withdrawn }
}
"""


def test_vault_lifecycle():
    owner = "kn1" + "a" * 33
    s = interpret_origination(VAULT, {"owner": owner, "deposited": 0, "withdrawn": 0})
    # Deposit 100
    s = interpret_call(VAULT, s, "deposit", {},
                       sender="kn1" + "b" * 33, amount=100, self_addr="kn1" + "c" * 33)
    assert s["deposited"] == 100
    assert interpret_view(VAULT, s, "available", {}) == 100
    # Withdraw 40 as owner
    s = interpret_call(VAULT, s, "withdraw", {"n": 40},
                       sender=owner, amount=0, self_addr="kn1" + "c" * 33)
    assert s["withdrawn"] == 40
    assert interpret_view(VAULT, s, "available", {}) == 60
    # Over-withdraw fails
    with pytest.raises(SkaldError, match="insufficient escrow"):
        interpret_call(VAULT, s, "withdraw", {"n": 1000},
                       sender=owner, amount=0, self_addr="kn1" + "c" * 33)


if __name__ == "__main__":
    test_parse_counter()
    test_origination_with_initial_storage()
    test_increment()
    test_add_positive()
    test_require_rejects()
    test_only_owner()
    test_view_does_not_mutate()
    test_invariant_enforced_on_origination()
    test_vault_lifecycle()
    print("All skald tests passed.")
