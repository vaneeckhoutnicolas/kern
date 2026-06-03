# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for kern.skald.typecheck — static type-checking before origination."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.skald import SkaldError
from kern.skald.typecheck import assert_type_correct, type_check


# --- Well-typed programs ---------------------------------------------------

COUNTER_OK = """
contract Counter {
    storage { count: int, owner: address, }
    invariant nonneg { count >= 0 }
    entry increment() { count = count + 1; }
    entry add(n: int) {
        require n > 0 with "must be positive";
        count = count + n;
    }
    view current() -> int { count }
}
"""


def test_counter_typechecks():
    errors = type_check(COUNTER_OK)
    assert errors == [], f"unexpected errors: {errors}"


VAULT_OK = """
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
        require deposited - withdrawn >= n with "insufficient";
        withdrawn = withdrawn + n;
    }
    view available() -> int { deposited - withdrawn }
}
"""


def test_vault_typechecks():
    errors = type_check(VAULT_OK)
    assert errors == [], f"unexpected errors: {errors}"


# --- Programs with type errors ---------------------------------------------

def test_assignment_type_mismatch():
    code = """
    contract X {
        storage { name: string, }
        entry set() { name = 42; }
    }
    """
    errs = type_check(code)
    assert any("cannot assign int to name" in str(e) for e in errs), errs


def test_require_must_be_bool():
    code = """
    contract X {
        storage { n: int, }
        entry e() { require 42 with "nope"; n = 0; }
    }
    """
    errs = type_check(code)
    assert any("require condition must be bool" in str(e) for e in errs), errs


def test_invariant_must_be_bool():
    code = """
    contract X {
        storage { n: int, }
        invariant bad { n + 1 }
    }
    """
    errs = type_check(code)
    assert any("invariant must be bool" in str(e) for e in errs), errs


def test_unknown_identifier():
    code = """
    contract X {
        storage { n: int, }
        entry e() { n = mystery + 1; }
    }
    """
    errs = type_check(code)
    assert any("undefined identifier 'mystery'" in str(e) for e in errs), errs


def test_view_cannot_mutate_storage():
    code = """
    contract X {
        storage { n: int, }
        view bad() -> int { n = n + 1; n }
    }
    """
    errs = type_check(code)
    assert any("view function cannot mutate" in str(e) for e in errs), errs


def test_view_return_type_mismatch():
    code = """
    contract X {
        storage { n: int, }
        view bad() -> bool { n }
    }
    """
    errs = type_check(code)
    assert any("body yields int" in str(e) for e in errs), errs


def test_view_must_declare_return_type():
    code = """
    contract X {
        storage { n: int, }
        view bad() { n }
    }
    """
    errs = type_check(code)
    assert any("must declare a return type" in str(e) for e in errs), errs


def test_let_type_mismatch():
    code = """
    contract X {
        storage { n: int, }
        entry e() { let x: int = "hello"; n = x; }
    }
    """
    errs = type_check(code)
    assert any("let x: int initialized with string" in str(e) for e in errs), errs


def test_binop_not_defined():
    code = """
    contract X {
        storage { n: int, addr: address, }
        entry e() { n = n + addr; }
    }
    """
    errs = type_check(code)
    assert any("+ not defined on (int, address)" in str(e) for e in errs), errs


def test_comparing_different_types():
    code = """
    contract X {
        storage { n: int, name: string, }
        view bad() -> bool { n == name }
    }
    """
    errs = type_check(code)
    assert any("== not defined on (int, string)" in str(e) for e in errs), errs


def test_calling_entry_from_expression_is_rejected():
    code = """
    contract X {
        storage { n: int, }
        entry mutate() { n = n + 1; }
        view bad() -> int { mutate() }
    }
    """
    errs = type_check(code)
    assert any("cannot call entry" in str(e) for e in errs), errs


def test_arity_mismatch():
    code = """
    contract X {
        storage { n: int, }
        internal add(a: int, b: int) -> int { a + b }
        view bad() -> int { add(1) }
    }
    """
    errs = type_check(code)
    assert any("expects 2 args, got 1" in str(e) for e in errs), errs


def test_assert_type_correct_raises():
    bad = """
    contract X {
        storage { n: int, }
        entry e() { n = "oops"; }
    }
    """
    with pytest.raises(SkaldError):
        assert_type_correct(bad)


def test_assert_type_correct_passes():
    assert_type_correct(COUNTER_OK)
    assert_type_correct(VAULT_OK)


def test_duplicate_storage_field():
    code = """
    contract X {
        storage { n: int, n: int, }
        entry e() { n = 1; }
    }
    """
    errs = type_check(code)
    assert any("duplicate field" in str(e) for e in errs), errs


def test_parameter_shadows_storage():
    code = """
    contract X {
        storage { n: int, }
        entry e(n: int) { n = n + 1; }
    }
    """
    errs = type_check(code)
    assert any("shadows storage field" in str(e) for e in errs), errs


def test_int_string_concat_rejected():
    code = """
    contract X {
        storage { s: string, }
        entry e() { s = s + 42; }
    }
    """
    errs = type_check(code)
    assert any("+ not defined on (string, int)" in str(e) for e in errs), errs


def test_string_concat_allowed():
    code = """
    contract X {
        storage { s: string, }
        entry e() { s = s + "!"; }
    }
    """
    errs = type_check(code)
    assert errs == [], errs


# --- Recursion / termination (call-graph must be acyclic) -------------------

def _recursion_errors(code):
    return [e for e in type_check(code) if "recursion" in str(e)]


def test_direct_recursion_rejected():
    code = """
    contract R {
        storage { x: int }
        internal loop(n: int) -> int {
            if (n <= 0) { return 0; }
            return loop(n - 1);
        }
        entry go(n: int) { x = loop(n); }
    }
    """
    rec = _recursion_errors(code)
    assert rec, "direct recursion should be rejected"
    assert "loop -> loop" in str(rec[0])


def test_mutual_recursion_rejected():
    code = """
    contract M {
        storage { x: int }
        internal a(n: int) -> int {
            if (n <= 0) { return 0; }
            return b(n - 1);
        }
        internal b(n: int) -> int { return a(n - 1); }
        entry go(n: int) { x = a(n); }
    }
    """
    assert _recursion_errors(code), "mutual recursion a<->b should be rejected"


def test_three_cycle_recursion_rejected():
    code = """
    contract C {
        storage { x: int }
        internal a(n: int) -> int { return b(n); }
        internal b(n: int) -> int { return c(n); }
        internal c(n: int) -> int { return a(n); }
        entry go(n: int) { x = a(n); }
    }
    """
    assert _recursion_errors(code), "3-cycle a->b->c->a should be rejected"


def test_acyclic_calls_allowed():
    # `quad` calls `double` twice — a call, but no cycle. Must be accepted.
    code = """
    contract OK {
        storage { x: int }
        internal double(n: int) -> int { return n + n; }
        internal quad(n: int) -> int { return double(n) + double(n); }
        entry go(n: int) { x = quad(n); }
    }
    """
    assert type_check(code) == [], type_check(code)


def test_diamond_call_graph_allowed():
    # top -> {left, right} -> base. A diamond is acyclic and must pass.
    code = """
    contract D {
        storage { x: int }
        internal base(n: int) -> int { return n + 1; }
        internal left(n: int) -> int { return base(n) + 1; }
        internal right(n: int) -> int { return base(n) + 2; }
        internal top(n: int) -> int { return left(n) + right(n); }
        entry go(n: int) { x = top(n); }
    }
    """
    assert type_check(code) == [], type_check(code)


if __name__ == "__main__":
    test_counter_typechecks()
    test_vault_typechecks()
    test_require_must_be_bool()
    test_invariant_must_be_bool()
    test_unknown_identifier()
    test_view_cannot_mutate_storage()
    test_view_return_type_mismatch()
    test_view_must_declare_return_type()
    test_let_type_mismatch()
    test_binop_not_defined()
    test_comparing_different_types()
    test_calling_entry_from_expression_is_rejected()
    test_arity_mismatch()
    test_assert_type_correct_passes()
    test_duplicate_storage_field()
    test_parameter_shadows_storage()
    test_int_string_concat_rejected()
    test_string_concat_allowed()
    test_direct_recursion_rejected()
    test_mutual_recursion_rejected()
    test_three_cycle_recursion_rejected()
    test_acyclic_calls_allowed()
    test_diamond_call_graph_allowed()
    print("All typecheck tests passed.")
