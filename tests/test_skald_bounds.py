# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A contract computes within bounds.

Until these bounds nothing limited what a contract computes. Squaring an
integer fourteen times left a state whose root no longer computed, and the
proposer built no block as long as that call waited in its mempool. A few
hundred bytes of code ran for seconds. And a code nested deeply enough was
created or refused according to the Python stack of the node that applied
it: a proposer built a block that the node validating it refused.

Four bounds hold in the interpreter:

- an integer is 64 bits, from -2^63 to 2^63 - 1, at every expression;
- a text is 4,096 bytes at most, counted in UTF-8, at every expression;
- an execution is 10,000 steps at most, its invariants included: a step is
  a statement executed or an expression evaluated;
- a statement is 64 levels deep at most when the code is read, and an
  execution is 64 levels deep at most, through the functions it calls.

What leaves a bound fails like a `require` that refuses: the operation pays
its fee, its nonce is taken, and nothing else changes. `balance` is what
the contract holds, with the amount of the call.
"""

import copy
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import kern.skald as skald  # noqa: E402
from kern.block import Block, BlockHeader, txs_merkle_root_hex  # noqa: E402
from kern.chain import Chain, apply_transaction, derive_contract_address, state_root_hex  # noqa: E402
from kern.consensus import propose_block  # noqa: E402
from kern.crypto import KernKeypair  # noqa: E402
from kern.skald import SkaldError, interpret_call, interpret_origination, interpret_view, parse  # noqa: E402
from kern.skald.typecheck import type_check  # noqa: E402
from kern.transaction import make_call, make_origination, make_transfer  # noqa: E402

INT_MIN, INT_MAX = -(2 ** 63), 2 ** 63 - 1
ZERO = "kn1" + "0" * 33
SOMEONE = "kn1" + "a" * 33
ITSELF = "kn1" + "c" * 33


def call(code, storage, entry, params=None, **context):
    """The storage after `entry(params)`, called by SOMEONE with no amount."""
    return interpret_call(code, storage, entry, params,
                          **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})


def outcome(action) -> str:
    """What `action` does, as a text that two runs can compare."""
    try:
        action()
    except SkaldError as error:
        return f"refused: {error}"
    except RecursionError:
        return "RecursionError"
    return "accepted"


def at_stack(extra: int, action):
    """Run `action` with `extra` more frames on the Python stack."""
    return action() if extra == 0 else at_stack(extra - 1, action)


# ---------------------------------------------------------------------------
# The four bounds have a name
# ---------------------------------------------------------------------------

def test_the_bounds_are_constants_of_the_interpreter():
    assert (getattr(skald, "INT_MIN", None), getattr(skald, "INT_MAX", None)) == (INT_MIN, INT_MAX)
    assert getattr(skald, "MAX_TEXT_BYTES", None) == 4096
    assert getattr(skald, "MAX_STEPS", None) == 10_000
    assert getattr(skald, "MAX_DEPTH", None) == 64


# ---------------------------------------------------------------------------
# An integer is 64 bits
# ---------------------------------------------------------------------------

VALUES = """
contract Values {
    storage {
        n: int,
        s: string,
        who: address,
    }
    entry set(v: int) { n = v; }
    entry add(a: int, b: int) { n = a + b; }
    entry sub(a: int, b: int) { n = a - b; }
    entry mul(a: int, b: int) { n = a * b; }
    entry div(a: int, b: int) { n = a / b; }
    entry neg(a: int) { n = -a; }
    entry lowest() { n = -9223372036854775808; }
    entry highest() { n = 9223372036854775807; }
    entry beyond() { n = 9223372036854775808; }
    entry modest(a: int) { n = (a * a) % 7; }
    entry keep(t: string) { s = t; }
    entry join(a: string, b: string) { s = a + b; }
    entry own(a: address) { who = a; }
    entry read() { n = n + 0; }
    entry touch() { s = "x"; }
    view twice() -> string { s + s }
}
"""
EMPTY = {"n": 0, "s": "", "who": ZERO}


@pytest.mark.parametrize("entry, params", [
    ("mul", {"a": 2 ** 62, "b": 2}),
    ("add", {"a": INT_MAX, "b": 1}),
    ("sub", {"a": INT_MIN, "b": 1}),
    ("neg", {"a": INT_MIN}),
    ("div", {"a": INT_MIN, "b": -1}),
], ids=["a product", "a sum", "a difference", "an opposite", "a quotient"])
def test_an_integer_that_leaves_64_bits_fails_the_call(entry, params):
    with pytest.raises(SkaldError, match="64 bits"):
        call(VALUES, EMPTY, entry, params)


def test_control_an_integer_at_either_end_passes():
    assert call(VALUES, EMPTY, "add", {"a": INT_MAX - 1, "b": 1})["n"] == INT_MAX
    assert call(VALUES, EMPTY, "sub", {"a": INT_MIN + 1, "b": 1})["n"] == INT_MIN
    assert call(VALUES, EMPTY, "mul", {"a": 2 ** 62, "b": -2})["n"] == INT_MIN
    assert call(VALUES, EMPTY, "neg", {"a": INT_MAX})["n"] == INT_MIN + 1
    assert call(VALUES, EMPTY, "div", {"a": INT_MIN, "b": 1})["n"] == INT_MIN
    assert call(VALUES, EMPTY, "set", {"v": INT_MAX})["n"] == INT_MAX
    assert call(VALUES, EMPTY, "set", {"v": INT_MIN})["n"] == INT_MIN
    assert call(VALUES, EMPTY, "lowest")["n"] == INT_MIN
    assert call(VALUES, EMPTY, "highest")["n"] == INT_MAX


def test_an_integer_is_bounded_where_it_is_computed_not_where_it_is_kept():
    """`(a * a) % 7` keeps a small integer. The square it goes through is
    not one: bounding what a contract keeps does not bound what it
    computes."""
    assert call(VALUES, EMPTY, "modest", {"a": 2 ** 31})["n"] == (2 ** 62) % 7
    with pytest.raises(SkaldError, match="64 bits"):
        call(VALUES, EMPTY, "modest", {"a": 2 ** 32})


def test_a_number_written_outside_64_bits_fails_where_it_is_evaluated():
    """The code is still read and created: only the entry that evaluates
    the number fails."""
    assert interpret_origination(VALUES, None) == EMPTY
    with pytest.raises(SkaldError, match="64 bits"):
        call(VALUES, EMPTY, "beyond")


def long_number(digits: int, sign: str = "") -> str:
    return ("contract Long { storage { n: int, } entry small() { n = 1; } entry long() { n = "
            + sign + "9" * digits + "; } entry padded() { n = " + sign + "0" * digits + "7; } }")


@pytest.mark.parametrize("digits", [20, 4300, 4301, 50_000])
def test_a_number_of_any_length_is_read_the_same_whatever_the_limit_python_puts_on_digits(digits):
    """Python converts a text of more than 4,300 digits to an integer only
    when the process lifted that limit: a contract that wrote such a number
    was read by a node started with PYTHONINTMAXSTRDIGITS=0 and by no
    other. The number is now read without being converted. It still fails
    where it is evaluated, and only there."""
    limit = sys.get_int_max_str_digits()
    seen = []
    for lifted in (limit, 0):
        sys.set_int_max_str_digits(lifted)
        try:
            for sign in ("", "-"):
                code = long_number(digits, sign)
                seen.append((
                    outcome(lambda: interpret_origination(code, None)),
                    outcome(lambda: call(code, {"n": 0}, "small")),
                    outcome(lambda: call(code, {"n": 0}, "long")).split(",")[0],
                    call(code, {"n": 0}, "padded") == {"n": int(sign + "7")},
                ))
        finally:
            sys.set_int_max_str_digits(limit)
    assert set(seen) == {("accepted", "accepted", "refused: an integer is 64 bits", True)}


@pytest.mark.parametrize("value", [INT_MAX + 1, INT_MIN - 1, 2 ** 200], ids=["2^63", "-2^63 - 1", "2^200"])
def test_an_integer_outside_64_bits_is_not_taken_as_a_parameter(value):
    with pytest.raises(SkaldError, match="64 bits"):
        call(VALUES, EMPTY, "set", {"v": value})


# ---------------------------------------------------------------------------
# A text is 4,096 bytes
# ---------------------------------------------------------------------------

def test_a_text_longer_than_4096_bytes_fails_the_call():
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "join", {"a": "a" * 4096, "b": "b"})
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "keep", {"t": "a" * 4097})


def test_an_address_is_a_text():
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "own", {"a": "kn1" + "a" * 4094})


def test_control_a_text_of_4096_bytes_passes():
    assert call(VALUES, EMPTY, "join", {"a": "a" * 2048, "b": "b" * 2048})["s"] == "a" * 2048 + "b" * 2048
    assert call(VALUES, EMPTY, "keep", {"t": "a" * 4096})["s"] == "a" * 4096
    assert call(VALUES, EMPTY, "keep", {"t": "é" * 2048})["s"] == "é" * 2048
    assert call(VALUES, EMPTY, "own", {"a": "kn1" + "a" * 4093})["who"] == "kn1" + "a" * 4093


def test_a_text_is_counted_in_bytes_of_utf8_not_in_characters():
    """2,049 times `é` is 2,049 characters and 4,098 bytes."""
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "keep", {"t": "é" * 2049})
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "join", {"a": "é" * 2048, "b": "a"})


def test_a_text_that_utf8_does_not_encode_is_counted_three_bytes_for_each_half_of_a_pair():
    """A text literal can hold half of a surrogate pair, `\\ud800`, which
    is no character and has no UTF-8. It is still a text of the devnet,
    counted as the three bytes that such a half would take."""
    half = "\ud800"
    assert call(VALUES, EMPTY, "keep", {"t": half * 1365})["s"] == half * 1365
    with pytest.raises(SkaldError, match="4096 bytes"):
        call(VALUES, EMPTY, "keep", {"t": half * 1366})


def doubled(times: int) -> str:
    return ("contract Grow { storage { s: string, } entry grow() { s = \"a\"; "
            + "s = s + s; " * times + "} }")


def test_a_text_doubled_beyond_4096_bytes_fails_the_call():
    """Twelve doublings of one byte make 4,096 bytes. The thirteenth
    fails, and so do the fifteen after it: 28 doublings were 268,435,456
    characters."""
    assert len(call(doubled(12), {"s": ""}, "grow")["s"]) == 4096
    for times in (13, 28):
        with pytest.raises(SkaldError, match="4096 bytes"):
            call(doubled(times), {"s": ""}, "grow")


def test_a_view_does_not_return_a_text_beyond_the_bound():
    assert interpret_view(VALUES, {"n": 0, "s": "a" * 2048}, "twice", None) == "a" * 4096
    with pytest.raises(SkaldError, match="4096 bytes"):
        interpret_view(VALUES, {"n": 0, "s": "a" * 2049}, "twice", None)


# ---------------------------------------------------------------------------
# What a contract is created with, and what it already keeps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("initial", [{"n": INT_MAX + 1}, {"n": INT_MIN - 1}, {"s": "a" * 4097}, {"s": "é" * 2049}],
                         ids=["2^63", "-2^63 - 1", "4,097 bytes", "2,049 characters of two bytes"])
def test_a_contract_is_not_created_with_a_value_outside_the_bounds(initial):
    with pytest.raises(SkaldError, match="64 bits|4096 bytes"):
        interpret_origination(VALUES, initial)


def test_control_a_contract_is_created_with_values_at_the_bounds():
    assert interpret_origination(VALUES, {"n": INT_MIN, "s": "é" * 2048}) == {"n": INT_MIN, "s": "é" * 2048, "who": ZERO}
    assert interpret_origination(VALUES, {"n": INT_MAX, "s": "a" * 4096}) == {"n": INT_MAX, "s": "a" * 4096, "who": ZERO}


def test_a_call_that_reads_a_kept_value_outside_the_bounds_fails():
    """A state made before the bounds can keep such a value. Reading it
    fails the call, as computing it would."""
    with pytest.raises(SkaldError, match="64 bits"):
        call(VALUES, {"n": 2 ** 64, "s": ""}, "read")
    with pytest.raises(SkaldError, match="4096 bytes"):
        interpret_view(VALUES, {"n": 0, "s": "a" * 5000}, "twice", None)


def test_control_a_call_that_does_not_read_it_passes():
    assert call(VALUES, {"n": 2 ** 64, "s": ""}, "touch") == {"n": 2 ** 64, "s": "x"}


# ---------------------------------------------------------------------------
# An execution is 10,000 steps
# ---------------------------------------------------------------------------

INCREMENT = "n = n + 1; "       # four steps: the statement, the sum, `n` and `1`
OPPOSITE = "n = -n; "           # three steps: the statement, the opposite and `n`
LOOK = "n; "                    # two steps: the statement and `n`


def counted(body: str, invariant: str = "") -> str:
    return "contract Counted { storage { n: int, } " + invariant + " entry go() { " + body + "} }"


def test_control_an_execution_of_10000_steps_passes():
    assert call(counted(INCREMENT * 2500), {"n": 0}, "go") == {"n": 2500}
    assert call(counted(INCREMENT * 2499 + LOOK + LOOK), {"n": 0}, "go") == {"n": 2499}


def test_the_step_after_the_10000th_fails_the_call():
    with pytest.raises(SkaldError, match="10000 steps"):
        call(counted(INCREMENT * 2499 + OPPOSITE + LOOK), {"n": 0}, "go")
    with pytest.raises(SkaldError, match="10000 steps"):
        call(counted(INCREMENT * 2500 + LOOK), {"n": 0}, "go")


def test_the_invariants_take_their_steps_in_the_same_budget():
    """An entry of 9,998 steps passes alone. With an invariant of three
    steps, the execution is 10,001 steps."""
    body = INCREMENT * 2499 + LOOK
    assert call(counted(body), {"n": 0}, "go") == {"n": 2499}
    assert call(counted(INCREMENT * 2499, "invariant positive { n >= 0 }"), {"n": 0}, "go") == {"n": 2499}
    with pytest.raises(SkaldError, match="10000 steps"):
        call(counted(body, "invariant positive { n >= 0 }"), {"n": 0}, "go")


def doubling(levels: int, last: str) -> str:
    """`levels` internal functions that each call the one before twice,
    and `last`, which calls the last of them: 2^levels calls of the first."""
    functions = ["internal f0() -> int { return 1; }"]
    for k in range(1, levels + 1):
        functions.append(f"internal f{k}() -> int {{ return f{k - 1}() + f{k - 1}(); }}")
    return "contract Doubling { storage { n: int, } " + " ".join(functions) + " " + last + " }"


def test_functions_that_call_each_other_twice_stop_at_the_budget():
    """Six levels are 64 calls and fourteen are 16,384. Before the budget,
    eighteen levels, 1,175 bytes of code, ran for about a second, and each
    level more doubled that time."""
    assert call(doubling(6, "entry go() { n = f6(); }"), {"n": 0}, "go") == {"n": 64}
    for levels in (14, 18):
        with pytest.raises(SkaldError, match="10000 steps"):
            call(doubling(levels, f"entry go() {{ n = f{levels}(); }}"), {"n": 0}, "go")


def test_a_view_stops_at_the_budget():
    assert interpret_view(doubling(6, "view heavy() -> int { f6() }"), {"n": 0}, "heavy", None) == 64
    with pytest.raises(SkaldError, match="10000 steps"):
        interpret_view(doubling(14, "view heavy() -> int { f14() }"), {"n": 0}, "heavy", None)


def test_the_invariants_of_a_creation_stop_at_the_budget():
    assert interpret_origination(doubling(6, "invariant heavy { f6() > 0 }"), None) == {"n": 0}
    with pytest.raises(SkaldError, match="10000 steps"):
        interpret_origination(doubling(14, "invariant heavy { f14() > 0 }"), None)


# ---------------------------------------------------------------------------
# A statement is 64 levels deep
# ---------------------------------------------------------------------------

def deep(shape: str, levels: int) -> str:
    """A contract whose deepest statement, or whose invariant, is `levels`
    deep. A statement, an expression and a pair of parentheses are one
    level each."""
    inside = levels - 2             # between the statement and the value at the bottom
    if shape == "parentheses":
        body = "n = " + "(" * inside + "1" + ")" * inside + ";"
    elif shape == "a sum":
        body = "n = " + " + ".join(["1"] * (inside + 1)) + ";"
    elif shape == "prefix operators":
        body = "b = " + "!" * inside + "b;"
    elif shape == "blocks":
        body = "if (true) { " * inside + "n = 1; " + "} " * inside
    elif shape == "else blocks":
        body = "if (false) { } else { " * inside + "n = 1; " + "} " * inside
    elif shape == "arguments":
        body = "n = " + "same(" * inside + "1" + ")" * inside + ";"
    elif shape == "a sum in parentheses":
        body = "n = (" + " + ".join(["1"] * inside) + ");"
    elif shape == "a sum in an argument":
        body = "n = same(" + " + ".join(["1"] * inside) + ");"
    elif shape == "the condition of an if":
        body = "if (" + " && ".join(["true"] * (inside + 1)) + ") { }"
    elif shape == "the condition of a require":
        body = "require " + " && ".join(["true"] * (inside + 1)) + ";"
    elif shape == "the message of a require":
        body = "require true with " + " + ".join(['"m"'] * (inside + 1)) + ";"
    elif shape == "an invariant":
        return ("contract Deep { storage { n: int, b: bool, } invariant deep { "
                + "(" * (levels - 1) + "true" + ")" * (levels - 1) + " } entry go() { n = 1; } }")
    elif shape == "a chain in an invariant":
        return ("contract Deep { storage { n: int, b: bool, } invariant deep { "
                + " && ".join(["true"] * levels) + " } entry go() { n = 1; } }")
    else:
        raise ValueError(shape)
    return ("contract Deep { storage { n: int, b: bool, } internal same(x: int) -> int { return x; } "
            "entry go() { " + body + " } }")


SHAPES = ["parentheses", "a sum", "prefix operators", "blocks", "else blocks", "arguments", "a sum in parentheses",
          "a sum in an argument", "the condition of an if", "the condition of a require", "the message of a require",
          "an invariant", "a chain in an invariant"]
START = {"n": 0, "b": False}


@pytest.mark.parametrize("shape", SHAPES)
def test_a_code_65_levels_deep_is_not_read(shape):
    code = deep(shape, 65)
    with pytest.raises(SkaldError, match="64 levels deep"):
        parse(code)
    with pytest.raises(SkaldError, match="64 levels deep"):
        type_check(code)
    with pytest.raises(SkaldError, match="64 levels deep"):
        interpret_origination(code, None)
    with pytest.raises(SkaldError, match="64 levels deep"):
        call(code, START, "go")


@pytest.mark.parametrize("shape", SHAPES)
def test_control_a_code_64_levels_deep_is_read_and_created(shape):
    code = deep(shape, 64)
    assert type_check(code) == []
    assert interpret_origination(code, None) == START


@pytest.mark.parametrize("shape, after", [
    ("parentheses", {"n": 1, "b": False}),
    ("a sum", {"n": 63, "b": False}),
    ("prefix operators", {"n": 0, "b": False}),
    ("blocks", {"n": 1, "b": False}),
    ("else blocks", {"n": 1, "b": False}),
    ("a sum in parentheses", {"n": 62, "b": False}),
    ("a sum in an argument", {"n": 62, "b": False}),
    ("the condition of an if", {"n": 0, "b": False}),
    ("the condition of a require", {"n": 0, "b": False}),
    ("the message of a require", {"n": 0, "b": False}),
    ("an invariant", {"n": 1, "b": False}),
    ("a chain in an invariant", {"n": 1, "b": False}),
])
def test_control_a_code_64_levels_deep_runs(shape, after):
    assert call(deep(shape, 64), START, "go") == after


def random_term(rng, depth: int) -> str:
    """A term `depth` levels deep: a value, parentheses, a prefix operator
    or a call."""
    if depth == 1:
        return rng.choice(["n", "true", "7", '"t"'])
    shape = rng.choice(["parentheses", "prefix", "call"])
    if shape == "parentheses":
        return "(" + random_expression(rng, depth - 1) + ")"
    if shape == "prefix":
        return rng.choice(["!", "- "]) + random_term(rng, depth - 1)
    arguments = [random_expression(rng, depth - 1)]
    arguments += [random_expression(rng, rng.randint(1, min(3, depth - 1))) for _ in range(rng.randint(0, 2))]
    rng.shuffle(arguments)
    return "same(" + ", ".join(arguments) + ")"


def random_expression(rng, depth: int) -> str:
    """An expression `depth` levels deep: a term, or a chain of sums whose
    tree is one level more than its deeper side."""
    if depth == 1 or rng.random() < 0.4:
        return random_term(rng, depth)
    shallow = rng.randint(1, min(3, depth - 1))
    if rng.random() < 0.5:
        return random_expression(rng, depth - 1) + " + " + random_term(rng, shallow)
    return random_expression(rng, shallow) + " + " + random_term(rng, depth - 1)


def random_statement(rng, depth: int) -> str:
    """A statement `depth` levels deep, two at least."""
    shallow = rng.randint(1, min(3, depth - 1))
    shapes = ["assign", "let", "return", "bare", "require"] + (["if", "else"] * 2 if depth > 2 else [])
    shape = rng.choice(shapes)
    if shape == "assign":
        return "n = " + random_expression(rng, depth - 1) + "; "
    if shape == "let":
        return "let x: int = " + random_expression(rng, depth - 1) + "; "
    if shape == "return":
        return "return " + random_expression(rng, depth - 1) + "; "
    if shape == "bare":
        return random_expression(rng, depth - 1) + "; "
    if shape == "require":
        sides = [random_expression(rng, depth - 1), random_expression(rng, shallow)]
        rng.shuffle(sides)
        return "require " + sides[0] + " with " + sides[1] + "; "
    aside = random_statement(rng, 1 + shallow) if rng.random() < 0.5 else ""
    if rng.random() < 0.3:      # the condition is the deepest thing the statement holds
        condition, inner = random_expression(rng, depth - 1), aside
    else:
        condition, inner = random_expression(rng, shallow), random_statement(rng, depth - 1)
    if shape == "if":
        return "if (" + condition + ") { " + aside + inner + "} "
    return "if (" + condition + ") { " + aside + "} else { " + inner + aside + "} "


def test_random_statements_are_read_exactly_when_they_are_64_levels_deep_at_most():
    """The depth is the one the generator builds, not one read back from
    the parser: a statement, an expression and a pair of parentheses are
    one level each, and a chain `a + b + c` is as deep as it is long."""
    rng = random.Random(64)
    read = refused = 0
    for _ in range(400):
        depth = rng.randint(56, 72)
        if rng.random() < 0.15:
            code = "contract Random { storage { n: int, } invariant deep { " + random_expression(rng, depth) + " } }"
        else:
            code = "contract Random { storage { n: int, } entry go() { " + random_statement(rng, depth) + "} }"
        answer = outcome(lambda: parse(code))
        assert answer == ("accepted" if depth <= 64 else "refused: a statement is 64 levels deep at most"), (depth, code)
        read += depth <= 64
        refused += depth > 64
    assert read > 100 and refused > 100


def recursion_depth() -> int:
    """How deep Python counts the call that asks: the lowest limit it
    accepts is one above it."""
    limit = sys.getrecursionlimit()
    low, high = 1, limit
    try:
        while low < high:
            middle = (low + high) // 2
            try:
                sys.setrecursionlimit(middle)
                high = middle
            except RecursionError:
                low = middle + 1
    finally:
        sys.setrecursionlimit(limit)
    return low


def test_control_a_code_at_the_bound_takes_fewer_than_250_frames_of_the_python_stack():
    """The parser, the type checker and the interpreter recurse on the
    code. At 64 levels they stay far from the 1,000 frames Python allows
    by default, wherever the node applies the transaction from."""
    runs = [(deep(shape, 64), START) for shape in SHAPES if shape != "arguments"]
    runs += [(chained(31), {"n": 0}), (deep("arguments", 63), START)]
    limit = sys.getrecursionlimit()
    for code, storage in runs:
        sys.setrecursionlimit(recursion_depth() + 250)
        try:
            assert type_check(code) == []
            interpret_origination(code, None)
            call(code, storage, "go")
        finally:
            sys.setrecursionlimit(limit)


def far_too_deep():
    return {
        "a sum of 2,000 terms": deep("a sum", 2001),
        "400 pairs of parentheses": deep("parentheses", 402),
        "5,000 prefix operators": deep("prefix operators", 5002),
        "300 blocks": deep("blocks", 302),
    }


@pytest.mark.parametrize("name", list(far_too_deep()))
def test_a_code_far_too_deep_is_refused_the_same_way_whatever_the_stack(name):
    """A node applies a transaction from several places, the proposer from
    a shorter stack than the node that validates its block. Before the
    bound, Python raised RecursionError at a depth that depended on that
    stack, and on the recursion limit of the process."""
    code = far_too_deep()[name]
    seen = {outcome(lambda: at_stack(extra, lambda: interpret_origination(code, None))) for extra in (0, 150, 300)}
    seen |= {outcome(lambda: at_stack(extra, lambda: call(code, START, "go"))) for extra in (0, 150, 300)}
    assert len(seen) == 1 and seen.pop().startswith("refused: ") and "64 levels deep" in outcome(lambda: parse(code))


CHILD = r'''
import sys
sys.path.insert(0, sys.argv[1])
sys.setrecursionlimit(int(sys.argv[2]))
from kern.skald import SkaldError, interpret_call, interpret_origination
ZERO = "kn1" + "0" * 33
def outcome(action):
    try:
        action()
    except SkaldError as error:
        return "refused"
    except BaseException as error:
        return "raised " + type(error).__name__
    return "accepted"
for marks in (62, 63, 300, 5_000, 100_000):
    code = "contract Deep { storage { b: bool, } entry go() { b = " + "!" * marks + "b; } }"
    print(marks, outcome(lambda: interpret_origination(code, None)),
          outcome(lambda: interpret_call(code, {"b": False}, "go", {}, sender=ZERO, amount=0, self_addr=ZERO)))
'''


def test_the_recursion_limit_of_the_process_changes_nothing():
    """In two processes of their own: one with the recursion limit Python
    starts with, one with the 100,000 that py_ecc sets when a node imports
    it. Before the bound, 5,000 prefix operators were created by the
    second and refused by the first."""
    answers = []
    for limit in ("1000", "100000"):
        done = subprocess.run([sys.executable, "-B", "-c", CHILD, str(ROOT), limit],
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr[-2000:]
        answers.append(done.stdout.split("\n"))
    assert answers[0] == answers[1] == ["62 accepted accepted", "63 refused refused", "300 refused refused",
                                        "5000 refused refused", "100000 refused refused", ""]


# ---------------------------------------------------------------------------
# An execution is 64 levels deep
# ---------------------------------------------------------------------------

def chained(functions: int, first: str = "return 1;") -> str:
    """`functions` internal functions in a chain, each calling the one
    before it once, and an entry that calls the last. The entry is two
    levels, a statement and a call, and so is each function."""
    lines = ["internal f0() -> int { " + first + " }"]
    for k in range(1, functions):
        lines.append(f"internal f{k}() -> int {{ return f{k - 1}(); }}")
    return ("contract Chained { storage { n: int, } " + " ".join(lines)
            + f" entry go() {{ n = f{functions - 1}(); }} }}")


def test_control_an_execution_64_levels_deep_passes():
    assert call(chained(31), {"n": 0}, "go") == {"n": 1}


def test_an_execution_65_levels_deep_fails_the_call():
    with pytest.raises(SkaldError, match="64 levels deep"):
        call(chained(31, "return 0 + 1;"), {"n": 0}, "go")
    with pytest.raises(SkaldError, match="64 levels deep"):
        call(chained(32), {"n": 0}, "go")


def test_a_code_that_is_read_can_be_too_deep_to_run():
    """62 calls of `same`, each in the argument of the one before, are a
    statement 64 levels deep. The innermost call runs its body two levels
    lower than its own."""
    code = deep("arguments", 64)
    assert type_check(code) == []
    with pytest.raises(SkaldError, match="an execution is 64 levels deep"):
        call(code, START, "go")
    assert call(deep("arguments", 63), START, "go") == {"n": 1, "b": False}


def test_a_chain_of_functions_fails_the_same_way_whatever_the_stack():
    """330 functions in a chain passed or raised RecursionError according
    to the stack of the caller."""
    code = chained(400)
    assert type_check(code) == []
    seen = {outcome(lambda: at_stack(extra, lambda: call(code, {"n": 0}, "go"))) for extra in (0, 150, 300)}
    assert seen == {"refused: an execution is 64 levels deep at most"}


# ---------------------------------------------------------------------------
# The search for recursion does not lean on the Python stack
# ---------------------------------------------------------------------------

@pytest.fixture
def the_recursion_limit_python_starts_with():
    """Another test of the session may have imported py_ecc, which sets
    the limit to 100,000."""
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        yield
    finally:
        sys.setrecursionlimit(limit)


def forward_chain(functions: int, last: str) -> str:
    """Functions that the search walks in the order of the chain: each one
    calls the next, and the last one runs `last`."""
    lines = [f"internal f{k:04d}() -> int {{ return f{k + 1:04d}(); }}" for k in range(functions - 1)]
    lines.append(f"internal f{functions - 1:04d}() -> int {{ {last} }}")
    return "contract Forward { storage { n: int, } " + " ".join(lines) + " entry go() { n = 1; } }"


def test_a_chain_of_2000_functions_is_checked_for_recursion(the_recursion_limit_python_starts_with):
    assert type_check(forward_chain(2000, "return 1;")) == []
    assert interpret_origination(forward_chain(2000, "return 1;"), None) == {"n": 0}


def test_a_cycle_of_2000_functions_is_found(the_recursion_limit_python_starts_with):
    errors = [str(error) for error in type_check(forward_chain(2000, "return f0000();"))]
    assert len(errors) == 1 and "recursion is not allowed in Skald" in errors[0]
    assert "call cycle: f0000 -> f0001 -> " in errors[0] and errors[0].count(" -> ") == 2000


def test_control_cycles_are_reported_as_before():
    code = """
    contract Cycles {
        storage { n: int, }
        internal z() -> int { return z(); }
        internal b() -> int { return z() + a(); }
        internal a() -> int { return b(); }
        entry go() { n = 1; }
    }
    """
    details = [error.detail for error in type_check(code)]
    assert [detail.split("call cycle: ")[1].split(")")[0] for detail in details] == ["a -> b -> a", "z -> z"]
    with pytest.raises(SkaldError, match="recursion is not allowed in Skald"):
        interpret_origination(code, None)


# ---------------------------------------------------------------------------
# `balance`, and what the invariants of a creation see
# ---------------------------------------------------------------------------

PURSE = """
contract Purse {
    storage { seen: int, }
    entry look() { seen = balance; }
}
"""

FUNDED = """
contract Funded {
    storage { n: int, nobody: address, }
    invariant apart { sender != self }
    invariant someone { sender != nobody }
    invariant somewhere { self != nobody }
    invariant funded { balance > 0 }
    entry touch() { n = n + 1; }
}
"""
UNTOUCHED = {"n": 0, "nobody": ZERO}


def test_balance_is_given_to_a_call():
    assert call(PURSE, {"seen": 0}, "look", balance=7) == {"seen": 7}
    assert call(PURSE, {"seen": 5}, "look") == {"seen": 0}


def test_the_invariants_of_a_creation_are_given_its_sender_its_address_and_what_it_holds():
    """`nobody` is left to its default, the zero address, which is also
    what `sender` and `self` are when a creation is not given them."""
    assert interpret_origination(FUNDED, None, sender=SOMEONE, self_addr=ITSELF, balance=1) == UNTOUCHED
    with pytest.raises(SkaldError, match="invariant 'funded' violated"):
        interpret_origination(FUNDED, None, sender=SOMEONE, self_addr=ITSELF)
    with pytest.raises(SkaldError, match="invariant 'apart' violated"):
        interpret_origination(FUNDED, None, sender=SOMEONE, self_addr=SOMEONE, balance=1)
    with pytest.raises(SkaldError, match="invariant 'someone' violated"):
        interpret_origination(FUNDED, None, self_addr=ITSELF, balance=1)
    with pytest.raises(SkaldError, match="invariant 'somewhere' violated"):
        interpret_origination(FUNDED, None, sender=SOMEONE, balance=1)


def test_control_a_creation_without_its_context_sees_the_zero_address_and_nothing_held():
    with pytest.raises(SkaldError, match="invariant 'apart' violated"):
        interpret_origination(FUNDED, None)


# ---------------------------------------------------------------------------
# In a block
# ---------------------------------------------------------------------------

KRN = 1_000_000
BAKER, ALICE, BOB = (KernKeypair.from_seed(bytes([seed]) * 32) for seed in (1, 3, 4))
SQUARES = "contract Squares { storage { n: int, } entry boom() { n = 2; " + "n = n * n; " * 14 + "} }"


def new_chain() -> Chain:
    state = {
        "balances": {ALICE.address: 500 * KRN, BOB.address: 500 * KRN},
        "nonces": {},
        "contracts": {},
        "validators": [{"address": BAKER.address, "pubkey": BAKER.public_key_b58, "stake": 1000 * KRN}],
    }
    header = BlockHeader(level=0, payload_round=0, timestamp=int(time.time()), parent_hash="0" * 64,
                         state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                         proposer=BAKER.address, proposer_pubkey=BAKER.public_key_b58)
    header.sign(BAKER)
    return Chain(Block(header=header, transactions=[], commits=[]), state["validators"], initial_state=state)


def proposed(chain: Chain, transactions) -> Block:
    return propose_block(parent=chain.head, mempool=list(transactions), proposer_keypair=BAKER,
                         proposer_pubkey_b58=BAKER.public_key_b58, state_before=chain.state, round_=1)


def next_block(chain: Chain, transactions) -> Block:
    block = proposed(chain, transactions)
    assert [tx.hash() for tx in block.transactions] == [tx.hash() for tx in transactions]
    chain.append(block)
    return block


def test_a_block_is_built_with_a_call_whose_integer_leaves_64_bits():
    """The call that squares 2 fourteen times. Before the bound it
    succeeded, the root of the state it left raised ValueError, and the
    proposer built no block as long as the call was in its mempool."""
    chain = new_chain()
    origination = make_origination(ALICE, SQUARES, None, 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())
    held = chain.state["balances"][ALICE.address]

    boom = make_call(ALICE, address, "boom", {}, nonce=1)
    next_block(chain, [boom, make_transfer(BOB, ALICE.address, 1, 0)])

    assert chain.height == 2
    assert chain.state["contracts"][address]["storage"] == {"n": 0}
    assert chain.state["balances"][ALICE.address] == held - boom.fee + 1
    assert chain.state["nonces"][ALICE.address] == 2
    assert len(state_root_hex(chain.state)) == 64


def test_a_call_that_leaves_a_bound_pays_its_fee_and_changes_nothing_else():
    chain = new_chain()
    origination = make_origination(ALICE, VALUES, None, 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())

    for entry, params, reason in [
        ("mul", {"a": 2 ** 62, "b": 2}, "64 bits"),
        ("join", {"a": "a" * 4096, "b": "b"}, "4096 bytes"),
        ("neg", {"a": INT_MIN}, "64 bits"),
    ]:
        state = copy.deepcopy(chain.state)
        expected = copy.deepcopy(chain.state)
        failed = make_call(ALICE, address, entry, params, amount=3 * KRN, nonce=1)
        result = apply_transaction(state, failed, baker=BAKER.address)
        assert not result.ok and reason in result.error, entry

        expected["balances"][ALICE.address] -= failed.fee
        expected["balances"][BAKER.address] = expected["balances"].get(BAKER.address, 0) + failed.fee
        expected["nonces"][ALICE.address] = 2
        assert state == expected, entry


def sum_of(terms: int) -> str:
    return "contract Sum { storage { n: int, } entry go() { n = " + " + ".join(["1"] * terms) + "; } }"


def in_a_block(code: str) -> str:
    """What becomes of a creation that the proposer puts in a block and
    that the chain then appends, as the node that validates it does."""
    chain = new_chain()
    block = proposed(chain, [make_origination(ALICE, code, None, 0)])
    assert len(block.transactions) == 1
    try:
        chain.append(block)
    except ValueError as error:
        return f"the block of the proposer is refused: {error}"
    return "created" if chain.state["contracts"] else "not created"


def test_the_proposer_and_the_node_that_validates_agree_on_the_deepest_contract():
    """A sum of 63 terms is a statement 64 levels deep. The search goes to
    the longest sum that a block creates, wherever it is: before the
    bound it was near 990 terms, where the proposer, whose stack is two
    frames shorter, still created the contract that the validation
    refused, and its block was refused with `state_root mismatch`."""
    created, refused = 1, 2048
    assert in_a_block(sum_of(created)) == "created" and in_a_block(sum_of(refused)) == "not created"
    while refused - created > 1:
        middle = (created + refused) // 2
        if in_a_block(sum_of(middle)) == "created":
            created = middle
        else:
            refused = middle
    assert in_a_block(sum_of(refused)) == "not created"
    assert (created, refused) == (63, 64)


def test_balance_is_what_the_contract_holds_with_the_amount_of_the_call():
    chain = new_chain()
    origination = make_origination(ALICE, PURSE, None, 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())

    next_block(chain, [make_call(ALICE, address, "look", {}, amount=3 * KRN, nonce=1)])
    assert chain.state["contracts"][address]["storage"] == {"seen": 3 * KRN}
    next_block(chain, [make_call(BOB, address, "look", {}, amount=1 * KRN, nonce=0)])
    assert chain.state["contracts"][address]["storage"] == {"seen": 4 * KRN}
    assert chain.state["balances"][address] == 4 * KRN


def test_a_creation_sees_its_sender_its_address_and_what_was_sent_there_before():
    chain = new_chain()
    origination = make_origination(ALICE, FUNDED, None, 0)
    address = derive_contract_address(origination.hash())

    empty_handed = copy.deepcopy(chain.state)
    result = apply_transaction(empty_handed, origination, baker=BAKER.address)
    assert not result.ok and result.error == "invariant 'funded' violated"

    next_block(chain, [make_transfer(BOB, address, 1, 0)])
    next_block(chain, [origination])
    assert chain.state["contracts"][address]["storage"] == UNTOUCHED


# ---------------------------------------------------------------------------
# The pages
# ---------------------------------------------------------------------------

def page(name: str) -> str:
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def test_the_page_of_the_language_states_the_bounds_of_the_interpreter():
    language = page("skald-language.md")
    assert "## Bounds" in language
    for row in [
        "| An integer | 64 bits, from -2^63 to 2^63 - 1 |",
        f"| A text | {skald.MAX_TEXT_BYTES:,} bytes |",
        f"| An execution | {skald.MAX_STEPS:,} steps |",
        f"| The nesting of the code | {skald.MAX_DEPTH} levels |",
        f"| The nesting of an execution | {skald.MAX_DEPTH} levels |",
    ]:
        assert row in language, row
    assert (skald.INT_MIN, skald.INT_MAX) == (-2 ** 63, 2 ** 63 - 1)
    assert "What `self` holds (in mukrn), with the `amount` of this call." in language
    assert "The current native-token balance" not in language
    assert "takes fewer than 250 frames of that stack" in language
    assert "Per-operation metering is not implemented." in language and "straightforward" not in language


def test_no_page_gives_an_integer_of_a_contract_more_than_64_bits():
    assert "int      — signed integer of 64 bits, from -2^63 to 2^63 - 1" in page("typecheck.md")
    assert "string   — UTF-8 byte sequence, of 4,096 bytes at most" in page("typecheck.md")
    assert "`int` (64 bits), `bool`, `string`, `address`" in page("whitepaper.md")
    for name in ("typecheck.md", "whitepaper.md", "skald-language.md"):
        assert "arbitrary precision" not in page(name).lower().replace("-", " "), name
    stability = page("api-stability.md")
    assert ("| What a contract takes and holds | Any JSON in the transaction. An integer outside 64 bits or a text "
            "beyond 4,096 bytes fails the operation, which pays its fee |") in stability
    assert "a code nested deeper than 64 levels is not read" in stability


# ---------------------------------------------------------------------------
# The contracts of the repository
# ---------------------------------------------------------------------------

EXAMPLES = sorted((ROOT / "kern" / "skald" / "examples").glob("*.skald"))
CREATED_WITH_DEFAULTS = {"counter", "sto-real-estate", "sto-startup-equity", "vault"}


def test_control_the_ten_examples_are_read_as_before():
    assert len(EXAMPLES) == 10
    created = set()
    for path in EXAMPLES:
        code = path.read_text(encoding="utf-8")
        assert type_check(code) == [], path.name
        answer = outcome(lambda: interpret_origination(code, None))
        assert answer == "accepted" or answer.startswith("refused: invariant "), (path.name, answer)
        if answer == "accepted":
            created.add(path.stem)
    assert created == CREATED_WITH_DEFAULTS
