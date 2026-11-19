# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A value has the type its contract declares.

Until this file the check of a value of type `int` took a boolean: Python
counts `True` and `False` among its integers. A contract was created with
`true` in an integer field, a call gave `true` to an integer parameter, and
the storage kept `true` where an integer was declared. The reverse was
refused already: 1 was never a boolean.

An integer is an integer and nothing else, wherever a value takes a type:
a value of the initial storage, a parameter, a value written to a field, a
`let`. What is not of its type fails like a `require` that refuses: the
operation pays its fee, its nonce is taken, and nothing else changes.

And a view sees what its contract holds. `interpret_view` takes `balance`,
which its caller reads in the state; without it a view saw 0, whatever the
contract held, where the page of the language said that `balance` is what
the contract holds.
"""

import copy
import inspect
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kern.block import Block, BlockHeader, txs_merkle_root_hex  # noqa: E402
from kern.chain import Chain, apply_transaction, derive_contract_address, state_root_hex  # noqa: E402
from kern.consensus import propose_block  # noqa: E402
from kern.crypto import KernKeypair  # noqa: E402
from kern.skald import SkaldError, interpret_call, interpret_origination, interpret_view  # noqa: E402
from kern.skald.typecheck import type_check  # noqa: E402
from kern.transaction import make_call, make_origination  # noqa: E402

INT_MIN, INT_MAX = -(2 ** 63), 2 ** 63 - 1
ZERO = "kn1" + "0" * 33
SOMEONE = "kn1" + "a" * 33
ITSELF = "kn1" + "c" * 33

TYPED = """
contract Typed {
    storage { count: int, flag: bool, label: string, owner: address, }
    entry set(by: int) { count = by; }
    entry add(by: int) { count = count + by; }
    entry turn(on: bool) { flag = on; }
    entry name(text: string) { label = text; }
    entry give(to: address) { owner = to; }
    entry keep() { count = count; }
    entry copy() { let seen: int = count; count = seen + 0; }
    internal same(n: int) -> int { return n; }
    entry through() { count = same(count) + 0; }
    view held() -> int { return balance; }
    view who() -> address { return sender; }
    view paid() -> int { return amount; }
    view here() -> address { return self; }
    view total() -> int { return count + count; }
    view plus(n: int) -> int { return count + n; }
}
"""
START = {"count": 5, "flag": False, "label": "", "owner": ZERO}
BOOLEANS = [True, False]


def call(entry, params=None, storage=None, **context):
    """The storage after `entry(params)`, called by SOMEONE with no amount."""
    return interpret_call(TYPED, START if storage is None else storage, entry, params,
                          **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})


def test_control_the_contract_of_these_tests_is_well_typed():
    assert type_check(TYPED) == []
    assert interpret_origination(TYPED, None) == {"count": 0, "flag": False, "label": "", "owner": ZERO}


# ---------------------------------------------------------------------------
# An integer is an integer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", BOOLEANS)
def test_a_boolean_is_not_an_integer_in_the_initial_storage(value):
    with pytest.raises(SkaldError, match=r"^initial_storage\.count: expected int, got bool$"):
        interpret_origination(TYPED, {"count": value})


@pytest.mark.parametrize("value", BOOLEANS)
@pytest.mark.parametrize("form", ["by name", "in a list", "alone"])
def test_a_boolean_is_not_an_integer_as_a_parameter(value, form):
    """The three forms a call carries its parameters in today."""
    params = {"by name": {"by": value}, "in a list": [value], "alone": value}[form]
    for entry in ("set", "add"):
        with pytest.raises(SkaldError, match=r"^" + entry + r"\(by\): expected int, got bool$"):
            call(entry, params)


@pytest.mark.parametrize("value", BOOLEANS)
def test_a_boolean_is_not_an_integer_for_a_view(value):
    with pytest.raises(SkaldError, match=r"^plus\(n\): expected int, got bool$"):
        interpret_view(TYPED, START, "plus", {"n": value})


@pytest.mark.parametrize("value", [0, 1, -1, 7, INT_MIN, INT_MAX])
def test_control_an_integer_is_an_integer(value):
    assert interpret_origination(TYPED, {"count": value})["count"] == value
    kept = call("set", {"by": value})["count"]
    assert kept == value and type(kept) is int
    assert call("set", [value])["count"] == value and call("set", value)["count"] == value


@pytest.mark.parametrize("value", BOOLEANS)
def test_control_a_boolean_is_a_boolean(value):
    assert interpret_origination(TYPED, {"flag": value})["flag"] is value
    assert call("turn", {"on": value})["flag"] is value


@pytest.mark.parametrize("value", [0, 1])
def test_control_an_integer_is_not_a_boolean(value):
    with pytest.raises(SkaldError, match=r"^initial_storage\.flag: expected bool, got int$"):
        interpret_origination(TYPED, {"flag": value})
    with pytest.raises(SkaldError, match=r"^turn\(on\): expected bool, got int$"):
        call("turn", {"on": value})


@pytest.mark.parametrize("value, named", [(1.0, "float"), (1.5, "float"), ("1", "str"), (None, "NoneType"),
                                          ([1], "list"), ({"n": 1}, "dict")])
def test_control_nothing_else_is_an_integer(value, named):
    with pytest.raises(SkaldError, match=r"^initial_storage\.count: expected int, got " + named + "$"):
        interpret_origination(TYPED, {"count": value})
    with pytest.raises(SkaldError, match=r"^set\(by\): expected int, got " + named + "$"):
        call("set", {"by": value})


def test_control_a_text_and_an_address_are_texts():
    assert call("name", {"text": "seven"})["label"] == "seven"
    assert call("give", {"to": SOMEONE})["owner"] == SOMEONE
    for entry, params in (("name", {"text": True}), ("name", {"text": 7}), ("give", {"to": True}),
                          ("give", {"to": 7}), ("give", {"to": "seven"})):
        with pytest.raises(SkaldError, match="expected"):
            call(entry, params)


def test_a_refused_parameter_leaves_the_storage_it_was_given():
    storage = dict(START)
    with pytest.raises(SkaldError):
        call("set", {"by": True}, storage)
    assert storage == START and type(storage["count"]) is int


# A state from before this check can hold `true` in an integer field. It is
# read as before, and counts for 1. Written back as it is, where a value
# takes the type `int`, it is refused like any boolean.
LEFT = {**START, "count": True}


def test_control_a_boolean_left_in_an_integer_field_is_read_as_before():
    assert call("add", {"by": 1}, LEFT)["count"] == 2
    assert interpret_view(TYPED, LEFT, "total", {}) == 2
    assert call("turn", {"on": True}, LEFT) == {**LEFT, "flag": True}


@pytest.mark.parametrize("entry, where", [("keep", "storage.count"), ("copy", "let seen"), ("through", "same(n)")])
def test_a_boolean_left_in_an_integer_field_is_not_written_back_as_an_integer(entry, where):
    with pytest.raises(SkaldError) as refusal:
        call(entry, None, LEFT)
    assert str(refusal.value) == f"{where}: expected int, got bool"


@pytest.mark.parametrize("entry", ["keep", "copy", "through"])
def test_control_an_integer_is_written_back(entry):
    assert call(entry) == START


# ---------------------------------------------------------------------------
# In a block
# ---------------------------------------------------------------------------

KRN = 1_000_000
BAKER, ALICE, BOB = (KernKeypair.from_seed(bytes([seed]) * 32) for seed in (1, 3, 4))


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


def next_block(chain: Chain, transactions) -> Block:
    block = propose_block(parent=chain.head, mempool=list(transactions), proposer_keypair=BAKER,
                          proposer_pubkey_b58=BAKER.public_key_b58, state_before=chain.state, round_=1)
    assert [tx.hash() for tx in block.transactions] == [tx.hash() for tx in transactions]
    chain.append(block)
    return block


def charged(state: dict, tx) -> dict:
    """`state` once `tx` has paid its fee and taken its nonce, and nothing else."""
    after = copy.deepcopy(state)
    after["balances"][tx.sender] -= tx.fee
    after["balances"][BAKER.address] = after["balances"].get(BAKER.address, 0) + tx.fee
    after["nonces"][tx.sender] = tx.nonce + 1
    return after


@pytest.mark.parametrize("value", BOOLEANS)
def test_a_creation_that_gives_a_boolean_to_an_integer_fails_and_pays_its_fee(value):
    chain = new_chain()
    origination = make_origination(ALICE, TYPED, {"count": value}, 0)
    state = copy.deepcopy(chain.state)
    result = apply_transaction(state, origination, baker=BAKER.address)
    assert not result.ok and result.error == "initial_storage.count: expected int, got bool"
    assert state == charged(chain.state, origination) and state["contracts"] == {}

    next_block(chain, [origination])
    assert chain.height == 1 and chain.state["contracts"] == {}
    assert derive_contract_address(origination.hash()) not in chain.state["balances"]


@pytest.mark.parametrize("value", BOOLEANS)
def test_a_call_that_gives_a_boolean_to_an_integer_fails_pays_its_fee_and_changes_nothing_else(value):
    chain = new_chain()
    origination = make_origination(ALICE, TYPED, {"count": 5}, 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())
    assert chain.state["contracts"][address]["storage"] == START

    refused = make_call(ALICE, address, "set", {"by": value}, amount=3 * KRN, nonce=1)
    state = copy.deepcopy(chain.state)
    result = apply_transaction(state, refused, baker=BAKER.address)
    assert not result.ok and result.error == "set(by): expected int, got bool"
    assert state == charged(chain.state, refused)                  # the amount of the call has not moved

    # The proposer and the node that validates agree, and the next call finds the integer it left.
    next_block(chain, [refused, make_call(ALICE, address, "add", {"by": 2}, amount=1 * KRN, nonce=2)])
    assert chain.height == 2
    assert chain.state["contracts"][address]["storage"] == {**START, "count": 7}
    assert chain.state["balances"][address] == 1 * KRN
    assert len(state_root_hex(chain.state)) == 64


def test_control_a_call_that_gives_an_integer_passes_in_a_block():
    chain = new_chain()
    origination = make_origination(ALICE, TYPED, {"count": 5, "flag": True}, 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())
    next_block(chain, [make_call(BOB, address, "set", {"by": 1}, nonce=0),
                       make_call(BOB, address, "turn", {"on": False}, nonce=1)])
    assert chain.state["contracts"][address]["storage"] == {**START, "count": 1}


# ---------------------------------------------------------------------------
# A view sees what its contract holds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("held", [1, 7, 3 * KRN, INT_MAX])
def test_a_view_sees_the_balance_its_caller_gives_it(held):
    assert interpret_view(TYPED, START, "held", {}, self_addr=ITSELF, balance=held) == held


def test_control_a_view_that_is_given_no_balance_sees_none():
    assert interpret_view(TYPED, START, "held", {}) == 0
    assert interpret_view(TYPED, START, "held", {}, self_addr=ITSELF) == 0


def test_balance_is_a_named_argument_of_a_view_and_is_0_when_it_is_left_out():
    parameters = inspect.signature(interpret_view).parameters
    assert list(parameters) == ["code", "storage", "view", "params", "self_addr", "balance"]
    assert parameters["balance"].kind is inspect.Parameter.KEYWORD_ONLY and parameters["balance"].default == 0
    assert parameters["self_addr"].kind is inspect.Parameter.KEYWORD_ONLY


def test_control_a_view_has_no_sender_and_no_amount():
    """Nobody signs a view, and nothing is paid to it."""
    assert interpret_view(TYPED, START, "who", {}, self_addr=ITSELF) == ZERO
    assert interpret_view(TYPED, START, "paid", {}, self_addr=ITSELF) == 0
    assert interpret_view(TYPED, START, "here", {}, self_addr=ITSELF) == ITSELF


def test_a_view_that_is_given_a_balance_still_has_no_sender_and_no_amount():
    assert interpret_view(TYPED, START, "who", {}, self_addr=ITSELF, balance=7) == ZERO
    assert interpret_view(TYPED, START, "paid", {}, self_addr=ITSELF, balance=7) == 0
    assert interpret_view(TYPED, START, "here", {}, self_addr=ITSELF, balance=7) == ITSELF


def test_a_balance_outside_64_bits_fails_the_view_that_reads_it():
    """What a view is given is within the bounds of what a contract computes."""
    with pytest.raises(SkaldError, match="an integer is 64 bits"):
        interpret_view(TYPED, START, "held", {}, balance=INT_MAX + 1)
    assert interpret_view(TYPED, START, "total", {}, balance=INT_MAX + 1) == 10     # a view that does not read it


def test_control_a_call_and_a_creation_are_given_their_balance_as_before():
    purse = "contract Purse { storage { seen: int, } entry look() { seen = balance; } }"
    after = interpret_call(purse, {"seen": 0}, "look", {}, sender=SOMEONE, amount=3, self_addr=ITSELF, balance=10)
    assert after == {"seen": 10}
    funded = "contract Funded { storage { n: int, } invariant funded { balance > 0 } }"
    assert interpret_origination(funded, None, sender=SOMEONE, self_addr=ITSELF, balance=1) == {"n": 0}
    with pytest.raises(SkaldError, match="invariant 'funded' violated"):
        interpret_origination(funded, None, sender=SOMEONE, self_addr=ITSELF)


# ---------------------------------------------------------------------------
# The page of the language
# ---------------------------------------------------------------------------

PAGE = (ROOT / "docs" / "skald-language.md").read_text(encoding="utf-8")


def test_the_page_says_that_a_type_takes_nothing_else():
    rules = PAGE[PAGE.index("## Storage rules"):PAGE.index("## Invariants")]
    assert ("A value given from outside, an initial value or a parameter, is checked the same way, and a type takes "
            "nothing else: `true` and `false` are not integers, and `1` is not a boolean.") in rules


def test_the_page_says_what_a_view_sees():
    names = PAGE[PAGE.index("## Built-in identifiers"):PAGE.index("## Function classes")]
    assert "These are available in every entry/view body:" in names
    assert ("A view is not part of a transaction: nobody signs it and nothing is paid to it. Its `sender` is the "
            "zero address and its `amount` is 0. Its `self` and its `balance` are what its caller gives it, and a "
            "caller that gives no balance gives 0. Nothing in the node calls a view yet: whatever does must read "
            "in the state what the contract holds.") in names
    notes = PAGE[PAGE.index("## Implementation notes"):]
    assert "interpret_view(code, storage, view, params, *, self_addr=..., balance=0) -> Any" in notes
    assert "interpret_view(code, storage, view, params, *, self_addr=...) -> Any" not in PAGE


def test_control_the_page_still_says_what_a_call_and_a_creation_see():
    names = PAGE[PAGE.index("## Built-in identifiers"):PAGE.index("## Function classes")]
    assert "| `balance` | `int`     | What `self` holds (in mukrn), with the `amount` of this call. |" in names
    assert "At origination, the invariants see the account that creates the contract as `sender`" in names


# ---------------------------------------------------------------------------
# The examples
# ---------------------------------------------------------------------------

EXAMPLES = sorted((ROOT / "kern" / "skald" / "examples").glob("*.skald"))
CREATED_WITH_DEFAULTS = {"counter", "sto-real-estate", "sto-startup-equity", "vault"}


def test_control_the_examples_are_created_as_before():
    assert len(EXAMPLES) == 10
    created = set()
    for path in EXAMPLES:
        code = path.read_text(encoding="utf-8")
        assert type_check(code) == [], path.name
        try:
            storage = interpret_origination(code, None)
        except SkaldError:
            continue                                      # an example that asks for its initial values
        created.add(path.stem)
        assert all(type(value) in (int, bool, str) for value in storage.values()), path.name
    assert created == CREATED_WITH_DEFAULTS
