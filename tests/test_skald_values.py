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
# What an execution is given is of its type
# ---------------------------------------------------------------------------
# The three functions put in an execution what their caller gives them:
# `sender`, `amount`, `self` and `balance`. The chain gives the sender and
# the amount of a transaction, the address of the contract and a balance of
# its state. A caller outside a chain gives what it wants, and until this
# part it was taken as it came: a view declared `-> int` returned `True`
# when its balance was `True`. The three functions now refuse, before they
# read the code, a `sender` or a `self` that is not an address and an
# `amount` or a `balance` that is not an integer.

SEEN = """
contract Seen {
    storage { who: address, here: address, paid: int, held: int, n: int, }
    entry look() { who = sender; here = self; paid = amount; held = balance; }
    entry both() { n = amount + balance; }
    entry rest() { n = n + 1; }
    view sum() -> int { return amount + balance; }
    view at() -> address { return self; }
    view idle() -> int { return n; }
}
"""
BLANK = {"who": ZERO, "here": ZERO, "paid": 0, "held": 0, "n": 0}
NOT_AN_ADDRESS = [7, True, 1.5, b"kn1" + b"a" * 33, ["kn1"], "", "abc", "KN1" + "a" * 33, " kn1" + "a" * 33]
NOT_AN_INTEGER = [True, False, None, 1.5, 1.0, "1", "", [1], b"1"]
ADDRESSES_GIVEN = [("origination", "sender"), ("origination", "self_addr"), ("call", "sender"),
                   ("call", "self_addr"), ("view", "self_addr")]
INTEGERS_GIVEN = [("origination", "balance"), ("call", "amount"), ("call", "balance"), ("view", "balance")]


def given(function, **context):
    """One of the three functions on `Seen`, through code that reads nothing
    of what the execution is given."""
    if function == "origination":
        return interpret_origination(SEEN, dict(BLANK), **context)
    if function == "call":
        return interpret_call(SEEN, BLANK, "rest", None,
                              **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})
    return interpret_view(SEEN, BLANK, "idle", None, **context)


def test_control_the_contract_that_looks_at_what_it_is_given_is_well_typed():
    assert type_check(SEEN) == []
    assert given("origination") == BLANK and given("call") == {**BLANK, "n": 1} and given("view") == 0


@pytest.mark.parametrize("function, name", ADDRESSES_GIVEN)
@pytest.mark.parametrize("value", NOT_AN_ADDRESS, ids=repr)
def test_what_is_not_an_address_is_refused_as_the_sender_and_as_the_contract(function, name, value):
    with pytest.raises(SkaldError) as refusal:
        given(function, **{name: value})
    assert str(refusal.value) == f"{'self' if name == 'self_addr' else name}: expected address, got {value!r}"


@pytest.mark.parametrize("function, name", INTEGERS_GIVEN)
@pytest.mark.parametrize("value", NOT_AN_INTEGER, ids=repr)
def test_what_is_not_an_integer_is_refused_as_an_amount_and_as_a_balance(function, name, value):
    with pytest.raises(SkaldError) as refusal:
        given(function, **{name: value})
    assert str(refusal.value) == f"{name}: expected int, got {type(value).__name__}"


@pytest.mark.parametrize("function, name", [("call", "sender"), ("call", "self_addr"), ("view", "self_addr")])
def test_a_call_and_a_view_do_not_take_none_for_an_address(function, name):
    with pytest.raises(SkaldError) as refusal:
        given(function, **{name: None})
    assert str(refusal.value) == f"{'self' if name == 'self_addr' else name}: expected address, got None"


ALONE = "contract Alone { storage { n: int, } invariant alone { sender == self } invariant empty { balance == 0 } }"


def test_control_an_origination_that_is_given_no_address_still_sees_the_zero_address():
    """Outside a chain, a caller that leaves `sender` and `self_addr` out,
    or gives `None`, gets the zero address for both, and a balance of 0."""
    assert interpret_origination(ALONE, None) == {"n": 0}
    assert interpret_origination(ALONE, None, sender=None, self_addr=None, balance=0) == {"n": 0}
    assert interpret_origination(ALONE, None, sender=ZERO, self_addr=ZERO) == {"n": 0}
    with pytest.raises(SkaldError, match="invariant 'alone' violated"):
        interpret_origination(ALONE, None, sender=SOMEONE, self_addr=ITSELF)
    with pytest.raises(SkaldError, match="invariant 'empty' violated"):
        interpret_origination(ALONE, None, balance=1)


@pytest.mark.parametrize("address", [ZERO, SOMEONE, ITSELF, "kn1", "kn1x"])
def test_control_a_text_that_starts_with_kn1_is_taken_for_an_address(address):
    """The check is the one a value of the type `address` gets, and no more:
    it does not ask for a whole address."""
    for function, name in ADDRESSES_GIVEN:
        given(function, **{name: address})
    seen = interpret_call(SEEN, BLANK, "look", None, sender=address, amount=0, self_addr=address)
    assert (seen["who"], seen["here"]) == (address, address)
    assert interpret_view(SEEN, BLANK, "at", None, self_addr=address) == address


@pytest.mark.parametrize("value", [0, 1, -1, 7, INT_MIN, INT_MAX])
def test_control_an_integer_is_taken_for_an_amount_and_for_a_balance(value):
    """A negative one too: the language has no unsigned type, and the chain
    gives none."""
    for function, name in INTEGERS_GIVEN:
        given(function, **{name: value})
    seen = interpret_call(SEEN, BLANK, "look", None, sender=SOMEONE, amount=value, self_addr=ITSELF, balance=value)
    assert (seen["paid"], seen["held"]) == (value, value)
    assert type(seen["paid"]) is int and type(seen["held"]) is int
    assert interpret_view(SEEN, BLANK, "sum", None, balance=value) == value


def test_a_refusal_comes_before_the_code_is_read():
    """The answer does not depend on the code: one that does not read, an
    entry or a view that does not exist, and the value is still what is
    refused."""
    with pytest.raises(SkaldError) as refusal:
        interpret_origination("not a contract", None, sender=7)
    assert str(refusal.value) == "sender: expected address, got 7"
    with pytest.raises(SkaldError) as refusal:
        interpret_origination("not a contract", None, balance=True)
    assert str(refusal.value) == "balance: expected int, got bool"
    for code, entry in (("not a contract", "rest"), (SEEN, "missing"), (SEEN, "idle")):
        with pytest.raises(SkaldError) as refusal:
            interpret_call(code, BLANK, entry, None, sender=SOMEONE, amount="3", self_addr=ITSELF)
        assert str(refusal.value) == "amount: expected int, got str"
    for code, view in (("not a contract", "idle"), (SEEN, "missing"), (SEEN, "rest")):
        with pytest.raises(SkaldError) as refusal:
            interpret_view(code, BLANK, view, None, self_addr=7)
        assert str(refusal.value) == "self: expected address, got 7"
    # The values are checked before the parameters are.
    with pytest.raises(SkaldError) as refusal:
        interpret_call(TYPED, START, "set", {"by": True}, sender=SOMEONE, amount=0, self_addr=ITSELF, balance=None)
    assert str(refusal.value) == "balance: expected int, got NoneType"


def test_control_a_code_that_does_not_read_is_refused_as_before_when_what_it_is_given_is_right():
    with pytest.raises(SkaldError, match="expected one of .'contract',. at pos 0, got ID 'not'"):
        interpret_origination("not a contract", None, sender=SOMEONE, self_addr=ITSELF, balance=1)
    with pytest.raises(SkaldError, match="no such entry: missing"):
        interpret_call(SEEN, BLANK, "missing", None, sender=SOMEONE, amount=0, self_addr=ITSELF)
    with pytest.raises(SkaldError, match="no such view: missing"):
        interpret_view(SEEN, BLANK, "missing", None, self_addr=ITSELF, balance=1)


@pytest.mark.parametrize("value", [True, "7", None, 1.5, [1]], ids=repr)
def test_a_view_does_not_return_a_balance_that_is_not_an_integer(value):
    """Declared `-> int`, it returned its balance as it came, or computed
    with it: `0 + True` is 1."""
    with pytest.raises(SkaldError) as refusal:
        interpret_view(SEEN, BLANK, "sum", None, self_addr=ITSELF, balance=value)
    assert str(refusal.value) == f"balance: expected int, got {type(value).__name__}"
    with pytest.raises(SkaldError) as refusal:
        interpret_view(TYPED, START, "held", {}, balance=value)
    assert str(refusal.value) == f"balance: expected int, got {type(value).__name__}"


@pytest.mark.parametrize("value", [7, True, None], ids=repr)
def test_a_view_does_not_return_a_contract_that_is_not_an_address(value):
    with pytest.raises(SkaldError) as refusal:
        interpret_view(SEEN, BLANK, "at", None, self_addr=value)
    assert str(refusal.value) == f"self: expected address, got {value!r}"


def test_a_call_does_not_compute_with_a_boolean():
    """`amount + balance` wrote 2 in an integer field when both were `True`."""
    with pytest.raises(SkaldError, match="expected int, got bool"):
        interpret_call(SEEN, BLANK, "both", None, sender=SOMEONE, amount=True, self_addr=ITSELF, balance=True)
    for name in ("amount", "balance"):
        with pytest.raises(SkaldError) as refusal:
            interpret_call(SEEN, BLANK, "both", None,
                           **{"sender": SOMEONE, "amount": 1, "self_addr": ITSELF, "balance": 1, name: True})
        assert str(refusal.value) == f"{name}: expected int, got bool"
    after = interpret_call(SEEN, BLANK, "both", None, sender=SOMEONE, amount=1, self_addr=ITSELF, balance=1)
    assert after["n"] == 2 and type(after["n"]) is int


def test_control_a_refused_execution_leaves_the_storage_it_was_given():
    storage = dict(BLANK)
    for context in ({"sender": 7}, {"self_addr": None}, {"amount": True}, {"balance": "1"}):
        with pytest.raises(SkaldError):
            interpret_call(SEEN, storage, "look", None,
                           **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})
    assert storage == BLANK


def test_control_a_bound_is_still_checked_where_an_expression_reads_the_value():
    """An integer outside 64 bits is an integer, and a text of more than
    4,096 bytes that starts with `kn1` passes the check of an address: the
    execution that reads one fails as before, and the one that does not
    read it passes as before."""
    big, long = INT_MAX + 1, "kn1" + "a" * 4094
    assert given("call", amount=big, balance=big) == {**BLANK, "n": 1}
    assert given("call", sender=long, self_addr=long) == {**BLANK, "n": 1}
    assert given("view", balance=big) == 0 and given("view", self_addr=long) == 0
    assert given("origination", sender=long, self_addr=long, balance=big) == BLANK
    for context in ({"amount": big}, {"balance": big}, {"amount": INT_MIN - 1}):
        with pytest.raises(SkaldError, match="an integer is 64 bits"):
            interpret_call(SEEN, BLANK, "look", None,
                           **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})
    for context in ({"sender": long}, {"self_addr": long}):
        with pytest.raises(SkaldError, match="a text is 4096 bytes at most"):
            interpret_call(SEEN, BLANK, "look", None,
                           **{"sender": SOMEONE, "amount": 0, "self_addr": ITSELF, **context})
    with pytest.raises(SkaldError, match="an integer is 64 bits"):
        interpret_view(SEEN, BLANK, "sum", None, balance=big)
    with pytest.raises(SkaldError, match="a text is 4096 bytes at most"):
        interpret_view(SEEN, BLANK, "at", None, self_addr=long)


def test_control_in_a_block_an_execution_is_given_addresses_and_integers():
    """What the chain gives: the sender and the amount of a transaction, the
    address of the contract and a balance of its state. The proposer and
    the node that validates agree, as before."""
    chain = new_chain()
    watched = SEEN.replace("view idle", "invariant kept { sender != self }\n    view idle")
    origination = make_origination(ALICE, watched, dict(BLANK), 0)
    next_block(chain, [origination])
    address = derive_contract_address(origination.hash())
    assert chain.state["contracts"][address]["storage"] == BLANK

    next_block(chain, [make_call(BOB, address, "look", {}, amount=3 * KRN, nonce=0),
                       make_call(ALICE, address, "rest", {}, nonce=1)])
    assert chain.height == 2
    storage = chain.state["contracts"][address]["storage"]
    assert storage == {"who": BOB.address, "here": address, "paid": 3 * KRN, "held": 3 * KRN, "n": 1}
    assert all(type(storage[name]) is int for name in ("paid", "held", "n"))
    assert address.startswith("kn1") and BOB.address.startswith("kn1")


def test_in_the_chain_an_execution_refused_at_its_entry_fails_like_any_other():
    """The chain reads a balance in its state, and it writes only integers
    there. This state is one it never writes, with `True` for what a
    contract holds: it is here to show what the chain does with the
    refusal. The operation fails like one whose `require` refuses: it pays
    its fee, its nonce is taken, and nothing else changes."""
    chain = new_chain()
    first = make_origination(ALICE, SEEN, dict(BLANK), 0)
    next_block(chain, [first])
    address = derive_contract_address(first.hash())
    before = copy.deepcopy(chain.state)
    before["balances"][address] = True

    resting = make_call(BOB, address, "rest", {}, nonce=0)
    state = copy.deepcopy(before)
    result = apply_transaction(state, resting, baker=BAKER.address)
    assert not result.ok and result.error == "balance: expected int, got bool"
    assert state == charged(before, resting) and state["contracts"][address]["storage"] == BLANK

    second = make_origination(ALICE, SEEN, dict(BLANK), 1)
    before["balances"][derive_contract_address(second.hash())] = True
    state = copy.deepcopy(before)
    result = apply_transaction(state, second, baker=BAKER.address)
    assert not result.ok and result.error == "balance: expected int, got bool"
    assert state == charged(before, second) and list(state["contracts"]) == [address]


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


def test_the_page_says_that_what_an_execution_is_given_is_of_its_type():
    notes = PAGE[PAGE.index("## Implementation notes"):]
    assert ("What an execution is given is of its type: `sender` and `self_addr` are texts that start with `kn1`, "
            "which is what the type `address` asks of a value, and `amount` and `balance` are integers, which "
            "`true` and `false` are not. A caller that gives anything else is refused before the code is read, "
            "whether the code reads the value or not. The bounds are checked as before, where an expression "
            "reads the value.") in notes


def test_the_page_of_the_checker_says_when_an_origination_checks_the_types():
    """Before anything is done with the code, and after the check of what
    the origination is given."""
    checker = (ROOT / "docs" / "typecheck.md").read_text(encoding="utf-8")
    assert "calls the type-checker before it does anything with the code:" in checker
    assert "as its first step" not in checker
    wrong = "contract Wrong { storage { n: int, } entry set() { n = true; } }"
    assert type_check(wrong) != []
    with pytest.raises(SkaldError, match="type errors in contract"):
        interpret_origination(wrong, None)
    with pytest.raises(SkaldError) as refusal:
        interpret_origination(wrong, None, balance=True)
    assert str(refusal.value) == "balance: expected int, got bool"


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
