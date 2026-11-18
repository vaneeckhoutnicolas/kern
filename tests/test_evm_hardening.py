# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""What a trace shares, what a call checks before it copies the world, and
what a static call may carry.

Five things were loose around the Mini-EVM. The node reaches none of them:
it calls no contract and builds no trace by hand. They are the edges of a
library that is exported.

- A context could not be assigned to, and could still be written through
  its dictionary. An execution kept the very object it was given, and a
  state read from a trace carried the object of the trace: what was written
  into either changed every state of the trace. A context has no dictionary
  now, an execution works on a copy of the context it is given, and a state
  read from a trace is a copy of the whole state.
- A trace built by hand kept the two states it was given, and checked
  nothing. It keeps copies, and refuses what is not a program of the
  machine, a state of it or a count.
- A call read the size of a storage before it copied the world, and the
  rest after: a program or a slot that the machine refuses cost a copy of
  every account. All of it is checked first now, and a call that cannot
  start copies nothing.
- An account whose code had no length made a call raise after its value had
  moved, and nothing came back.
- A call marked static that carried a value did not run, whatever its kind,
  and gave no gas back. A DELEGATECALL moves no value: marked static, it
  runs, its program reads the value and cannot write, as in Ethereum. A
  CALL or a STATICCALL that carries one still does not run, and gives back
  all its gas, like any call that does not start.

A test named `test_control_...` passed before these rules and still does: it
shows that what the others catch is the rule that was missing, and not the
way they are written.
"""

from __future__ import annotations

import copy
import dataclasses
import pickle
import sys
import tracemalloc
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.evm import (
    Account,
    ExecContext,
    FrameKind,
    Op,
    VmState,
    WorldState,
    call_contract,
    execute,
    run,
    step,
)
from kern.evm import frames, vm

ROOT = Path(__file__).resolve().parent.parent
STABILITY = ROOT / "docs" / "api-stability.md"
CALLS_PAGE = ROOT / "docs" / "multi-frame-evm.md"

JUMPDEST = 0x5B                                          # the byte, written here as a number
GAS = 100_000
CODE_BYTES = 1_048_576                                   # the longest program, written here as a number
CONTEXT = dict(address=7, caller=9, value=3, calldata=b"\x05" * 32, block_number=4, block_timestamp=6)
OTHER_CALLDATA = b"\x01" * 32


def push(value: int) -> bytes:
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


def write(slot: int, value: int) -> bytes:
    return push(value) + push(slot) + bytes([Op.SSTORE])


def returned(value: int) -> bytes:
    return value.to_bytes(32, "big")


def section(page: Path, title: str) -> str:
    """The text of a section of a page, from its title to the next title of
    the same depth or of a lesser one."""
    text = page.read_text(encoding="utf-8")
    start = text.index("\n" + title)
    depth = len(title) - len(title.lstrip("#"))
    end = len(text)
    for marks in range(1, depth + 1):
        found = text.find("\n" + "#" * marks + " ", start + 1)
        if found != -1:
            end = min(end, found)
    return text[start:end]


def written(target, **values) -> None:
    """Past the dataclass: Python lets `object.__setattr__` through on any
    object, a frozen one included."""
    for name, value in values.items():
        object.__setattr__(target, name, value)


# ---------------------------------------------------------------------------
# A trace shares no context with the code that built it or that reads it
# ---------------------------------------------------------------------------

# Keeps the first word of its calldata in slot 1: every commitment after the
# first step depends on the context, and the storage does too.
KEEPS_ITS_CALLDATA = push(0) + bytes([Op.CALLDATALOAD]) + push(1) + bytes([Op.SSTORE]) + push(2) + bytes([Op.STOP])


def a_trace():
    given = ExecContext(**CONTEXT)
    return given, execute(KEEPS_ITS_CALLDATA, gas=GAS, context=given)


def is_whole(trace) -> bool:
    """Every state read again hashes to its commitment, and the last one
    kept what the calldata of the execution said."""
    return ([state.commitment() for state in trace.states] == trace.commitments
            and trace.states[-1].storage == {1: int.from_bytes(CONTEXT["calldata"], "big")}
            and all(state.context == ExecContext(**CONTEXT) for state in trace.states))


def test_a_context_has_no_dictionary_to_write_into():
    """`vars(context)["calldata"] = ...` was accepted on a context that
    could not be assigned to."""
    context = ExecContext(**CONTEXT)
    assert not hasattr(context, "__dict__")
    with pytest.raises(TypeError):
        vars(context)


def test_a_context_takes_no_attribute_more():
    context = ExecContext(**CONTEXT)
    with pytest.raises(AttributeError):
        written(context, note="one more")
    assert vm.not_a_state(VmState(gas=GAS, context=context)) is None


def test_what_is_written_into_the_context_given_to_an_execution_changes_nothing_in_its_trace():
    """The trace held the object it was given: its nine states out of nine
    stopped hashing to their commitments."""
    given, trace = a_trace()
    assert is_whole(trace)
    written(given, calldata=OTHER_CALLDATA, value=8)
    assert given.calldata == OTHER_CALLDATA
    assert is_whole(trace)


def test_a_run_works_on_a_copy_of_the_context_it_is_given():
    given = ExecContext(**CONTEXT)
    final = run(KEEPS_ITS_CALLDATA, gas=GAS, context=given)
    assert final.context is not given and final.context == given
    written(given, calldata=OTHER_CALLDATA)
    assert final.context == ExecContext(**CONTEXT)


READINGS = {
    "its first state": lambda states: [states[0]],
    "a state in the middle": lambda states: [states[3]],
    "its last state": lambda states: [states[-1]],
    "a slice of it": lambda states: states[1:4],
    "all of it, one after the other": lambda states: list(states),
}


@pytest.mark.parametrize("name", sorted(READINGS))
def test_what_is_written_into_the_context_of_a_state_read_from_a_trace_changes_nothing_in_the_trace(name):
    _, trace = a_trace()
    for state in READINGS[name](trace.states):
        written(state.context, calldata=OTHER_CALLDATA, address=1)
        assert state.context.calldata == OTHER_CALLDATA
    assert is_whole(trace)


@pytest.mark.parametrize("position", [0, 3, -1])
def test_two_readings_of_a_state_of_a_trace_share_nothing(position):
    _, trace = a_trace()
    one, other = trace.states[position], trace.states[position]
    assert one == other
    for name in ("stack", "memory", "storage", "context"):
        assert getattr(one, name) is not getattr(other, name), name


def test_control_a_context_cannot_be_assigned_to():
    context = ExecContext(**CONTEXT)
    for name, value in dict(CONTEXT, calldata=OTHER_CALLDATA).items():
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(context, name, value)
    assert context == ExecContext(**CONTEXT)


def test_control_a_context_is_copied_compared_and_carried_by_its_values():
    context = ExecContext(**CONTEXT)
    assert dataclasses.asdict(context) == CONTEXT
    assert dataclasses.replace(context, value=5) == ExecContext(**{**CONTEXT, "value": 5})
    for twin in (copy.copy(context), copy.deepcopy(context), pickle.loads(pickle.dumps(context)),
                 dataclasses.replace(context)):
        assert twin == context and hash(twin) == hash(context)
    assert context.to_dict()["calldata"] == CONTEXT["calldata"].hex()


def test_control_the_states_of_a_run_share_their_context():
    """No copy at each step: a step gives a state that carries the context
    of the state it was given."""
    state = VmState(gas=GAS, context=ExecContext(**CONTEXT))
    after = step(state, KEEPS_ITS_CALLDATA)
    assert after.context is state.context and after is not state


def test_control_the_machine_takes_no_step_from_a_state_whose_context_lost_a_field():
    context = ExecContext(**CONTEXT)
    object.__delattr__(context, "calldata")
    state = VmState(gas=GAS, context=context)
    assert vm.not_a_state(state) == "its context is not an ExecContext"
    with pytest.raises(ValueError, match="its context is not an ExecContext"):
        step(state, KEEPS_ITS_CALLDATA)


# ---------------------------------------------------------------------------
# A trace built by hand
# ---------------------------------------------------------------------------

def built_by_hand():
    _, trace = a_trace()
    first, last = trace.states[0], trace.states[-1]
    return trace, first, last, vm.TraceStates(KEEPS_ITS_CALLDATA, first, last, trace.n_steps)


def reads_like(built, trace) -> bool:
    return ([state.commitment() for state in built] == trace.commitments
            and [built[position].commitment() for position in range(len(built))] == trace.commitments
            and built[-1].commitment() == trace.commitments[-1] and len(built) == trace.n_steps + 1)


def test_control_a_trace_built_by_hand_from_the_states_of_an_execution_reads_like_it():
    trace, _, _, built = built_by_hand()
    assert reads_like(built, trace)


@pytest.mark.parametrize("which", ["the first state", "the last state"])
def test_what_is_done_to_a_state_given_to_a_trace_built_by_hand_changes_nothing_in_it(which):
    """The trace kept the two objects: changing the first one changed
    every state it gave afterwards."""
    trace, first, last, built = built_by_hand()
    state = first if which == "the first state" else last
    state.gas -= 1_000
    state.stack.append(1)
    state.memory.extend(bytes(32))
    state.storage[9] = 9
    written(state.context, calldata=OTHER_CALLDATA)
    assert reads_like(built, trace)


def a_state_whose_stack_holds_a_text() -> VmState:
    return VmState(gas=GAS, stack=["1"])


NOT_A_TRACE = {
    "a first state that is a text": (dict(first="a state"), "it is not a VmState"),
    "a first state whose stack holds a text": (dict(first=a_state_whose_stack_holds_a_text()),
                                               "its stack holds something other than a word"),
    "a last state that is nothing": (dict(last=None), "it is not a VmState"),
    "a last state that is reverted and not halted": (dict(last=VmState(gas=GAS, reverted=True)),
                                                     "it is reverted and not halted"),
    "a program that is a bytearray": (dict(code=bytearray(KEEPS_ITS_CALLDATA)), "it is not bytes"),
    "a program beyond the limit": (dict(code=bytes(CODE_BYTES + 1)), "it is beyond the limit"),
    "a negative number of steps": (dict(n_steps=-1), "its number of steps is not a count"),
    "a number of steps that is a boolean": (dict(n_steps=True), "its number of steps is not a count"),
    "a number of steps that is a text": (dict(n_steps="6"), "its number of steps is not a count"),
    "a number of steps with a fraction": (dict(n_steps=6.0), "its number of steps is not a count"),
}


@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in NOT_A_TRACE])
def test_a_trace_built_by_hand_refuses_what_is_not_a_program_a_state_or_a_count(name):
    """It took anything, and failed later, or never."""
    changes, reason = NOT_A_TRACE[name]
    trace, first, last, _ = built_by_hand()
    given = {**dict(code=KEEPS_ITS_CALLDATA, first=first, last=last, n_steps=trace.n_steps), **changes}
    with pytest.raises(ValueError, match=reason):
        vm.TraceStates(given["code"], given["first"], given["last"], given["n_steps"])


def test_the_trace_of_an_execution_is_not_checked_and_copied_a_second_time(monkeypatch):
    """`execute` hands its trace two states that nothing else holds: it
    does not go through what a trace built by hand goes through."""
    def by_hand(self, code, first, last, n_steps):
        pytest.fail("the trace of an execution was built as a trace is built by hand")

    monkeypatch.setattr(vm.TraceStates, "__init__", by_hand)
    trace = execute(KEEPS_ITS_CALLDATA, gas=GAS, context=ExecContext(**CONTEXT))
    assert is_whole(trace)


# ---------------------------------------------------------------------------
# A call checks what it would run before it copies the world
# ---------------------------------------------------------------------------

CALLER, CONTRACT = 0xAA, 0xCC
RETURNS_7 = push(7) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])
WRITES = write(1, 9) + RETURNS_7                          # writes 9 in slot 1, then returns 7
READS = push(1) + bytes([Op.SLOAD]) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])
RETURNS_ITS_VALUE = bytes([Op.CALLVALUE]) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])
BEFORE_THE_WRITE = GAS - 3 - 3                            # two pushes come before the SSTORE
OTHERS = 300                                              # accounts that have nothing to do with the call


class DerivedStorage(dict):
    pass


def world(code=RETURNS_7, storage=None, others: int = 0) -> WorldState:
    w = WorldState()
    w.accounts[CALLER] = Account(balance=1_000)
    w.accounts[CONTRACT] = Account(code=code, storage={} if storage is None else storage)
    for address in range(0x1000, 0x1000 + others):
        w.accounts[address] = Account(balance=1, storage={slot: slot + 1 for slot in range(1, 65)})
    return w


def call(w: WorldState, **how):
    how = {**dict(kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=0, calldata=b"", gas=GAS), **how}
    result = call_contract(w, **how)
    return result.success, result.return_data, result.gas_remaining


def balances(w: WorldState) -> dict:
    return {address: account.balance for address, account in w.accounts.items() if account.balance}


def peak_of(action) -> int:
    """The most memory `action` held at once, in bytes."""
    tracemalloc.start()
    try:
        action()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# The account the call would run: its code and its storage, and the part of
# what the machine says that names what is wrong.
CANNOT_START = {
    "a value that is not a word": (dict(storage={1: 2**256}), "its storage holds something other than a word"),
    "a value that is a text": (dict(storage={1: "2"}), "its storage holds something other than a word"),
    "a slot that is a text": (dict(storage={"1": 1}), "its storage holds something other than a word"),
    "a slot below zero": (dict(storage={-1: 1}), "its storage holds something other than a word"),
    "a slot that holds zero": (dict(storage={1: 0}), "a slot of its storage holds zero"),
    "a storage of a derived class": (dict(storage=DerivedStorage({1: 1})), "its storage is not a dict"),
    "a storage that is a list": (dict(storage=[(1, 2)]), "its storage is not a dict"),
    "a storage that is nothing": (dict(storage=None), "its storage is not a dict"),
    "a program beyond the limit": (dict(code=bytes(CODE_BYTES + 1)), "it is beyond the limit"),
    "a program that is a bytearray": (dict(code=bytearray(RETURNS_7)), "it is not bytes"),
    "a code that is a text": (dict(code="6007"), "it is not bytes"),
    "a code that is nothing": (dict(code=None), "it is not bytes"),
    "a code that is a number": (dict(code=7), "it is not bytes"),
}
EACH_THAT_CANNOT_START = [pytest.param(name, id=name.replace(" ", "-")) for name in CANNOT_START]


def a_world_whose_call_cannot_start(name: str, others: int = 0) -> WorldState:
    w = world(others=others)
    account = w.accounts[CONTRACT]
    for field, held in CANNOT_START[name][0].items():
        setattr(account, field, held)
    return w


@pytest.mark.parametrize("value", [0, 7])
@pytest.mark.parametrize("name", EACH_THAT_CANNOT_START)
def test_a_call_that_cannot_start_moves_nothing_and_leaves_the_accounts_they_were(name, value):
    """A code that had no length raised after the value had moved, and the
    caller was left 7 short. What the machine refused was refused after a
    snapshot: the world came back as copies of its accounts."""
    w = a_world_whose_call_cannot_start(name)
    accounts = dict(w.accounts)
    held = balances(w)
    with pytest.raises(ValueError, match=CANNOT_START[name][1]):
        call(w, value=value)
    assert balances(w) == held == {CALLER: 1_000}
    assert w.accounts.keys() == accounts.keys()
    assert all(w.accounts[address] is account for address, account in accounts.items())


@pytest.mark.parametrize("name", EACH_THAT_CANNOT_START)
def test_a_call_that_cannot_start_copies_nothing(name):
    """It copied every account of the world before it read the program or
    a slot: here, three hundred accounts that the call does not touch."""
    w = a_world_whose_call_cannot_start(name, others=OTHERS)
    a_copy_of_the_world = peak_of(w.snapshot)

    def refused():
        with pytest.raises(ValueError):
            call(w, value=7)

    assert peak_of(refused) * 20 < a_copy_of_the_world


def test_a_delegated_call_that_cannot_start_copies_nothing_either():
    """A DELEGATECALL runs on the storage of the caller: that is the
    storage it checks."""
    w = world(others=OTHERS)
    w.accounts[CALLER].storage = {1: 2**256}
    accounts = dict(w.accounts)
    a_copy_of_the_world = peak_of(w.snapshot)

    def refused():
        with pytest.raises(ValueError, match="its storage holds something other than a word"):
            call(w, kind=FrameKind.DELEGATECALL)

    assert peak_of(refused) * 20 < a_copy_of_the_world
    assert all(w.accounts[address] is account for address, account in accounts.items())


def test_control_a_storage_beyond_the_limit_is_refused_on_its_size_before_the_world_is_copied():
    w = world(storage={slot: 1 for slot in range(1, 16_386)}, others=OTHERS)
    accounts = dict(w.accounts)
    a_copy_of_the_world = peak_of(w.snapshot)

    def refused():
        with pytest.raises(ValueError, match="its storage is beyond the limit"):
            call(w, value=7)

    assert peak_of(refused) * 20 < a_copy_of_the_world
    assert all(w.accounts[address] is account for address, account in accounts.items())


def test_control_a_call_that_can_start_moves_its_value_and_keeps_what_its_program_writes():
    w = world(WRITES, storage={2: 5})
    assert call(w, value=7) == (True, returned(7), GAS - 20_000 - 24)
    assert balances(w) == {CALLER: 993, CONTRACT: 7} and w.accounts[CONTRACT].storage == {1: 9, 2: 5}


def test_control_a_call_to_an_account_without_code_moves_the_value_and_runs_nothing():
    w = world(code=b"")
    assert call(w, value=7) == (True, b"", GAS)
    assert balances(w) == {CALLER: 993, CONTRACT: 7}


def test_control_a_call_to_a_precompile_reads_no_code_at_its_address():
    """Address 0x04 gives back what it is given. Nothing runs the code of
    an account that sits there: the call does not read it."""
    w = world()
    w.accounts[0x04] = Account(code=None, storage={1: 2**256})
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=0x04, value=0, calldata=b"kern", gas=GAS)
    assert result.success and result.return_data == b"kern"


# ---------------------------------------------------------------------------
# A static call moves no value
# ---------------------------------------------------------------------------

def test_a_delegated_call_marked_static_runs_with_the_value_it_is_given():
    """It did not run. A DELEGATECALL moves no value: its program reads
    the value of the call, static or not."""
    plain = call(world(RETURNS_ITS_VALUE), kind=FrameKind.DELEGATECALL, value=5)
    w = world(RETURNS_ITS_VALUE)
    assert call(w, kind=FrameKind.DELEGATECALL, is_static=True, value=5) == plain
    assert plain[:2] == (True, returned(5)) and 0 < plain[2] < GAS
    assert balances(w) == {CALLER: 1_000}


def test_a_delegated_call_marked_static_that_carries_a_value_cannot_write():
    w = world(WRITES)
    before = copy.deepcopy(w.accounts)
    assert call(w, kind=FrameKind.DELEGATECALL, is_static=True, value=5) == (False, b"", BEFORE_THE_WRITE)
    assert w.accounts == before


MOVES_A_VALUE = {
    "STATICCALL": dict(kind=FrameKind.STATICCALL),
    "STATICCALL marked static": dict(kind=FrameKind.STATICCALL, is_static=True),
    "CALL marked static": dict(kind=FrameKind.CALL, is_static=True),
}


@pytest.mark.parametrize("name", sorted(MOVES_A_VALUE))
def test_a_static_call_that_would_move_a_value_does_not_run_and_gives_back_all_its_gas(name):
    """It gave no gas back, where the other call that does not start, the
    one whose caller does not hold the value, gives back all of it."""
    w = world(WRITES)
    accounts = dict(w.accounts)
    assert call(w, value=5, **MOVES_A_VALUE[name]) == (False, b"", GAS)
    assert balances(w) == {CALLER: 1_000} and w.accounts[CONTRACT].storage == {}
    assert all(w.accounts[address] is account for address, account in accounts.items())


def test_control_a_call_whose_caller_does_not_hold_the_value_gives_back_all_its_gas():
    w = world(WRITES)
    assert call(w, value=1_001) == (False, b"", GAS)
    assert balances(w) == {CALLER: 1_000} and w.accounts[CONTRACT].storage == {}


STATIC = {
    "STATICCALL": (dict(kind=FrameKind.STATICCALL), CONTRACT),
    "CALL marked static": (dict(kind=FrameKind.CALL, is_static=True), CONTRACT),
    "DELEGATECALL marked static": (dict(kind=FrameKind.DELEGATECALL, is_static=True), CALLER),
}


@pytest.mark.parametrize("name", sorted(STATIC))
def test_control_a_static_call_without_a_value_reads_and_succeeds(name):
    how, holder = STATIC[name]
    w = world(READS)
    w.accounts[holder].storage = {1: 4}
    success, data, left = call(w, **how)
    assert (success, data) == (True, returned(4)) and 0 < left < GAS


# ---------------------------------------------------------------------------
# Two controls on where a jump lands
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", range(1, 33))
def test_control_no_byte_of_the_data_of_a_push_cut_by_the_end_of_the_program_is_a_jump_destination(size):
    """A PUSH whose data the end of the program cuts short: what is left of
    its data is data, whatever its length, and a jump to it is a bad jump."""
    head = push(0) + bytes([Op.JUMP])                      # the 0 is replaced by the place aimed at
    for left in range(size):
        tail = bytes([Op.PUSH1 + size - 1]) + bytes([JUMPDEST]) * left
        assert not any(vm._jump_destinations(tail))
        for aimed in range(left):
            code = push(len(head) + 1 + aimed) + bytes([Op.JUMP]) + tail
            final = run(code, gas=GAS)
            assert final.halted and final.reverted and "invalid jump dest" in final.last_error, (size, left, aimed)


def test_control_a_jump_lands_on_the_jumpdest_that_follows_a_byte_0x5f():
    """The machine does not execute 0x5f, which is PUSH0 in Ethereum. It
    holds no data there either: the byte after it is an instruction."""
    code = push(4) + bytes([Op.JUMP, 0x5F, Op.JUMPDEST, Op.STOP])
    assert list(vm._jump_destinations(code)) == [0, 0, 0, 0, 1, 0]
    final = run(code, gas=GAS)
    assert final.halted and not final.reverted and final.pc == 5
    alone = run(bytes([0x5F, Op.STOP]), gas=GAS)
    assert alone.reverted and "unknown opcode 0x5f" in alone.last_error


# ---------------------------------------------------------------------------
# The pages and the texts of the code say it
# ---------------------------------------------------------------------------

def test_section_2_9_says_what_a_trace_shares_and_what_a_call_checks_first():
    text = section(STABILITY, "### 2.9 ")
    for sentence in (
        "The context of a state cannot be assigned to, and it has no dictionary to write into. The states of a run "
        "share theirs.",
        "An execution works on a copy of the context it is given, and a state read from a trace is a copy of the "
        "whole state, its context included: a trace shares no object with the code that built it or that reads it, "
        "so that nothing done to what it was given or to what it hands out changes it.",
        "A trace built by hand refuses what is not a program or a state of the machine, and keeps copies of the two "
        "states it is given.",
        "Neither does a call whose code or storage does not make a state of the machine: both are checked before "
        "the world is copied and before any value moves, so a call that cannot start copies nothing and moves "
        "nothing.",
        "`tests/test_evm_hardening.py` holds what a trace shares, what a call checks before it copies the world and "
        "what a static call may carry.",
    ):
        assert sentence in text, sentence
    assert "a state read from a trace is a copy of everything else" not in STABILITY.read_text(encoding="utf-8")


def test_the_page_of_calls_says_what_a_static_call_may_carry_and_what_a_call_checks_first():
    text = section(CALLS_PAGE, "## The three kinds of call")
    for sentence in (
        "- A static call moves no value. A `CALL` marked static, or a `STATICCALL`, that carries one does not run, "
        "and gives back all its gas. A `DELEGATECALL` moves none: marked static, it runs, its program reads the "
        "value of its call and cannot write, as in Ethereum.",
        "- A call whose value the caller does not hold fails, and gives back all its gas: its program did not run.",
        "- A call whose code or storage does not make a state of the machine does not start: `ValueError`, before "
        "the world is copied and before any value moves.",
        "| `DELEGATECALL` | The storage of the caller | Not moved; the program reads it as the value of its call |",
        "| `STATICCALL` | The storage of the contract, which the program cannot write | Refused: a static call "
        "that carries a value does not run |",
    ):
        assert sentence in text, sentence
    assert "gives no gas back" not in CALLS_PAGE.read_text(encoding="utf-8")


def flat(text: str) -> str:
    return " ".join(text.split())


def test_the_texts_of_the_code_say_the_same():
    call_text, trace_text, context_text = (flat(thing.__doc__) for thing in
                                           (call_contract, vm.TraceStates, ExecContext))
    for sentence in (
        "All of it is checked before the world is copied and before any value moves, the size of that storage "
        "first: nothing is copied, and the accounts of the world are the objects they were.",
        "A static call moves no value. A `CALL` marked static, or a `STATICCALL`, that carries one does not run, "
        "and gives back all its gas, like a call whose caller does not hold the value.",
        "A `DELEGATECALL` moves none: marked static, it runs with the value it is given, which its program reads.",
    ):
        assert sentence in call_text, sentence
    for sentence in (
        "What is handed out is a copy that shares nothing with the trace, its context included: nothing done to "
        "it changes the trace.",
        "The trace keeps copies of the two states: nothing done to them afterwards changes it.",
        "Nothing checks that the last state is the one the program reaches after that many steps",
    ):
        assert sentence in trace_text, sentence
    assert "it has no dictionary to write into" in context_text
    assert "a trace shares no object with the code that built it or that reads it" in context_text
    source = flat(Path(frames.__file__).read_text(encoding="utf-8"))
    assert "A call first checks the code and the storage it would run on" in source
    for withdrawn in ("Reject value transfer in static calls",
                      "The size of that storage is read before the world is copied.",
                      "A call takes a snapshot of it first"):
        assert withdrawn not in source, withdrawn
