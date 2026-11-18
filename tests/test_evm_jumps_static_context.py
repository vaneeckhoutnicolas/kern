# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Where a jump lands, what a static call may do, and what a context is.

Three things were wrong in the Mini-EVM and around it.

- A jump looked at the byte it aimed at, and at nothing else. A byte 0x5b in
  the data of a PUSH is not a JUMPDEST: Ethereum refuses a jump to it, and
  the machine took it. A jump now lands on a JUMPDEST that is an
  instruction. That is read from the program alone, once for a run.
- A static call to a program that wrote succeeded, and what was written was
  dropped. The program now halts, reverted, on the first SSTORE it reaches,
  and the call fails. Only `run` has that mode: `step`, `execute` and the
  referee of a step have none.
- The states of an execution share their context, and a context could be
  assigned to: changing the context of a state read from a trace changed
  every state of the trace, and none hashed to its commitment any more. A
  context can no longer be assigned to.

Two functions of the gas module said what the machine does not do:
`sstore_cost` gave 100 for a write that changes nothing, where the machine
takes 5,000, and `sstore_refund` was called by nothing. Headers of the
modules said more than the machine does.

A test named `test_control_...` passed before these rules and still does: it
shows that what the others catch is the rule that was missing, and not the
way they are written. The names this change adds are read from `kern.evm`
inside each test, so that a test fails alone where a name is missing.
"""

from __future__ import annotations

import copy
import dataclasses
import inspect
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import kern.evm
from kern.evm import (
    Account,
    ExecContext,
    FrameKind,
    Op,
    VmState,
    WorldState,
    call_contract,
    execute,
    single_step_verify,
    step,
)
from kern.evm import dynamic_gas, vm

ROOT = Path(__file__).resolve().parent.parent
STABILITY = ROOT / "docs" / "api-stability.md"
CALLS_PAGE = ROOT / "docs" / "multi-frame-evm.md"

JUMPDEST = 0x5B                                          # the byte, written here as a number
GAS = 100_000


def push(value: int) -> bytes:
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


def write(slot: int, value: int) -> bytes:
    return push(value) + push(slot) + bytes([Op.SSTORE])


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


# ---------------------------------------------------------------------------
# A jump lands on a JUMPDEST that is an instruction
# ---------------------------------------------------------------------------

# The jump aims at the data of the second PUSH1, which is the byte 0x5b.
INTO_DATA = bytes([Op.PUSH1, 4, Op.JUMP, Op.PUSH1, JUMPDEST, Op.STOP])
INTO_DATA_IF = bytes([Op.PUSH1, 1, Op.PUSH1, 6, Op.JUMPI, Op.PUSH1, JUMPDEST, Op.STOP])
NOT_TAKEN = bytes([Op.PUSH1, 0, Op.PUSH1, 6, Op.JUMPI, Op.PUSH1, JUMPDEST, Op.STOP])
ONTO_A_JUMPDEST = bytes([Op.PUSH1, 4, Op.JUMP, Op.STOP, Op.JUMPDEST, Op.STOP])
ONTO_A_STOP = bytes([Op.PUSH1, 3, Op.JUMP, Op.STOP, Op.JUMPDEST, Op.STOP])

# What the jump leaves when it is refused: where it stood, the gas after its
# price, and its operands taken off the stack.
REFUSED = {
    "JUMP": (INTO_DATA, dict(pc=2, gas=GAS - 3 - 8, error="invalid jump dest 4")),
    "JUMPI": (INTO_DATA_IF, dict(pc=4, gas=GAS - 3 - 3 - 10, error="invalid jumpi dest 6")),
}


def is_refused(last: VmState, pc: int, gas: int, error: str) -> None:
    assert (last.halted, last.reverted) == (True, True)
    assert (last.pc, last.gas, last.stack, last.last_error) == (pc, gas, [], error)


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_a_jump_does_not_land_on_a_byte_of_data(name):
    """The program went on from the data of the PUSH and stopped as if
    nothing had happened."""
    code, left = REFUSED[name]
    trace = execute(code, gas=GAS)
    is_refused(trace.states[-1], **left)


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_a_run_refuses_the_same_jump(name):
    code, left = REFUSED[name]
    is_refused(kern.evm.run(code, gas=GAS), **left)


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_a_single_step_refuses_the_same_jump(name):
    code, left = REFUSED[name]
    before = VmState(pc=left["pc"], stack=[4] if name == "JUMP" else [1, 6], gas=1_000)
    after = step(before, code)
    assert (after.halted, after.reverted, after.pc, after.stack) == (True, True, left["pc"], [])
    assert after.last_error == left["error"]


def test_a_state_read_from_a_trace_is_the_refused_one():
    trace = execute(INTO_DATA, gas=GAS)
    assert trace.n_steps == 2
    assert [state.commitment() for state in trace.states] == trace.commitments
    is_refused(trace.states[2], **REFUSED["JUMP"][1])


def test_the_referee_of_a_step_refutes_a_sequencer_whose_jump_landed_on_data():
    """Both parties agree on the state before the jump. The sequencer claims
    the state where the jump landed, the challenger the state where it is
    refused. The referee gave the step to the sequencer."""
    agreed = VmState(pc=2, stack=[4], gas=GAS - 3)
    landed = VmState(pc=4, stack=[], gas=GAS - 3 - 8)
    refused = VmState(pc=2, stack=[], gas=GAS - 3 - 8, halted=True, reverted=True)
    verdict = single_step_verify(INTO_DATA, agreed, landed.commitment_hex(), refused.commitment_hex(), 2)
    assert verdict.challenger_wins
    assert verdict.verified_commitment == refused.commitment_hex()


def test_control_the_referee_gives_the_step_to_a_sequencer_whose_jump_landed_on_a_jumpdest():
    agreed = VmState(pc=2, stack=[4], gas=GAS - 3)
    landed = VmState(pc=4, stack=[], gas=GAS - 3 - 8)
    verdict = single_step_verify(ONTO_A_JUMPDEST, agreed, landed.commitment_hex(), "dd" * 32, 2)
    assert verdict.sequencer_wins


def test_control_a_jump_lands_on_a_jumpdest():
    last = execute(ONTO_A_JUMPDEST, gas=GAS).states[-1]
    assert (last.halted, last.reverted, last.pc, last.gas) == (True, False, 5, GAS - 3 - 8 - 1)


def test_control_a_jump_to_another_instruction_is_refused():
    is_refused(execute(ONTO_A_STOP, gas=GAS).states[-1], pc=2, gas=GAS - 3 - 8, error="invalid jump dest 3")


def test_control_a_conditional_jump_that_is_not_taken_looks_at_no_destination():
    last = execute(NOT_TAKEN, gas=GAS).states[-1]
    assert (last.halted, last.reverted, last.stack) == (True, False, [JUMPDEST])


def after_a_push_of(size: int) -> bytes:
    """A jump, then a PUSH of `size` bytes that are all 0x5b, then a
    JUMPDEST and a STOP. The jump is at 2, the data from 4 to 3 + size and
    the JUMPDEST at 4 + size."""
    return bytes([Op.PUSH1, 0, Op.JUMP, Op.PUSH1 + size - 1]) + bytes([JUMPDEST]) * size + bytes([Op.JUMPDEST, Op.STOP])


def jump_to(code: bytes, dest: int) -> VmState:
    """The state after the jump at 2 in `code`, aimed at `dest`."""
    return step(VmState(pc=2, stack=[dest], gas=1_000), code)


@pytest.mark.parametrize("size", range(1, 33))
def test_no_byte_of_the_data_of_a_push_takes_a_jump(size):
    code = after_a_push_of(size)
    for dest in range(4, 4 + size):
        assert code[dest] == JUMPDEST
        assert jump_to(code, dest).reverted, dest


@pytest.mark.parametrize("size", range(1, 33))
def test_control_the_jumpdest_that_follows_the_data_of_a_push_takes_a_jump(size):
    code = after_a_push_of(size)
    after = jump_to(code, 4 + size)
    assert (after.reverted, after.pc) == (False, 4 + size)


def test_control_a_jumpdest_after_a_data_byte_that_looks_like_a_push_takes_a_jump():
    """The data of the PUSH1 is 0x60, the number of PUSH1: read as an
    instruction, it would take the JUMPDEST for its data."""
    code = bytes([Op.PUSH1, 5, Op.JUMP, Op.PUSH1, Op.PUSH1, Op.JUMPDEST, Op.STOP])
    after = jump_to(code, 5)
    assert (after.reverted, after.pc) == (False, 5)


def test_the_data_of_a_push_that_the_end_of_the_program_cuts_takes_no_jump():
    """A PUSH2 with one byte of data left: that byte is 0x5b, and it is the
    last byte of the program."""
    code = bytes([Op.PUSH1, 6, Op.JUMP, Op.PUSH1, 0, Op.PUSH2, JUMPDEST])
    assert jump_to(code, 6).reverted
    assert jump_to(code, 7).reverted and jump_to(code, 1 << 255).reverted


def starts_of(code: bytes) -> list:
    """Where the instructions of `code` start: a second writing of the rule,
    which cuts the program instruction by instruction."""
    starts, rest, at = [], code, 0
    while rest:
        starts.append(at)
        size = 1 + (rest[0] - 0x5F if 0x60 <= rest[0] <= 0x7F else 0)
        rest, at = rest[size:], at + size
    return starts


def a_body(rng: random.Random) -> bytes:
    """A few instructions drawn among those that matter here: JUMPDEST, the
    PUSH family with data that is often 0x5b or the number of a PUSH, and
    anything else."""
    body = b""
    for _ in range(rng.randrange(1, 12)):
        draw = rng.random()
        if draw < 0.3:
            body += bytes([JUMPDEST])
        elif draw < 0.8:
            size = rng.choice([1, 1, 2, 3, 4, 31, 32])
            data = bytes(rng.choice([JUMPDEST, JUMPDEST, 0x60, 0x7F, rng.randrange(256)]) for _ in range(size))
            body += bytes([Op.PUSH1 + size - 1]) + data
        else:
            body += bytes([rng.randrange(256)])
    if rng.random() < 0.3:                                # a PUSH that the end of the program cuts
        body += bytes([Op.PUSH1 + rng.randrange(1, 32)]) + bytes([JUMPDEST]) * rng.randrange(0, 2)
    return body


def test_a_jump_lands_where_a_second_writing_of_the_rule_says():
    """300 programs drawn with a fixed seed. From the jump at 2, every byte
    of the program and two places beyond it are aimed at, by JUMP and by
    JUMPI."""
    rng = random.Random(37)
    refused_on_data = 0
    for _ in range(300):
        code = bytes([Op.PUSH1, 0, Op.JUMP]) + a_body(rng)
        may_land = {at for at in starts_of(code) if code[at] == JUMPDEST}
        for dest in range(len(code) + 2):
            lands = dest in may_land
            by_jump = step(VmState(pc=2, stack=[dest], gas=1_000), code)
            by_jumpi = step(VmState(pc=2, stack=[1, dest], gas=1_000), bytes([Op.PUSH1, 0, Op.JUMPI]) + code[3:])
            assert (by_jump.reverted, by_jumpi.reverted) == (not lands, not lands), (code.hex(), dest)
            if lands:
                assert (by_jump.pc, by_jumpi.pc) == (dest, dest)
            elif dest < len(code) and code[dest] == JUMPDEST:
                refused_on_data += 1
    assert refused_on_data > 500                          # the draw does aim at bytes of data


# A countdown from 5: each turn but the last jumps back to the JUMPDEST at 2.
COUNTS_DOWN = bytes([Op.PUSH1, 5, Op.JUMPDEST, Op.PUSH1, 1, Op.SWAP1, Op.SUB, Op.DUP1, Op.PUSH1, 2, Op.JUMPI, Op.STOP])


def counted(patch) -> list:
    """From here on, each reading of a program is noted."""
    read = []
    whole = vm._jump_destinations

    def noting(code):
        read.append(len(code))
        return whole(code)

    patch.setattr(vm, "_jump_destinations", noting)
    return read


def test_control_the_program_that_counts_down_reaches_its_jump_five_times_and_takes_it_four_times():
    trace = execute(COUNTS_DOWN, gas=GAS)
    at_the_jump = [position for position in range(trace.n_steps) if trace.states[position].pc == 10]
    taken = [position for position in at_the_jump if trace.states[position + 1].pc == 2]
    assert (len(at_the_jump), len(taken)) == (5, 4)
    assert trace.states[-1].halted and not trace.states[-1].reverted and trace.states[-1].stack == [0]


def test_an_execution_reads_its_program_once_and_its_trace_does_not_read_it_again(monkeypatch):
    read = counted(monkeypatch)
    trace = execute(COUNTS_DOWN, gas=GAS)
    assert read == [len(COUNTS_DOWN)]
    assert [state.commitment() for state in trace.states] == trace.commitments
    assert trace.states[7].commitment() == trace.commitments[7]
    assert read == [len(COUNTS_DOWN)]


def test_control_a_trace_built_from_its_two_ends_gives_the_states_of_the_execution():
    """`TraceStates` is built here as `execute` builds it, from the program,
    the first state, the last one and the number of steps."""
    trace = execute(COUNTS_DOWN, gas=GAS)
    by_hand = vm.TraceStates(COUNTS_DOWN, trace.states[0], trace.states[-1], trace.n_steps)
    assert [state.commitment() for state in by_hand] == trace.commitments
    assert by_hand[7].commitment() == trace.commitments[7]


def test_a_run_reads_its_program_once(monkeypatch):
    read = counted(monkeypatch)
    last = kern.evm.run(COUNTS_DOWN, gas=GAS)
    assert last.halted and not last.reverted
    assert read == [len(COUNTS_DOWN)]


def test_a_program_is_not_read_when_no_jump_aims_at_a_byte_0x5b(monkeypatch):
    read = counted(monkeypatch)
    execute(bytes([Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD, Op.STOP]), gas=GAS)     # no jump
    execute(ONTO_A_STOP, gas=GAS)                                           # a jump to another byte
    execute(NOT_TAKEN, gas=GAS)                                             # a jump that is not taken
    step(VmState(pc=0, gas=1_000), ONTO_A_JUMPDEST)                         # a step that is not a jump
    assert read == []
    step(VmState(pc=2, stack=[4], gas=1_000), ONTO_A_JUMPDEST)              # a single step reads for itself
    assert read == [len(ONTO_A_JUMPDEST)]


# ---------------------------------------------------------------------------
# A static call cannot write
# ---------------------------------------------------------------------------

CALLER, CONTRACT = 0xAA, 0xCC
RETURNS_7 = push(7) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])
WRITES = write(1, 9) + RETURNS_7                          # writes 9 in slot 1, then returns 7
READS = push(1) + bytes([Op.SLOAD]) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])
# Jumps over its write: the SSTORE is in the program and is not reached.
SKIPS_ITS_WRITE = push(8) + bytes([Op.JUMP]) + write(1, 9) + bytes([Op.JUMPDEST]) + RETURNS_7
BEFORE_THE_WRITE = GAS - 3 - 3                            # two pushes come before the SSTORE

STATIC = {
    "STATICCALL": dict(kind=FrameKind.STATICCALL),
    "CALL marked static": dict(kind=FrameKind.CALL, is_static=True),
    "DELEGATECALL marked static": dict(kind=FrameKind.DELEGATECALL, is_static=True),
}


def world(code: bytes, storage: dict | None = None) -> WorldState:
    w = WorldState()
    w.accounts[CALLER] = Account(balance=1_000, storage=dict(storage or {}))
    w.accounts[CONTRACT] = Account(code=code, storage=dict(storage or {}))
    return w


def call(w: WorldState, **how):
    how = {**dict(caller=CALLER, address=CONTRACT, value=0, calldata=b"", gas=GAS), **how}
    result = call_contract(w, **how)
    return result.success, result.return_data, result.gas_remaining


def returned(value: int) -> bytes:
    return value.to_bytes(32, "big")


@pytest.mark.parametrize("name", sorted(STATIC))
def test_a_static_call_to_a_program_that_writes_fails(name):
    """It succeeded, returned 7, and what it had written was dropped."""
    w = world(WRITES)
    before = copy.deepcopy(w.accounts)
    assert call(w, **STATIC[name]) == (False, b"", BEFORE_THE_WRITE)
    assert w.accounts == before


@pytest.mark.parametrize("name", sorted(STATIC))
def test_a_static_call_fails_on_a_write_that_would_change_nothing(name):
    """The slot holds 5 and the program writes 5."""
    w = world(write(1, 5) + bytes([Op.STOP]), storage={1: 5})
    before = copy.deepcopy(w.accounts)
    assert call(w, **STATIC[name]) == (False, b"", BEFORE_THE_WRITE)
    assert w.accounts == before


@pytest.mark.parametrize("name", sorted(STATIC))
def test_control_a_static_call_that_only_reads_succeeds(name):
    w = world(READS, storage={1: 5})
    before = copy.deepcopy(w.accounts)
    success, data, left = call(w, **STATIC[name])
    assert (success, data) == (True, returned(5)) and left < GAS
    assert w.accounts == before


@pytest.mark.parametrize("name", sorted(STATIC))
def test_control_a_static_call_succeeds_when_its_program_does_not_reach_its_write(name):
    assert Op.SSTORE in SKIPS_ITS_WRITE and SKIPS_ITS_WRITE[8] == JUMPDEST
    w = world(SKIPS_ITS_WRITE)
    success, data, _ = call(w, **STATIC[name])
    assert (success, data) == (True, returned(7))
    assert w.get(CONTRACT).storage == {} and w.get(CALLER).storage == {}


@pytest.mark.parametrize("kind, holder", [(FrameKind.CALL, CONTRACT), (FrameKind.DELEGATECALL, CALLER)])
def test_control_the_same_program_writes_when_its_call_is_not_static(kind, holder):
    w = world(WRITES)
    success, data, left = call(w, kind=kind)
    assert (success, data) == (True, returned(7)) and left == GAS - 20_000 - 24
    assert w.get(holder).storage == {1: 9}


def test_control_a_static_call_that_carries_a_value_does_not_run_and_gives_no_gas_back():
    w = world(WRITES)
    before = copy.deepcopy(w.accounts)
    assert call(w, kind=FrameKind.STATICCALL, value=1) == (False, b"", 0)
    assert w.accounts == before


def test_a_static_run_halts_before_the_write_and_leaves_the_state_as_it_was():
    last = kern.evm.run(WRITES, gas=GAS, static=True)
    assert (last.halted, last.reverted, last.last_error) == (True, True, "write in a static call at pc=4")
    assert (last.pc, last.stack, last.gas, last.storage, bytes(last.memory), last.output) == (
        4, [9, 1], BEFORE_THE_WRITE, {}, b"", b"")
    # It is the state of the execution before its write, halted and reverted.
    expected = execute(WRITES, gas=GAS).states[2]
    expected.halted = expected.reverted = True
    assert last.commitment() == expected.commitment()


def test_a_static_run_refuses_a_write_before_it_looks_at_its_price():
    """With 10,000 of gas the write could not be paid: the reason given is
    the write, and the gas is what it was."""
    last = kern.evm.run(WRITES, gas=10_000, static=True)
    assert (last.reverted, last.gas, last.last_error) == (True, 10_000 - 6, "write in a static call at pc=4")


@pytest.mark.parametrize("code", [READS, SKIPS_ITS_WRITE, RETURNS_7], ids=["reads", "skips its write", "returns 7"])
def test_a_static_run_of_a_program_that_does_not_write_is_its_run(code):
    static = kern.evm.run(code, gas=GAS, initial_storage={1: 5}, static=True)
    plain = kern.evm.run(code, gas=GAS, initial_storage={1: 5})
    assert static.commitment() == plain.commitment() and static.halted and not static.reverted


def test_control_a_run_ends_where_the_execution_ends():
    for code in (WRITES, READS, SKIPS_ITS_WRITE, INTO_DATA, COUNTS_DOWN):
        assert kern.evm.run(code, gas=GAS).commitment() == execute(code, gas=GAS).commitments[-1]


def test_only_a_run_has_a_static_mode():
    """A step is a function of the state and of the program: the machine of
    the referee has no mode."""
    assert "static" in inspect.signature(kern.evm.run).parameters
    for function in (execute, step, single_step_verify, vm._advance):
        assert "static" not in inspect.signature(function).parameters, function.__name__
    assert inspect.signature(kern.evm.run).parameters["static"].default is False


# What a call gives back when its program halts, of 100,000 of gas.
HALTS = {
    "REVERT": (push(0) + push(0) + bytes([Op.REVERT]), GAS - 6),
    "a byte that is no instruction": (push(0) + bytes([0xFE]), GAS - 3),
    "LOG0": (push(0) + push(0) + bytes([Op.LOG0]), GAS - 6 - 375),
    "a jump to a STOP": (ONTO_A_STOP, GAS - 3 - 8),
    "ADD on an empty stack": (bytes([Op.ADD]), GAS - 3),
    "a memory the gas does not pay": (push(0) + bytes([Op.PUSH4, 0, 0x20, 0, 0, Op.MSTORE]), GAS - 6),
}


@pytest.mark.parametrize("name", sorted(HALTS))
def test_control_a_call_that_fails_gives_back_the_gas_its_program_had_left(name):
    code, left = HALTS[name]
    w = world(code)
    success, _, gas = call(w, kind=FrameKind.CALL)
    assert (success, gas) == (False, left)


def test_the_page_of_calls_says_what_a_static_call_may_do():
    text = section(CALLS_PAGE, "## The three kinds of call")
    for sentence in (
        "| `STATICCALL` | The storage of the contract, which the program cannot write | Refused: a static call "
        "that carries a value does not run |",
        "- A static call cannot write. Its program halts, reverted, on the first SSTORE it reaches, even one that "
        "would change nothing, and the call fails, as in Ethereum.",
        "- A call gives back the gas its program had left when it stopped, whether the call succeeded or failed: "
        "the machine keeps the gas of the state it reached",
        "In Ethereum a call that fails gives gas back only when its program ends on REVERT.",
        "A static call that carries a value does not run, and gives no gas back.",
    ):
        assert sentence in text, sentence
    for withdrawn in ("writes nothing to the world", "nothing is written to the world"):
        assert withdrawn not in CALLS_PAGE.read_text(encoding="utf-8")
        assert withdrawn not in (ROOT / "kern" / "evm" / "frames.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A context cannot be assigned to
# ---------------------------------------------------------------------------

CONTEXT = dict(address=0xC0DE, caller=0xAA, value=9, calldata=b"\x00" * 32, block_number=7,
               block_timestamp=1_794_000_000)
OTHER = dict(address=123, caller=5, value=1, calldata=b"\x01" * 32, block_number=8, block_timestamp=1)
# Jumps to 8 when the first word of its calldata is not zero, and writes there.
READS_ITS_CALLDATA = (push(0) + bytes([Op.CALLDATALOAD]) + push(8) + bytes([Op.JUMPI, Op.STOP, Op.STOP, Op.JUMPDEST])
                      + write(1, 7) + bytes([Op.STOP]))


@pytest.mark.parametrize("name", sorted(CONTEXT))
def test_a_context_cannot_be_assigned_to(name):
    context = ExecContext(**CONTEXT)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(context, name, OTHER[name])
    assert context == ExecContext(**CONTEXT)


def test_the_context_of_a_state_read_from_a_trace_cannot_be_changed_and_the_trace_holds():
    """Changing the address of the context of one state read from a trace
    changed every state of the trace: none hashed to its commitment."""
    trace = execute(READS_ITS_CALLDATA, gas=GAS, context=ExecContext(**CONTEXT))
    for position in (0, 2, trace.n_steps):
        with pytest.raises(dataclasses.FrozenInstanceError):
            trace.states[position].context.address = 123
    for state in trace.states:
        with pytest.raises(dataclasses.FrozenInstanceError):
            state.context.calldata = b"\x01" * 32
    assert [state.commitment() for state in trace.states] == trace.commitments
    assert [trace.states[position].commitment() for position in range(trace.n_steps + 1)] == trace.commitments


def test_the_caller_cannot_change_the_context_it_gave_once_the_execution_is_made():
    """With other calldata the states read from the trace took the other
    branch of the program."""
    given = ExecContext(**CONTEXT)
    trace = execute(READS_ITS_CALLDATA, gas=GAS, context=given)
    with pytest.raises(dataclasses.FrozenInstanceError):
        given.calldata = b"\x01" * 32
    assert [state.commitment() for state in trace.states] == trace.commitments
    assert trace.states[-1].storage == {}


def test_the_state_a_step_returns_cannot_change_the_context_of_the_state_it_was_given():
    before = VmState(gas=1_000, context=ExecContext(**CONTEXT))
    was = before.commitment()
    after = step(before, bytes([Op.PUSH1, 1, Op.STOP]))
    with pytest.raises(dataclasses.FrozenInstanceError):
        after.context.value = 99
    assert before.commitment() == was


def test_control_a_state_read_from_a_trace_is_a_copy_of_the_rest():
    trace = execute(READS_ITS_CALLDATA, gas=GAS, context=ExecContext(**CONTEXT))
    for state in trace.states:
        state.stack.append(5)
        state.memory.extend(b"\x01" * 32)
        state.storage[9] = 9
        state.pc, state.gas = 77, 0
    assert [state.commitment() for state in trace.states] == trace.commitments


def test_control_another_context_is_made_from_one():
    given = ExecContext(**CONTEXT)
    other = dataclasses.replace(given, calldata=b"\x01" * 32)
    assert given == ExecContext(**CONTEXT) and other.calldata == b"\x01" * 32 and other.address == given.address
    taken = execute(READS_ITS_CALLDATA, gas=GAS, context=other).states[-1]
    assert taken.storage == {1: 7}


def test_control_a_context_with_one_more_attribute_is_not_the_context_of_a_state():
    """What cannot be assigned can still be written into the object: the
    machine turns that object away."""
    context = ExecContext(**CONTEXT)
    vars(context)["note"] = "one more"
    assert vm.not_a_state(VmState(gas=1_000, context=context)) == "its context is not an ExecContext"


def test_section_2_9_says_what_keeps_a_context_and_what_runs_a_static_call():
    text = section(STABILITY, "### 2.9 ")
    for sentence in (
        "The context of a state cannot be assigned to: the states of an execution share it, and a state read from "
        "a trace is a copy of everything else, so that nothing done to it changes the trace.",
        "A static call goes through `run` with its `static` mode, where a program halts on the first write it "
        "reaches ([`multi-frame-evm.md`](multi-frame-evm.md)); `step`, `execute` and the referee of a step have no "
        "such mode.",
        "`tests/test_evm_jumps_static_context.py` holds where a jump lands, what a static call may do and what "
        "keeps a context as it is.",
    ):
        assert sentence in text, sentence


def test_section_2_8_says_where_a_jump_lands():
    text = section(STABILITY, "### 2.8 ")
    for sentence in (
        "A jump lands on a JUMPDEST that is an instruction, as in Ethereum.",
        "A byte `0x5b` in the data of a PUSH is not one: a `JUMP` to it, or a `JUMPI` whose condition is not "
        "zero, halts the machine, reverted, like a jump to any other byte.",
        "Where a jump may land is read from the program alone: it is the same for the two parties of a dispute "
        "and for the referee.",
    ):
        assert sentence in text, sentence


# ---------------------------------------------------------------------------
# The price functions and the headers say what the machine does
# ---------------------------------------------------------------------------

def taken_by_the_machine(current: int, new: int) -> int:
    """What a step takes to write `new` in a slot that holds `current`."""
    before = VmState(gas=GAS, stack=[new, 7], storage={7: current} if current else {})
    taken = before.gas - step(before, bytes([Op.SSTORE])).gas
    assert taken == (20_000 if current == 0 and new != 0 else 5_000)
    return taken


@pytest.mark.parametrize("held", [0, 1, 2])
def test_the_price_function_gives_what_the_machine_takes_for_a_write_that_changes_nothing(held):
    """It gave 100, and the machine took 5,000."""
    assert dynamic_gas.sstore_cost(held, held) == taken_by_the_machine(held, held) == 5_000


@pytest.mark.parametrize("current, new", [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)])
def test_control_the_price_function_gives_what_the_machine_takes_for_a_write_that_changes_a_slot(current, new):
    assert dynamic_gas.sstore_cost(current, new) == taken_by_the_machine(current, new)


def test_no_function_of_refund_is_left():
    """Section 2.9 says that no gas is refunded: `sstore_refund` was called
    by nothing, and read a parameter `original` that the state no longer
    holds."""
    assert not hasattr(dynamic_gas, "sstore_refund")
    assert not hasattr(dynamic_gas, "G_SSTORE_CLEAR_REFUND")
    for path in sorted((ROOT / "kern").rglob("*.py")):
        assert "sstore_refund" not in path.read_text(encoding="utf-8"), path.name


# A phrase a file no longer holds, each with the file that held it.
WITHDRAWN = [
    ("kern/evm/__init__.py", "real EVM-compatible execution semantics"),
    ("kern/evm/__init__.py", "multi-frame"),
    ("kern/evm/opcodes.py", "real EVM-compatible execution semantics"),
    ("kern/evm/opcodes.py", "runs unchanged."),
    ("kern/evm/opcodes.py", "Storage (SSTORE/SLOAD) — modeled at the rollup level"),
    ("kern/evm/dynamic_gas.py", "matching the Ethereum Yellow Paper"),
    ("kern/evm/dynamic_gas.py", "original_value"),
    ("kern/evm/dynamic_gas.py", "warm-read"),
    ("kern/evm/vm.py", "frozen-ish"),
    ("kern/evm/vm.py", "re-executed on L1"),
    ("kern/evm/frames.py", "for its subcalls"),
    ("kern/evm/frames.py", "caller frame"),
    ("tests/test_evm_frames.py", "multi-frame"),
]


@pytest.mark.parametrize("path, phrase", WITHDRAWN, ids=[f"{path}: {phrase[:28]}" for path, phrase in WITHDRAWN])
def test_a_header_no_longer_says_what_the_machine_does_not_do(path, phrase):
    assert phrase not in (ROOT / path).read_text(encoding="utf-8")


def test_the_header_of_the_machine_names_the_nine_fields_of_a_commitment():
    header = inspect.getdoc(vm)
    form = VmState(gas=1).canonical().decode()
    committed = [field.name for field in dataclasses.fields(VmState) if f'"{field.name}":' in form]
    assert len(committed) == 9
    for name in committed:
        assert f"- {name}:" in header, name
    assert "`last_error`" in header and "outside the commitment" in header
