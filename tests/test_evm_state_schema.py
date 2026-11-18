# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A state of the Mini-EVM is a state of the schema of structure version 1.

Section 9.22 of docs/api-stability.md gives a state of the Mini-EVM its
types and its bounds, and says that its sizes are the ones the machine
applies today (section 2.9). This file holds that sentence, and what the
table of differences (section 9.9) says of the form the devnet writes.

The schema is not implemented: the machine hashes its states with the
function of the devnet, and writes its storage as a list of pairs. What is
compared here is what a state holds. Each state the machine reaches is
written in the form of structure version 1, and the reference of the
schemas (tests/schema_reference.py) is asked whether it accepts it.

Nothing here reads a state from outside: the machine takes objects of
Python, and no text.

The machine has its own check of a state (`not_a_state`), which the referee
of a dispute applies to what it is handed. The last tests hold the two
together: what the schema refuses of a state, that check refuses, and what
that check takes for a state, the schema accepts.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import kern.evm
import schema_reference as sch
from evm_states import a_program, a_state
from kern.evm import (
    MAX_CALLDATA_BYTES,
    MAX_MEMORY_BYTES,
    MAX_STACK_WORDS,
    MAX_STORAGE_SLOTS,
    ExecContext,
    Op,
    VmState,
    execute,
    step,
)

NETWORK = bytes.fromhex(json.loads(sch.ref.VECTORS.read_text(encoding="utf-8"))["network_id"])
SCHEMA = "Mini-EVM state"
WORD = 32
LARGEST_GAS = (1 << 63) - 1


def written(state: VmState) -> dict:
    """A state of the machine in the form of structure version 1: words in
    decimal, bytes in hexadecimal, the storage as an object."""
    context = state.context
    return {
        "pc": state.pc,
        "stack": [str(word) for word in state.stack],
        "memory": bytes(state.memory).hex(),
        "gas": state.gas,
        "halted": state.halted,
        "output": state.output.hex(),
        "reverted": state.reverted,
        "storage": {str(slot): str(held) for slot, held in state.storage.items()},
        "context": {
            "address": str(context.address),
            "caller": str(context.caller),
            "value": str(context.value),
            "calldata": context.calldata.hex(),
            "block_number": context.block_number,
            "block_timestamp": context.block_timestamp,
        },
    }


def verdict(state: VmState) -> str:
    return sch.verdict(SCHEMA, written(state), NETWORK)


def push(value: int) -> bytes:
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


CALL = ExecContext(address=0xC0FFEE, caller=(1 << 160) - 1, value=(1 << 256) - 1, calldata=bytes(range(36)),
                   block_number=7, block_timestamp=1_794_000_000)

# Programs that end in every way the machine ends, each with the gas it is given.
PROGRAMS = {
    "returns a word it stored": (push(42) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN]),
                                 100_000),
    "writes two slots and clears one": (push(7) + push(1) + bytes([Op.SSTORE]) + push(9) + push(2)
                                        + bytes([Op.SSTORE]) + push(0) + push(1) + bytes([Op.SSTORE, Op.STOP]),
                                        100_000),
    "reverts with an output": (push(1) + push(0) + bytes([Op.MSTORE8]) + push(1) + push(0) + bytes([Op.REVERT]),
                               100_000),
    "runs out of gas": (push(1) + push(1) + bytes([Op.ADD]) + push(0) + bytes([Op.MSTORE, Op.STOP]), 8),
    "halts on an unknown instruction": (push(1) + bytes([Op.INVALID]), 100_000),
    "hashes its calldata size": (bytes([Op.CALLDATASIZE]) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0)
                                 + bytes([Op.SHA3, Op.CALLER, Op.ADDRESS, Op.CALLVALUE, Op.STOP]), 100_000),
    "reaches for memory beyond the limit": (push(1) + push(2 * MAX_MEMORY_BYTES) + bytes([Op.MSTORE]), 10**10),
    "fills the memory to its limit": (push(MAX_MEMORY_BYTES) + push(0) + bytes([Op.RETURN]), 10**8),
}


def test_the_machine_applies_the_sizes_of_the_schema():
    limit = sch.LIMITS
    assert MAX_STACK_WORDS == limit["evm_stack"] == 1_024
    assert MAX_MEMORY_BYTES == MAX_CALLDATA_BYTES == limit["evm_bytes"] == 1_048_576
    assert MAX_STORAGE_SLOTS == limit["evm_storage"] == 16_384
    assert MAX_MEMORY_BYTES % WORD == 0                      # the memory goes by words, and so does its limit


@pytest.mark.parametrize("name", PROGRAMS)
def test_every_state_of_an_execution_is_a_state_of_the_schema(name):
    code, gas = PROGRAMS[name]
    trace = execute(code, gas=gas, context=CALL, initial_storage={5: 6})
    assert trace.states[-1].halted
    for position, state in enumerate(trace.states):
        assert verdict(state) == "accepted", (name, position)


def test_the_executions_above_end_in_every_way_a_state_ends():
    """So that the test before them says something of each sentence of the
    schema: a state that returned, one that failed with an output, one that
    failed without, and a storage that lost a slot."""
    finals = {name: execute(code, gas=gas, context=CALL, initial_storage={5: 6}).states[-1]
              for name, (code, gas) in PROGRAMS.items()}
    assert {(final.reverted, bool(final.output)) for final in finals.values()} == \
        {(False, True), (False, False), (True, True), (True, False)}
    cleared = finals["writes two slots and clears one"]
    assert cleared.storage == {5: 6, 2: 9} and written(cleared)["storage"] == {"5": "6", "2": "9"}
    assert "out of gas" in finals["runs out of gas"].last_error
    assert "memory limit" in finals["reaches for memory beyond the limit"].last_error
    assert len(finals["fills the memory to its limit"].output) == MAX_MEMORY_BYTES
    # The machine never leaves a state that reverted and has not halted, nor an output before it halts.
    for name, (code, gas) in PROGRAMS.items():
        for state in execute(code, gas=gas, context=CALL, initial_storage={5: 6}).states:
            assert state.halted or not (state.reverted or state.output), name


def test_a_stack_that_reaches_its_limit_is_still_a_state_of_the_schema():
    loop = bytes([Op.JUMPDEST, Op.PUSH1, 1, Op.PUSH1, 0, Op.JUMP])
    state = VmState(gas=10**6)
    while not state.halted:
        state = step(state, loop)
        assert verdict(state) == "accepted"
    assert len(state.stack) == MAX_STACK_WORDS and "stack limit" in state.last_error


def full() -> dict:
    return dict(gas=LARGEST_GAS, stack=[(1 << 256) - 1] * MAX_STACK_WORDS, memory=bytearray(MAX_MEMORY_BYTES),
                storage={slot: 1 for slot in range(1, MAX_STORAGE_SLOTS + 1)},
                context=ExecContext(calldata=bytes(MAX_CALLDATA_BYTES)))


def test_a_state_at_the_limits_is_a_state_for_the_machine_and_for_the_schema():
    state = VmState(**full())
    assert verdict(state) == "accepted"
    assert step(state, bytes([Op.STOP])).halted


@pytest.mark.parametrize("part, more, refusal", [
    ("stack", dict(stack=[1] * (MAX_STACK_WORDS + 1)), "out_of_range"),
    ("memory", dict(memory=bytearray(MAX_MEMORY_BYTES + WORD)), "bad_text"),
    ("output", dict(halted=True, output=bytes(MAX_MEMORY_BYTES + 1)), "bad_text"),
    ("storage", dict(storage={slot: 1 for slot in range(1, MAX_STORAGE_SLOTS + 2)}), "out_of_range"),
    ("calldata", dict(context=ExecContext(calldata=bytes(MAX_CALLDATA_BYTES + 1))), "bad_text"),
])
def test_what_is_too_large_for_the_machine_is_too_large_for_the_schema(part, more, refusal):
    state = VmState(**{**full(), **more})
    assert verdict(state) == refusal
    with pytest.raises(ValueError, match=f"its {part} is beyond the limit"):
        step(state, bytes([Op.STOP]))


def test_the_devnet_commits_to_the_same_nine_fields_in_another_form():
    """What section 9.9 says of a state: the same fields, a storage written
    as a list of pairs, a hash of 64 characters."""
    state = execute(PROGRAMS["writes two slots and clears one"][0], gas=100_000, context=CALL,
                    initial_storage={5: 6}).states[-1]
    today, version_1 = json.loads(state.canonical()), written(state)
    assert list(version_1) == [name for name, _, _ in sch.EVM_STATE.fields]
    assert sorted(today) == sorted(version_1) and len(today) == 9
    assert sorted(today["context"]) == sorted(name for name, _, _ in sch.EVM_CONTEXT.fields)
    for name in ("pc", "stack", "memory", "gas", "halted", "output", "reverted"):
        assert today[name] == version_1[name], name
    assert today["storage"] == [["2", "9"], ["5", "6"]] and version_1["storage"] == {"2": "9", "5": "6"}
    assert len(state.commitment_hex()) == 64 and len(sch.evm_state_hash(NETWORK, version_1).hex()) == 96


# ---------------------------------------------------------------------------
# The check of the machine and the schema
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", PROGRAMS)
def test_every_state_of_an_execution_is_a_state_for_the_check_of_the_machine(name):
    code, gas = PROGRAMS[name]
    for position, state in enumerate(execute(code, gas=gas, context=CALL, initial_storage={5: 6}).states):
        assert kern.evm.not_a_state(state) is None, (name, position)


WORD_MAX = (1 << 256) - 1
ADDRESS_MAX = (1 << 160) - 1


def in_order(**changes) -> VmState:
    """A state that uses every field, then `changes`."""
    parts = dict(pc=3, stack=[1, 2], memory=bytearray(2 * WORD), gas=1_000, halted=False, output=b"", reverted=False,
                 storage={7: 5}, context=CALL)
    parts.update(changes)
    return VmState(**parts)


def called(**changes) -> ExecContext:
    return ExecContext(**{**vars(CALL), **changes})


# What is outside the ranges and the sentences of section 9.22, with the
# answer of the schema and the answer of the machine.
OUTSIDE = {
    "a word of 2^256 in the stack": (dict(stack=[WORD_MAX + 1]), "bad_text",
                                     "its stack holds something other than a word"),
    "a negative word in the stack": (dict(stack=[-1]), "bad_text", "its stack holds something other than a word"),
    "a pc of 2^63": (dict(pc=LARGEST_GAS + 1), "out_of_range", "its pc is out of range"),
    "a negative pc": (dict(pc=-1), "out_of_range", "its pc is out of range"),
    "a gas of 2^63": (dict(gas=LARGEST_GAS + 1), "out_of_range", "its gas is out of range"),
    "a negative gas": (dict(gas=-1), "out_of_range", "its gas is out of range"),
    "a memory of 33 bytes": (dict(memory=bytearray(WORD + 1)), "bad_text", "its memory is not a number of words"),
    "a slot that holds zero": (dict(storage={7: 0}), "inconsistent", "a slot of its storage holds zero"),
    "a slot named 2^256": (dict(storage={WORD_MAX + 1: 5}), "bad_text",
                           "its storage holds something other than a word"),
    "a slot that holds 2^256": (dict(storage={7: WORD_MAX + 1}), "bad_text",
                                "its storage holds something other than a word"),
    "reverted and not halted": (dict(reverted=True), "inconsistent", "it is reverted and not halted"),
    "an output before it halts": (dict(output=b"\x01"), "inconsistent", "it has an output and is not halted"),
    "an address of 2^160": (dict(context=called(address=ADDRESS_MAX + 1)), "bad_text",
                            "an address of its context is out of range"),
    "a caller of 2^160": (dict(context=called(caller=ADDRESS_MAX + 1)), "bad_text",
                          "an address of its context is out of range"),
    "a value of 2^256": (dict(context=called(value=WORD_MAX + 1)), "bad_text",
                         "the value of its context is out of range"),
    "a block number of 2^63": (dict(context=called(block_number=LARGEST_GAS + 1)), "out_of_range",
                               "the block of its context is out of range"),
    "a negative block time": (dict(context=called(block_timestamp=-1)), "out_of_range",
                              "the block of its context is out of range"),
}


def test_the_state_the_next_test_changes_is_a_state_for_both():
    assert verdict(in_order()) == "accepted" and kern.evm.not_a_state(in_order()) is None


@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in OUTSIDE])
def test_what_the_schema_refuses_of_a_state_the_machine_refuses(name):
    changes, refusal, answer = OUTSIDE[name]
    state = in_order(**changes)
    assert verdict(state) == refusal
    assert kern.evm.not_a_state(state) == answer


def test_what_the_machine_takes_for_a_state_the_schema_accepts():
    """States drawn at random, the first one at the limits. Each is a state
    for the check of the machine, and the schema accepts it once it is
    written in the form of structure version 1."""
    rng = random.Random(9_22)
    for draw in range(300):
        state = a_state(rng, a_program(rng), large=draw == 0)
        assert kern.evm.not_a_state(state) is None, draw
        assert verdict(state) == "accepted", draw
