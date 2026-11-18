# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The referee of the Mini-EVM reads what the two parties committed to.

A dispute ends on one step. Both parties agreed on the commitment of the
state before it, one of them hands that state in, and the referee
(`single_step_verify`, `RollupState.resolve_challenge`) runs the step. The
verdict is worth what that state is worth. Five things were wrong.

- The price of a write to the storage read a field of the state that its
  commitment did not hold. Two states of one commitment paid 20,000 and
  5,000 for the same write, and the party that handed the state in chose
  the verdict. The price now reads the slot and the value written, and a
  state holds nothing outside its commitment but its last error.
- A state was read as it came. A stack of texts hashes like a stack of
  words and does not behave like it: `ISZERO`, `EQ` and `SLOAD` gave the
  challenger a batch that was right, and `ADD` left the referee with an
  exception of Python. What is handed in is now checked in full, its sizes
  first, before anything copies it, hashes it or reads a word of it:
  by `step`, and so by the referee of a step, and by `resolve_challenge`
  before it hashes it.
- A call ran through `execute`, which kept every state and hashed each
  one, to read the last. A call now goes through `run`, and a trace keeps
  its commitments, its first state and its last.
- A call that was still running when the step limit of the machine cut it
  came back as a success, with what it had written. It now fails.
- An initial storage beyond the limit was copied before it was refused,
  and a program had no limit at all.

A test named `test_control_...` passed before these rules and still does: it
shows that what the others catch is the rule that was missing, and not the
way they are written. The names this change adds are read from `kern.evm`
inside each test, so that a test fails alone where a name is missing.
"""

from __future__ import annotations

import copy
import functools
import inspect
import json
import random
import sys
import time
import tracemalloc
from dataclasses import fields, replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import kern.evm
import kern.rollup
from evm_states import a_program, a_state
from kern.crypto import KernKeypair
from kern.evm import (
    ExecContext,
    ExecutionTrace,
    FrameKind,
    Op,
    VmState,
    WorldState,
    call_contract,
    create_contract,
    execute,
    single_step_verify,
    step,
)
from kern.evm import dynamic_gas, frames, vm
from kern.rollup import Batch, BatchStatus, FraudProof, Rollup, RollupState, program_hash

# The limits, written here as numbers: a test that read them from the code
# would follow the code wherever it went.
STACK = 1_024
MEMORY = 1_048_576
STORAGE = 16_384
CALLDATA = 1_048_576
CODE = 1_048_576

WORD_MAX = (1 << 256) - 1
ADDRESS_MAX = (1 << 160) - 1
INT_MAX = (1 << 63) - 1
MIB = 1 << 20

NOT_A_STATE = "not a state of the Mini-EVM"
NOT_A_PROGRAM = "not a program of the Mini-EVM"


def push(value: int) -> bytes:
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


def write(slot: int, value: int) -> bytes:
    return push(value) + push(slot) + bytes([Op.SSTORE])


def read_back(state: VmState) -> VmState:
    """The state that the commitment of `state` holds, and nothing more:
    what a party builds from the committed form, without the object."""
    form = json.loads(state.canonical())
    context = form["context"]
    return VmState(
        pc=form["pc"], stack=[int(word) for word in form["stack"]], memory=bytearray.fromhex(form["memory"]),
        gas=form["gas"], halted=form["halted"], output=bytes.fromhex(form["output"]), reverted=form["reverted"],
        storage={int(slot): int(held) for slot, held in form["storage"]},
        context=ExecContext(
            address=int(context["address"]), caller=int(context["caller"]), value=int(context["value"]),
            calldata=bytes.fromhex(context["calldata"]), block_number=context["block_number"],
            block_timestamp=context["block_timestamp"],
        ),
    )


def neither_copied_nor_hashed(patch) -> None:
    """From here on, copying a state or hashing one fails the test."""
    patch.setattr(VmState, "clone", lambda self: pytest.fail("the state was copied"))
    patch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))


def challenge(code: bytes, honest, seq, chal):
    """A rollup whose only batch runs `code`, challenged and bisected down
    to one step. `seq` and `chal` are the commitments each side reveals."""
    sequencer = KernKeypair.from_seed(bytes([0x71]) * 32)
    rollup = Rollup(
        rollup_id="kern-evm-test",
        bridge_address=KernKeypair.from_seed(bytes([0x72]) * 32).address,
        sequencer_address=sequencer.address,
        sequencer_pubkey=sequencer.public_key_b58,
        sequencer_bond=1,
        challenge_window_seconds=600,
        genesis_state_root=honest.commitments[0].hex(),
    )
    state = RollupState(rollup=rollup)
    batch = Batch(
        rollup_id=rollup.rollup_id, batch_index=0,
        parent_state_root=honest.commitments[0].hex(), state_root=seq[-1],
        tx_hashes=[], tx_data_hash=program_hash(code), timestamp=int(time.time()),
        sequencer=sequencer.address, sequencer_pubkey=sequencer.public_key_b58,
    )
    batch.sign(sequencer)
    assert state.post_batch(batch, 1, int(time.time()))[0]
    proof = FraudProof("kern-evm-test", 0, "kn1challenger", chal[-1], seq[-1], {"n_steps": honest.n_steps})
    assert state.open_challenge(proof, int(time.time()))[0]
    bis = state.bisections[0]
    while not bis.is_ready_for_single_step:
        assert state.challenge_round(0, seq[bis.mid], chal[bis.mid])[0]
    return state, bis


def lying_from(commitments, step_index: int, lie: str):
    return commitments[:step_index] + [lie] * (len(commitments) - step_index)


def an_honest_sequencer_is_challenged_on_step(code: bytes, position: int, **start):
    """The sequencer posts the truth. The challenger lies from the state
    after step `position` on, so that the dispute ends on that step."""
    honest = execute(code, gas=100_000, **start)
    truth = [commitment.hex() for commitment in honest.commitments]
    state, bis = challenge(code, honest, seq=truth, chal=lying_from(truth, position + 1, "dd" * 32))
    assert (bis.lo, bis.hi) == (position, position + 1)
    return state, honest, truth


def still_open(state: RollupState) -> bool:
    return state.batches[0].status == BatchStatus.CHALLENGED and 0 in state.active_challenges


# ---------------------------------------------------------------------------
# The price of a write reads what is committed
# ---------------------------------------------------------------------------

# A slot that holds 5 when the program starts: emptied, then written again.
EMPTIED_THEN_WRITTEN = write(7, 0) + write(7, 9) + bytes([Op.STOP])
THE_SECOND_WRITE = 5                                     # the step that runs it: two pushes come before each write


def paid(trace, position: int) -> int:
    return trace.states[position].gas - trace.states[position + 1].gas


def test_a_step_reads_nothing_that_the_commitment_of_a_state_does_not_hold():
    """Every state of an execution, read back from its committed form, takes
    the step the execution took. The second write did not: its price read
    what the slot held when the program started."""
    trace = execute(EMPTIED_THEN_WRITTEN, gas=100_000, initial_storage={7: 5})
    assert trace.states[-1].halted and not trace.states[-1].reverted
    for position in range(trace.n_steps):
        before = read_back(trace.states[position])
        assert before.commitment() == trace.commitments[position]
        assert step(before, EMPTIED_THEN_WRITTEN).commitment() == trace.commitments[position + 1], position


def test_a_slot_emptied_and_written_again_pays_as_a_slot_that_holds_zero():
    trace = execute(EMPTIED_THEN_WRITTEN, gas=100_000, initial_storage={7: 5})
    assert [paid(trace, 2), paid(trace, THE_SECOND_WRITE)] == [5_000, 20_000]
    assert trace.states[-1].storage == {7: 9}


def test_control_a_slot_empty_at_the_start_pays_the_same_each_time_it_is_filled():
    trace = execute(write(7, 9) + write(7, 0) + write(7, 9) + bytes([Op.STOP]), gas=100_000)
    assert [paid(trace, position) for position in (2, 5, 8)] == [20_000, 5_000, 20_000]


@pytest.mark.parametrize("current", [0, 1, 2])
@pytest.mark.parametrize("new", [0, 1, 2])
def test_control_a_write_costs_20000_in_a_slot_that_holds_zero_and_5000_elsewhere(current, new):
    state = VmState(gas=100_000, stack=[new, 7], storage={7: current} if current else {})
    after = step(state, bytes([Op.SSTORE]))
    assert not after.reverted
    assert state.gas - after.gas == (20_000 if current == 0 and new != 0 else 5_000)


def test_the_price_of_a_write_is_a_function_of_the_slot_and_of_the_value_written():
    assert list(inspect.signature(dynamic_gas.sstore_cost).parameters) == ["current", "new"]
    assert dynamic_gas.sstore_cost(0, 42) == 20_000
    assert dynamic_gas.sstore_cost(99, 42) == 5_000
    assert dynamic_gas.sstore_cost(99, 0) == 5_000
    assert dynamic_gas.sstore_cost(42, 42) == dynamic_gas.sstore_cost(0, 0) == 5_000


def test_a_state_holds_nothing_outside_its_commitment_but_its_last_error():
    committed = set(json.loads(VmState().canonical()))
    assert {field.name for field in fields(VmState)} - committed == {"last_error"}
    assert len(committed) == 9


def test_a_rollup_gives_an_honest_sequencer_its_batch_on_a_state_read_back_from_its_commitment():
    """The challenger disputes the second write and hands in a state it
    built from the commitment both parties agreed on. That state paid
    another price, and the batch was reverted."""
    state, honest, truth = an_honest_sequencer_is_challenged_on_step(
        EMPTIED_THEN_WRITTEN, THE_SECOND_WRITE, initial_storage={7: 5})
    handed_in = read_back(honest.states[THE_SECOND_WRITE])
    assert handed_in.commitment_hex() == truth[THE_SECOND_WRITE]
    assert state.resolve_challenge(0, EMPTIED_THEN_WRITTEN, handed_in) == (True, "sequencer")
    assert state.batches[0].status == BatchStatus.PENDING


# ---------------------------------------------------------------------------
# What is not a state of the machine
# ---------------------------------------------------------------------------

CONTEXT = dict(address=0xC0DE, caller=0xAA, value=9, calldata=b"\x01\x02", block_number=7,
               block_timestamp=1_794_000_000)


def a_state_with(**changes) -> VmState:
    """A state of the machine that uses every field, then `changes`."""
    parts = dict(pc=3, stack=[1, 2], memory=bytearray(64), gas=1_000, halted=False, output=b"", reverted=False,
                 storage={7: 5}, context=ExecContext(**CONTEXT))
    parts.update(changes)
    return VmState(**parts)


def in_a_context_with(**changes) -> VmState:
    return a_state_with(context=ExecContext(**{**CONTEXT, **changes}))


class DerivedState(VmState):
    pass


class DerivedContext(ExecContext):
    pass


class DerivedStorage(dict):
    pass


def with_one_more_attribute(target):
    """Written into the dictionary of the object."""
    vars(target)["note"] = "one more"
    return target


def whose_context_lost_a_field() -> VmState:
    """A context has no dictionary and takes no attribute more. One of its
    fields can still be taken away."""
    context = ExecContext(**CONTEXT)
    object.__delattr__(context, "value")
    return a_state_with(context=context)


def that_answers_for_its_own_commitment() -> VmState:
    state = a_state_with()
    state.commitment_hex = lambda: "00" * 32          # the instance answers, and not the class
    return state


def that_lost_a_field() -> VmState:
    state = a_state_with()
    del state.pc
    return state


# What is handed in, each with the part of the answer of the machine that names it.
NOT_STATES = {
    # the object
    "nothing": (lambda: None, "it is not a VmState"),
    "a dictionary of the fields": (lambda: dict(vars(a_state_with())), "it is not a VmState"),
    "a class derived from the state": (lambda: DerivedState(gas=1_000), "it is not a VmState"),
    "a state with one more attribute": (lambda: with_one_more_attribute(a_state_with()), "it is not a VmState"),
    "a state that answers for its own commitment": (that_answers_for_its_own_commitment, "it is not a VmState"),
    "a state that lost a field": (that_lost_a_field, "it is not a VmState"),
    # the stack
    "a stack that is a tuple": (lambda: a_state_with(stack=(1, 2)), "its stack is not a list"),
    "no stack": (lambda: a_state_with(stack=None), "its stack is not a list"),
    "a text in the stack": (lambda: a_state_with(stack=["1", 2]), "its stack holds something other than a word"),
    "a boolean in the stack": (lambda: a_state_with(stack=[True, 2]), "its stack holds something other than a word"),
    "a float in the stack": (lambda: a_state_with(stack=[1.0, 2]), "its stack holds something other than a word"),
    "a negative word": (lambda: a_state_with(stack=[1, -1]), "its stack holds something other than a word"),
    "a word of 2^256": (lambda: a_state_with(stack=[WORD_MAX + 1]), "its stack holds something other than a word"),
    # the memory
    "a memory of bytes": (lambda: a_state_with(memory=bytes(64)), "its memory is not a bytearray"),
    "a memory that is a list": (lambda: a_state_with(memory=[0] * 64), "its memory is not a bytearray"),
    "a memory of 33 bytes": (lambda: a_state_with(memory=bytearray(33)), "its memory is not a number of words"),
    # the output
    "an output that is a bytearray": (lambda: a_state_with(halted=True, output=bytearray(b"\x01")),
                                      "its output is not a bytes"),
    "an output that is a text": (lambda: a_state_with(halted=True, output="01"), "its output is not a bytes"),
    # the storage
    "a storage that is a list of pairs": (lambda: a_state_with(storage=[(7, 5)]), "its storage is not a dict"),
    "a storage of a class derived from dict": (lambda: a_state_with(storage=DerivedStorage({7: 5})),
                                               "its storage is not a dict"),
    "a slot named by a text": (lambda: a_state_with(storage={"7": 5}),
                               "its storage holds something other than a word"),
    "a slot named by a boolean": (lambda: a_state_with(storage={True: 5}),
                                  "its storage holds something other than a word"),
    "a slot named by a negative number": (lambda: a_state_with(storage={-1: 5}),
                                          "its storage holds something other than a word"),
    "a slot that holds a text": (lambda: a_state_with(storage={7: "5"}),
                                 "its storage holds something other than a word"),
    "a slot that holds 2^256": (lambda: a_state_with(storage={7: WORD_MAX + 1}),
                                "its storage holds something other than a word"),
    "a slot that holds zero": (lambda: a_state_with(storage={7: 0}), "a slot of its storage holds zero"),
    # the program counter and the gas
    "a negative pc": (lambda: a_state_with(pc=-1), "its pc is out of range"),
    "a pc of 2^63": (lambda: a_state_with(pc=INT_MAX + 1), "its pc is out of range"),
    "a pc that is a boolean": (lambda: a_state_with(pc=True), "its pc is out of range"),
    "a pc that is a text": (lambda: a_state_with(pc="3"), "its pc is out of range"),
    "a pc that is a float": (lambda: a_state_with(pc=3.0), "its pc is out of range"),
    "a negative gas": (lambda: a_state_with(gas=-1), "its gas is out of range"),
    "a gas of 2^63": (lambda: a_state_with(gas=INT_MAX + 1), "its gas is out of range"),
    "a gas that is a boolean": (lambda: a_state_with(gas=True), "its gas is out of range"),
    "a gas that is a text": (lambda: a_state_with(gas="1000"), "its gas is out of range"),
    # halted and reverted
    "halted that is 1": (lambda: a_state_with(halted=1), "halted or reverted is not a boolean"),
    "halted that is nothing": (lambda: a_state_with(halted=None), "halted or reverted is not a boolean"),
    "reverted that is 0": (lambda: a_state_with(reverted=0), "halted or reverted is not a boolean"),
    "reverted and not halted": (lambda: a_state_with(reverted=True), "it is reverted and not halted"),
    "an output before it halts": (lambda: a_state_with(output=b"\x01"), "it has an output and is not halted"),
    # the context
    "no context": (lambda: a_state_with(context=None), "its context is not an ExecContext"),
    "a context that is a dictionary": (lambda: a_state_with(context=dict(CONTEXT)),
                                       "its context is not an ExecContext"),
    "a context of a derived class": (lambda: a_state_with(context=DerivedContext(**CONTEXT)),
                                     "its context is not an ExecContext"),
    "a context that lost a field": (whose_context_lost_a_field, "its context is not an ExecContext"),
    "an address that is a text": (lambda: in_a_context_with(address="5"), "an address of its context is out of range"),
    "an address of 2^160": (lambda: in_a_context_with(address=ADDRESS_MAX + 1),
                            "an address of its context is out of range"),
    "a negative address": (lambda: in_a_context_with(address=-1), "an address of its context is out of range"),
    "a caller of 2^160": (lambda: in_a_context_with(caller=ADDRESS_MAX + 1),
                          "an address of its context is out of range"),
    "a caller that is a boolean": (lambda: in_a_context_with(caller=True),
                                   "an address of its context is out of range"),
    "a value of 2^256": (lambda: in_a_context_with(value=WORD_MAX + 1), "the value of its context is out of range"),
    "a value that is a text": (lambda: in_a_context_with(value="9"), "the value of its context is out of range"),
    "calldata that is a bytearray": (lambda: in_a_context_with(calldata=bytearray(b"\x01")),
                                     "its calldata is not bytes"),
    "calldata that is a text": (lambda: in_a_context_with(calldata="01"), "its calldata is not bytes"),
    "a negative block number": (lambda: in_a_context_with(block_number=-1),
                                "the block of its context is out of range"),
    "a block number of 2^63": (lambda: in_a_context_with(block_number=INT_MAX + 1),
                               "the block of its context is out of range"),
    "a block time that is a boolean": (lambda: in_a_context_with(block_timestamp=True),
                                       "the block of its context is out of range"),
    "a block time that is a float": (lambda: in_a_context_with(block_timestamp=1.5),
                                     "the block of its context is out of range"),
}
EACH_NOT_STATE = [pytest.param(name, id=name.replace(" ", "-")) for name in NOT_STATES]


# The program that state stands in: its pc is at the ADD.
ADDS = bytes(3) + bytes([Op.ADD, Op.STOP])


def test_control_the_state_the_others_are_made_from_runs():
    state = a_state_with()
    assert step(state, ADDS).stack == [3]
    assert single_step_verify(ADDS, state, "aa" * 32, "bb" * 32, 1).challenger_wins


def test_the_state_the_others_are_made_from_is_a_state_of_the_machine():
    assert kern.evm.not_a_state(a_state_with()) is None
    assert kern.evm.not_a_state(a_state_with(halted=True, reverted=True, output=b"\x01")) is None
    kern.evm.require_state(a_state_with())


# Each of these is too large, and holds something else that is out of order.
TOO_LARGE = {
    "stack": lambda: a_state_with(stack=[1] * STACK + ["a text"]),
    "memory": lambda: a_state_with(memory=bytearray(MEMORY + 33)),
    "output": lambda: a_state_with(halted=True, reverted=0, output=bytes(MEMORY + 1)),
    "storage": lambda: a_state_with(storage={**{slot: 1 for slot in range(1, STORAGE + 1)}, "a text": 0}),
    "calldata": lambda: in_a_context_with(calldata=bytes(CALLDATA + 1), block_number=-1),
}


@pytest.mark.parametrize("part", TOO_LARGE)
def test_the_check_of_a_state_reads_its_sizes_before_what_it_holds(part, monkeypatch):
    """The size is what the machine names: it has read no word of a state
    that is too large."""
    handed_in = TOO_LARGE[part]()
    neither_copied_nor_hashed(monkeypatch)
    assert kern.evm.not_a_state(handed_in) == f"its {part} is beyond the limit"


@pytest.mark.parametrize("name", EACH_NOT_STATE)
def test_the_machine_says_what_keeps_an_object_from_being_a_state(name, monkeypatch):
    build, answer = NOT_STATES[name]
    handed_in = build()
    neither_copied_nor_hashed(monkeypatch)
    assert kern.evm.not_a_state(handed_in) == answer
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: {answer}$"):
        kern.evm.require_state(handed_in)


@pytest.mark.parametrize("name", EACH_NOT_STATE)
def test_the_machine_takes_no_step_from_what_is_not_a_state(name, monkeypatch):
    build, answer = NOT_STATES[name]
    handed_in = build()
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: {answer}$"):
        step(handed_in, ADDS)


@pytest.mark.parametrize("name", EACH_NOT_STATE)
def test_the_referee_of_a_step_gives_no_verdict_on_what_is_not_a_state(name, monkeypatch):
    build, answer = NOT_STATES[name]
    handed_in = build()
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: {answer}$"):
        single_step_verify(ADDS, handed_in, "aa" * 32, "bb" * 32, 1)


ORDINARY = bytes([Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD, Op.PUSH1, 3, Op.ADD, Op.STOP])


@pytest.mark.parametrize("name", EACH_NOT_STATE)
def test_a_rollup_turns_away_what_is_not_a_state_before_it_hashes_it(name, monkeypatch):
    build, answer = NOT_STATES[name]
    state, honest, _ = an_honest_sequencer_is_challenged_on_step(ORDINARY, 2)
    handed_in = build()
    agreed = honest.states[2]
    with monkeypatch.context() as patch:
        neither_copied_nor_hashed(patch)
        assert state.resolve_challenge(0, ORDINARY, handed_in) == (False, f"pre_state is {NOT_A_STATE}: {answer}")
    # The challenge is still open, and the state both parties agreed on settles it.
    assert still_open(state)
    assert state.resolve_challenge(0, ORDINARY, agreed) == (True, "sequencer")


# ---------------------------------------------------------------------------
# A state that hashes like the agreed one and is not it
# ---------------------------------------------------------------------------

def of(state: VmState, **changes) -> VmState:
    """`state`, with other objects in some of its fields."""
    other = state.clone()
    for name, value in changes.items():
        setattr(other, name, value)
    return other


def with_a_text_address(state: VmState) -> VmState:
    return of(state, context=replace(state.context, address=str(state.context.address)))


# The program, the step that is disputed, what the execution starts from, and
# what the challenger hands in: it has the commitment of the honest state.
LOOKALIKES = {
    "ISZERO on a text": (push(0) + bytes([Op.ISZERO, Op.STOP]), 1, {}, lambda s: of(s, stack=["0"])),
    "EQ on a text and a word": (push(3) + push(3) + bytes([Op.EQ, Op.STOP]), 2, {}, lambda s: of(s, stack=["3", 3])),
    "SLOAD of a slot named by a text on the stack": (
        push(7) + bytes([Op.SLOAD, Op.STOP]), 1, dict(initial_storage={7: 5}), lambda s: of(s, stack=["7"])),
    "SLOAD from a storage keyed by a text": (
        push(7) + bytes([Op.SLOAD, Op.STOP]), 1, dict(initial_storage={7: 5}), lambda s: of(s, storage={"7": 5})),
    "SSTORE to a storage keyed by a text": (
        write(7, 9) + bytes([Op.STOP]), 2, dict(initial_storage={7: 5}), lambda s: of(s, storage={"7": 5})),
    "SLOAD of a slot that holds a text": (
        push(7) + bytes([Op.SLOAD, Op.STOP]), 1, dict(initial_storage={7: 5}), lambda s: of(s, storage={7: "5"})),
    "ADD on texts": (push(1) + push(2) + bytes([Op.ADD, Op.STOP]), 2, {}, lambda s: of(s, stack=["1", "2"])),
    "JUMP to a text": (push(3) + bytes([Op.JUMP, Op.JUMPDEST, Op.STOP]), 1, {}, lambda s: of(s, stack=["3"])),
    "ADDRESS of a text": (bytes([Op.ADDRESS, Op.STOP]), 0, dict(context=ExecContext(address=5)), with_a_text_address),
}


@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in LOOKALIKES])
def test_a_state_that_hashes_like_the_agreed_one_and_is_not_it_wins_nothing(name):
    """The sequencer is honest. The challenger hands in an object that has
    the commitment both agreed on and other types inside. It reverted the
    batch, or left the referee with an exception of Python."""
    code, position, start, lookalike = LOOKALIKES[name]
    state, honest, truth = an_honest_sequencer_is_challenged_on_step(code, position, **start)
    agreed = honest.states[position]
    handed_in = lookalike(agreed)
    assert handed_in.commitment_hex() == truth[position]

    assert state.resolve_challenge(0, code, handed_in) != (True, "challenger")
    assert still_open(state)
    ok, reason = state.resolve_challenge(0, code, handed_in)
    assert not ok and reason.startswith(f"pre_state is {NOT_A_STATE}: ")
    assert state.resolve_challenge(0, code, agreed) == (True, "sequencer")
    assert state.batches[0].status == BatchStatus.PENDING


def test_an_object_that_answers_for_its_own_commitment_wins_nothing():
    """`resolve_challenge` asked the object it was handed for its
    commitment. An object that answers with the agreed one, whatever it
    holds, had the referee run a state nobody agreed on."""
    state, honest, truth = an_honest_sequencer_is_challenged_on_step(ORDINARY, 2)
    handed_in = VmState(gas=1, halted=True)
    handed_in.commitment_hex = lambda: truth[2]
    ok, reason = state.resolve_challenge(0, ORDINARY, handed_in)
    assert (ok, reason) == (False, f"pre_state is {NOT_A_STATE}: it is not a VmState")
    assert state.resolve_challenge(0, ORDINARY, honest.states[2]) == (True, "sequencer")


# ---------------------------------------------------------------------------
# The machine reaches no other state
# ---------------------------------------------------------------------------

def test_a_step_from_a_state_of_the_machine_gives_a_state_of_the_machine():
    """States drawn at random, small ones and ones at the limits, each in
    front of a program drawn with it. No step raises, none changes the state
    it is given, and each gives a state of the machine."""
    rng = random.Random(27_28)
    for draw in range(1_500):
        code = a_program(rng)
        state = a_state(rng, code, large=draw % 100 == 0)
        assert kern.evm.not_a_state(state) is None, draw
        seen = state.commitment()
        after = step(state, code)
        assert kern.evm.not_a_state(after) is None, (draw, code.hex())
        assert state.commitment() == seen, draw


def test_no_instruction_takes_a_state_of_the_machine_out_of_the_machine():
    """The 256 values of a byte, as the one instruction of a program, from
    states whose stacks hold the words that sit on the edge of something."""
    rng = random.Random(21)
    for byte in range(256):
        code = bytes([byte]) + bytes(32)
        for _ in range(8):
            state = a_state(rng, code)
            state.pc = 0
            assert kern.evm.not_a_state(step(state, code)) is None, f"opcode {byte:#04x}"


def test_control_a_step_that_does_not_halt_the_machine_costs_gas():
    """So the gas bounds the steps of a run: no instruction runs for nothing
    and leaves the machine running."""
    rng = random.Random(32)
    for byte in range(256):
        code = bytes([byte]) + bytes(32)
        for _ in range(8):
            state = a_state(rng, code)
            state.pc, state.halted, state.reverted, state.output = 0, False, False, b""
            after = step(state, code)
            assert after.halted or after.gas < state.gas, f"opcode {byte:#04x}"


# ---------------------------------------------------------------------------
# A call keeps no trace, and a trace keeps its commitments
# ---------------------------------------------------------------------------

CALLER, CONTRACT = 0xAA, 0xCC
IDENTITY = 0x04
HELD = 8_192                                              # bytes of memory held by the program below


def holds_its_memory() -> bytes:
    """Extends the memory to `HELD` bytes, then loops until the gas runs out."""
    head = push(0) + push(HELD - 32) + bytes([Op.MSTORE])
    return head + bytes([Op.JUMPDEST]) + push(len(head)) + bytes([Op.JUMP])


def world(code: bytes = bytes([Op.STOP])) -> WorldState:
    w = WorldState()
    w.get(CALLER).balance = 1_000
    w.get(CONTRACT).code = code
    return w


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


def test_control_the_program_that_holds_its_memory_runs_for_thousands_of_steps():
    trace = execute(holds_its_memory(), gas=20_000)
    final = trace.states[-1]
    assert trace.n_steps > 4_000 and len(final.memory) == HELD and "out of gas" in final.last_error


def test_a_call_hashes_no_state(monkeypatch):
    w = world(holds_its_memory())
    monkeypatch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=0, calldata=b"", gas=20_000)
    assert not result.success and result.gas_remaining < 12


def test_a_call_keeps_no_state_on_its_way():
    """Thousands of steps on 8,192 bytes of memory: the call held each of
    those memories until it ended, tens of mebibytes to read one state."""
    w = world(holds_its_memory())
    held = peak_of(lambda: call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=0,
                                         calldata=b"", gas=20_000))
    assert held < MIB


def test_a_creation_hashes_no_state_and_keeps_none(monkeypatch):
    w = world()
    monkeypatch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))
    held = peak_of(lambda: create_contract(w, creator=CALLER, init_code=holds_its_memory(), value=0, gas=20_000))
    assert held < MIB


def test_a_trace_keeps_one_commitment_for_each_step_and_two_states():
    kept = {}

    def trace_it():
        kept["trace"] = execute(holds_its_memory(), gas=20_000)

    tracemalloc.start()
    try:
        trace_it()
        held_at_the_end = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    trace = kept["trace"]
    assert len(trace.commitments) == trace.n_steps + 1 > 4_000
    assert held_at_the_end < MIB
    assert trace.states[-1].commitment() == trace.commitments[-1]


SMALL = write(7, 9) + push(42) + push(0) + bytes([Op.MSTORE]) + push(32) + push(0) + bytes([Op.RETURN])


def test_control_the_states_of_a_trace_are_the_states_of_its_steps():
    trace = execute(SMALL, gas=100_000, context=ExecContext(**CONTEXT), initial_storage={5: 6})
    states = trace.states
    assert len(states) == trace.n_steps + 1 == len(trace.commitments) == 10
    for position in range(len(states)):
        assert states[position].commitment() == trace.commitments[position]
        assert states[position - len(states)].commitment() == trace.commitments[position]
    assert [state.commitment() for state in states] == trace.commitments
    assert [state.commitment() for state in states[2:5]] == trace.commitments[2:5]
    assert [state.commitment() for state in states[::3]] == trace.commitments[::3]
    assert [state.commitment() for state in states[:-1]] == trace.commitments[:-1]
    assert [state.commitment() for state in states[::-1]] == trace.commitments[::-1]
    assert [state.commitment() for state in states[7:1:-2]] == trace.commitments[7:1:-2]
    assert states[4:4] == [] and len(states[:]) == 10
    for outside in (len(states), -len(states) - 1):
        with pytest.raises(IndexError):
            states[outside]
    assert states[-1].halted and states[-1].output == (42).to_bytes(32, "big") and states[-1].storage == {5: 6, 7: 9}


def test_changing_a_state_read_from_a_trace_changes_nothing_in_the_trace():
    trace = execute(SMALL, gas=100_000, initial_storage={5: 6})
    trace.states[0].stack.append(5)
    trace.states[0].storage.clear()
    trace.states[-1].stack.append(5)
    seen = []
    for state in trace.states:
        seen.append(state.commitment())
        state.memory.extend(b"\x01" * 32)
        state.stack.append(5)
    assert seen == trace.commitments
    for position in range(trace.n_steps + 1):
        assert trace.states[position].commitment() == trace.commitments[position]


def test_control_an_execution_runs_on_its_own_copy_of_the_storage_it_is_given():
    given = {5: 6}
    trace = execute(SMALL, gas=100_000, initial_storage=given)
    given[5], given[8] = 7, 9
    assert trace.states[0].commitment() == trace.commitments[0]
    assert trace.states[0].storage == {5: 6} and trace.states[-1].storage == {5: 6, 7: 9}


def test_control_a_trace_made_of_a_list_of_states_still_reads():
    """The form the public examples write: the states of one trace and the
    commitments of another."""
    honest = execute(ORDINARY)
    lied = list(honest.commitments)
    lied[-1] = b"\xee" * 32
    fake = ExecutionTrace(states=honest.states, commitments=lied)
    assert fake.n_steps == honest.n_steps == 6
    from_a_list = ExecutionTrace(states=list(honest.states), commitments=list(honest.commitments))
    assert from_a_list.n_steps == 6 and from_a_list.states[3].commitment() == honest.commitments[3]


RUNS = {
    "returns": (SMALL, dict(gas=100_000, initial_storage={5: 6})),
    "reverts": (push(1) + push(0) + bytes([Op.MSTORE8]) + push(1) + push(0) + bytes([Op.REVERT]), dict(gas=100_000)),
    "runs out of gas": (holds_its_memory(), dict(gas=2_000)),
    "reads its context": (bytes([Op.CALLER, Op.CALLVALUE, Op.ADDRESS, Op.STOP]),
                          dict(gas=100, context=ExecContext(**CONTEXT))),
    "is cut by the step limit": (holds_its_memory(), dict(gas=20_000, max_steps=40)),
    "takes no step": (ORDINARY, dict(max_steps=0)),
}


@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in RUNS])
def test_run_gives_the_last_state_of_an_execution_and_hashes_nothing(name, monkeypatch):
    code, how = RUNS[name]
    trace = execute(code, **how)
    with monkeypatch.context() as patch:
        patch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))
        last = kern.evm.run(code, **how)
    assert last.commitment() == trace.commitments[-1]
    assert last.last_error == trace.states[-1].last_error
    assert last.halted == (name not in ("is cut by the step limit", "takes no step"))


# ---------------------------------------------------------------------------
# A call that the step limit cuts
# ---------------------------------------------------------------------------

WRITES_THEN_LOOPS = write(7, 9) + bytes([Op.JUMPDEST]) + push(len(write(7, 9))) + bytes([Op.JUMP])


def cut_after(patch, steps: int) -> None:
    """Make the calls of a test stop after `steps` steps, as they stop after
    1,000,000: whichever function a call goes through gets that limit."""
    for name in ("execute", "run"):
        whole = getattr(vm, name, None)
        if whole is not None:
            patch.setattr(frames, name, functools.partial(whole, max_steps=steps), raising=False)


def test_control_the_program_that_loops_is_still_running_after_50_steps():
    last = execute(WRITES_THEN_LOOPS, gas=1_000_000, max_steps=50).states[-1]
    assert not last.halted and not last.reverted and last.storage == {7: 9} and last.gas == 979_810


def test_a_call_that_the_step_limit_cuts_fails_and_leaves_the_world_as_it_was(monkeypatch):
    """It came back as a success, with the slot it had written and the
    value it had been sent."""
    w = world(WRITES_THEN_LOOPS)
    cut_after(monkeypatch, 50)
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"",
                           gas=1_000_000)
    assert (result.success, result.return_data, result.gas_remaining) == (False, b"", 979_810)
    assert w.get(CONTRACT).storage == {}
    assert balances(w) == {CALLER: 1_000}


def test_control_the_same_call_succeeds_when_its_program_halts_in_time(monkeypatch):
    w = world(write(7, 9) + bytes([Op.STOP]))
    cut_after(monkeypatch, 50)
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"",
                           gas=1_000_000)
    assert result.success and w.get(CONTRACT).storage == {7: 9} and balances(w) == {CALLER: 990, CONTRACT: 10}


def test_a_creation_that_the_step_limit_cuts_creates_nothing(monkeypatch):
    w = world()
    cut_after(monkeypatch, 50)
    address, result = create_contract(w, creator=CALLER, init_code=WRITES_THEN_LOOPS, value=10, gas=1_000_000)
    assert address is None and not result.success and result.gas_remaining == 979_810
    assert balances(w) == {CALLER: 1_000}
    assert [account.code for account in w.accounts.values() if account.code] == [bytes([Op.STOP])]
    assert all(not account.storage for account in w.accounts.values())


# ---------------------------------------------------------------------------
# Before anything is copied
# ---------------------------------------------------------------------------

def too_large_a_storage() -> dict:
    return {slot: 1 for slot in range(1, STORAGE + 2)}


@pytest.mark.parametrize("door", ["execute", "run"])
def test_an_initial_storage_beyond_the_limit_is_refused_before_it_is_copied(door):
    """It was refused after two copies of it."""
    storage = too_large_a_storage()

    def start():
        with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: its storage is beyond the limit$"):
            getattr(kern.evm, door)(bytes([Op.STOP]), gas=1_000, initial_storage=storage)

    assert peak_of(start) < sys.getsizeof(storage) // 4


def test_a_call_copies_nothing_of_a_storage_beyond_the_limit():
    """The call copied the world, storage and all, before the machine
    refused that storage."""
    w = world()
    w.get(CONTRACT).storage = too_large_a_storage()

    def call():
        with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: its storage is beyond the limit$"):
            call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"",
                          gas=100_000)

    assert peak_of(call) < sys.getsizeof(w.get(CONTRACT).storage) // 4
    assert balances(w) == {CALLER: 1_000}


def test_a_delegated_call_copies_nothing_of_the_storage_of_its_caller_when_it_is_beyond_the_limit():
    """A delegated call runs the code of the contract on the storage of its
    caller: that storage is the one whose size is read."""
    w = world(write(1, 2) + bytes([Op.STOP]))
    w.get(CALLER).storage = too_large_a_storage()

    def call():
        with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: its storage is beyond the limit$"):
            call_contract(w, kind=FrameKind.DELEGATECALL, caller=CALLER, address=CONTRACT, value=0, calldata=b"",
                          gas=100_000)

    assert peak_of(call) < sys.getsizeof(w.get(CALLER).storage) // 4
    assert len(w.get(CALLER).storage) == STORAGE + 1 and not w.get(CONTRACT).storage


def test_control_a_delegated_call_runs_on_the_storage_of_its_caller():
    w = world(write(1, 2) + bytes([Op.STOP]))
    w.get(CALLER).storage = {slot: 1 for slot in range(1, STORAGE + 1)}
    w.get(CONTRACT).storage = {9: 9}
    result = call_contract(w, kind=FrameKind.DELEGATECALL, caller=CALLER, address=CONTRACT, value=0, calldata=b"",
                           gas=100_000)
    assert result.success and w.get(CALLER).storage[1] == 2 and w.get(CONTRACT).storage == {9: 9}


def test_control_a_call_runs_on_a_storage_at_the_limit():
    w = world(write(1, 2) + bytes([Op.STOP]))
    w.get(CONTRACT).storage = {slot: 1 for slot in range(1, STORAGE + 1)}
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=0, calldata=b"",
                           gas=100_000)
    assert result.success and w.get(CONTRACT).storage[1] == 2 and len(w.get(CONTRACT).storage) == STORAGE


# ---------------------------------------------------------------------------
# A program of the machine
# ---------------------------------------------------------------------------

def test_the_limit_of_a_program_is_public_and_is_this_number():
    assert kern.evm.MAX_CODE_BYTES == vm.MAX_CODE_BYTES == CODE
    assert vm.MAX_MEMORY_BYTES == CODE                     # the code of a contract is an output of the machine


STARTS = {
    "step": lambda code: step(VmState(gas=1_000), code),
    "execute": lambda code: execute(code, gas=1_000),
    "run": lambda code: kern.evm.run(code, gas=1_000),
    "single_step_verify": lambda code: single_step_verify(code, VmState(gas=1_000), "aa" * 32, "bb" * 32, 1),
}


@pytest.mark.parametrize("door", STARTS)
def test_the_machine_runs_no_program_beyond_the_limit(door, monkeypatch):
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"^{NOT_A_PROGRAM}: it is beyond the limit$"):
        STARTS[door](bytes(CODE + 1))


@pytest.mark.parametrize("door", ["step", "execute", "single_step_verify"])
def test_control_a_program_at_the_limit_runs(door):
    STARTS[door](bytes(CODE))


def test_run_takes_a_program_at_the_limit():
    assert kern.evm.run(bytes(CODE), gas=1_000).halted


@pytest.mark.parametrize("door", ["step", "execute", "run", "single_step_verify"])
@pytest.mark.parametrize("code", [bytearray([Op.STOP]), [int(Op.STOP)], "00", None],
                         ids=["a-bytearray", "a-list", "a-text", "nothing"])
def test_a_program_is_bytes(door, code, monkeypatch):
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"^{NOT_A_PROGRAM}: it is not bytes$"):
        STARTS[door](code)


def test_a_rollup_turns_away_a_program_beyond_the_limit_before_it_hashes_it(monkeypatch):
    state, honest, _ = an_honest_sequencer_is_challenged_on_step(ORDINARY, 2)
    agreed = honest.states[2]
    with monkeypatch.context() as patch:
        patch.setattr(kern.rollup, "program_hash", lambda code: pytest.fail("the program was hashed"))
        neither_copied_nor_hashed(patch)
        assert state.resolve_challenge(0, bytes(CODE + 1), agreed) == \
            (False, "code is beyond the limit of the Mini-EVM")
    assert still_open(state)
    assert state.resolve_challenge(0, ORDINARY, agreed) == (True, "sequencer")


def test_control_a_rollup_settles_a_challenge_on_a_program_at_the_limit():
    code = ORDINARY + bytes(CODE - len(ORDINARY))
    assert len(code) == CODE
    state, honest, _ = an_honest_sequencer_is_challenged_on_step(code, 2)
    assert state.resolve_challenge(0, code, honest.states[2]) == (True, "sequencer")


def test_a_call_runs_no_code_beyond_the_limit_and_moves_nothing():
    w = world(bytes(CODE + 1))
    before = copy.deepcopy(w.accounts)
    with pytest.raises(ValueError, match=f"^{NOT_A_PROGRAM}: it is beyond the limit$"):
        call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"", gas=100_000)
    assert w.accounts == before


def test_a_creation_runs_no_code_beyond_the_limit_and_moves_nothing():
    w = world()
    before = copy.deepcopy(w.accounts)
    with pytest.raises(ValueError, match=f"^{NOT_A_PROGRAM}: it is beyond the limit$"):
        create_contract(w, creator=CALLER, init_code=bytes(CODE + 1), value=10, gas=100_000)
    assert w.accounts == before


# ---------------------------------------------------------------------------
# What a run starts from
# ---------------------------------------------------------------------------

# What an execution is given, each with the part of the answer that names it.
NO_START = {
    "a negative gas": (dict(gas=-1), "its gas is out of range"),
    "a gas of 2^63": (dict(gas=INT_MAX + 1), "its gas is out of range"),
    "a gas that is a boolean": (dict(gas=True), "its gas is out of range"),
    "an address of 2^160": (dict(context=ExecContext(address=ADDRESS_MAX + 1)),
                            "an address of its context is out of range"),
    "a value of 2^256": (dict(context=ExecContext(value=WORD_MAX + 1)), "the value of its context is out of range"),
    "calldata that is a bytearray": (dict(context=ExecContext(calldata=bytearray(b"\x01"))),
                                     "its calldata is not bytes"),
    "a negative block number": (dict(context=ExecContext(block_number=-1)),
                                "the block of its context is out of range"),
    "a context that is a dictionary": (dict(context=dict(CONTEXT)), "its context is not an ExecContext"),
    "a slot that holds zero": (dict(initial_storage={7: 0}), "a slot of its storage holds zero"),
    "a slot named by a text": (dict(initial_storage={"7": 5}), "its storage holds something other than a word"),
    "a slot that holds a text": (dict(initial_storage={7: "5"}), "its storage holds something other than a word"),
    "a storage that is a list of pairs": (dict(initial_storage=[(7, 5)]), "its storage is not a dict"),
    "a storage of a class derived from dict": (dict(initial_storage=DerivedStorage({7: 5})),
                                               "its storage is not a dict"),
}


@pytest.mark.parametrize("door", ["execute", "run"])
@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in NO_START])
def test_an_execution_does_not_start_on_what_makes_no_state(name, door, monkeypatch):
    given, answer = NO_START[name]
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: {answer}$"):
        getattr(kern.evm, door)(bytes([Op.STOP]), **{"gas": 1_000, **given})


def test_control_an_execution_starts_on_the_largest_numbers_a_state_holds():
    context = ExecContext(address=ADDRESS_MAX, caller=ADDRESS_MAX, value=WORD_MAX, calldata=b"\x01",
                          block_number=INT_MAX, block_timestamp=INT_MAX)
    final = execute(bytes([Op.STOP]), gas=INT_MAX, context=context, initial_storage={WORD_MAX: WORD_MAX}).states[-1]
    assert final.halted and not final.reverted and final.gas == INT_MAX


# What a call is given, with a call that is in order as the rest.
NO_CALL = {
    "a gas of 2^63": dict(gas=INT_MAX + 1),
    "a negative gas": dict(gas=-1),
    "a value of 2^256": dict(value=WORD_MAX + 1),
    "a negative value": dict(value=-1),
    "a caller of 2^160": dict(caller=ADDRESS_MAX + 1),
    "an address of 2^160": dict(address=ADDRESS_MAX + 1),
    "a negative block number": dict(block_number=-1),
    "a block time of 2^63": dict(block_timestamp=INT_MAX + 1),
}


@pytest.mark.parametrize("target", [CONTRACT, IDENTITY], ids=["contract", "precompile"])
@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in NO_CALL])
def test_a_call_does_not_start_on_a_context_that_makes_no_state_and_moves_nothing(name, target):
    w = world()
    before = copy.deepcopy(w.accounts)
    call = dict(kind=FrameKind.CALL, caller=CALLER, address=target, value=10, calldata=b"", gas=100_000)
    call.update(NO_CALL[name])
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: "):
        call_contract(w, **call)
    assert w.accounts == before


@pytest.mark.parametrize("target", [CONTRACT, IDENTITY], ids=["contract", "precompile"])
@pytest.mark.parametrize("calldata", [bytearray(b"\x01"), "01", None], ids=["a-bytearray", "a-text", "nothing"])
def test_a_call_carries_bytes(calldata, target):
    w = world()
    before = copy.deepcopy(w.accounts)
    with pytest.raises(ValueError, match="^calldata is not bytes$"):
        call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=target, value=10, calldata=calldata, gas=100_000)
    assert w.accounts == before


def test_a_call_does_not_run_on_a_storage_that_makes_no_state_and_gives_the_value_back():
    w = world()
    w.get(CONTRACT).storage = {7: 0}
    before = copy.deepcopy(w.accounts)
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: a slot of its storage holds zero$"):
        call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"", gas=100_000)
    assert w.accounts == before


NO_CREATION = {
    "a creator of 2^160": dict(creator=ADDRESS_MAX + 1),
    "a negative creator": dict(creator=-1),
    "a gas of 2^63": dict(gas=INT_MAX + 1),
    "a value of 2^256": dict(value=WORD_MAX + 1),
    "a negative block number": dict(block_number=-1),
}


@pytest.mark.parametrize("name", [pytest.param(name, id=name.replace(" ", "-")) for name in NO_CREATION])
def test_a_creation_does_not_start_on_what_makes_no_state_and_moves_nothing(name):
    w = world()
    before = copy.deepcopy(w.accounts)
    creation = dict(creator=CALLER, init_code=bytes([Op.STOP]), value=10, gas=100_000)
    creation.update(NO_CREATION[name])
    with pytest.raises(ValueError, match=f"^{NOT_A_STATE}: "):
        create_contract(w, **creation)
    assert w.accounts == before


@pytest.mark.parametrize("init_code", [bytearray([Op.STOP]), [int(Op.STOP)], "00"],
                         ids=["a-bytearray", "a-list", "a-text"])
def test_a_creation_runs_bytes(init_code):
    w = world()
    before = copy.deepcopy(w.accounts)
    with pytest.raises(ValueError, match=f"^{NOT_A_PROGRAM}: it is not bytes$"):
        create_contract(w, creator=CALLER, init_code=init_code, value=10, gas=100_000)
    assert w.accounts == before


def test_control_a_creation_in_order_creates_a_contract():
    w = world()
    returns_one_byte = push(Op.STOP) + push(0) + bytes([Op.MSTORE8]) + push(1) + push(0) + bytes([Op.RETURN])
    address, result = create_contract(w, creator=CALLER, init_code=returns_one_byte, value=10, gas=100_000)
    assert result.success and w.get(address).code == bytes([Op.STOP]) and balances(w) == {CALLER: 990, address: 10}


# ---------------------------------------------------------------------------
# The names of this change
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["MAX_CODE_BYTES", "TraceStates", "not_a_state", "require_program",
                                  "require_state", "run"])
def test_the_names_of_this_change_are_public(name):
    assert name in kern.evm.__all__ and hasattr(kern.evm, name)
