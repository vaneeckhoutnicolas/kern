# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The Mini-EVM applies the limits of its state.

A state of the machine holds at most 1,024 words of stack, 1,048,576 bytes
of memory (and as much output, which is a copy of a range of the memory),
16,384 slots of storage and 1,048,576 bytes of calldata.

Gas was the only bound, and it is not one. Every instruction pays for the
memory it extends, but a gas of 64 bits pays for a great deal of it: a
range of 2^40 bytes costs 2,305,843,112,292,909,056 units, less than the
largest such gas. The step then asked the host for that memory, and the
referee of a dispute (`single_step_verify`, `RollupState.resolve_challenge`)
got an exception of Python, or no answer at all, where a verdict was due.
The stack and the storage had no bound either.

The rules now:

- An instruction that would take the stack, the memory or the storage
  beyond a limit halts, reverted, before any memory is reserved. Like a
  step that cannot pay, it leaves the gas, the stack, the memory and the
  storage as they were. The gas is looked at first: an instruction that
  can neither pay nor fit halts for want of gas.
- A state that is already beyond a limit is not a state of the machine.
  `step`, `execute` and `single_step_verify` raise `ValueError` before
  anything copies it, and `resolve_challenge` turns it away before it is
  hashed: the challenge stays open for the state both parties agreed on.

No test here makes the host reserve memory beyond the limit, before these
rules or after them. `_expand_memory`, the one function that reserves
memory, is replaced by a watch that fails the test when it is asked for
more. Before the rules, it is the watch that fails these tests.

A test named `test_control_...` passed before these rules and still does: it
shows that what the others catch is the missing limit, and not the way they
are written.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import kern.evm
from kern.crypto import KernKeypair
from kern.evm import (
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
from kern.rollup import Batch, BatchStatus, FraudProof, Rollup, RollupState, program_hash

# The limits, written here as numbers: a test that read them from the code
# would follow the code wherever it went.
STACK = 1_024
MEMORY = 1_048_576
STORAGE = 16_384
CALLDATA = 1_048_576

WORD = 32
MIB = 1 << 20
TIB = 1 << 40
LARGEST_GAS = (1 << 63) - 1
PUSH_PRICE = 3

# The six instructions that extend the memory.
MEMORY_OPS = [
    pytest.param(Op.RETURN, id="RETURN"),
    pytest.param(Op.REVERT, id="REVERT"),
    pytest.param(Op.SHA3, id="SHA3"),
    pytest.param(Op.MSTORE, id="MSTORE"),
    pytest.param(Op.MLOAD, id="MLOAD"),
    pytest.param(Op.MSTORE8, id="MSTORE8"),
]
# The three that take a range, which can be empty.
RANGE_OPS = [
    pytest.param(Op.RETURN, id="RETURN"),
    pytest.param(Op.REVERT, id="REVERT"),
    pytest.param(Op.SHA3, id="SHA3"),
]
# Sizes beyond the limit, each with a gas that pays for it.
PAID = [
    pytest.param(2 * MIB, 10**10, id="2MiB"),
    pytest.param(TIB, LARGEST_GAS, id="1TiB"),
]


@pytest.fixture(autouse=True)
def watch(monkeypatch):
    """Stand in for the function that reserves memory: it reserves within
    the limit and fails the test beyond it. Returns the sizes asked for."""
    asked = []
    reserve = vm._expand_memory

    def watched(mem, end):
        asked.append(end)
        if end > MEMORY:
            pytest.fail(f"the machine asked the host for {end} bytes of memory")
        reserve(mem, end)

    monkeypatch.setattr(vm, "_expand_memory", watched)
    return asked


def push(value: int) -> bytes:
    """The shortest PUSH that holds `value`."""
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


def reach(op: int, end: int) -> bytes:
    """A program whose last instruction, `op`, reaches for the memory up to
    the byte `end`, from nothing."""
    if op in (Op.RETURN, Op.REVERT, Op.SHA3):
        return push(end) + push(0) + bytes([op])
    if op == Op.MSTORE:
        return push(1) + push(end - WORD) + bytes([op])
    if op == Op.MSTORE8:
        return push(1) + push(end - 1) + bytes([op])
    assert op == Op.MLOAD
    return push(end - WORD) + bytes([op])


def empty_range(op: int, offset: int) -> bytes:
    """`op` on the range of no byte that starts at `offset`."""
    return push(0) + push(offset) + bytes([op])


def store(offset: int, value: int) -> bytes:
    return push(value) + push(offset) + bytes([Op.MSTORE])


def price(op: int, end: int) -> int:
    """What `reach(op, end)` costs: its PUSH, the memory, and the words SHA3 hashes."""
    pushes = 1 if op == Op.MLOAD else 2
    words = dynamic_gas.sha3_cost(end) if op == Op.SHA3 else 3 * (op in (Op.MSTORE, Op.MLOAD, Op.MSTORE8))
    return PUSH_PRICE * pushes + dynamic_gas.memory_expansion_cost(0, end) + words


def last_step(code: bytes, gas: int, **more):
    """The last two states of the execution of `code`: before and after its last step."""
    trace = execute(code, gas=gas, **more)
    return trace.states[-2], trace.states[-1]


def halted_at(state: VmState, what: str) -> bool:
    return state.halted and state.reverted and f"{what} limit" in (state.last_error or "")


def for_want_of_gas(state: VmState) -> bool:
    return state.halted and state.reverted and "out of gas" in (state.last_error or "")


def nothing_else_changed(before: VmState, after: VmState) -> None:
    """`after` is `before`, halted and reverted."""
    assert after.halted and after.reverted and not before.halted
    assert after.gas == before.gas
    assert after.pc == before.pc
    assert after.stack == before.stack
    assert bytes(after.memory) == bytes(before.memory)
    assert after.storage == before.storage
    assert after.output == before.output


def within_the_limits(state: VmState) -> bool:
    return (len(state.stack) <= STACK and len(state.memory) <= MEMORY and len(state.output) <= MEMORY
            and len(state.storage) <= STORAGE and len(state.context.calldata) <= CALLDATA)


# ---------------------------------------------------------------------------
# The memory
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("end, gas", PAID)
@pytest.mark.parametrize("op", MEMORY_OPS)
def test_control_the_sizes_tested_here_can_be_paid(op, end, gas):
    """What stops these sizes is not the gas."""
    assert price(op, end) < gas


@pytest.mark.parametrize("end, gas", PAID)
@pytest.mark.parametrize("op", MEMORY_OPS)
def test_an_instruction_that_reaches_beyond_the_memory_limit_halts_and_reserves_nothing(op, end, gas, watch):
    before, after = last_step(reach(op, end), gas)
    assert halted_at(after, "memory")
    nothing_else_changed(before, after)
    assert len(after.memory) == 0 and after.output == b""
    assert watch == []


@pytest.mark.parametrize("offset, gas", PAID)
@pytest.mark.parametrize("op", RANGE_OPS)
def test_an_empty_range_beyond_the_memory_limit_halts_too(op, offset, gas, watch):
    """An empty range extends the memory up to its start, and pays for it."""
    before, after = last_step(empty_range(op, offset), gas)
    assert halted_at(after, "memory")
    nothing_else_changed(before, after)
    assert watch == []


@pytest.mark.parametrize("op", MEMORY_OPS)
def test_control_the_memory_reaches_its_limit(op):
    trace = execute(reach(op, MEMORY), gas=10**8)
    final = trace.states[-1]
    assert len(final.memory) == MEMORY
    assert "limit" not in (final.last_error or "")
    assert final.halted and final.reverted == (op == Op.REVERT)
    if op in (Op.RETURN, Op.REVERT):
        assert len(final.output) == MEMORY


def test_control_what_the_memory_costs_at_its_limit():
    """32,768 words: three units each, and their square over 512."""
    _, final = last_step(reach(Op.RETURN, MEMORY), 10**8)
    assert 10**8 - final.gas == 2 * PUSH_PRICE + 98_304 + 2_097_152


@pytest.mark.parametrize("past", [1, WORD], ids=["one-byte", "one-word"])
@pytest.mark.parametrize("op", MEMORY_OPS)
def test_the_memory_does_not_pass_its_limit(op, past, watch):
    before, after = last_step(reach(op, MEMORY + past), 10**8)
    assert halted_at(after, "memory")
    nothing_else_changed(before, after)
    assert watch == []


def test_control_an_empty_range_at_the_limit_fits():
    _, final = last_step(empty_range(Op.RETURN, MEMORY), 10**8)
    assert final.halted and not final.reverted
    assert len(final.memory) == MEMORY and final.output == b""


# A memory of 65,536 bytes with something in it, at both ends.
HELD = store(0, 0xABCD) + store(65_504, 0x1234)


@pytest.mark.parametrize("op", MEMORY_OPS)
def test_a_memory_already_held_keeps_its_bytes_when_the_next_extension_is_beyond_the_limit(op, watch):
    before, after = last_step(HELD + reach(op, 2 * MIB), 10**10)
    assert len(before.memory) == 65_536
    assert before.memory[30:32] == b"\xab\xcd" and before.memory[65_534:] == b"\x12\x34"
    assert halted_at(after, "memory")
    nothing_else_changed(before, after)
    assert max(watch) == 65_536


@pytest.mark.parametrize("op", MEMORY_OPS)
def test_control_a_memory_already_held_keeps_its_bytes_when_the_next_extension_cannot_be_paid(op):
    """Within the limit this time, and too dear: 100,000 units do not pay for 1,048,576 bytes."""
    before, after = last_step(HELD + reach(op, MEMORY), 100_000)
    assert len(before.memory) == 65_536
    assert for_want_of_gas(after)
    nothing_else_changed(before, after)


@pytest.mark.parametrize("op", [Op.RETURN, Op.MSTORE], ids=["RETURN", "MSTORE"])
def test_control_an_instruction_that_can_neither_pay_nor_fit_halts_for_want_of_gas(op):
    before, after = last_step(reach(op, TIB), 1_000_000)
    assert for_want_of_gas(after)
    nothing_else_changed(before, after)


# ---------------------------------------------------------------------------
# The stack
# ---------------------------------------------------------------------------

# One word more at each turn.
LOOP = bytes([Op.JUMPDEST, Op.PUSH1, 1, Op.PUSH1, 0, Op.JUMP])

GROW_THE_STACK = [Op.PUSH1, Op.PUSH32, Op.DUP1, Op.DUP16, Op.PC, Op.MSIZE, Op.GAS, Op.CALLDATASIZE]
DO_NOT_GROW_IT = [Op.POP, Op.ADD, Op.ISZERO, Op.SWAP16, Op.MLOAD, Op.SLOAD]


def full_stack() -> VmState:
    return VmState(gas=10**6, stack=[1] * STACK)


def test_the_stack_stops_at_its_limit():
    state = VmState(gas=10**6)
    before = state
    for _ in range(5_000):
        before, state = state, step(state, LOOP)
        if state.halted:
            break
    assert halted_at(state, "stack")
    assert len(state.stack) == STACK
    nothing_else_changed(before, state)


@pytest.mark.parametrize("op", GROW_THE_STACK, ids=lambda op: kern.evm.opcode_name(op))
def test_a_full_stack_takes_no_word_more(op):
    before = full_stack()
    after = step(before, bytes([op]) + bytes(32))
    assert halted_at(after, "stack")
    nothing_else_changed(before, after)


@pytest.mark.parametrize("op", DO_NOT_GROW_IT, ids=lambda op: kern.evm.opcode_name(op))
def test_control_a_full_stack_still_runs_what_does_not_grow_it(op):
    after = step(full_stack(), bytes([op]))
    assert not after.halted and after.last_error is None
    assert STACK - 1 <= len(after.stack) <= STACK


# ---------------------------------------------------------------------------
# The storage
# ---------------------------------------------------------------------------

def full_storage() -> dict:
    return {key: 1 for key in range(1, STORAGE + 1)}


def write(key: int, value: int) -> bytes:
    return push(value) + push(key) + bytes([Op.SSTORE])


def test_a_full_storage_takes_no_slot_more():
    before, after = last_step(write(STORAGE + 1, 7), 10**6, initial_storage=full_storage())
    assert halted_at(after, "storage")
    nothing_else_changed(before, after)
    assert len(after.storage) == STORAGE and STORAGE + 1 not in after.storage


def test_control_a_full_storage_still_writes_the_slots_it_holds():
    final = execute(write(5, 7), gas=10**6, initial_storage=full_storage()).states[-1]
    assert final.halted and not final.reverted
    assert len(final.storage) == STORAGE and final.storage[5] == 7


def test_control_a_slot_set_to_zero_makes_room_for_another():
    code = write(5, 0) + write(STORAGE + 1, 7)
    final = execute(code, gas=10**6, initial_storage=full_storage()).states[-1]
    assert final.halted and not final.reverted
    assert len(final.storage) == STORAGE and 5 not in final.storage and final.storage[STORAGE + 1] == 7


def test_control_a_zero_written_to_a_new_slot_of_a_full_storage_takes_no_room():
    final = execute(write(STORAGE + 1, 0), gas=10**6, initial_storage=full_storage()).states[-1]
    assert final.halted and not final.reverted
    assert len(final.storage) == STORAGE


# ---------------------------------------------------------------------------
# A state beyond the limits is not a state of the machine
# ---------------------------------------------------------------------------

def beyond(part: str) -> VmState:
    """A state that holds one unit too many of `part`."""
    if part == "stack":
        return VmState(gas=1_000, stack=[1] * (STACK + 1))
    if part == "memory":
        return VmState(gas=1_000, memory=bytearray(MEMORY + WORD))
    if part == "output":
        return VmState(gas=1_000, halted=True, output=bytes(MEMORY + 1))
    if part == "storage":
        return VmState(gas=1_000, storage={key: 1 for key in range(1, STORAGE + 2)})
    if part == "original storage":
        return VmState(gas=1_000, original_storage={key: 1 for key in range(1, STORAGE + 2)})
    assert part == "calldata"
    return VmState(gas=1_000, context=ExecContext(calldata=bytes(CALLDATA + 1)))


def at_the_limits() -> VmState:
    return VmState(
        gas=1_000, stack=[1] * STACK, memory=bytearray(MEMORY), storage=full_storage(),
        original_storage=full_storage(), context=ExecContext(calldata=bytes(CALLDATA)),
    )


# The part that is too large, and the name the machine gives it.
PARTS = [
    pytest.param("stack", "stack", id="stack"),
    pytest.param("memory", "memory", id="memory"),
    pytest.param("output", "output", id="output"),
    pytest.param("storage", "storage", id="storage"),
    pytest.param("original storage", "storage", id="original-storage"),
    pytest.param("calldata", "calldata", id="calldata"),
]


def neither_copied_nor_hashed(patch) -> None:
    """From here on, copying a state or hashing one fails the test."""
    patch.setattr(VmState, "clone", lambda self: pytest.fail("the state was copied"))
    patch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))


@pytest.mark.parametrize("part, named", PARTS)
def test_a_state_beyond_a_limit_is_not_stepped(part, named, monkeypatch):
    state = beyond(part)
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"not a state of the Mini-EVM: its {named} is beyond the limit"):
        step(state, bytes([Op.STOP]))


@pytest.mark.parametrize("part, named", PARTS)
def test_the_referee_of_a_step_gives_no_verdict_on_a_state_beyond_a_limit(part, named, monkeypatch):
    state = beyond(part)
    neither_copied_nor_hashed(monkeypatch)
    with pytest.raises(ValueError, match=f"its {named} is beyond the limit"):
        single_step_verify(bytes([Op.STOP]), state, "00" * 32, "11" * 32, 1)


def test_control_a_state_at_the_limits_is_a_state():
    after = step(at_the_limits(), bytes([Op.STOP]))
    assert after.halted and not after.reverted
    assert within_the_limits(after)


@pytest.mark.parametrize("part, named", PARTS)
def test_the_machine_names_what_is_beyond_the_limits(part, named):
    assert kern.evm.beyond_limits(beyond(part)) == named


def test_the_machine_finds_nothing_beyond_the_limits_in_a_state_that_is_at_them():
    assert kern.evm.beyond_limits(at_the_limits()) is None
    assert kern.evm.beyond_limits(VmState()) is None


def test_the_limits_are_public_and_are_these_numbers():
    assert kern.evm.MAX_STACK_WORDS == STACK
    assert kern.evm.MAX_MEMORY_BYTES == MEMORY
    assert kern.evm.MAX_STORAGE_SLOTS == STORAGE
    assert kern.evm.MAX_CALLDATA_BYTES == CALLDATA
    for name in ("MAX_STACK_WORDS", "MAX_MEMORY_BYTES", "MAX_STORAGE_SLOTS", "MAX_CALLDATA_BYTES", "beyond_limits"):
        assert name in kern.evm.__all__


def test_an_execution_does_not_start_on_calldata_beyond_the_limit(monkeypatch):
    monkeypatch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))
    with pytest.raises(ValueError, match="its calldata is beyond the limit"):
        execute(bytes([Op.STOP]), gas=1_000, context=ExecContext(calldata=bytes(CALLDATA + 1)))


def test_an_execution_does_not_start_on_a_storage_beyond_the_limit(monkeypatch):
    monkeypatch.setattr(VmState, "canonical", lambda self: pytest.fail("the state was hashed"))
    with pytest.raises(ValueError, match="its storage is beyond the limit"):
        execute(bytes([Op.STOP]), gas=1_000, initial_storage={key: 1 for key in range(1, STORAGE + 2)})


def test_control_an_execution_starts_at_the_limits():
    final = execute(
        bytes([Op.STOP]), gas=1_000, context=ExecContext(calldata=bytes(CALLDATA)), initial_storage=full_storage(),
    ).states[-1]
    assert final.halted and not final.reverted


# ---------------------------------------------------------------------------
# The referee of a dispute
# ---------------------------------------------------------------------------

def before_the_last_instruction(code: bytes, gas: int) -> VmState:
    """The state `code` is in when only its last instruction is left to run."""
    state = VmState(gas=gas)
    while state.pc < len(code) - 1:
        state = step(state, code)
    return state


@pytest.mark.parametrize("op", MEMORY_OPS)
def test_the_referee_of_a_step_gives_a_verdict_on_an_instruction_beyond_the_memory_limit(op, watch):
    code = reach(op, TIB)
    pre_state = before_the_last_instruction(code, LARGEST_GAS)
    truth = step(pre_state, code)
    assert halted_at(truth, "memory")
    honest, false = truth.commitment_hex(), "ee" * 32

    kept = single_step_verify(code, pre_state, honest, false, 3)
    assert kept.sequencer_wins and kept.verified_commitment == honest
    refuted = single_step_verify(code, pre_state, false, honest, 3)
    assert refuted.challenger_wins and refuted.verified_commitment == honest
    assert watch == []


def test_the_referee_of_a_step_gives_a_verdict_on_an_instruction_beyond_the_stack_limit():
    code = bytes([Op.PUSH1, 9])
    pre_state = full_stack()
    truth = step(pre_state, code)
    assert halted_at(truth, "stack")
    honest = truth.commitment_hex()
    assert single_step_verify(code, pre_state, honest, "ee" * 32, 1).sequencer_wins
    assert single_step_verify(code, pre_state, "ee" * 32, honest, 1).challenger_wins


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


@pytest.mark.parametrize("op", [Op.RETURN, Op.MSTORE], ids=["RETURN", "MSTORE"])
def test_a_rollup_settles_a_challenge_on_an_instruction_beyond_the_limit(op, watch):
    """The last step of the batch halts at the memory limit. A sequencer that
    posts that halted state keeps its batch; one that posts anything else
    loses it."""
    code = reach(op, TIB)
    honest = execute(code, gas=LARGEST_GAS)
    assert halted_at(honest.states[-1], "memory")
    truth = [c.hex() for c in honest.commitments]
    last = honest.n_steps

    state, bis = challenge(code, honest, seq=truth, chal=lying_from(truth, last, "dd" * 32))
    assert state.resolve_challenge(0, code, honest.states[bis.lo]) == (True, "sequencer")
    assert state.batches[0].status == BatchStatus.PENDING

    state, bis = challenge(code, honest, seq=lying_from(truth, last, "ee" * 32), chal=truth)
    assert state.resolve_challenge(0, code, honest.states[bis.lo]) == (True, "challenger")
    assert state.batches[0].status == BatchStatus.REVERTED
    assert watch == []


ORDINARY = bytes([Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD, Op.PUSH1, 3, Op.ADD, Op.STOP])


@pytest.mark.parametrize("part, named", PARTS)
def test_a_rollup_turns_away_a_pre_state_beyond_the_limits_before_it_hashes_it(part, named, monkeypatch):
    honest = execute(ORDINARY)
    truth = [c.hex() for c in honest.commitments]
    state, bis = challenge(ORDINARY, honest, seq=lying_from(truth, 3, "ee" * 32), chal=truth)

    too_large = beyond(part)
    with monkeypatch.context() as patch:
        neither_copied_nor_hashed(patch)
        ok, reason = state.resolve_challenge(0, ORDINARY, too_large)
    assert not ok
    assert reason == f"pre_state is not a state of the Mini-EVM: its {named} is beyond the limit"

    # The challenge is still open, and the state both parties agreed on settles it.
    assert state.batches[0].status == BatchStatus.CHALLENGED and 0 in state.active_challenges
    assert state.resolve_challenge(0, ORDINARY, honest.states[bis.lo]) == (True, "challenger")


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------

CALLER, CONTRACT = 0xAA, 0xCC
IDENTITY = 0x04


def world() -> WorldState:
    w = WorldState()
    w.get(CALLER).balance = 1_000
    w.get(CONTRACT).code = bytes([Op.STOP])
    return w


def balances(w: WorldState) -> dict:
    return {address: account.balance for address, account in w.accounts.items() if account.balance}


@pytest.mark.parametrize("target", [CONTRACT, IDENTITY], ids=["contract", "precompile"])
def test_a_call_does_not_start_on_calldata_beyond_the_limit(target):
    w = world()
    with pytest.raises(ValueError, match="calldata is beyond the limit"):
        call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=target, value=10,
                      calldata=bytes(CALLDATA + 1), gas=100_000)
    assert balances(w) == {CALLER: 1_000}


@pytest.mark.parametrize("target", [CONTRACT, IDENTITY], ids=["contract", "precompile"])
def test_control_a_call_carries_calldata_up_to_the_limit(target):
    w = world()
    result = call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=target, value=10,
                           calldata=bytes(CALLDATA), gas=100_000)
    assert result.success
    assert balances(w) == {CALLER: 990, target: 10}


def test_a_call_does_not_start_on_a_storage_beyond_the_limit_and_gives_the_value_back():
    w = world()
    w.get(CONTRACT).storage = {key: 1 for key in range(1, STORAGE + 2)}
    with pytest.raises(ValueError, match="its storage is beyond the limit"):
        call_contract(w, kind=FrameKind.CALL, caller=CALLER, address=CONTRACT, value=10, calldata=b"", gas=100_000)
    assert balances(w) == {CALLER: 1_000}
    assert len(w.get(CONTRACT).storage) == STORAGE + 1


# ---------------------------------------------------------------------------
# Every instruction, from a state at the limits
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("word", [TIB // 2, 31], ids=["words-of-2^39", "words-of-31"])
def test_no_instruction_takes_a_state_at_the_limits_beyond_them(word, watch):
    """The 256 values of a byte, as the one instruction of a program: a
    stack full of `word`, which the instruction reads as offsets, lengths,
    keys and values, on a memory and a storage that are full. The largest
    gas pays for a range of 2^39 bytes that starts at the byte 2^39."""
    state = VmState(
        gas=LARGEST_GAS, stack=[word] * STACK, memory=bytearray(MEMORY), storage=full_storage(),
        original_storage=full_storage(), context=ExecContext(calldata=bytes(CALLDATA)),
    )
    for byte in range(256):
        after = step(state, bytes([byte]) + bytes(32))
        assert within_the_limits(after), f"opcode {byte:#04x}"
        assert max(watch, default=0) <= MEMORY, f"opcode {byte:#04x}"
