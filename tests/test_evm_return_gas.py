# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""RETURN and REVERT pay for the memory they extend.

The Mini-EVM charges an instruction for the memory it makes the machine
hold: three units of gas a word of 32 bytes, and the square of the number
of words over 512 (kern/evm/dynamic_gas.py). MLOAD, MSTORE, MSTORE8 and
SHA3 paid it. RETURN and REVERT did not: they extend the memory up to the
end of the range they hand back, and their price was 0.

A program of eight bytes then had the machine hold as much memory as it
named, and hand back as much output, for the six units of its two PUSH:
16,777,216 bytes of each, where the same memory costs MSTORE more than
five hundred million units. A length that no machine can hold left the
step by an exception of Python, `MemoryError` or `OverflowError`, where a
failed step was due: the referee of a dispute (`single_step_verify`) got
no verdict.

The rule now: RETURN and REVERT pay `memory_expansion_cost` up to the end
of the range they hand back, like every instruction that touches the
memory. A step that cannot pay fails for want of gas, before it touches
the memory.

An empty range still pays for the way to its start, as SHA3 does in this
machine. Ethereum charges nothing for an empty range: bringing the four
instructions in line with it is another change.

A test named `test_control_...` passed before this rule and still does: it
shows that what the others catch is the defect, and not the way they are
written.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.evm import Op, VmState, execute, single_step_verify, step

WORD = 32
PUSH_PRICE = 3
MSTORE_PRICE = 3

ENDS = [pytest.param(Op.RETURN, id="RETURN"), pytest.param(Op.REVERT, id="REVERT")]
HUGE = [
    pytest.param(1 << 62, id="2^62"),
    pytest.param(1 << 255, id="2^255"),
    pytest.param((1 << 256) - 1, id="2^256-1"),
]
# The gas of an ordinary execution, and the largest integer of 64 bits with
# a sign: no gas of that size pays for the lengths above.
GAS = [pytest.param(1_000_000, id="gas-1e6"), pytest.param((1 << 63) - 1, id="gas-2^63-1")]


def push(value: int) -> bytes:
    """The shortest PUSH that holds `value`."""
    size = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + size - 1]) + value.to_bytes(size, "big")


def end(op: int, offset: int, length: int) -> bytes:
    """`op`, RETURN or REVERT, on the range of `length` bytes that starts at `offset`."""
    return push(length) + push(offset) + bytes([op])


def store(offset: int, value: int = 1) -> bytes:
    """MSTORE of `value` at `offset`."""
    return push(value) + push(offset) + bytes([Op.MSTORE])


def last(code: bytes, gas: int) -> VmState:
    """The state in which `code` stops."""
    return execute(code, gas=gas).states[-1]


def held(size: int) -> int:
    """The memory that holds `size` bytes: whole words."""
    return (size + WORD - 1) // WORD * WORD


def memory_price(size: int) -> int:
    """What a memory of `size` bytes costs from nothing: three units a word,
    and the square of the number of words over 512."""
    words = held(size) // WORD
    return 3 * words + words * words // 512


def failed_for_want_of_gas(state: VmState) -> bool:
    return state.halted and state.reverted and "out of gas" in (state.last_error or "")


# ---------------------------------------------------------------------------
# The price
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("op", ENDS)
@pytest.mark.parametrize("offset, length", [
    (0, 1), (1, 1), (0, 32), (0, 33), (0, 64), (64, 64), (992, 32), (0, 1_024), (0, 32_768), (31, 32_738),
])
def test_an_end_pays_for_the_memory_it_extends(op, offset, length):
    gas = 10_000_000
    state = last(end(op, offset, length), gas)
    assert state.halted and state.reverted == (op == Op.REVERT)
    assert gas - state.gas == 2 * PUSH_PRICE + memory_price(offset + length)
    assert len(state.memory) == held(offset + length)
    assert state.output == bytes(length)


@pytest.mark.parametrize("op", ENDS)
@pytest.mark.parametrize("size", [32, 64, 1_024, 32_768, 1 << 20])
def test_an_end_pays_what_mstore_pays_for_the_same_memory(op, size):
    """One price for one memory, whichever instruction asks for it."""
    gas = 1 << 40
    by_mstore = gas - last(store(size - WORD) + bytes([Op.STOP]), gas).gas - 2 * PUSH_PRICE - MSTORE_PRICE
    by_end = gas - last(end(op, 0, size), gas).gas - 2 * PUSH_PRICE
    assert by_end == by_mstore == memory_price(size)


@pytest.mark.parametrize("op", ENDS)
def test_an_end_pays_only_for_what_it_adds(op):
    """A memory of one word, then an end that needs four: the price of four
    words in all, and not that of one and then of four."""
    gas = 1_000
    state = last(store(0, 0xABCD) + end(op, 0, 4 * WORD), gas)
    assert gas - state.gas == 4 * PUSH_PRICE + MSTORE_PRICE + memory_price(4 * WORD)
    assert len(state.memory) == 4 * WORD
    assert state.output == (0xABCD).to_bytes(WORD, "big") + bytes(3 * WORD)


@pytest.mark.parametrize("op", ENDS)
def test_an_empty_end_pays_for_the_way_to_its_start(op):
    """As SHA3 does in this machine."""
    gas = 1_000
    state = last(end(op, 1_024, 0), gas)
    assert state.halted and state.reverted == (op == Op.REVERT)
    assert gas - state.gas == 2 * PUSH_PRICE + memory_price(1_024)
    assert len(state.memory) == 1_024 and state.output == b""


# ---------------------------------------------------------------------------
# A step that cannot pay
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("op", ENDS)
def test_an_end_that_cannot_pay_fails_and_leaves_the_memory(op):
    """The program of eight bytes."""
    code = end(op, 0, 1 << 24)
    assert len(code) == 8
    state = last(code, 100)
    assert failed_for_want_of_gas(state)
    assert state.gas == 100 - 2 * PUSH_PRICE
    assert len(state.memory) == 0 and state.output == b""


@pytest.mark.parametrize("op", ENDS)
def test_an_end_fails_one_unit_short_of_its_price(op):
    code = end(op, 0, 32_768)
    price = 2 * PUSH_PRICE + memory_price(32_768)
    short = last(code, price - 1)
    assert failed_for_want_of_gas(short) and len(short.memory) == 0 and short.output == b""
    exact = last(code, price)
    assert exact.halted and exact.gas == 0 and exact.reverted == (op == Op.REVERT)
    assert len(exact.memory) == 32_768 and exact.output == bytes(32_768)


@pytest.mark.parametrize("op", ENDS)
def test_an_empty_end_far_away_cannot_pay_either(op):
    state = last(end(op, 1 << 24, 0), 100)
    assert failed_for_want_of_gas(state) and len(state.memory) == 0 and state.output == b""


@pytest.mark.parametrize("op", ENDS)
@pytest.mark.parametrize("length", HUGE)
@pytest.mark.parametrize("gas", GAS)
def test_a_length_no_machine_can_hold_fails_like_any_step(op, length, gas):
    """It left the step by `MemoryError` or `OverflowError`."""
    state = last(end(op, 0, length), gas)
    assert failed_for_want_of_gas(state) and len(state.memory) == 0 and state.output == b""


@pytest.mark.parametrize("op", ENDS)
@pytest.mark.parametrize("offset", HUGE)
@pytest.mark.parametrize("gas", GAS)
def test_a_start_no_machine_can_reach_fails_like_any_step(op, offset, gas):
    state = last(end(op, offset, 1), gas)
    assert failed_for_want_of_gas(state) and len(state.memory) == 0 and state.output == b""


@pytest.mark.parametrize("op", ENDS)
@pytest.mark.parametrize("length", HUGE)
@pytest.mark.parametrize("gas", GAS)
def test_the_referee_of_a_dispute_gets_a_verdict(op, length, gas):
    """`single_step_verify` runs the disputed step. A step that cannot pay
    leads to a failed state, which has a commitment like any other: whoever
    claimed it is right."""
    code = end(op, 0, length)
    before = step(step(VmState(gas=gas), code), code)
    assert before.stack == [length, 0] and not before.halted

    failed = before.clone()
    failed.halted = True
    failed.reverted = True
    truth, other = failed.commitment_hex(), "00" * 32

    verdict = single_step_verify(code, before, truth, other, 3)
    assert verdict.sequencer_wins and verdict.verified_commitment == truth
    verdict = single_step_verify(code, before, other, truth, 3)
    assert verdict.challenger_wins and verdict.verified_commitment == truth


def test_no_instruction_buys_more_memory_than_its_gas_pays_for():
    """Every opcode, one step from an empty memory, with 1,000 units of gas and
    a stack of large values. 1,000 units pay for 281 words at most."""
    gas = 1_000
    affordable = max(words for words in range(400) if memory_price(words * WORD) <= gas) * WORD
    assert affordable == 281 * WORD

    too_large = []
    for op in range(256):
        code = bytes([op]) + bytes(33)          # room for what a PUSH reads
        after = step(VmState(gas=gas, stack=[1 << 20] * 17), code)
        if len(after.memory) > affordable or len(after.output) > affordable:
            too_large.append(f"0x{op:02x}: {len(after.memory):,} bytes of memory and "
                             f"{len(after.output):,} of output for {gas - after.gas} units")
    assert too_large == []


# ---------------------------------------------------------------------------
# What does not change
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("op", ENDS)
def test_control_an_end_inside_the_memory_pays_nothing_more(op):
    gas = 1_000
    state = last(store(0, 0xABCD) + end(op, 0, WORD), gas)
    assert gas - state.gas == 4 * PUSH_PRICE + MSTORE_PRICE + memory_price(WORD)
    assert state.output == (0xABCD).to_bytes(WORD, "big") and bytes(state.memory) == state.output
    assert state.halted and state.reverted == (op == Op.REVERT)


@pytest.mark.parametrize("op", ENDS)
def test_control_an_end_of_nothing_at_the_start_is_free(op):
    state = last(end(op, 0, 0), 100)
    assert state.gas == 100 - 2 * PUSH_PRICE
    assert len(state.memory) == 0 and state.output == b""
    assert state.halted and state.reverted == (op == Op.REVERT)


@pytest.mark.parametrize("op", ENDS)
def test_control_an_end_without_its_two_values_fails(op):
    for code in (bytes([op]), push(0) + bytes([op])):
        state = last(code, 100)
        assert state.halted and state.reverted
        assert len(state.memory) == 0 and state.output == b""


def test_control_the_other_instructions_pay_as_before():
    """MSTORE, MLOAD, MSTORE8 and SHA3, each on a memory it extends to 1,024
    bytes: 32 words, 98 units."""
    gas, size = 100_000, 1_024
    assert memory_price(size) == 98
    used = {
        "MSTORE": gas - last(store(size - WORD) + bytes([Op.STOP]), gas).gas,
        "MLOAD": gas - last(push(size - WORD) + bytes([Op.MLOAD, Op.STOP]), gas).gas,
        "MSTORE8": gas - last(push(1) + push(size - 1) + bytes([Op.MSTORE8, Op.STOP]), gas).gas,
        "SHA3": gas - last(push(size) + push(0) + bytes([Op.SHA3, Op.STOP]), gas).gas,
    }
    assert used == {"MSTORE": 107, "MLOAD": 104, "MSTORE8": 107, "SHA3": 326}


@pytest.mark.parametrize("code", [
    pytest.param(store(1 << 24) + bytes([Op.STOP]), id="MSTORE"),
    pytest.param(push(1 << 24) + bytes([Op.MLOAD, Op.STOP]), id="MLOAD"),
    pytest.param(push(1) + push(1 << 24) + bytes([Op.MSTORE8, Op.STOP]), id="MSTORE8"),
    pytest.param(push(1 << 24) + push(0) + bytes([Op.SHA3, Op.STOP]), id="SHA3"),
])
def test_control_the_instructions_that_paid_already_refuse_what_they_cannot_pay(code):
    state = last(code, 1_000)
    assert failed_for_want_of_gas(state) and len(state.memory) == 0
