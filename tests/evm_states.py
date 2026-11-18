# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""States of the Mini-EVM drawn at random, for the tests that sweep them.

Every state drawn here is a state of the machine: it has the types, the
ranges and the sizes that section 9.22 of docs/api-stability.md gives a
state. The draw takes its generator from the caller, which seeds it: the
same states come out on every run.

This is no test file. tests/test_evm_referee.py and
tests/test_evm_state_schema.py draw from it.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.evm import ExecContext, VmState

WORD_MAX = (1 << 256) - 1
ADDRESS_MAX = (1 << 160) - 1
INT_MAX = (1 << 63) - 1

# Words that sit on the edge of something: a word of memory, the limits of a
# state, the largest gas, an address, the sign bit of a word.
EDGES = [0, 1, 2, 31, 32, 33, 255, 256, 1_023, 1_024, 1_048_575, 1_048_576, 1_048_577, INT_MAX, INT_MAX + 1,
         (1 << 64) - 1, ADDRESS_MAX, 1 << 255, WORD_MAX - 1, WORD_MAX]


def a_word(rng: random.Random) -> int:
    draw = rng.random()
    if draw < 0.5:
        return rng.choice(EDGES)
    if draw < 0.8:
        return rng.randrange(4_096)
    return rng.randrange(WORD_MAX + 1)


def a_program(rng: random.Random) -> bytes:
    """One instruction of any value and the bytes that follow it, or a few
    bytes of anything."""
    if rng.random() < 0.5:
        return bytes([rng.randrange(256)]) + rng.randbytes(rng.randrange(34))
    return rng.randbytes(rng.randrange(1, 40))


def a_state(rng: random.Random, code: bytes, large: bool = False) -> VmState:
    """A state of the machine in front of `code`. A `large` one holds as
    much as a state holds, or one unit less."""
    halted = rng.random() < 0.05
    words_of_stack = rng.choice([1_022, 1_023, 1_024]) if large else rng.choice([0, 1, 2, 3, 4, 7, 16, 17])
    words_of_memory = 32_768 if large else rng.choice([0, 0, 1, 2, 3, 32])
    slots = rng.choice([16_383, 16_384]) if large else rng.choice([0, 0, 1, 2, 5])
    storage: dict = {}
    while len(storage) < slots:
        slot = len(storage) + 1 if large else a_word(rng)
        storage[slot] = rng.randrange(1, 1_000) if rng.random() < 0.7 else WORD_MAX
    return VmState(
        pc=rng.choice([0, 0, 0, 1, len(code) - 1, len(code), len(code) + 5, INT_MAX]),
        stack=[a_word(rng) for _ in range(words_of_stack)],
        memory=bytearray(32 * words_of_memory) if large else bytearray(rng.randbytes(32 * words_of_memory)),
        gas=rng.choice([0, 1, 2, 3, 5, 20, 100, 5_000, 20_000, 1_000_000, 2_195_462, INT_MAX - 1, INT_MAX]),
        halted=halted,
        output=rng.randbytes(rng.choice([0, 1, 32])) if halted else b"",
        reverted=halted and rng.random() < 0.5,
        storage=storage,
        context=ExecContext(
            address=rng.choice([0, 1, ADDRESS_MAX]), caller=rng.choice([0, 5, ADDRESS_MAX]), value=a_word(rng),
            calldata=rng.randbytes(rng.choice([0, 1, 4, 36, 100])),
            block_number=rng.choice([0, 7, INT_MAX]), block_timestamp=rng.choice([0, 1_794_000_000, INT_MAX]),
        ),
    )
