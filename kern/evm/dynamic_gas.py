# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.dynamic_gas
====================

The part of the price of an instruction that depends on what it does.

Each instruction of the Mini-EVM has a static price in
`kern.evm.opcodes.GAS_COST`. `kern.evm.vm` adds, from this module, what
depends on the state and on the operands:

- the memory an instruction reaches: `memory_expansion_cost`, 3 gas for
  each word and the square of the number of words divided by 512
- SSTORE: `sstore_cost`, read from the slot and from the value written
- SHA3: `sha3_cost`, 6 gas for each 32-byte word of input
- EXP: `exp_cost`, from the length of the exponent
- LOG0 to LOG4: `log_cost`. The machine prices them and halts on them: it
  emits no event

Section 2.9 of docs/api-stability.md says where the rules of this
machine are its own and not those of Ethereum: no gas is refunded, a
read of the storage costs the same each time, and a write is priced
from the slot and the value written.

`call_cost`, `call_stipend`, `copy_cost` and `create_cost` are called by
nothing in `kern`: the machine executes neither a call, nor a creation,
nor a copy instruction.

Pricing constants
-----------------

The constants are those of the fee schedule of the Ethereum Yellow
Paper. We expose them as named constants here for auditability.
"""

from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Base gas constants (Yellow Paper "Appendix G")
# ---------------------------------------------------------------------------

# Memory
G_MEMORY = 3              # per word of newly-allocated memory
G_MEMORY_QUAD_DENOM = 512 # quadratic memory denominator

# SSTORE
G_SSTORE_SET = 20_000     # storing non-zero to a previously-zero slot
G_SSTORE_RESET = 5_000    # any other write

# CALL family
G_CALL_BASE = 700
G_CALL_VALUE = 9_000      # additional if call carries value
G_CALL_NEW_ACCOUNT = 25_000  # additional if creating a new account
G_CALL_STIPEND = 2_300    # forwarded gas to callee on value transfer

# LOG
G_LOG_BASE = 375
G_LOG_PER_TOPIC = 375
G_LOG_PER_BYTE = 8

# SHA3 / KECCAK
G_SHA3_BASE = 30
G_SHA3_PER_WORD = 6

# Copy operations (CODECOPY, RETURNDATACOPY, CALLDATACOPY)
G_COPY_PER_WORD = 3

# EXP
G_EXP_BASE = 10
G_EXP_PER_BYTE = 50       # per byte of the exponent's representation

# CREATE
G_CREATE = 32_000
G_CREATE_PER_BYTE = 200   # for the deployed code size

# Account access (post-Berlin EIP-2929)
G_COLD_ACCOUNT_ACCESS = 2_600
G_WARM_ACCESS = 100
G_COLD_SLOAD = 2_100
G_WARM_SLOAD = 100


# ---------------------------------------------------------------------------
# Memory expansion cost
# ---------------------------------------------------------------------------

def memory_cost(words: int) -> int:
    """Total cost to maintain `words` words of memory: linear + quadratic.

    Formula (Yellow Paper eq. 326):
        cost(w) = G_MEMORY * w + w² / G_MEMORY_QUAD_DENOM
    """
    if words <= 0:
        return 0
    return G_MEMORY * words + (words * words) // G_MEMORY_QUAD_DENOM


def memory_expansion_cost(current_bytes: int, new_end_bytes: int) -> int:
    """Gas cost for expanding memory to cover [0, new_end_bytes).

    Returns 0 if no expansion is needed."""
    if new_end_bytes <= current_bytes:
        return 0
    # Round up to word (32 bytes) boundary.
    current_words = (current_bytes + 31) // 32
    new_words = (new_end_bytes + 31) // 32
    if new_words <= current_words:
        return 0
    return memory_cost(new_words) - memory_cost(current_words)


# ---------------------------------------------------------------------------
# SSTORE cost (EIP-2200 simplified)
# ---------------------------------------------------------------------------

def sstore_cost(current: int, new: int) -> int:
    """The price of writing `new` in a slot that holds `current`: what the
    machine takes for the instruction, its static price included.

    Two prices, read from the slot and from the value written, and from
    nothing else:
    - SET:   current = 0, new ≠ 0   → G_SSTORE_SET (20 000)
    - RESET: any other write        → G_SSTORE_RESET (5 000), a write that
             changes nothing included

    EIP-2200 also reads what the slot held when the transaction started,
    prices a write that changes nothing lower, and refunds gas. This
    machine does none of the three: the value at the start is not in the
    state the two parties of a dispute commit to, and the price of a step
    is a function of the committed state.
    """
    if current == 0 and new != 0:
        return G_SSTORE_SET       # zero-to-nonzero: full set price
    return G_SSTORE_RESET         # any other write, one that changes nothing included


# ---------------------------------------------------------------------------
# SHA3 / hash family
# ---------------------------------------------------------------------------

def sha3_cost(input_byte_length: int) -> int:
    """SHA3 cost = base + per-word."""
    words = (input_byte_length + 31) // 32
    return G_SHA3_BASE + G_SHA3_PER_WORD * words


# ---------------------------------------------------------------------------
# LOG family
# ---------------------------------------------------------------------------

def log_cost(num_topics: int, data_byte_length: int) -> int:
    """LOG cost = base + per-topic + per-byte."""
    return (G_LOG_BASE
            + G_LOG_PER_TOPIC * num_topics
            + G_LOG_PER_BYTE * data_byte_length)


# ---------------------------------------------------------------------------
# CALL family
# ---------------------------------------------------------------------------

def call_cost(
    *,
    has_value: bool,
    creates_new_account: bool,
    cold_access: bool,
) -> int:
    """CALL gas cost depends on whether value is transferred, whether the
    target account exists, and whether it's been touched in this tx."""
    cost = G_CALL_BASE
    if has_value:
        cost += G_CALL_VALUE
    if creates_new_account:
        cost += G_CALL_NEW_ACCOUNT
    if cold_access:
        cost += (G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)
    return cost


def call_stipend(has_value: bool) -> int:
    """Free gas forwarded to the callee on value-transferring CALLs.
    This ensures the callee has enough gas to log the receipt at minimum."""
    return G_CALL_STIPEND if has_value else 0


# ---------------------------------------------------------------------------
# EXP cost (depends on exponent's byte length)
# ---------------------------------------------------------------------------

def exp_cost(exponent: int) -> int:
    """EXP gas = base + per-byte-of-exponent."""
    if exponent == 0:
        return G_EXP_BASE
    byte_length = (exponent.bit_length() + 7) // 8
    return G_EXP_BASE + G_EXP_PER_BYTE * byte_length


# ---------------------------------------------------------------------------
# Copy operations
# ---------------------------------------------------------------------------

def copy_cost(byte_length: int) -> int:
    """COPY family: 3 gas per word copied (rounded up)."""
    words = (byte_length + 31) // 32
    return G_COPY_PER_WORD * words


# ---------------------------------------------------------------------------
# CREATE cost
# ---------------------------------------------------------------------------

def create_cost(deployed_code_length: int) -> int:
    """CREATE base cost + per-byte of deployed code."""
    return G_CREATE + G_CREATE_PER_BYTE * deployed_code_length
