# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.dynamic_gas
====================

Dynamic gas costs matching the Ethereum Yellow Paper.

The v0.3 Mini-EVM used static per-opcode gas (e.g., SSTORE = 5000 always).
Real Ethereum charges variable costs depending on:

- Memory expansion: quadratic above 724 words
- SSTORE: depends on (current_value, new_value, original_value) → set/reset/clear cases
- CALL: depends on value transfer, account creation, cold/warm access
- LOG: 8 gas per byte of log data, plus 375 base + 375 per topic
- SHA3: 6 gas per 32-byte word of input
- COPY operations: 3 gas per 32-byte word copied
- EXP: variable based on exponent byte length

This module computes the dynamic cost for each operation that has one,
given the pre-execution VM state and the operation parameters. It is
called from `kern.evm.vm.step()` before the static cost is applied.

Pricing constants
-----------------

Yellow Paper section H.1 ("Fee schedule") gives the canonical values.
We expose them as named constants here for auditability.
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
G_SSTORE_RESET = 5_000    # any other modification
G_SSTORE_CLEAR_REFUND = 15_000  # clearing a slot — gets refunded (capped)

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

def sstore_cost(current: int, new: int, original: int) -> int:
    """Compute SSTORE cost given the current value, the value being
    written, and the original value at the start of the transaction.

    Simplified version of EIP-2200's three-case model:
    - SET:   original=0, current=0, new≠0  → G_SSTORE_SET (20 000)
    - RESET: any other write where it actually changes  → G_SSTORE_RESET (5000)
    - NOOP:  current = new  → small cost (warm-storage read)
    """
    if current == new:
        return G_WARM_SLOAD       # no-op write costs warm-read
    if original == current:
        # First write in this transaction.
        if original == 0:
            return G_SSTORE_SET   # zero-to-nonzero: full set price
        return G_SSTORE_RESET     # other: reset price
    # Subsequent write in same tx — cheaper because the slot is already warm
    return G_WARM_SLOAD


def sstore_refund(current: int, new: int, original: int) -> int:
    """Gas refunded for clearing a slot (new = 0). Capped by the EVM
    at half the transaction gas spent — we just return the gross."""
    if current != 0 and new == 0:
        return G_SSTORE_CLEAR_REFUND
    return 0


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
