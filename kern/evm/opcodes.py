# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.opcodes
================

Opcode definitions for Kern's Mini-EVM — a deliberate subset of the
Ethereum Virtual Machine sufficient to demonstrate the bisection
fraud-proof protocol with real EVM-compatible execution semantics.

The subset covers stack manipulation, arithmetic, memory, basic
control flow, and termination. It does NOT cover:
- Storage (SSTORE/SLOAD) — modeled at the rollup level
- Calls (CALL/STATICCALL/DELEGATECALL) — single-contract execution only
- Logs (LOG0-LOG4) — events not modeled
- Precompiles, contract creation, value transfer

A real production rollup verifier would extend this with the full EVM
opcode set. The protocol around it (bisection, single-step verification,
fraud proof structure) is fully implemented here.

Opcode values match the Ethereum Yellow Paper for the supported subset,
so a real EVM bytecode using only these opcodes runs unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class Op(IntEnum):
    # 0x00 — termination
    STOP = 0x00

    # 0x01-0x0b — arithmetic
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    MOD = 0x06
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0a
    SIGNEXTEND = 0x0b

    # 0x10-0x1d — comparison & bitwise
    LT = 0x10
    GT = 0x11
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1a
    SHL = 0x1b
    SHR = 0x1c
    SAR = 0x1d

    # 0x20 — keccak/sha3
    SHA3 = 0x20

    # 0x30-0x3f — environment
    ADDRESS = 0x30
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36

    # 0x40-0x4a — block info
    TIMESTAMP = 0x42
    NUMBER = 0x43

    # 0x50-0x5b — stack, memory, flow
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5a
    JUMPDEST = 0x5b

    # 0x60-0x7f — PUSH1..PUSH32 (all defined as a range; specific aliases below)
    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH8 = 0x67
    PUSH16 = 0x6f
    PUSH32 = 0x7f

    # 0x80-0x8f — DUP1..DUP16
    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP8 = 0x87
    DUP16 = 0x8f

    # 0x90-0x9f — SWAP1..SWAP16
    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP8 = 0x97
    SWAP16 = 0x9f

    # 0xa0-0xa4 — LOG0..LOG4 (events)
    LOG0 = 0xa0
    LOG1 = 0xa1
    LOG2 = 0xa2
    LOG3 = 0xa3
    LOG4 = 0xa4

    # 0xf0-0xf5 — calls, create
    CREATE = 0xf0
    CALL = 0xf1
    CALLCODE = 0xf2
    DELEGATECALL = 0xf4
    STATICCALL = 0xfa
    CREATE2 = 0xf5

    # 0xf3 — RETURN
    RETURN = 0xf3
    # 0xfd — REVERT
    REVERT = 0xfd
    # 0xfe — INVALID (always reverts)
    INVALID = 0xfe


# Per-opcode gas cost (subset; matches yellow paper "base" tier for simplicity)
GAS_COST = {
    Op.STOP: 0, Op.RETURN: 0, Op.REVERT: 0, Op.JUMPDEST: 1,
    Op.ADD: 3, Op.SUB: 3, Op.LT: 3, Op.GT: 3, Op.EQ: 3,
    Op.ISZERO: 3, Op.AND: 3, Op.OR: 3, Op.XOR: 3, Op.NOT: 3,
    Op.BYTE: 3, Op.SHL: 3, Op.SHR: 3, Op.SAR: 3,
    Op.POP: 2, Op.PC: 2, Op.MSIZE: 2, Op.GAS: 2,
    Op.MUL: 5, Op.DIV: 5, Op.MOD: 5, Op.SIGNEXTEND: 5,
    Op.ADDMOD: 8, Op.MULMOD: 8,
    Op.EXP: 10,  # simplified; real EVM is dynamic
    Op.MLOAD: 3, Op.MSTORE: 3, Op.MSTORE8: 3,
    Op.SLOAD: 100, Op.SSTORE: 5_000,  # simplified; real EVM has dynamic cost
    Op.JUMP: 8, Op.JUMPI: 10,
    Op.SHA3: 30,
    Op.ADDRESS: 2, Op.CALLER: 2, Op.CALLVALUE: 2,
    Op.CALLDATALOAD: 3, Op.CALLDATASIZE: 2,
    Op.TIMESTAMP: 2, Op.NUMBER: 2,
    # v0.5 additions
    Op.CALL: 700, Op.STATICCALL: 700, Op.DELEGATECALL: 700,
    Op.CREATE: 32_000, Op.CREATE2: 32_000,
    Op.CALLCODE: 700,
    Op.INVALID: 0,
    Op.LOG0: 375, Op.LOG1: 750, Op.LOG2: 1125,
    Op.LOG3: 1500, Op.LOG4: 1875,
}
# PUSH/DUP/SWAP cost 3 each (all variants in their ranges).
for op_val in range(Op.PUSH1, Op.PUSH32 + 1):
    GAS_COST[op_val] = 3
for op_val in range(Op.DUP1, Op.DUP16 + 1):
    GAS_COST[op_val] = 3
for op_val in range(Op.SWAP1, Op.SWAP16 + 1):
    GAS_COST[op_val] = 3


def push_size(opcode: int) -> int:
    """How many immediate bytes follow this PUSH opcode? 0 if not a PUSH."""
    if Op.PUSH1 <= opcode <= Op.PUSH32:
        return opcode - Op.PUSH1 + 1
    return 0


def is_push(opcode: int) -> bool:
    return Op.PUSH1 <= opcode <= Op.PUSH32


def is_dup(opcode: int) -> bool:
    return Op.DUP1 <= opcode <= Op.DUP16


def is_swap(opcode: int) -> bool:
    return Op.SWAP1 <= opcode <= Op.SWAP16


def opcode_name(opcode: int) -> str:
    try:
        return Op(opcode).name
    except ValueError:
        if is_push(opcode):
            return f"PUSH{opcode - Op.PUSH1 + 1}"
        if is_dup(opcode):
            return f"DUP{opcode - Op.DUP1 + 1}"
        if is_swap(opcode):
            return f"SWAP{opcode - Op.SWAP1 + 1}"
        return f"INVALID(0x{opcode:02x})"
