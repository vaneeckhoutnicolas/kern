# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.vm
===========

The Mini-EVM step-wise executor.

The defining property of this VM, for the purposes of fraud proofs, is
that it produces a sequence of **state commitments** — one per executed
instruction. Each commitment is a blake2b-256 hash of the canonical
serialization of the VM state (PC, stack, memory, gas, halt status).

The bisection protocol relies on this property: a challenger and a
defender each compute the trace of commitments for the same input,
then narrow down to the first commitment where they disagree. That
single step is then re-executed on L1 by the verifier, which
deterministically decides who's right.

State commitment includes:
- pc:     program counter
- stack:  list of 256-bit words (top of stack = end of list)
- memory: byte array, padded to a multiple of 32
- gas:    remaining gas
- halted: terminated? (STOP / RETURN / REVERT / out-of-gas)
- output: return data if halted via RETURN/REVERT
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .opcodes import GAS_COST, Op, is_dup, is_push, is_swap, opcode_name, push_size


# 256-bit modulus for arithmetic (matches EVM word size)
_WORD_MAX = 1 << 256
_WORD_MASK = _WORD_MAX - 1


class EvmError(Exception):
    """Raised for invalid execution (stack underflow, bad jump, etc.).
    These cause the VM to halt with revert status."""


@dataclass
class ExecContext:
    """The transaction-level execution context: who called, with what value,
    against what contract, with what input data, in what block. All fields
    are committed to the trace's initial state so the verifier can re-run
    deterministically."""

    address: int = 0          # `self` — contract being executed (as int)
    caller: int = 0           # `msg.sender` — caller address (as int)
    value: int = 0            # `msg.value` — wei attached
    calldata: bytes = b""     # input data
    block_number: int = 0
    block_timestamp: int = 0

    def to_dict(self) -> dict:
        return {
            "address": str(self.address),
            "caller": str(self.caller),
            "value": str(self.value),
            "calldata": self.calldata.hex(),
            "block_number": self.block_number,
            "block_timestamp": self.block_timestamp,
        }


@dataclass
class VmState:
    """A complete snapshot of the EVM at one point in execution."""

    pc: int = 0
    stack: List[int] = field(default_factory=list)
    memory: bytearray = field(default_factory=bytearray)
    gas: int = 0
    halted: bool = False
    output: bytes = b""
    reverted: bool = False
    # v0.4 additions:
    storage: Dict[int, int] = field(default_factory=dict)  # contract storage
    context: ExecContext = field(default_factory=ExecContext)
    # v1.0-rc: snapshot of storage at the start of the transaction, used
    # for EIP-2200 SSTORE pricing. Populated by `execute()`; if absent
    # (e.g., reading old serialized states), SSTORE pricing falls back
    # to current-state-only mode (same as v0.3-v0.9).
    original_storage: Dict[int, int] = field(default_factory=dict)
    # Last error message for debugging (not part of commitment for now)
    last_error: Optional[str] = None

    # ---- canonical serialization (for commitment hashing) -------------------

    def canonical(self) -> bytes:
        d = {
            "pc": self.pc,
            "stack": [str(x) for x in self.stack],  # stringify to avoid JSON int loss
            "memory": self.memory.hex(),
            "gas": self.gas,
            "halted": self.halted,
            "output": self.output.hex(),
            "reverted": self.reverted,
            # Storage as sorted list of (key_str, value_str) for canonicity.
            "storage": sorted([[str(k), str(v)] for k, v in self.storage.items()]),
            "context": self.context.to_dict(),
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    def commitment(self) -> bytes:
        """The blake2b-256 hash of the canonical encoding."""
        return hashlib.blake2b(self.canonical(), digest_size=32, key=b"kern.evm").digest()

    def commitment_hex(self) -> str:
        return self.commitment().hex()

    def clone(self) -> "VmState":
        return VmState(
            pc=self.pc,
            stack=list(self.stack),
            memory=bytearray(self.memory),
            gas=self.gas,
            halted=self.halted,
            output=self.output,
            reverted=self.reverted,
            storage=dict(self.storage),
            original_storage=dict(self.original_storage),
            context=self.context,  # frozen-ish; safe to share
            last_error=self.last_error,
        )


# ---------------------------------------------------------------------------
# Step executor
# ---------------------------------------------------------------------------

def _peek_op(code: bytes, pc: int) -> int:
    if pc >= len(code):
        return Op.STOP  # implicit STOP beyond the code
    return code[pc]


def _pop(stack: List[int], n: int = 1) -> List[int]:
    if len(stack) < n:
        raise EvmError(f"stack underflow: need {n}, have {len(stack)}")
    out = stack[-n:][::-1]  # popped in LIFO order
    del stack[-n:]
    return out


def _push(stack: List[int], v: int) -> None:
    stack.append(v & _WORD_MASK)


def _expand_memory(mem: bytearray, end: int) -> None:
    """Grow memory to at least `end` bytes (rounded up to 32-byte word)."""
    if end > len(mem):
        # round up to multiple of 32
        new_size = ((end + 31) // 32) * 32
        mem.extend(b"\x00" * (new_size - len(mem)))


def _peek_stack(stack: List[int], n: int) -> List[int]:
    """Non-destructive view of the top N stack values, in pop-order.
    Returns [] if the stack doesn't have enough items; the actual gas
    check happens next and will catch the underflow."""
    if len(stack) < n:
        return []
    # Stack convention: top is end of list. Pop order: last-in first-out.
    return list(reversed(stack[-n:]))


def _exp_byte_size(exponent: int) -> int:
    """Number of bytes needed to represent the exponent (0 → 0, 255 → 1, 256 → 2)."""
    if exponent == 0:
        return 0
    return (exponent.bit_length() + 7) // 8


def _dynamic_extra_cost(op: int, state: "VmState", code: bytes) -> int:
    """Compute the *extra* gas cost beyond the static GAS_COST[op] for the
    next instruction, given the current state. Non-destructive: must not
    mutate the state.

    Returns 0 for opcodes that have no dynamic component.

    This is the v1.0-rc wiring of `kern.evm.dynamic_gas` into the VM:
    memory expansion, SHA3 word cost, EXP exponent cost, SSTORE 3-case
    pricing, LOG data+topic cost, MSTORE/MLOAD/MSTORE8 memory expansion.
    """
    from . import dynamic_gas as dg

    mem_size = len(state.memory)

    if op in (Op.MLOAD, Op.MSTORE):
        vals = _peek_stack(state.stack, 1)
        if not vals:
            return 0
        offset = vals[0]
        return dg.memory_expansion_cost(mem_size, offset + 32)

    if op == Op.MSTORE8:
        vals = _peek_stack(state.stack, 1)
        if not vals:
            return 0
        offset = vals[0]
        return dg.memory_expansion_cost(mem_size, offset + 1)

    if op == Op.SHA3:
        vals = _peek_stack(state.stack, 2)
        if len(vals) < 2:
            return 0
        offset, length = vals[0], vals[1]
        # sha3_cost() returns total (30 + 6/word); subtract static base 30
        # already counted by GAS_COST[SHA3] to avoid double-charging.
        extra_for_words = dg.sha3_cost(length) - 30
        return max(0, extra_for_words) + dg.memory_expansion_cost(mem_size, offset + length)

    if op == Op.EXP:
        vals = _peek_stack(state.stack, 2)
        if len(vals) < 2:
            return 0
        exponent = vals[1]
        # exp_cost() returns total; static EXP cost in GAS_COST is 10.
        total = dg.exp_cost(_exp_byte_size(exponent))
        return max(0, total - 10)

    if op == Op.SSTORE:
        vals = _peek_stack(state.stack, 2)
        if len(vals) < 2:
            return 0
        key, new_val = vals[0], vals[1]
        current = state.storage.get(key, 0)
        original = state.original_storage.get(key, current)
        # sstore_cost() returns total; subtract static SSTORE cost (we set 5000
        # in v0.3 opcodes.py — but the new dynamic model takes over fully).
        # GAS_COST[SSTORE] is the BASE static value; replace it.
        static = GAS_COST.get(Op.SSTORE, 5000)
        return max(0, dg.sstore_cost(current, new_val, original) - static)

    if op in (Op.LOG0, Op.LOG1, Op.LOG2, Op.LOG3, Op.LOG4):
        n_topics = op - Op.LOG0
        vals = _peek_stack(state.stack, 2 + n_topics)
        if len(vals) < 2:
            return 0
        offset, length = vals[0], vals[1]
        # log_cost() returns total; LOG0 static = 375, LOG_N = 375 + 375*N
        static = GAS_COST.get(op, 375 + 375 * n_topics)
        return max(0, dg.log_cost(n_topics, length) - static) + dg.memory_expansion_cost(mem_size, offset + length)

    return 0


def step(state: VmState, code: bytes) -> VmState:
    """Execute exactly one EVM instruction. Returns the post-step state.

    Pure function: does not mutate the input state. Always advances PC
    (or sets halted=True). Out-of-gas, bad jumps, stack underflow, and
    unknown opcodes all halt with `reverted=True`."""
    s = state.clone()

    if s.halted:
        return s  # halted is a fixed point

    op = _peek_op(code, s.pc)

    # Gas check: static base + dynamic extra (memory expansion, SSTORE pricing,
    # SHA3 word cost, EXP exponent length, LOG data/topics). v1.0-rc.
    static = GAS_COST.get(op, 0)
    extra = _dynamic_extra_cost(op, s, code)
    cost = static + extra
    if s.gas < cost:
        s.halted = True
        s.reverted = True
        s.last_error = f"out of gas at pc={s.pc}, op={opcode_name(op)} (need {cost}, have {s.gas})"
        return s
    s.gas -= cost

    try:
        # ----- termination -------------------------------------------------
        if op == Op.STOP:
            s.halted = True
            return s

        if op == Op.RETURN:
            offset, length = _pop(s.stack, 2)
            _expand_memory(s.memory, offset + length)
            s.output = bytes(s.memory[offset:offset + length])
            s.halted = True
            return s

        if op == Op.REVERT:
            offset, length = _pop(s.stack, 2)
            _expand_memory(s.memory, offset + length)
            s.output = bytes(s.memory[offset:offset + length])
            s.halted = True
            s.reverted = True
            return s

        # ----- arithmetic --------------------------------------------------
        if op == Op.ADD:
            a, b = _pop(s.stack, 2)
            _push(s.stack, a + b)
        elif op == Op.SUB:
            a, b = _pop(s.stack, 2)
            _push(s.stack, (a - b) & _WORD_MASK)
        elif op == Op.MUL:
            a, b = _pop(s.stack, 2)
            _push(s.stack, a * b)
        elif op == Op.DIV:
            a, b = _pop(s.stack, 2)
            _push(s.stack, 0 if b == 0 else a // b)
        elif op == Op.MOD:
            a, b = _pop(s.stack, 2)
            _push(s.stack, 0 if b == 0 else a % b)
        elif op == Op.EXP:
            base, exp = _pop(s.stack, 2)
            _push(s.stack, pow(base, exp, _WORD_MAX) if exp >= 0 else 0)

        # ----- comparison & bitwise ----------------------------------------
        elif op == Op.LT:
            a, b = _pop(s.stack, 2)
            _push(s.stack, 1 if a < b else 0)
        elif op == Op.GT:
            a, b = _pop(s.stack, 2)
            _push(s.stack, 1 if a > b else 0)
        elif op == Op.EQ:
            a, b = _pop(s.stack, 2)
            _push(s.stack, 1 if a == b else 0)
        elif op == Op.ISZERO:
            (a,) = _pop(s.stack, 1)
            _push(s.stack, 1 if a == 0 else 0)
        elif op == Op.AND:
            a, b = _pop(s.stack, 2)
            _push(s.stack, a & b)
        elif op == Op.OR:
            a, b = _pop(s.stack, 2)
            _push(s.stack, a | b)
        elif op == Op.XOR:
            a, b = _pop(s.stack, 2)
            _push(s.stack, a ^ b)
        elif op == Op.NOT:
            (a,) = _pop(s.stack, 1)
            _push(s.stack, (~a) & _WORD_MASK)

        # ----- stack & memory ----------------------------------------------
        elif op == Op.POP:
            _pop(s.stack, 1)
        elif op == Op.MLOAD:
            (offset,) = _pop(s.stack, 1)
            _expand_memory(s.memory, offset + 32)
            word = int.from_bytes(s.memory[offset:offset + 32], "big")
            _push(s.stack, word)
        elif op == Op.MSTORE:
            offset, value = _pop(s.stack, 2)
            _expand_memory(s.memory, offset + 32)
            s.memory[offset:offset + 32] = value.to_bytes(32, "big")
        elif op == Op.PC:
            _push(s.stack, s.pc)
        elif op == Op.MSIZE:
            _push(s.stack, len(s.memory))
        elif op == Op.JUMPDEST:
            pass  # no-op marker

        # ----- control flow -------------------------------------------------
        elif op == Op.JUMP:
            (dest,) = _pop(s.stack, 1)
            if dest >= len(code) or code[dest] != Op.JUMPDEST:
                raise EvmError(f"invalid jump dest {dest}")
            s.pc = dest
            return s
        elif op == Op.JUMPI:
            dest, cond = _pop(s.stack, 2)
            if cond != 0:
                if dest >= len(code) or code[dest] != Op.JUMPDEST:
                    raise EvmError(f"invalid jumpi dest {dest}")
                s.pc = dest
                return s

        # ----- PUSH --------------------------------------------------------
        elif is_push(op):
            n = push_size(op)
            data = code[s.pc + 1 : s.pc + 1 + n]
            if len(data) < n:
                data = data + b"\x00" * (n - len(data))
            _push(s.stack, int.from_bytes(data, "big"))
            s.pc += n  # advance over immediates

        # ----- DUP ---------------------------------------------------------
        elif is_dup(op):
            depth = op - Op.DUP1 + 1
            if len(s.stack) < depth:
                raise EvmError(f"DUP{depth}: stack underflow")
            _push(s.stack, s.stack[-depth])

        # ----- SWAP --------------------------------------------------------
        elif is_swap(op):
            depth = op - Op.SWAP1 + 1
            if len(s.stack) < depth + 1:
                raise EvmError(f"SWAP{depth}: stack underflow")
            s.stack[-1], s.stack[-1 - depth] = s.stack[-1 - depth], s.stack[-1]

        # ----- additional arithmetic (v0.4) --------------------------------
        elif op == Op.ADDMOD:
            a, b, n = _pop(s.stack, 3)
            _push(s.stack, 0 if n == 0 else (a + b) % n)
        elif op == Op.MULMOD:
            a, b, n = _pop(s.stack, 3)
            _push(s.stack, 0 if n == 0 else (a * b) % n)
        elif op == Op.SIGNEXTEND:
            byte_idx, x = _pop(s.stack, 2)
            if byte_idx >= 31:
                _push(s.stack, x)
            else:
                bit_pos = byte_idx * 8 + 7
                sign_bit = (x >> bit_pos) & 1
                if sign_bit:
                    mask = ((1 << (256 - bit_pos - 1)) - 1) << (bit_pos + 1)
                    _push(s.stack, (x | mask) & _WORD_MASK)
                else:
                    mask = (1 << (bit_pos + 1)) - 1
                    _push(s.stack, x & mask)

        # ----- additional bitwise (v0.4) -----------------------------------
        elif op == Op.BYTE:
            i, x = _pop(s.stack, 2)
            if i >= 32:
                _push(s.stack, 0)
            else:
                _push(s.stack, (x >> (8 * (31 - i))) & 0xff)
        elif op == Op.SHL:
            shift, value = _pop(s.stack, 2)
            _push(s.stack, 0 if shift >= 256 else (value << shift) & _WORD_MASK)
        elif op == Op.SHR:
            shift, value = _pop(s.stack, 2)
            _push(s.stack, 0 if shift >= 256 else value >> shift)
        elif op == Op.SAR:
            shift, value = _pop(s.stack, 2)
            # Signed shift right
            sign_bit = (value >> 255) & 1
            if shift >= 256:
                _push(s.stack, _WORD_MASK if sign_bit else 0)
            elif sign_bit == 0:
                _push(s.stack, value >> shift)
            else:
                # Extend with 1-bits.
                shifted = value >> shift
                mask = ((1 << shift) - 1) << (256 - shift)
                _push(s.stack, (shifted | mask) & _WORD_MASK)

        # ----- hashing (v0.4) ---------------------------------------------
        elif op == Op.SHA3:
            offset, length = _pop(s.stack, 2)
            _expand_memory(s.memory, offset + length)
            data = bytes(s.memory[offset:offset + length])
            digest = hashlib.sha3_256(data).digest()
            _push(s.stack, int.from_bytes(digest, "big"))

        # ----- environment (v0.4) -----------------------------------------
        elif op == Op.ADDRESS:
            _push(s.stack, s.context.address)
        elif op == Op.CALLER:
            _push(s.stack, s.context.caller)
        elif op == Op.CALLVALUE:
            _push(s.stack, s.context.value)
        elif op == Op.CALLDATALOAD:
            (offset,) = _pop(s.stack, 1)
            cd = s.context.calldata
            if offset >= len(cd):
                _push(s.stack, 0)
            else:
                slice_ = cd[offset:offset + 32]
                # Right-pad with zero bytes if short.
                if len(slice_) < 32:
                    slice_ = slice_ + b"\x00" * (32 - len(slice_))
                _push(s.stack, int.from_bytes(slice_, "big"))
        elif op == Op.CALLDATASIZE:
            _push(s.stack, len(s.context.calldata))
        elif op == Op.TIMESTAMP:
            _push(s.stack, s.context.block_timestamp)
        elif op == Op.NUMBER:
            _push(s.stack, s.context.block_number)

        # ----- storage (v0.4) ---------------------------------------------
        elif op == Op.SLOAD:
            (key,) = _pop(s.stack, 1)
            _push(s.stack, s.storage.get(key, 0))
        elif op == Op.SSTORE:
            key, value = _pop(s.stack, 2)
            if value == 0:
                s.storage.pop(key, None)  # zero values are not stored
            else:
                s.storage[key] = value & _WORD_MASK
        elif op == Op.MSTORE8:
            offset, value = _pop(s.stack, 2)
            _expand_memory(s.memory, offset + 1)
            s.memory[offset] = value & 0xff
        elif op == Op.GAS:
            _push(s.stack, s.gas)

        else:
            raise EvmError(f"unknown opcode 0x{op:02x} at pc={s.pc}")

        # Default PC advance (single byte opcodes; PUSH advances above)
        s.pc += 1

    except EvmError as e:
        s.halted = True
        s.reverted = True
        s.last_error = str(e)

    return s


# ---------------------------------------------------------------------------
# Trace generation
# ---------------------------------------------------------------------------

@dataclass
class ExecutionTrace:
    """The full execution trace of a program: every intermediate state
    commitment, indexed by step number.

    `states[0]` is the initial state; `states[i+1] = step(states[i])`.
    `commitments[i]` is the hash of `states[i]`.

    For a program that terminates in N steps, len(states) = N+1, and
    states[N].halted == True.
    """

    states: List[VmState]
    commitments: List[bytes]

    @property
    def n_steps(self) -> int:
        return len(self.states) - 1

    def commitment_at(self, step_idx: int) -> bytes:
        return self.commitments[step_idx]


def execute(
    code: bytes,
    *,
    gas: int = 1_000_000,
    max_steps: int = 1_000_000,
    context: Optional[ExecContext] = None,
    initial_storage: Optional[Dict[int, int]] = None,
) -> ExecutionTrace:
    """Run `code` from a fresh VM state until it halts (or max_steps).

    Optional parameters:
    - `context`: the transaction-level context (caller, value, calldata,
      block info). Defaults to all-zero.
    - `initial_storage`: pre-populated contract storage. Defaults to empty.

    Returns the full trace. Each entry in `states` represents the VM
    AFTER one more instruction has been executed; `states[0]` is the
    initial state (before any instruction)."""
    initial = VmState(
        gas=gas,
        storage=dict(initial_storage or {}),
        original_storage=dict(initial_storage or {}),  # v1.0-rc: SSTORE pricing baseline
        context=context or ExecContext(),
    )
    states: List[VmState] = [initial]
    commitments: List[bytes] = [initial.commitment()]

    for _ in range(max_steps):
        last = states[-1]
        if last.halted:
            break
        nxt = step(last, code)
        states.append(nxt)
        commitments.append(nxt.commitment())

    return ExecutionTrace(states=states, commitments=commitments)
