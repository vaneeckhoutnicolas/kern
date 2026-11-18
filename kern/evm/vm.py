# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm.vm
===========

The Mini-EVM step-wise executor.

For the fraud proofs of a rollup, this machine gives one **state
commitment** for each instruction it executes: the BLAKE2b hash, under
the key `kern.evm`, of the canonical serialization of the state.

The bisection protocol relies on this property: a challenger and a
defender each compute the trace of commitments for the same input,
then narrow down to the first commitment where they disagree. That
single step is then run again by a referee (`single_step_verify`),
which decides who is right.

The commitment of a state holds nine fields:
- pc:       program counter
- stack:    list of 256-bit words (top of stack = end of list)
- memory:   byte array, a whole number of 32-byte words
- gas:      remaining gas
- halted:   terminated? (STOP, RETURN, REVERT, or an instruction the
            machine refuses)
- output:   return data if halted by RETURN or REVERT
- reverted: halted by REVERT or by a refusal
- storage:  the slots that do not hold zero
- context:  what the execution was given (address, caller, value,
            calldata, block number, block timestamp)

`last_error` says why the machine halted. It is outside the commitment
and no step reads it.

A step is a function of the committed state and of the program. Where a
jump may land is read from the program alone.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from .opcodes import GAS_COST, Op, is_dup, is_push, is_swap, opcode_name, push_size


# 256-bit modulus for arithmetic (matches EVM word size)
_WORD_MAX = 1 << 256
_WORD_MASK = _WORD_MAX - 1


class EvmError(Exception):
    """Raised for invalid execution (stack underflow, bad jump, etc.).
    These cause the VM to halt with revert status."""


@dataclass(frozen=True, slots=True)
class ExecContext:
    """The transaction-level execution context: who called, with what value,
    against what contract, with what input data, in what block. All fields
    are committed to the trace's initial state so the verifier can re-run
    deterministically.

    A context does not change once it is built: assigning to one of its
    fields raises `dataclasses.FrozenInstanceError`, and it has no
    dictionary to write into. The states of a run share theirs. An
    execution works on a copy of the context it is given, and a state read
    from a trace carries a copy of its own: a trace shares no object with
    the code that built it or that reads it. `dataclasses.replace` makes
    another context, and `dataclasses.asdict` gives its six values."""

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
            context=self.context,  # a context cannot be assigned to: the states share it
            last_error=self.last_error,
        )


def _a_copy(context: ExecContext) -> ExecContext:
    """Another context with the same six values."""
    return ExecContext(context.address, context.caller, context.value, context.calldata,
                       context.block_number, context.block_timestamp)


def _apart(state: VmState) -> VmState:
    """A copy of `state` that shares nothing with it, its context included:
    what a trace keeps of a state it is given, and what it hands out."""
    copy = state.clone()
    copy.context = _a_copy(state.context)
    return copy


# ---------------------------------------------------------------------------
# The limits of a state
# ---------------------------------------------------------------------------

# A state of the machine holds no more than this. An instruction that would
# take it further halts instead, and a state that is already beyond is not a
# state of the machine: nothing copies it, hashes it or runs it.
MAX_STACK_WORDS = 1_024
MAX_MEMORY_BYTES = 1_048_576  # the output is a copy of a range of the memory
MAX_STORAGE_SLOTS = 16_384
MAX_CALLDATA_BYTES = 1_048_576
# The machine runs no program longer than this. The code of a contract is an
# output of the machine, which is no longer.
MAX_CODE_BYTES = 1_048_576


def beyond_limits(state: "VmState") -> Optional[str]:
    """Name what `state` holds beyond the limits of the machine, or None.

    Only lengths are read, so that a state far too large is turned away
    before anything copies it or hashes it."""
    if len(state.stack) > MAX_STACK_WORDS:
        return "stack"
    if len(state.memory) > MAX_MEMORY_BYTES:
        return "memory"
    if len(state.output) > MAX_MEMORY_BYTES:
        return "output"
    if len(state.storage) > MAX_STORAGE_SLOTS:
        return "storage"
    if len(state.context.calldata) > MAX_CALLDATA_BYTES:
        return "calldata"
    return None


# ---------------------------------------------------------------------------
# What a state of the machine is
# ---------------------------------------------------------------------------

_ADDRESS_MAX = (1 << 160) - 1
_INT_MAX = (1 << 63) - 1
_STATE_FIELDS = frozenset(f.name for f in fields(VmState))
_CONTEXT_FIELDS = frozenset(f.name for f in fields(ExecContext))


def _is_number(value: Any, highest: int) -> bool:
    """An integer from 0 to `highest`. A boolean is not one."""
    return type(value) is int and 0 <= value <= highest


def not_a_state(state: Any) -> Optional[str]:
    """Say what keeps `state` from being a state of the machine, or None.

    A state of the machine is a `VmState` and nothing more, whose fields
    have the types, the ranges and the sizes of structure version 1
    (`docs/api-stability.md`, section 9.22). The machine reaches no other
    state. A state handed in from outside is one only if this says so: a
    word written as a text hashes like the word and does not behave like
    it. Sizes are read first, and nothing is copied or hashed."""
    if type(state) is not VmState or vars(state).keys() != _STATE_FIELDS:
        return "it is not a VmState"
    for name, kind in (("stack", list), ("memory", bytearray), ("output", bytes), ("storage", dict)):
        if type(getattr(state, name)) is not kind:
            return f"its {name} is not a {kind.__name__}"
    context = state.context
    if type(context) is not ExecContext or not all(hasattr(context, name) for name in _CONTEXT_FIELDS):
        return "its context is not an ExecContext"
    if type(context.calldata) is not bytes:
        return "its calldata is not bytes"
    beyond = beyond_limits(state)
    if beyond:
        return f"its {beyond} is beyond the limit"
    if len(state.memory) % 32:
        return "its memory is not a number of words"
    if not _is_number(state.pc, _INT_MAX):
        return "its pc is out of range"
    if not _is_number(state.gas, _INT_MAX):
        return "its gas is out of range"
    if type(state.halted) is not bool or type(state.reverted) is not bool:
        return "halted or reverted is not a boolean"
    for word in state.stack:
        if not _is_number(word, _WORD_MASK):
            return "its stack holds something other than a word"
    for slot, held in state.storage.items():
        if not _is_number(slot, _WORD_MASK) or not _is_number(held, _WORD_MASK):
            return "its storage holds something other than a word"
        if held == 0:
            return "a slot of its storage holds zero"
    if not _is_number(context.address, _ADDRESS_MAX) or not _is_number(context.caller, _ADDRESS_MAX):
        return "an address of its context is out of range"
    if not _is_number(context.value, _WORD_MASK):
        return "the value of its context is out of range"
    if not _is_number(context.block_number, _INT_MAX) or not _is_number(context.block_timestamp, _INT_MAX):
        return "the block of its context is out of range"
    if state.reverted and not state.halted:
        return "it is reverted and not halted"
    if state.output and not state.halted:
        return "it has an output and is not halted"
    return None


def require_state(state: Any) -> None:
    """`ValueError` unless `state` is a state of the machine (`not_a_state`)."""
    reason = not_a_state(state)
    if reason:
        raise ValueError(f"not a state of the Mini-EVM: {reason}")


def require_program(code: Any) -> None:
    """`ValueError` unless `code` is a program of the machine: `bytes`, of
    `MAX_CODE_BYTES` at most. Its type and its length are read, and nothing
    else."""
    if type(code) is not bytes:
        raise ValueError("not a program of the Mini-EVM: it is not bytes")
    if len(code) > MAX_CODE_BYTES:
        raise ValueError("not a program of the Mini-EVM: it is beyond the limit")


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


class _MemoryLimit(Exception):
    """An instruction reached for memory beyond the limit of the machine.
    Raised before anything is reserved; `step` turns it into a halted
    state, and it never leaves this module."""


def _reach_memory(mem: bytearray, end: int) -> None:
    """Make the memory reach `end`, within the limit of the machine: the
    one way an instruction extends the memory."""
    if end > MAX_MEMORY_BYTES:
        raise _MemoryLimit(end)
    _expand_memory(mem, end)


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

    Every instruction that makes `step` extend the memory pays for it
    here, RETURN and REVERT among them: the gas check comes before the
    instruction, so a step that cannot pay never touches the memory.
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

    if op in (Op.RETURN, Op.REVERT):
        # The range handed back is read from the memory, which grows up to
        # its end. These two paid nothing: a few bytes of code held as much
        # memory, and handed back as much output, as they named.
        vals = _peek_stack(state.stack, 2)
        if len(vals) < 2:
            return 0
        offset, length = vals[0], vals[1]
        return dg.memory_expansion_cost(mem_size, offset + length)

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
        # The price reads the slot and the value written: both are in the
        # commitment of the state. sstore_cost() returns the total, of which
        # the static SSTORE cost is already counted.
        static = GAS_COST.get(Op.SSTORE, 5000)
        return max(0, dg.sstore_cost(current, new_val) - static)

    if op in (Op.LOG0, Op.LOG1, Op.LOG2, Op.LOG3, Op.LOG4):
        # `step` does not execute the LOG family: events are not modelled,
        # and a LOG halts as an unknown opcode without extending the memory.
        # This is what that halted step is charged, and what a LOG pays
        # from the day the machine runs it.
        n_topics = op - Op.LOG0
        vals = _peek_stack(state.stack, 2 + n_topics)
        if len(vals) < 2:
            return 0
        offset, length = vals[0], vals[1]
        # log_cost() returns total; LOG0 static = 375, LOG_N = 375 + 375*N
        static = GAS_COST.get(op, 375 + 375 * n_topics)
        return max(0, dg.log_cost(n_topics, length) - static) + dg.memory_expansion_cost(mem_size, offset + length)

    return 0


def _halted_at_limit(state: VmState, code: bytes, what: str, detail: str = "") -> VmState:
    """The state after an instruction that would take `state` beyond a
    limit: the machine halts, reverted, and nothing else changes."""
    s = state.clone()
    s.halted = True
    s.reverted = True
    s.last_error = f"{what} limit at pc={s.pc}, op={opcode_name(_peek_op(code, s.pc))}{detail}"
    return s


# ---------------------------------------------------------------------------
# Where a jump may land
# ---------------------------------------------------------------------------

_JUMPDEST = int(Op.JUMPDEST)
_PUSH1 = int(Op.PUSH1)
_PUSH32 = int(Op.PUSH32)


def _jump_destinations(code: bytes) -> bytes:
    """One byte for each byte of `code`: 1 where a jump may land.

    A jump lands on a JUMPDEST that is an instruction. A byte 0x5b in the
    data of a PUSH is not one, and what is data is known only by reading
    the program from its start: each PUSH says how many bytes of data
    follow it."""
    marks = bytearray(len(code))
    pc, end = 0, len(code)
    while pc < end:
        op = code[pc]
        if op == _JUMPDEST:
            marks[pc] = 1
        elif _PUSH1 <= op <= _PUSH32:
            pc += op - _PUSH1 + 1
        pc += 1
    return bytes(marks)


class _Landings:
    """Where a jump may land in one program. The program is read the first
    time a jump aims at a byte 0x5b, and once: a run, or a trace, keeps
    what it read. A single `step` reads the program for itself."""

    __slots__ = ("_code", "_marks")

    def __init__(self, code: bytes) -> None:
        self._code = code
        self._marks: Optional[bytes] = None

    def __contains__(self, dest: int) -> bool:
        code = self._code
        if dest >= len(code) or code[dest] != _JUMPDEST:
            return False
        if self._marks is None:
            self._marks = _jump_destinations(code)
        return self._marks[dest] == 1


def step(state: VmState, code: bytes) -> VmState:
    """Execute exactly one EVM instruction. Returns the post-step state.

    Pure function: does not mutate the input state. Always advances PC
    (or sets halted=True). Out-of-gas, bad jumps, stack underflow, and
    unknown opcodes all halt with `reverted=True`.

    A jump lands on a JUMPDEST that is an instruction. A byte 0x5b in the
    data of a PUSH is not one, and a jump to it is a bad jump. Where a jump
    may land is read from `code` and from nothing else.

    So does an instruction that would take the stack, the memory or the
    storage beyond the limits of the machine. Like a step that cannot
    pay, it leaves the gas, the stack, the memory and the storage as they
    were, and it halts before any memory is reserved. The gas is looked
    at first: an instruction that can neither pay nor fit halts for want
    of gas.

    What is not a state of the machine is not run: `ValueError`, its
    sizes read first, before anything copies it, hashes it or reads a word
    of it (`not_a_state`). Nor is what is not a program of the machine
    (`require_program`)."""
    require_program(code)
    require_state(state)
    return _advance(state, code, _Landings(code))


def _advance(state: VmState, code: bytes, landings: _Landings) -> VmState:
    """`step`, for a state the machine made itself and a program it has
    checked: the loops of `execute`, `run` and `TraceStates`, which would
    otherwise read every word of each state they have just built, and the
    whole program at each jump."""
    try:
        s = _step(state, code, landings)
    except _MemoryLimit as reached:
        return _halted_at_limit(state, code, "memory", f" (needs {reached.args[0]} bytes)")
    beyond = beyond_limits(s)
    if beyond:
        # The stack and the storage grow by one word or one slot at most:
        # the step is set aside once it is known to go too far.
        return _halted_at_limit(state, code, beyond)
    return s


def _step(state: VmState, code: bytes, landings: _Landings) -> VmState:
    """The instruction itself: `step`, less the limits of the state."""
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
            _reach_memory(s.memory, offset + length)
            s.output = bytes(s.memory[offset:offset + length])
            s.halted = True
            return s

        if op == Op.REVERT:
            offset, length = _pop(s.stack, 2)
            _reach_memory(s.memory, offset + length)
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
            _reach_memory(s.memory, offset + 32)
            word = int.from_bytes(s.memory[offset:offset + 32], "big")
            _push(s.stack, word)
        elif op == Op.MSTORE:
            offset, value = _pop(s.stack, 2)
            _reach_memory(s.memory, offset + 32)
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
            if dest not in landings:
                raise EvmError(f"invalid jump dest {dest}")
            s.pc = dest
            return s
        elif op == Op.JUMPI:
            dest, cond = _pop(s.stack, 2)
            if cond != 0:
                if dest not in landings:
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
            _reach_memory(s.memory, offset + length)
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
            _reach_memory(s.memory, offset + 1)
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

class TraceStates:
    """The states of an execution, read like a list: `states[i]` is the
    state after `i` steps, `states[-1]` the last one.

    Only the first state and the last one are kept. Any other is run again
    from the first, without hashing anything: a trace holds one commitment
    for each step, and not one copy of the memory for each step. What is
    handed out is a copy that shares nothing with the trace, its context
    included: nothing done to it changes the trace.

    A trace built by hand is given a program, a first state, a last state
    and a number of steps. `ValueError` when the program is not a program
    of the machine, when one of the two states is not a state of it, or
    when the number of steps is not a count. The trace keeps copies of the
    two states: nothing done to them afterwards changes it. Nothing checks
    that the last state is the one the program reaches after that many
    steps: `execute` builds the trace of an execution."""

    def __init__(self, code: bytes, first: VmState, last: VmState, n_steps: int) -> None:
        require_program(code)
        require_state(first)
        require_state(last)
        if type(n_steps) is not int or n_steps < 0:
            raise ValueError("not a trace of the Mini-EVM: its number of steps is not a count")
        self._code = code
        self._first = _apart(first)
        self._last = _apart(last)
        self._n_steps = n_steps
        self._landings = _Landings(code)

    @classmethod
    def _of_an_execution(cls, code: bytes, first: VmState, last: VmState, n_steps: int,
                         landings: _Landings) -> "TraceStates":
        """The trace of `execute`: its two states are the machine's own,
        which nothing else holds, and its program was read once."""
        states = cls.__new__(cls)
        states._code, states._first, states._last = code, first, last
        states._n_steps, states._landings = n_steps, landings
        return states

    def __len__(self) -> int:
        return self._n_steps + 1

    def __iter__(self) -> Iterator[VmState]:
        state = self._first
        yield _apart(state)
        for _ in range(self._n_steps):
            state = _advance(state, self._code, self._landings)
            yield _apart(state)

    def __getitem__(self, index: Union[int, slice]) -> Any:
        if isinstance(index, slice):
            wanted = range(*index.indices(len(self)))
            found = {position: state for position, state in enumerate(self) if position in wanted}
            return [found[position] for position in wanted]
        position = index + len(self) if index < 0 else index
        if not 0 <= position < len(self):
            raise IndexError("no such step in the trace")
        if position == self._n_steps:
            return _apart(self._last)
        state = self._first
        for _ in range(position):
            state = _advance(state, self._code, self._landings)
        return _apart(state)


@dataclass
class ExecutionTrace:
    """The full execution trace of a program: every intermediate state
    commitment, indexed by step number.

    `states[0]` is the initial state; `states[i+1] = step(states[i])`.
    `commitments[i]` is the hash of `states[i]`.

    For a program that terminates in N steps, len(states) = N+1, and
    states[N].halted == True.

    `execute` keeps the commitments, the first state and the last one:
    its `states` give any other back by running the program again.
    """

    states: Union[List[VmState], TraceStates]
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
    initial state (before any instruction).

    The trace keeps one commitment for each step, the first state and the
    last one (`TraceStates`). Every state is hashed on the way: a call,
    which reads the last state and no other, goes through `run`.

    `ValueError` when `code` is not a program of the machine, or when the
    gas, the context and the initial storage do not make a state of it:
    nothing is copied, nothing is hashed and nothing runs."""
    initial = _initial_state(code, gas, context, initial_storage)
    commitments: List[bytes] = [initial.commitment()]
    landings = _Landings(code)

    last = initial
    for _ in range(max_steps):
        if last.halted:
            break
        last = _advance(last, code, landings)
        commitments.append(last.commitment())

    states = TraceStates._of_an_execution(code, initial, last, len(commitments) - 1, landings)
    return ExecutionTrace(states=states, commitments=commitments)


def _initial_state(code: bytes, gas: int, context: Optional[ExecContext],
                   initial_storage: Optional[Dict[int, int]]) -> VmState:
    """The state a program starts from, or `ValueError`. The size of the
    initial storage is read before its first copy. The state holds a copy
    of the context it is given: the caller keeps its own."""
    require_program(code)
    storage: Dict[int, int] = {}
    if initial_storage is not None:
        if type(initial_storage) is not dict:
            raise ValueError("not a state of the Mini-EVM: its storage is not a dict")
        if len(initial_storage) > MAX_STORAGE_SLOTS:
            raise ValueError("not a state of the Mini-EVM: its storage is beyond the limit")
        storage = dict(initial_storage)
    initial = VmState(gas=gas, storage=storage, context=ExecContext() if context is None else context)
    require_state(initial)
    initial.context = _a_copy(initial.context)
    return initial


def _halted_at_write(state: VmState) -> VmState:
    """The state of a static run whose next instruction is a write: the
    run halts, reverted, and nothing else changes."""
    s = state.clone()
    s.halted = True
    s.reverted = True
    s.last_error = f"write in a static call at pc={s.pc}"
    return s


def run(
    code: bytes,
    *,
    gas: int = 1_000_000,
    max_steps: int = 1_000_000,
    context: Optional[ExecContext] = None,
    initial_storage: Optional[Dict[int, int]] = None,
    static: bool = False,
) -> VmState:
    """Run `code` as `execute` does and return its last state alone.

    Nothing is kept on the way and nothing is hashed: this is what a call
    needs. The last state is not halted when `max_steps` ran out first.

    With `static`, the program cannot write. It halts, reverted, on the
    first SSTORE it reaches, even one that would change nothing, and the
    state is what it was before that instruction, its gas included: the
    write is refused before its price is looked at. This is the run of a
    static call. `step` and `execute` have no such mode: a step is a
    function of the state and of the program, and a fraud proof is never
    about a static call.

    `ValueError` as for `execute`."""
    state = _initial_state(code, gas, context, initial_storage)
    landings = _Landings(code)
    for _ in range(max_steps):
        if state.halted:
            break
        if static and _peek_op(code, state.pc) == Op.SSTORE:
            state = _halted_at_write(state)
            break
        state = _advance(state, code, landings)
    return state
