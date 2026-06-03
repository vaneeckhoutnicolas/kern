# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.evm
========

Mini-EVM and fraud-proof framework for Kern's optimistic rollups.

This package implements a deliberate subset of the Ethereum Virtual
Machine sufficient to demonstrate the full bisection-based fraud-proof
protocol with real EVM-compatible execution semantics.

Top-level API:

    from kern.evm import execute, ExecutionTrace, VmState
    from kern.evm import (
        BisectionState, bisection_round, run_full_bisection,
        single_step_verify, SingleStepResult,
    )
    from kern.evm import Op, opcode_name

See `docs/evm-fraud-proofs.md` for the full protocol description.
"""

from .opcodes import Op, opcode_name
from .vm import EvmError, ExecContext, ExecutionTrace, VmState, execute, step
from .bisection import (
    BisectionState,
    SingleStepResult,
    bisection_round,
    run_full_bisection,
    single_step_verify,
)
from .frames import (
    Account,
    CallResult,
    Frame,
    FrameKind,
    PRECOMPILES,
    WorldState,
    call_contract,
    create_contract,
    derive_create_address,
    derive_create2_address,
    execute_precompile,
    is_precompile,
)

__all__ = [
    "Op", "opcode_name",
    "EvmError", "ExecContext", "ExecutionTrace", "VmState", "execute", "step",
    "BisectionState", "SingleStepResult",
    "bisection_round", "run_full_bisection", "single_step_verify",
    # frames / multi-frame
    "Account", "CallResult", "Frame", "FrameKind", "WorldState",
    "PRECOMPILES", "is_precompile", "execute_precompile",
    "call_contract", "create_contract",
    "derive_create_address", "derive_create2_address",
]
