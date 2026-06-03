# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.skald.typecheck
====================

Static type checker for Skald contracts. Runs *before* origination so
that any type error is caught at deploy time rather than at first call.

The checker walks the AST produced by `kern.skald.parse` and verifies:

1. Every storage field has a declared type, no duplicates.
2. Every function parameter has a declared type.
3. Every variable reference resolves to a known name (storage field,
   parameter, local `let`, or built-in).
4. Every expression has a well-defined type and operators are applied to
   compatible operand types.
5. Every storage assignment matches the declared field type.
6. Every `let` binding's declared type matches the initializer expression.
7. Every `view` function has a return type and its body's final
   expression matches it.
8. Every `require` condition is `bool`.
9. Every `if` condition is `bool`.
10. Every invariant body evaluates to `bool`.
11. No function is directly or mutually recursive (the call graph is
    acyclic), so every call provably terminates with a statically bounded
    depth — a determinism requirement, see `_check_no_recursion`.

The checker reports the *first* type error encountered. Future versions
will accumulate and report all errors in one pass.

Public API:

    type_check(code: str) -> List[TypeError]   # empty list = ok
    assert_type_correct(code: str)             # raises if not ok
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import BUILTINS, Contract, Func, Invariant, Param, SkaldError, parse


# Types are represented as strings: "int", "bool", "string", "address",
# plus the special "unit" for statements with no value.
Type = str

PRIMITIVES = {"int", "bool", "string", "address"}


@dataclass
class TypeError(Exception):
    where: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.where}] {self.detail}"


# Operator typing rules: (op, left, right) -> result type.
_BINOP_RULES: Dict[str, List[Tuple[str, str, str]]] = {
    "+":  [("int", "int", "int"), ("string", "string", "string")],
    "-":  [("int", "int", "int")],
    "*":  [("int", "int", "int")],
    "/":  [("int", "int", "int")],
    "%":  [("int", "int", "int")],
    "<":  [("int", "int", "bool")],
    ">":  [("int", "int", "bool")],
    "<=": [("int", "int", "bool")],
    ">=": [("int", "int", "bool")],
    "==": [(t, t, "bool") for t in ("int", "bool", "string", "address")],
    "!=": [(t, t, "bool") for t in ("int", "bool", "string", "address")],
    "&&": [("bool", "bool", "bool")],
    "||": [("bool", "bool", "bool")],
}

_UNARY_RULES: Dict[str, List[Tuple[str, str]]] = {
    "-": [("int", "int")],
    "!": [("bool", "bool")],
}


class TypeChecker:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.storage_types: Dict[str, Type] = {}
        self.errors: List[TypeError] = []

    # ----------------------------------------------------------- entry points

    def check(self) -> List[TypeError]:
        self._check_storage_schema()
        self._check_invariants()
        for fn in self.contract.functions.values():
            self._check_function(fn)
        self._check_no_recursion()
        return self.errors

    # ----------------------------------------------------------- termination

    def _check_no_recursion(self) -> None:
        """Reject direct or mutual recursion among declared functions.

        Skald is specified as a *non-recursive*, loop-free language so that
        every call provably terminates and the cost of a call is statically
        bounded. This is not merely a stylistic rule: the reference
        interpreter executes Skald on the host (Python) call stack, so an
        unbounded recursion would terminate only when the host hits its
        own stack limit. That limit differs across machines, OS builds, and
        interpreter versions, which means a recursive contract could succeed
        on one validator and fail on another — producing *divergent state
        roots* and breaking consensus. Forbidding recursion at deploy time
        closes that determinism hole.

        Implementation: build the static call graph among declared functions
        and report every cycle found via depth-first search.
        """
        graph: Dict[str, set] = {}
        for fn in self.contract.functions.values():
            callees: set = set()
            for stmt in fn.body:
                self._collect_calls_stmt(stmt, callees)
            # Only edges to *declared* functions matter; calls to unknown
            # names are reported separately by the expression checker.
            graph[fn.name] = {c for c in callees if c in self.contract.functions}

        color: Dict[str, int] = {}  # 0=unvisited, 1=on-stack, 2=done
        reported: set = set()
        path: List[str] = []

        def dfs(node: str) -> None:
            color[node] = 1
            path.append(node)
            for nxt in sorted(graph.get(node, ())):
                state = color.get(nxt, 0)
                if state == 1:  # back-edge -> cycle
                    i = path.index(nxt)
                    cyc = path[i:] + [nxt]
                    key = frozenset(cyc)
                    if key not in reported:
                        reported.add(key)
                        self.errors.append(TypeError(
                            where="contract",
                            detail=(
                                "recursion is not allowed in Skald (call "
                                f"cycle: {' -> '.join(cyc)}); rewrite without "
                                "recursion so execution depth is statically "
                                "bounded and deterministic across all nodes"
                            ),
                        ))
                elif state == 0:
                    dfs(nxt)
            path.pop()
            color[node] = 2

        for n in sorted(graph):
            if color.get(n, 0) == 0:
                dfs(n)

    def _collect_calls_stmt(self, stmt, out: set) -> None:
        tag = stmt[0]
        if tag == "assign":
            self._collect_calls_expr(stmt[2], out)
        elif tag == "let":
            self._collect_calls_expr(stmt[3], out)
        elif tag == "require":
            self._collect_calls_expr(stmt[1], out)
            if stmt[2] is not None:
                self._collect_calls_expr(stmt[2], out)
        elif tag == "if":
            self._collect_calls_expr(stmt[1], out)
            for s in stmt[2]:
                self._collect_calls_stmt(s, out)
            for s in stmt[3]:
                self._collect_calls_stmt(s, out)
        elif tag == "return":
            self._collect_calls_expr(stmt[1], out)
        elif tag == "expr":
            self._collect_calls_expr(stmt[1], out)

    def _collect_calls_expr(self, expr, out: set) -> None:
        tag = expr[0]
        if tag == "call":
            out.add(expr[1])
            for a in expr[2]:
                self._collect_calls_expr(a, out)
        elif tag == "bin":
            self._collect_calls_expr(expr[2], out)
            self._collect_calls_expr(expr[3], out)
        elif tag == "unary":
            self._collect_calls_expr(expr[2], out)
        # num / str / bool / id carry no calls

    # ----------------------------------------------------------- schema

    def _check_storage_schema(self) -> None:
        seen: set = set()
        for p in self.contract.storage_schema:
            if p.name in seen:
                self.errors.append(TypeError(
                    where="storage", detail=f"duplicate field {p.name!r}",
                ))
            seen.add(p.name)
            if p.type_ not in PRIMITIVES:
                self.errors.append(TypeError(
                    where=f"storage.{p.name}",
                    detail=f"unknown type {p.type_!r} (allowed: {sorted(PRIMITIVES)})",
                ))
            self.storage_types[p.name] = p.type_

    # ----------------------------------------------------------- invariants

    def _check_invariants(self) -> None:
        for inv in self.contract.invariants:
            t = self._type_of_expr(inv.expr, locals_={}, where=f"invariant {inv.name}")
            if t is not None and t != "bool":
                self.errors.append(TypeError(
                    where=f"invariant {inv.name}",
                    detail=f"invariant must be bool, got {t}",
                ))

    # ----------------------------------------------------------- functions

    def _check_function(self, fn: Func) -> None:
        # Parameter types must be primitives, no name collisions with storage.
        locals_: Dict[str, Type] = {}
        seen: set = set()
        for p in fn.params:
            if p.name in seen:
                self.errors.append(TypeError(
                    where=f"{fn.kind} {fn.name}",
                    detail=f"duplicate parameter {p.name!r}",
                ))
            if p.type_ not in PRIMITIVES:
                self.errors.append(TypeError(
                    where=f"{fn.kind} {fn.name}({p.name})",
                    detail=f"unknown parameter type {p.type_!r}",
                ))
            if p.name in self.storage_types:
                self.errors.append(TypeError(
                    where=f"{fn.kind} {fn.name}",
                    detail=f"parameter {p.name!r} shadows storage field",
                ))
            seen.add(p.name)
            locals_[p.name] = p.type_

        # Return type must be primitive (or absent).
        if fn.return_type and fn.return_type not in PRIMITIVES:
            self.errors.append(TypeError(
                where=f"{fn.kind} {fn.name}",
                detail=f"unknown return type {fn.return_type!r}",
            ))

        # Views must declare a return type. Entries and internals may not.
        if fn.kind == "view" and not fn.return_type:
            self.errors.append(TypeError(
                where=f"view {fn.name}",
                detail="view function must declare a return type",
            ))

        # Walk body. Collect declared `let`s into locals as we go.
        last_expr_type: Optional[Type] = None
        for stmt in fn.body:
            last_expr_type = self._check_stmt(stmt, fn, locals_)

        # For views without an explicit return, the last expression statement
        # must match the declared return type.
        if fn.kind == "view" and fn.return_type:
            # Detect explicit `return` somewhere (validator: every return must match).
            # If no explicit return, the final expression statement is the value.
            has_return = any(s[0] == "return" for s in fn.body)
            if not has_return:
                if last_expr_type is None:
                    self.errors.append(TypeError(
                        where=f"view {fn.name}",
                        detail="view body must end with an expression",
                    ))
                elif last_expr_type != fn.return_type:
                    self.errors.append(TypeError(
                        where=f"view {fn.name}",
                        detail=f"return type {fn.return_type} but body yields {last_expr_type}",
                    ))

        # Entry functions must not mutate storage in a way that depends on
        # being a view. Sanity: entries should only assign to storage of the
        # declared type. (Storage type-check happens inside _check_stmt.)

    # ----------------------------------------------------------- statements

    def _check_stmt(self, stmt, fn: Func, locals_: Dict[str, Type]) -> Optional[Type]:
        tag = stmt[0]
        where = f"{fn.kind} {fn.name}"

        if tag == "assign":
            name, expr = stmt[1], stmt[2]
            target_type = locals_.get(name) or self.storage_types.get(name)
            if target_type is None:
                self.errors.append(TypeError(
                    where=where, detail=f"assignment to undeclared {name!r}",
                ))
                return None
            t = self._type_of_expr(expr, locals_, where)
            if t is not None and t != target_type:
                self.errors.append(TypeError(
                    where=where,
                    detail=f"cannot assign {t} to {name} of type {target_type}",
                ))
            # Disallow mutating storage from a `view`.
            if fn.kind == "view" and name in self.storage_types:
                self.errors.append(TypeError(
                    where=where,
                    detail=f"view function cannot mutate storage field {name!r}",
                ))
            return None

        if tag == "let":
            name, type_, expr = stmt[1], stmt[2], stmt[3]
            if name in locals_ or name in self.storage_types:
                self.errors.append(TypeError(
                    where=where, detail=f"let {name!r} shadows existing binding",
                ))
            if type_ not in PRIMITIVES:
                self.errors.append(TypeError(
                    where=where, detail=f"unknown type {type_!r} in let",
                ))
            t = self._type_of_expr(expr, locals_, where)
            if t is not None and t != type_:
                self.errors.append(TypeError(
                    where=where,
                    detail=f"let {name}: {type_} initialized with {t}",
                ))
            locals_[name] = type_
            return None

        if tag == "require":
            cond, msg = stmt[1], stmt[2]
            tc = self._type_of_expr(cond, locals_, where)
            if tc is not None and tc != "bool":
                self.errors.append(TypeError(
                    where=where, detail=f"require condition must be bool, got {tc}",
                ))
            if msg is not None:
                tm = self._type_of_expr(msg, locals_, where)
                if tm is not None and tm != "string":
                    self.errors.append(TypeError(
                        where=where, detail=f"require message must be string, got {tm}",
                    ))
            return None

        if tag == "if":
            cond, then_s, else_s = stmt[1], stmt[2], stmt[3]
            tc = self._type_of_expr(cond, locals_, where)
            if tc is not None and tc != "bool":
                self.errors.append(TypeError(
                    where=where, detail=f"if condition must be bool, got {tc}",
                ))
            # Each branch gets its own local scope (lets don't leak).
            for branch_name, branch in (("then", then_s), ("else", else_s)):
                branch_locals = dict(locals_)
                for s in branch:
                    self._check_stmt(s, fn, branch_locals)
            return None

        if tag == "return":
            t = self._type_of_expr(stmt[1], locals_, where)
            if fn.return_type and t is not None and t != fn.return_type:
                self.errors.append(TypeError(
                    where=where,
                    detail=f"return {t} but function returns {fn.return_type}",
                ))
            return t

        if tag == "expr":
            return self._type_of_expr(stmt[1], locals_, where)

        self.errors.append(TypeError(where=where, detail=f"unknown statement {tag!r}"))
        return None

    # ----------------------------------------------------------- expressions

    def _type_of_expr(self, expr, locals_: Dict[str, Type], where: str) -> Optional[Type]:
        tag = expr[0]
        if tag == "num":     return "int"
        if tag == "str":     return "string"
        if tag == "bool":    return "bool"

        if tag == "id":
            name = expr[1]
            if name in locals_:
                return locals_[name]
            if name in self.storage_types:
                return self.storage_types[name]
            if name in BUILTINS:
                return {
                    "sender": "address",
                    "amount": "int",
                    "self": "address",
                    "balance": "int",
                }[name]
            self.errors.append(TypeError(
                where=where, detail=f"undefined identifier {name!r}",
            ))
            return None

        if tag == "unary":
            op, sub = expr[1], expr[2]
            ts = self._type_of_expr(sub, locals_, where)
            if ts is None:
                return None
            for in_t, out_t in _UNARY_RULES.get(op, []):
                if in_t == ts:
                    return out_t
            self.errors.append(TypeError(
                where=where, detail=f"unary {op} not defined on {ts}",
            ))
            return None

        if tag == "bin":
            op, l, r = expr[1], expr[2], expr[3]
            tl = self._type_of_expr(l, locals_, where)
            tr = self._type_of_expr(r, locals_, where)
            if tl is None or tr is None:
                return None
            for in_l, in_r, out_t in _BINOP_RULES.get(op, []):
                if in_l == tl and in_r == tr:
                    return out_t
            self.errors.append(TypeError(
                where=where,
                detail=f"{op} not defined on ({tl}, {tr})",
            ))
            return None

        if tag == "call":
            name, args = expr[1], expr[2]
            fn = self.contract.functions.get(name)
            if fn is None:
                self.errors.append(TypeError(
                    where=where, detail=f"call to unknown function {name!r}",
                ))
                return None
            if fn.kind not in ("view", "internal"):
                self.errors.append(TypeError(
                    where=where,
                    detail=f"cannot call {fn.kind} {name!r} from expression",
                ))
                return None
            if len(args) != len(fn.params):
                self.errors.append(TypeError(
                    where=where,
                    detail=f"{name} expects {len(fn.params)} args, got {len(args)}",
                ))
                return fn.return_type
            for i, (arg, p) in enumerate(zip(args, fn.params)):
                ta = self._type_of_expr(arg, locals_, where)
                if ta is not None and ta != p.type_:
                    self.errors.append(TypeError(
                        where=where,
                        detail=f"{name}() arg {i} ({p.name}): expected {p.type_}, got {ta}",
                    ))
            return fn.return_type

        self.errors.append(TypeError(where=where, detail=f"unknown expression tag {tag!r}"))
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def type_check(code: str) -> List[TypeError]:
    """Return a list of type errors in `code`. Empty list = the contract
    is well-typed."""
    contract = parse(code)
    return TypeChecker(contract).check()


def assert_type_correct(code: str) -> None:
    """Raise SkaldError with a summary if `code` is not well-typed."""
    errors = type_check(code)
    if errors:
        lines = [f"  - {e}" for e in errors]
        raise SkaldError("type errors in contract:\n" + "\n".join(lines))
