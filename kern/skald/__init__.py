# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.skald
==========

Skald is the contract language for Kern. It is statically typed in spirit
(this MVP interpreter performs runtime checking; a real implementation
would type-check at compile time) and features:

- Resource-typed storage: declared schema, no shadowing, atomic update.
- Declarative invariants: predicates that must hold after every entry call.
- A clean separation between `entry` (state-mutating), `view` (pure read),
  and `internal` (private helper) functions.
- Built-ins for the chain context: `sender`, `amount`, `self`, `balance`.

This module exposes two functions used by `kern.chain`:

    interpret_origination(code, initial_storage) -> storage_dict
    interpret_call(code, storage, entry, params, *, sender, amount, self_addr)
        -> new_storage_dict

The grammar implemented here is a subset of the full Skald spec; see
`docs/skald-language.md` for the complete syntax and semantics.

Example contract
----------------

    contract Counter {
        storage {
            count: int,
            owner: address,
        }

        invariant nonneg {
            count >= 0
        }

        entry increment() {
            count = count + 1;
        }

        entry add(n: int) {
            require n > 0 with "must be positive";
            count = count + n;
        }

        view current() -> int {
            count
        }
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SkaldError(Exception):
    """Raised on any Skald-level error: parse, type, runtime, invariant."""


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

TOKEN_SPEC: List[Tuple[str, str]] = [
    ("COMMENT",  r"//[^\n]*"),
    ("NUMBER",   r"-?\d+"),
    ("STRING",   r'"(?:\\.|[^"\\])*"'),
    ("ID",       r"[A-Za-z_][A-Za-z0-9_]*"),
    ("OP",       r"==|!=|<=|>=|&&|\|\||->|[+\-*/%<>=!,;:{}().]"),
    ("WS",       r"\s+"),
]

_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pat})" for name, pat in TOKEN_SPEC)
)

KEYWORDS = {
    "contract", "storage", "entry", "view", "internal", "invariant",
    "if", "else", "require", "with", "let", "true", "false", "return",
}


@dataclass
class Token:
    kind: str
    value: str
    pos: int


def tokenize(src: str) -> List[Token]:
    tokens: List[Token] = []
    for m in _TOKEN_RE.finditer(src):
        kind = m.lastgroup
        val = m.group()
        if kind in ("WS", "COMMENT"):
            continue
        if kind == "ID" and val in KEYWORDS:
            kind = "KW"
        tokens.append(Token(kind, val, m.start()))
    tokens.append(Token("EOF", "", len(src)))
    return tokens


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

@dataclass
class Param:
    name: str
    type_: str  # "int", "address", "string", "bool"


@dataclass
class Func:
    name: str
    kind: str  # "entry", "view", "internal"
    params: List[Param]
    return_type: Optional[str]
    body: list  # list of statements


@dataclass
class Invariant:
    name: str
    expr: Any  # expression AST


@dataclass
class Contract:
    storage_schema: List[Param]
    invariants: List[Invariant]
    functions: Dict[str, Func]


# Statements are tagged tuples for compactness:
#   ("assign", name, expr)
#   ("require", expr, message_expr | None)
#   ("if", cond, then_stmts, else_stmts)
#   ("expr", expr)
#   ("return", expr)
#   ("let", name, type, expr)
#
# Expressions:
#   ("num", n) | ("str", s) | ("bool", b) | ("id", name)
#   ("bin", op, l, r) | ("unary", op, e) | ("call", name, [args])


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens: List[Token]):
        self.toks = tokens
        self.i = 0

    def peek(self, offset: int = 0) -> Token:
        return self.toks[self.i + offset]

    def eat(self, *kinds_or_values) -> Token:
        t = self.peek()
        if not kinds_or_values:
            # No constraint — just consume and return.
            self.i += 1
            return t
        for k in kinds_or_values:
            if t.kind == k or t.value == k:
                self.i += 1
                return t
        raise SkaldError(
            f"expected one of {kinds_or_values} at pos {t.pos}, got {t.kind} '{t.value}'"
        )

    def accept(self, *kinds_or_values) -> Optional[Token]:
        t = self.peek()
        for k in kinds_or_values:
            if t.kind == k or t.value == k:
                self.i += 1
                return t
        return None

    # contract := 'contract' ID '{' (storage | invariant | func)* '}'
    def parse_contract(self) -> Contract:
        self.eat("contract")
        self.eat("ID")  # contract name (kept for documentation only)
        self.eat("{")
        storage_schema: List[Param] = []
        invariants: List[Invariant] = []
        functions: Dict[str, Func] = {}
        while not self.accept("}"):
            kw = self.peek().value
            if kw == "storage":
                if storage_schema:
                    raise SkaldError("duplicate storage block")
                storage_schema = self.parse_storage()
            elif kw == "invariant":
                invariants.append(self.parse_invariant())
            elif kw in ("entry", "view", "internal"):
                f = self.parse_func()
                if f.name in functions:
                    raise SkaldError(f"duplicate function {f.name}")
                functions[f.name] = f
            else:
                t = self.peek()
                raise SkaldError(f"unexpected token at pos {t.pos}: {t.value!r}")
        return Contract(storage_schema, invariants, functions)

    def parse_storage(self) -> List[Param]:
        self.eat("storage")
        self.eat("{")
        params: List[Param] = []
        while not self.accept("}"):
            params.append(self.parse_param())
            self.accept(",")
        return params

    def parse_param(self) -> Param:
        name = self.eat("ID").value
        self.eat(":")
        type_ = self.eat("ID").value
        return Param(name, type_)

    def parse_invariant(self) -> Invariant:
        self.eat("invariant")
        name = self.eat("ID").value
        self.eat("{")
        e = self.parse_expr()
        self.eat("}")
        return Invariant(name, e)

    def parse_func(self) -> Func:
        kind = self.eat("KW").value  # entry | view | internal
        name = self.eat("ID").value
        self.eat("(")
        params: List[Param] = []
        if not self.accept(")"):
            params.append(self.parse_param())
            while self.accept(","):
                params.append(self.parse_param())
            self.eat(")")
        ret = None
        if self.accept("->"):
            ret = self.eat("ID").value
        self.eat("{")
        body: list = []
        while not self.accept("}"):
            body.append(self.parse_stmt())
        return Func(name, kind, params, ret, body)

    # --- statements -------------------------------------------------------

    def parse_stmt(self):
        t = self.peek()
        if t.value == "require":
            return self.parse_require()
        if t.value == "if":
            return self.parse_if()
        if t.value == "let":
            return self.parse_let()
        if t.value == "return":
            return self.parse_return()
        # assignment or expression statement
        if t.kind == "ID" and self.peek(1).value == "=":
            name = self.eat("ID").value
            self.eat("=")
            e = self.parse_expr()
            self.eat(";")
            return ("assign", name, e)
        e = self.parse_expr()
        # allow expression statements (e.g., bare function calls)
        if self.accept(";"):
            return ("expr", e)
        # bare trailing expression (view body): caller will detect it
        return ("expr", e)

    def parse_require(self):
        self.eat("require")
        cond = self.parse_expr()
        msg = None
        if self.accept("with"):
            msg = self.parse_expr()
        self.eat(";")
        return ("require", cond, msg)

    def parse_if(self):
        self.eat("if")
        self.eat("(")
        cond = self.parse_expr()
        self.eat(")")
        self.eat("{")
        then_stmts: list = []
        while not self.accept("}"):
            then_stmts.append(self.parse_stmt())
        else_stmts: list = []
        if self.accept("else"):
            self.eat("{")
            while not self.accept("}"):
                else_stmts.append(self.parse_stmt())
        return ("if", cond, then_stmts, else_stmts)

    def parse_let(self):
        self.eat("let")
        name = self.eat("ID").value
        self.eat(":")
        type_ = self.eat("ID").value
        self.eat("=")
        e = self.parse_expr()
        self.eat(";")
        return ("let", name, type_, e)

    def parse_return(self):
        self.eat("return")
        e = self.parse_expr()
        self.eat(";")
        return ("return", e)

    # --- expressions: Pratt-style precedence climbing --------------------

    _PREC = {
        "||": 1, "&&": 2,
        "==": 3, "!=": 3,
        "<": 4, ">": 4, "<=": 4, ">=": 4,
        "+": 5, "-": 5,
        "*": 6, "/": 6, "%": 6,
    }

    def parse_expr(self, min_prec: int = 0):
        left = self.parse_unary()
        while True:
            t = self.peek()
            prec = self._PREC.get(t.value)
            if prec is None or prec < min_prec:
                return left
            op = self.eat().value
            right = self.parse_expr(prec + 1)
            left = ("bin", op, left, right)

    def parse_unary(self):
        if self.accept("-"):
            return ("unary", "-", self.parse_unary())
        if self.accept("!"):
            return ("unary", "!", self.parse_unary())
        return self.parse_atom()

    def parse_atom(self):
        t = self.peek()
        if t.kind == "NUMBER":
            self.i += 1
            return ("num", int(t.value))
        if t.kind == "STRING":
            self.i += 1
            return ("str", _unescape(t.value[1:-1]))
        if t.value == "true":
            self.i += 1
            return ("bool", True)
        if t.value == "false":
            self.i += 1
            return ("bool", False)
        if t.value == "(":
            self.i += 1
            e = self.parse_expr()
            self.eat(")")
            return e
        if t.kind == "ID":
            name = self.eat("ID").value
            if self.accept("("):
                args = []
                if not self.accept(")"):
                    args.append(self.parse_expr())
                    while self.accept(","):
                        args.append(self.parse_expr())
                    self.eat(")")
                return ("call", name, args)
            return ("id", name)
        raise SkaldError(f"unexpected token in expression at pos {t.pos}: {t.value!r}")


def _unescape(s: str) -> str:
    return s.encode("utf-8").decode("unicode_escape")


def parse(src: str) -> Contract:
    tokens = tokenize(src)
    return _Parser(tokens).parse_contract()


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------

BUILTINS = {"sender", "amount", "self", "balance"}


def _coerce_default(type_: str) -> Any:
    return {
        "int": 0,
        "address": "kn1" + "0" * 33,
        "string": "",
        "bool": False,
    }.get(type_, None)


def _typecheck(value: Any, type_: str, *, where: str) -> None:
    if type_ == "int" and not isinstance(value, int):
        raise SkaldError(f"{where}: expected int, got {type(value).__name__}")
    if type_ == "string" and not isinstance(value, str):
        raise SkaldError(f"{where}: expected string, got {type(value).__name__}")
    if type_ == "bool" and not isinstance(value, bool):
        raise SkaldError(f"{where}: expected bool, got {type(value).__name__}")
    if type_ == "address":
        if not (isinstance(value, str) and value.startswith("kn1")):
            raise SkaldError(f"{where}: expected address, got {value!r}")


class _Interp:
    def __init__(
        self,
        contract: Contract,
        storage: Dict[str, Any],
        ctx: Dict[str, Any],
    ):
        self.contract = contract
        self.storage = storage  # mutated in place
        self.ctx = ctx
        self.locals: Dict[str, Any] = {}

    def lookup(self, name: str) -> Any:
        if name in self.locals:
            return self.locals[name]
        if name in self.storage:
            return self.storage[name]
        if name in BUILTINS:
            return self.ctx[name]
        raise SkaldError(f"undefined identifier: {name}")

    def eval_expr(self, e) -> Any:
        tag = e[0]
        if tag == "num":
            return e[1]
        if tag == "str":
            return e[1]
        if tag == "bool":
            return e[1]
        if tag == "id":
            return self.lookup(e[1])
        if tag == "unary":
            v = self.eval_expr(e[2])
            if e[1] == "-":
                return -v
            if e[1] == "!":
                return not v
        if tag == "bin":
            op, l, r = e[1], e[2], e[3]
            lv = self.eval_expr(l)
            # short-circuit
            if op == "&&":
                return bool(lv) and bool(self.eval_expr(r))
            if op == "||":
                return bool(lv) or bool(self.eval_expr(r))
            rv = self.eval_expr(r)
            return _binop(op, lv, rv)
        if tag == "call":
            name, args = e[1], e[2]
            arg_values = [self.eval_expr(a) for a in args]
            if name in self.contract.functions:
                fn = self.contract.functions[name]
                if fn.kind not in ("internal", "view"):
                    raise SkaldError(f"cannot call {fn.kind} function from expression: {name}")
                return self._call(fn, arg_values)
            raise SkaldError(f"unknown function: {name}")
        raise SkaldError(f"unknown expression tag: {tag}")

    def exec_stmt(self, s) -> Optional[Any]:
        tag = s[0]
        if tag == "assign":
            name, e = s[1], s[2]
            v = self.eval_expr(e)
            if name not in self.storage and name not in self.locals:
                raise SkaldError(f"cannot assign to undeclared {name}")
            if name in self.locals:
                self.locals[name] = v
            else:
                # Storage assignment: type-check against schema.
                schema = next(p for p in self.contract.storage_schema if p.name == name)
                _typecheck(v, schema.type_, where=f"storage.{name}")
                self.storage[name] = v
            return None
        if tag == "let":
            name, type_, e = s[1], s[2], s[3]
            v = self.eval_expr(e)
            _typecheck(v, type_, where=f"let {name}")
            self.locals[name] = v
            return None
        if tag == "require":
            cond, msg = s[1], s[2]
            if not self.eval_expr(cond):
                m = self.eval_expr(msg) if msg is not None else "requirement failed"
                raise SkaldError(f"require: {m}")
            return None
        if tag == "if":
            cond, then_s, else_s = s[1], s[2], s[3]
            block = then_s if self.eval_expr(cond) else else_s
            for st in block:
                r = self.exec_stmt(st)
                if r is _RETURN:
                    return r
            return None
        if tag == "expr":
            return self.eval_expr(s[1])
        if tag == "return":
            self._return_value = self.eval_expr(s[1])
            return _RETURN
        raise SkaldError(f"unknown statement tag: {tag}")

    def _call(self, fn: Func, args: List[Any]) -> Any:
        if len(args) != len(fn.params):
            raise SkaldError(f"{fn.name}: arity mismatch ({len(args)} vs {len(fn.params)})")
        saved_locals = self.locals
        self.locals = {}
        for p, a in zip(fn.params, args):
            _typecheck(a, p.type_, where=f"{fn.name}({p.name})")
            self.locals[p.name] = a
        self._return_value = None
        last: Any = None
        for st in fn.body:
            r = self.exec_stmt(st)
            if r is _RETURN:
                last = self._return_value
                break
            last = r
        self.locals = saved_locals
        return last

    def check_invariants(self) -> None:
        for inv in self.contract.invariants:
            if not self.eval_expr(inv.expr):
                raise SkaldError(f"invariant '{inv.name}' violated")


_RETURN = object()  # sentinel


def _binop(op: str, a: Any, b: Any) -> Any:
    try:
        if op == "+":   return a + b
        if op == "-":   return a - b
        if op == "*":   return a * b
        if op == "/":   return a // b   # integer division
        if op == "%":   return a % b
        if op == "==":  return a == b
        if op == "!=":  return a != b
        if op == "<":   return a < b
        if op == ">":   return a > b
        if op == "<=":  return a <= b
        if op == ">=":  return a >= b
    except Exception as e:
        raise SkaldError(f"binop {op} failed on {a!r}, {b!r}: {e}")
    raise SkaldError(f"unknown binop: {op}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def interpret_origination(code: str, initial_storage: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Parse `code`, type-check it, validate against `initial_storage`, and
    return the initial storage dict.

    Type-checking is mandatory at origination — a contract that fails to
    type-check cannot be deployed."""
    # Import here to avoid circular import (typecheck imports from this module).
    from .typecheck import type_check as _type_check
    errors = _type_check(code)
    if errors:
        lines = [f"  - {e}" for e in errors]
        raise SkaldError("type errors in contract:\n" + "\n".join(lines))

    contract = parse(code)
    storage: Dict[str, Any] = {}
    initial_storage = initial_storage or {}
    for p in contract.storage_schema:
        if p.name in initial_storage:
            v = initial_storage[p.name]
        else:
            v = _coerce_default(p.type_)
        _typecheck(v, p.type_, where=f"initial_storage.{p.name}")
        storage[p.name] = v
    # Run invariants on the initial state.
    interp = _Interp(contract, storage, ctx={
        "sender": "kn1" + "0" * 33,
        "amount": 0,
        "self": "kn1" + "0" * 33,
        "balance": 0,
    })
    interp.check_invariants()
    return storage


def interpret_call(
    code: str,
    storage: Dict[str, Any],
    entry: str,
    params: Any,
    *,
    sender: str,
    amount: int,
    self_addr: str,
) -> Dict[str, Any]:
    """Execute `entry(params)` against a deep-copy of `storage`, check
    invariants, and return the new storage. Raises SkaldError on any
    Skald-level failure."""
    import copy
    contract = parse(code)
    new_storage = copy.deepcopy(storage)
    if entry not in contract.functions:
        raise SkaldError(f"no such entry: {entry}")
    fn = contract.functions[entry]
    if fn.kind != "entry":
        raise SkaldError(f"{entry} is a {fn.kind}, not an entry")

    # params: either a dict {name: value} or a list, matching fn.params.
    if isinstance(params, dict):
        args = [params[p.name] for p in fn.params]
    elif isinstance(params, list):
        args = params
    elif params is None:
        args = []
    else:
        args = [params]

    interp = _Interp(contract, new_storage, ctx={
        "sender": sender,
        "amount": amount,
        "self": self_addr,
        "balance": 0,  # production: read from state
    })
    interp._call(fn, args)
    interp.check_invariants()
    return new_storage


def interpret_view(
    code: str,
    storage: Dict[str, Any],
    view: str,
    params: Any,
    *,
    self_addr: str = "kn1" + "0" * 33,
) -> Any:
    """Run a `view` function and return its value. Storage is not modified."""
    import copy
    contract = parse(code)
    if view not in contract.functions:
        raise SkaldError(f"no such view: {view}")
    fn = contract.functions[view]
    if fn.kind != "view":
        raise SkaldError(f"{view} is a {fn.kind}, not a view")

    args: List[Any]
    if isinstance(params, dict):
        args = [params[p.name] for p in fn.params]
    elif isinstance(params, list):
        args = params
    elif params is None:
        args = []
    else:
        args = [params]

    interp = _Interp(contract, copy.deepcopy(storage), ctx={
        "sender": "kn1" + "0" * 33,
        "amount": 0,
        "self": self_addr,
        "balance": 0,
    })
    return interp._call(fn, args)
