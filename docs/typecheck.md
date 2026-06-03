# Skald Static Type Checking

This document describes the static type checker for Skald, implemented in [`kern/skald/typecheck.py`](../kern/skald/typecheck.py) and wired into the origination pipeline.

The motivation: a contract that contains type errors must never be deployed. Catching errors at origination time — rather than at first call — turns silent runtime failures into loud, fixable deployment failures.

---

## What the checker enforces

| Rule | Example error |
|------|---------------|
| Storage fields have primitive, declared types | `unknown type 'mystery'` |
| No duplicate storage field names | `duplicate field 'count'` |
| Function parameter types are known primitives | `unknown parameter type 'foobar'` |
| Parameters do not shadow storage fields | `parameter 'count' shadows storage field` |
| Every variable reference resolves | `undefined identifier 'mystery'` |
| Arithmetic on compatible operand types | `+ not defined on (int, address)` |
| Comparisons between same-typed operands | `== not defined on (int, string)` |
| Boolean operators on bool operands | `&& not defined on (int, int)` |
| Assignments match the declared type | `cannot assign string to count of type int` |
| `let` binding initializers match the declared type | `let x: int initialized with string` |
| `require` conditions are bool | `require condition must be bool, got int` |
| `require` messages are string | `require message must be string, got int` |
| `if` conditions are bool | `if condition must be bool, got int` |
| Invariant bodies are bool | `invariant must be bool, got int` |
| Views declare a return type | `view function must declare a return type` |
| View bodies match the declared return type | `return type bool but body yields int` |
| Views do not mutate storage | `view function cannot mutate storage field 'n'` |
| Calls have the right arity | `add expects 2 args, got 1` |
| Call argument types match parameters | `add() arg 0 (n): expected int, got string` |
| Only `view` and `internal` functions can be called from expressions | `cannot call entry 'mutate' from expression` |

## Type rules

### Primitive types

Skald has exactly four primitive types in v0.2:

```
int      — arbitrary-precision signed integer
bool     — true | false
string   — UTF-8 byte sequence
address  — kn1... account identifier
```

A separate `unit` type exists internally for statements that have no value (assignments, requires, etc.), but it is not user-visible.

### Operator typing

| Operator | Argument types          | Result type |
|----------|-------------------------|-------------|
| `+`      | `(int, int)`            | `int`       |
| `+`      | `(string, string)`      | `string`    |
| `-`, `*`, `/`, `%` | `(int, int)`  | `int`       |
| `<`, `>`, `<=`, `>=` | `(int, int)` | `bool`     |
| `==`, `!=` | `(T, T)` for primitive T | `bool`    |
| `&&`, `\|\|` | `(bool, bool)`       | `bool`      |
| unary `-` | `int`                  | `int`       |
| unary `!` | `bool`                 | `bool`      |

Notably absent: implicit type coercions. `1 + "x"` is a type error, not an attempt to convert.

### Function call typing

For a function `f(p_1: T_1, ..., p_n: T_n) -> R`:

- Call `f(a_1, ..., a_n)` requires exactly `n` arguments.
- Argument `a_i` must have type `T_i`.
- The call's result type is `R` (or `unit` if `R` is absent).

Only `view` and `internal` functions can be invoked from inside an expression context. `entry` functions are entry points for external transactions; they are not internally callable as values.

### View and entry distinction

The checker enforces that:

- An `entry` function may mutate storage but cannot be called from inside an expression.
- A `view` function must declare a return type, must not mutate storage, and its body's last expression must match the return type.
- An `internal` function may or may not mutate storage; it can be called from any context within the same contract.

## Integration with origination

The function `interpret_origination` in [`kern/skald/__init__.py`](../kern/skald/__init__.py) calls the type-checker as its first step:

```python
def interpret_origination(code, initial_storage):
    errors = type_check(code)
    if errors:
        raise SkaldError("type errors in contract:\n" + "\n".join(f"  - {e}" for e in errors))
    # ... proceed with origination
```

Concretely: an `originate` transaction carrying source code that fails to type-check will have its origination rejected at the protocol level, and the fee is charged (per the standard failure semantics — see [`tokenomics.md`](tokenomics.md)). The bad contract is not deployed.

## Using the checker independently

The checker is also a library function. Tools that want to validate Skald source before submitting a transaction can import it:

```python
from kern.skald.typecheck import type_check, assert_type_correct

# Return a list of errors (empty = ok)
errors = type_check(my_source)
for e in errors:
    print(e)

# Or raise on any error:
assert_type_correct(my_source)
```

Tooling that wraps this — IDE integrations, linters, deployment CLIs — gets the same guarantees the chain itself enforces.

## What's not in v0.2

The type system is intentionally minimal. The following features are planned for a future Skald version:

- **Compound types** — `map<K, V>`, `list<T>`, `option<T>`, `(a, b)` tuples. Currently storage and parameters must be primitive.
- **Generic functions** — `internal fn first<T>(xs: list<T>) -> option<T>`. Requires compound types first.
- **Refinement types** — `int where x > 0`, allowing the type system to encode some of what currently lives in invariants and requires.
- **Effect tracking** — distinguishing pure expressions from those that read storage from those that mutate storage, enabling more aggressive parallelization in the future KVM.
- **Custom error types** — instead of `with "..."`, declared error variants that can be pattern-matched off-chain.

These are listed in roughly priority order. The first two (compound types + generics) unlock most real-world contracts; the latter three are research-grade improvements with smaller immediate impact.

## Reference

The implementation is around 250 lines of Python. It walks the AST in a single pass, collecting type errors as it goes. There is no formal type inference — types are explicitly declared on storage, parameters, locals, and view returns. This keeps the checker simple, predictable, and easy for developers to reason about (and easy for IDEs to extend).
