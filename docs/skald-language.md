# Skald — the Kern contract language

> *Skald (Old Norse): a court poet, charged with composing sagas that outlive the kings they served.*

Skald is the smart contract language of Kern. It is small, statically reasoned about, and designed to make formal verification approachable rather than aspirational. The reference compiler and interpreter live in [`kern/skald/`](../kern/skald/).

## Design principles

- **Small surface area.** Skald has a few primitive types, no inheritance, no implicit conversions, no dynamic dispatch, no recursion at all (the static call graph must be acyclic, rejected at deploy time). The grammar fits on one page.
- **Declarative invariants.** Every contract declares the conditions that must hold across all state transitions. The runtime enforces them. Invariants are not comments.
- **Resource-typed storage.** Storage is a typed schema; no dynamic field names. Updates are atomic — either the whole entry call succeeds and the new state passes all invariants, or the call reverts and storage is unchanged.
- **Clean separation between read and write.** `entry` mutates; `view` reads; `internal` is a private helper. The protocol can call `view` functions cheaply, off-chain, with no fees.

## Comparison with other contract languages

Skald is not trying to be the most powerful smart-contract language. It is trying to be the most *legible* one — readable not only by the engineer who writes it, but by the auditor who reviews it and the regulator who must be convinced the contract does what it claims. The table below positions Skald against the languages a team would realistically evaluate.

| Dimension | Solidity (Ethereum) | Vyper (Ethereum) | Michelson (Tezos) | Rust + Anchor (Solana) | Move (Aptos / Sui) | Clarity (Stacks) | **Skald (Kern)** |
|---|---|---|---|---|---|---|---|
| **Paradigm** | OOP, imperative | Pythonic, imperative | Stack-based, low-level | Systems, imperative | Resource-oriented | Functional, LISP-like | Declarative + small imperative core |
| **Type system** | Static, weak coercions | Static, stricter | Static, strongly typed | Static, very rich | Static, linear resources | Static, decidable | Static, 4 primitive types, no implicit coercion |
| **Invariants** | Manual `require`/`assert`; external tools (Certora, Scribble) for real invariants | Manual asserts | Via external formal proofs | Manual checks | Move Prover (opt-in, compile-time) | Some via asserts + decidability | **First-class `invariant` blocks, runtime-enforced on every state transition and at origination** |
| **Reentrancy** | Famous footgun; needs guards | Reduced but possible | Possible | Possible (account confusion) | Hard by design (resources) | Impossible by design | Impossible — no dynamic dispatch, no external calls mid-entry, atomic state transition |
| **Inheritance / dynamic dispatch** | Yes (both) | No inheritance | N/A | Traits / generics | Modules, no inheritance | No | None — flat contracts only |
| **Recursion / unbounded loops** | Yes | Bounded | Yes | Yes | Yes | No (decidable) | No — recursion statically rejected; no loop construct |
| **Turing-complete** | Yes | Yes | Yes | Yes | Yes | No (decidable) | No (bounded) |
| **Formal verification** | External (Certora, K, SMTChecker) | External | Native target for proofs (Coq/mi-cho-coq) | External (Kani) | Move Prover (built-in) | Decidability aids analysis | Runtime invariant enforcement (not a proof system — see limits below) |
| **Readability for non-engineers** | Low (semantics hide in modifiers, inheritance) | Medium | Very low (stack machine) | Low (account model, lifetimes) | Medium | Medium-high (explicit, no hidden state) | **High — grammar fits one page; invariants stated in plain Boolean expressions** |
| **Ecosystem maturity** | Largest by far | Mature, niche | Mature | Large, growing | Growing | Small | **None yet — reference implementation only** |

### What Skald borrows, and from whom

Skald is not a from-scratch invention; it is a deliberate synthesis:

- From **Clarity** (Stacks): the conviction that *decidability and the absence of reentrancy are worth giving up Turing-completeness for*. A contract whose behaviour cannot be fully analysed is a contract a regulator cannot trust.
- From **Move** (Aptos/Sui): the idea that the language should make whole *classes* of bugs unrepresentable rather than merely detectable. Move does this with linear resource types; Skald does it with runtime-enforced invariants and a tiny surface.
- From **Vyper** (Ethereum): the discipline of a small, auditable surface area — no inheritance, no inline assembly, no clever metaprogramming.
- From **Michelson** (Tezos): the principle that the on-chain artifact should be amenable to formal reasoning (though Skald keeps the *source* readable rather than optimising for a proof assistant).

### The one thing Skald does that the others do not

Every other language in the table treats invariants as something you *add* — a library, an external prover, a discipline of manual `require` statements. In Skald, the invariant is a **first-class language construct that the runtime enforces unconditionally**:

```
contract Vault {
    storage { total_deposited: int, total_withdrawn: int, balance: int, }

    invariant solvency { balance == total_deposited - total_withdrawn }
    invariant non_negative { balance >= 0 }

    entry withdraw(amount: int) {
        require amount > 0 with "amount must be positive";
        require amount <= balance with "insufficient balance";
        balance = balance - amount;
        total_withdrawn = total_withdrawn + amount;
    }
}
```

After *every* `entry` call, the interpreter evaluates `solvency` and `non_negative` over the post-call storage. If either is false, the entire transaction reverts. The author cannot forget to check; the reviewer cannot miss the check; the regulator reads the two `invariant` lines and knows the contract can never become insolvent or go negative — without reading a single line of the function bodies.

This is the property that matters for institutional legibility: **the guarantees are stated separately from the logic, in a form a non-programmer can verify.** For an STO that must satisfy the Prospectus Regulation, or a fund that must satisfy AIFMD, the invariant block *is* the compliance statement, enforced by the protocol rather than asserted in a prospectus.

### Skald's limitations — stated honestly

In keeping with the project's refusal to oversell:

- **Runtime enforcement is not formal proof.** Move's Prover and Michelson's Coq models can prove properties hold for *all* inputs at compile time. Skald checks invariants at *runtime* for the inputs that actually occur. This catches violations and reverts them, but it does not mathematically prove they can never arise. A formal-methods layer for Skald is a candidate for a future version, not a v1.1-rc feature.
- **Bounded expressiveness is a real cost.** No recursion (statically rejected by the type checker) and no loop construct means some algorithms cannot be expressed in Skald directly. This is deliberate — those belong in rollups or off-chain — but it is a genuine limitation for some use cases.
- **No ecosystem yet.** Solidity has a decade of tooling, libraries, and audited patterns. Skald has a reference implementation and ten example contracts. This gap closes only with time and adoption.
- **Invariant evaluation has a gas cost.** Checking all invariants after every entry call is not free. For contracts with many invariants over large storage, this is a measurable overhead — the price of the guarantee.

The honest summary: Skald trades raw power and ecosystem maturity for legibility and a class of guarantees enforced by the protocol itself. For Kern's institutional thesis, that is the right trade. For a high-frequency DeFi protocol that needs maximum expressiveness, it may not be — and that is what the EVM rollup layer is for.

## Grammar

```
contract       := 'contract' Ident '{' contract_item* '}'
contract_item  := storage_decl | invariant_decl | func_decl

storage_decl   := 'storage' '{' (param ',')* '}'
invariant_decl := 'invariant' Ident '{' expr '}'

func_decl      := func_kind Ident '(' params? ')' return_type? '{' stmt* '}'
func_kind      := 'entry' | 'view' | 'internal'
params         := param (',' param)*
param          := Ident ':' type
return_type    := '->' type
type           := 'int' | 'address' | 'string' | 'bool'

stmt           := assign_stmt | let_stmt | require_stmt | if_stmt
                | return_stmt | expr ';'
assign_stmt    := Ident '=' expr ';'
let_stmt       := 'let' Ident ':' type '=' expr ';'
require_stmt   := 'require' expr ('with' expr)? ';'
if_stmt        := 'if' '(' expr ')' '{' stmt* '}' ('else' '{' stmt* '}')?
return_stmt    := 'return' expr ';'

expr           := <Pratt expression with the operators listed below>
```

## Operators (lowest to highest precedence)

| Precedence | Operators              | Associativity |
|-----------:|------------------------|:-------------:|
|         1  | `\|\|`                  | left          |
|         2  | `&&`                    | left          |
|         3  | `==` `!=`               | left          |
|         4  | `<` `>` `<=` `>=`       | left          |
|         5  | `+` `-`                 | left          |
|         6  | `*` `/` `%`             | left          |
|       (u)  | unary `-` unary `!`     | right         |

Integer division (`/`) is truncating. Boolean operators short-circuit.

## Built-in identifiers

These are available in every entry/view body:

| Name      | Type      | Meaning                                           |
|-----------|-----------|---------------------------------------------------|
| `sender`  | `address` | The account that signed the calling transaction.  |
| `amount`  | `int`     | The value (in mukrn) attached to this call.       |
| `self`    | `address` | The address of the contract being executed.       |
| `balance` | `int`     | The current native-token balance of `self`.       |

## Function classes

- **`entry`** — externally callable, may mutate storage. After execution, all invariants must hold.
- **`view`** — externally callable, must not mutate storage. Last expression (without semicolon) is the return value.
- **`internal`** — callable only from other functions of the same contract. Used to factor logic out of entries and views.

## Storage rules

Storage is declared once per contract. Each storage field has a name and a type. At origination, the caller provides the initial values (in the `params`/`initial_storage` field of the origination transaction). Any field omitted from the initial storage is given a type-specific default:

| Type      | Default          |
|-----------|------------------|
| `int`     | `0`              |
| `bool`    | `false`          |
| `string`  | `""`             |
| `address` | `kn1` + 33 zeros |

Storage assignments are type-checked at runtime. (A future static type checker will enforce this at compile time.)

## Invariants

Each invariant is a Boolean expression over storage fields. After every entry call, the interpreter evaluates all invariants over the post-call storage. If any returns `false`, the entire transaction is reverted (storage unchanged, fee still debited per the spec).

Invariants are also evaluated at origination, against the initial storage. A contract that cannot be originated with valid invariants is rejected before it is deployed.

## Example: Counter

```skald
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
        require n > 0 with "delta must be positive";
        count = count + n;
    }

    entry reset() {
        require sender == owner with "only owner can reset";
        count = 0;
    }

    view current() -> int {
        count
    }
}
```

## Example: Vault

```skald
contract Vault {
    storage {
        owner: address,
        deposited: int,
        withdrawn: int,
    }

    invariant accounting {
        deposited >= withdrawn
    }

    entry deposit() {
        require amount > 0 with "must attach a positive amount";
        deposited = deposited + amount;
    }

    entry withdraw(n: int) {
        require sender == owner with "only owner can withdraw";
        require n > 0 with "amount must be positive";
        require deposited - withdrawn >= n with "insufficient escrow";
        withdrawn = withdrawn + n;
    }

    view available() -> int {
        deposited - withdrawn
    }
}
```

## What's not in v0.1

These features are part of the Skald design but are deliberately left out of the reference implementation, to keep the v0.1 spec stable while the protocol matures:

- **Compound types** — `map<K, V>`, `list<T>`, `option<T>`, `(a, b)` tuples. Currently storage fields must be primitive.
- **Cross-contract calls** — Skald can only mutate `self`'s storage in v0.1. Inter-contract messages will arrive via an explicit `emit` statement that produces internal transactions.
- **Static type checking** — types are checked at runtime; a separate compile step will catch errors before origination.
- **Gas metering** — a fixed gas cost is charged per entry call. Per-operation metering is straightforward but not yet implemented.
- **Cryptographic primitives** — `blake2b`, `ed25519_verify`, etc., as Skald built-ins.

## Implementation notes

The reference implementation in `kern/skald/__init__.py` is a tree-walking interpreter — sufficient for correctness, not for production performance. The eventual KVM is a register-based bytecode VM with explicit gas accounting and the same observable semantics as the interpreter.

The interpreter exposes three entry points to the rest of the node:

```python
interpret_origination(code: str, initial_storage: dict) -> dict
interpret_call(code, storage, entry, params, *, sender, amount, self_addr) -> dict
interpret_view(code, storage, view, params, *, self_addr=...) -> Any
```

Each call parses the source from scratch (no caching yet); a production node will store compiled KVM bytecode in the contract's state and skip re-parsing.
