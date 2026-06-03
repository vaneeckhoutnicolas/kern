# Kern v1.0 API Stability Specification

This document declares which parts of the Kern protocol and reference implementation are **frozen at v1.0** — i.e., will not change without a protocol amendment (the on-chain governance process described in [`governance.md`](governance.md)).

It exists for two reasons:

1. **For application developers**: to know which APIs are safe to depend on without fear of breaking changes.
2. **For node operators and downstream implementers**: to know which protocol surfaces define interoperability — i.e., what an alternative client implementation (in Rust, Go, OCaml, etc.) must implement identically.

**Status**: this is a v1.0-rc document — the freeze takes effect at v1.0 (after audit cycle 1). v1.0-rc may still iterate on these surfaces if audit findings require it. After v1.0, the only way to change anything in this document is through the protocol-amendment governance cycle.

---

## 1. Stability tiers

We use three tiers:

| Tier | Meaning | Change path |
|---|---|---|
| **Frozen** | Cannot change without breaking the chain | Protocol amendment (≥ 80% supermajority + 25-day cycle) |
| **Stable** | Stable API contract; can be extended additively without breaking | Protocol amendment for changes; semver-minor for additions |
| **Beta** | Best-effort stability; may change in v1.x with reasonable notice | Documented in release notes |

---

## 2. Frozen surfaces

These cannot change in v1.x. Anything depending on these will continue to work for the entire v1.x series.

### 2.1 Transaction format

The on-the-wire encoding of a `Transaction`:

```
Transaction = {
    "kind":           string (OpKind enum value),
    "sender":         string (kn1... base58check address),
    "sender_pubkey":  string (9X... base58check pubkey),
    "nonce":          int (>= 0),
    "fee":            int (mukrn, > 0),
    "gas_limit":      int (>= 0),
    "recipient":      string or null,
    "amount":         int (mukrn, >= 0),
    "code":           string or null (Skald source for ORIGINATE),
    "initial_storage": object or null,
    "entry":          string or null (entry point name for CALL),
    "params":         any,
    "signature":      string (9X... base58check signature)
}
```

**Frozen fields**: All fields above. New fields cannot be added in v1.x.

**Frozen OpKinds** (v1.0 baseline):
- `transfer`
- `originate`
- `call`
- `governance_propose`
- `governance_vote`
- `slash_equivocation`
- `delegate_stake`
- `undelegate_stake`

**Added in v1.1** (non-breaking additions; existing v1.0 clients ignore unknown OpKinds in mempool):
- `attest`
- `revoke_attestation`
- `slash_attestation_equivocation`

Adding a new OpKind in a v1.x minor release is an additive (non-breaking) change permitted under the versioning policy in §6. Adding a new OpKind in a patch release (v1.x.y) is not permitted. Removing an OpKind requires a protocol amendment.

### 2.2 Signed-payload computation

The bytes signed by the sender's private key are the canonical JSON of the transaction *without* the signature field, with keys sorted alphabetically and no whitespace. This is the function `Transaction._signed_payload()` in [`kern/transaction.py`](../kern/transaction.py).

**Frozen**: the canonical encoding rule, the choice of fields included, the byte representation.

### 2.3 Block format

```
Block = {
    "header": BlockHeader,
    "transactions": [Transaction, ...],
    "commits": [Commit, ...]    # endorsement signatures
}

BlockHeader = {
    "level":              int (height, monotonic),
    "round":              int (BFT round, monotonic per level),
    "timestamp":          int (unix seconds),
    "parent_hash":        string (hex, 64 chars),
    "state_root":         string (hex, 64 chars),
    "txs_root":           string (hex, 64 chars),
    "proposer":           string (kn1... address),
    "proposer_pubkey":    string (9X... pubkey),
    "signature":          string
}
```

**Frozen**: the field set, types, and serialization order for hashing.

### 2.4 State-root commitment

The function `state_root_hex(state)` is governance-amendable (the `state_root_function` field in state, with values `"json"` or `"trie"`). For v1.0 mainnet, the default is `"trie"` — the binary Merkle trie implementation in [`kern/trie.py`](../kern/trie.py).

**Frozen**: the dispatch mechanism (state field → function selection). The trie implementation itself is **stable** — its keying, hashing, and proof format are part of the interoperability contract for any future light client.

### 2.5 Address format

Addresses are `kn1` followed by 33 base58check characters, derived as:
```
address = base58check_encode(0x0142 || blake2b(pubkey, digest_size=20))
```

**Frozen**: the prefix, the hash, the encoding.

Public keys are `9X` followed by 50+ base58check characters, derived as `base58check_encode(0x0d0f || pubkey_32_bytes)`.

Signatures are `9X` followed by 100+ base58check characters, derived as `base58check_encode(0x097f || sig_64_bytes)`.

### 2.6 Hash function

All in-protocol hashing uses **blake2b-256** (32-byte output) with **domain-separated keys**:

| Domain | Key | Use |
|---|---|---|
| `kern.tx.hash` | Transaction identity hash | Transaction merkle root, mempool key |
| `kern.block.hash` | Block header hash | Chain links |
| `kern.state` | State commitment (legacy "json" mode) | Pre-trie state root |
| `kern.trie.node` | Trie internal node | State trie hashing |
| `kern.trie.leaf` | Trie leaf node | State trie hashing |
| `kern.addr` | Address derivation | base58check input |

**Frozen**: blake2b-256 as the hash function. Adding more domains is allowed (no break); changing existing ones is a protocol amendment.

### 2.7 Signature scheme

**Ed25519** for all signatures (transaction, block, endorsement, governance vote).

**Frozen**. A change to a different curve would require a hard fork (validators would need to re-key).

### 2.8 KVM (EVM rollup) opcode set

The opcodes implemented by [`kern/evm/vm.py`](../kern/evm/vm.py) and [`kern/evm/frames.py`](../kern/evm/frames.py) are listed in [`docs/multi-frame-evm.md`](multi-frame-evm.md) (~60 opcodes; the same subset used by Solidity emit at the EVM London hardfork level).

**Stable** (can be extended additively): new opcodes can be added in v1.x via protocol amendment. Existing opcodes' semantics are frozen.

### 2.9 Gas pricing

The Yellow-Paper-equivalent gas costs in [`kern/evm/dynamic_gas.py`](../kern/evm/dynamic_gas.py).

**Stable**: constants can be tuned via protocol amendment based on operational data, but the *shape* of the pricing (memory expansion quadratic, SSTORE 3-case, etc.) is frozen.

### 2.10 Precompile addresses

| Address | Function | Notes |
|---|---|---|
| 0x01 | ECRECOVER (Ed25519) | Kern uses Ed25519 instead of secp256k1 |
| 0x02 | SHA256 | Standard |
| 0x03 | RIPEMD160 | Standard |
| 0x04 | IDENTITY | Standard |
| 0x05 | MODEXP | Standard |
| 0x06 | BN_ADD (BN254) | Standard |
| 0x07 | BN_MUL (BN254) | Standard |
| 0x08 | BN_PAIRING (BN254) | Standard, EIP-197 |
| 0x09 | BLAKE2F | Placeholder in v1.0; full F-compression in v1.x |

**Frozen**: addresses and roles. Adding new addresses (0x0a, 0x0b…) is a protocol amendment.

### 2.11 Governance state machine

The phases and thresholds in [`kern/governance.py`](../kern/governance.py):

| Track | Phases | Threshold | Quorum |
|---|---|---|---|
| Protocol | Submitted → Exploration → Cooldown → Adoption → Activated | 80% supermajority | 25% |
| Treasury | Submitted → Voting → Executed | 50% majority | 25% |

**Frozen**: state machine shape. Phase durations are **stable** (amendable).

### 2.12 Staking and delegation

- **Min validator self-stake**: 10 000 KRN (frozen)
- **Validator unbonding period**: 14 days (stable)
- **Default validator commission**: 10% (stable; per-validator override frozen)
- **Slashing penalty**: 30% of stake (stable)
- **Whistleblower reward**: 10% of slashed amount (stable)
- **Delegation mechanism**: Liquid PoS, custody preserved, no lockup (frozen — this is the user-facing contract)

### 2.13 Genesis distribution

The 100M KRN distribution per [`tokenomics.md`](tokenomics.md) §4:
- 70% public sale
- 10% founder (4-year vest, 1-year cliff)
- 15% Foundation
- 3% early contributors
- 2% validator bootstrap

**Frozen at genesis ceremony**. Cannot be changed after the genesis block is signed.

---

## 3. Stable surfaces (extensible)

### 3.1 RPC API

The 12 endpoints exposed by [`kern/rpc.py`](../kern/rpc.py):

```
GET  /chain/head
GET  /chain/block/{level}
GET  /chain/block/by_hash/{hash}
GET  /chain/balance/{address}
GET  /chain/nonce/{address}
GET  /chain/contract/{address}
POST /chain/inject_transaction
GET  /chain/mempool
GET  /chain/validators
GET  /chain/health
GET  /chain/governance
GET  /metrics
```

**Stable**: paths, methods, and response shapes are frozen for v1.x. New endpoints can be added (additive); existing ones cannot break.

Response payload field additions (new keys in existing JSON objects) are allowed in v1.x. Field removals or type changes are not.

### 3.2 Python module entry points

The following are the public API of the `kern` package — what external code is expected to import:

```python
from kern.crypto import KernKeypair
from kern.transaction import (
    OpKind, Transaction,
    make_transfer, make_origination, make_call,
    make_governance_propose, make_governance_vote,
    make_slash_equivocation,
    make_delegate_stake, make_undelegate_stake,
)
from kern.block import Block, BlockHeader
from kern.chain import (
    apply_block, apply_transaction, empty_state,
    initial_state_from_genesis, state_root_hex,
    effective_stake, delegators_of, commission_rate_of,
)
from kern.governance import (
    ProtocolGovernance, TreasuryGovernance,
    ProtocolPhase, TreasuryPhase, Vote,
)
```

**Stable**: function signatures and dataclass field sets are part of the contract.

Internal helpers (`_apply_*`, `_credit`, `_debit`, etc., with leading underscore) are explicitly **not** part of the API — they may change in any patch release.

### 3.3 Skald language

The Skald lexer, parser, AST, and interpreter as of v1.0. The static type checker in [`kern/skald/typecheck.py`](../kern/skald/typecheck.py).

**Stable**: existing contract source code that compiles in v1.0 will continue to compile in all v1.x.

### 3.4 Storage schema

The SQLite schema in [`kern/storage.py`](../kern/storage.py) — blocks, state, mempool tables.

**Stable**: existing columns and types are frozen. Migrations for added tables/columns are allowed in v1.x and will be transparent (auto-applied at node startup).

---

## 4. Beta surfaces

These are best-effort but explicitly not frozen — they may change in v1.x with release notes.

- **Metrics names** (`kern.observability.REGISTRY`) — new metrics may be added, existing names should be stable but could be renamed if industry conventions change.
- **Log line format** — JSON-line structured logs may add new fields.
- **Test utilities** in `tests/` — internal harnesses, may change at any time.
- **Bootstrap scripts** in `scripts/` and `networks/` — operational tooling, may evolve freely.
- **Genesis pool placeholder addresses** — the deterministic addresses generated by `scripts/build_v1_genesis.py` from seeds 0xF0..0xF4 are placeholders only. The real mainnet genesis uses Foundation-multisig addresses generated independently.

---

## 5. What this means for an alternative client implementation

A Rust/Go/OCaml implementation of Kern (call it "kern-rs") must implement, identically:

1. The transaction signed-payload computation (§2.2)
2. The block hash computation (§2.3)
3. The state-root function (§2.4) for whichever mode is active (governance-controlled)
4. The address derivation rule (§2.5)
5. The blake2b-256 domain-separated hashing (§2.6)
6. The Ed25519 signature verification (§2.7)
7. The KVM opcode semantics including gas pricing (§2.8, §2.9)
8. The precompile semantics at each address (§2.10)
9. The governance state machine transitions (§2.11)
10. The staking + delegation logic (§2.12)

Any divergence in any of these causes a chain split. These are the **interoperability surfaces**.

A kern-rs implementation does **not** need to replicate:
- The Python module structure (an alternative client can be architected differently)
- The RPC paths verbatim (an alternative client can expose its own RPC; only the *semantics* of read-only endpoints matter)
- The SQLite schema (an alternative client can use any storage backend)
- The test harness (an alternative client has its own)

---

## 6. Versioning policy

| Version | Compatibility guarantee |
|---|---|
| v1.0 | First stable. All §2 surfaces frozen. |
| v1.0.x | Bug fixes only. No API changes. |
| v1.x.0 | Additive features. New OpKinds via protocol amendment. New RPC endpoints OK. |
| v1.x.x | Bug fixes within minor. |
| v2.0 | Breaking changes via protocol amendment. Reserved for the next major coordinated upgrade. |

Every release of the reference implementation will be tagged in git with `vX.Y.Z`. The version in `pyproject.toml` matches the tag.

---

## 7. Deprecation policy

When a Stable surface needs to be retired (rare):

1. **Announcement** in release notes for v1.x.0: feature marked deprecated.
2. **Continued operation** for at least 12 months in subsequent v1.x.y releases.
3. **Removal** only at v2.0 (next major), via protocol amendment governance.

No Stable surface should ever be removed in a v1.x patch.

---

## 8. Bug fix vs breaking change — how we decide

When an implementation bug is discovered that affects a Frozen or Stable surface, we apply this triage:

| Bug class | Fix path |
|---|---|
| Implementation diverges from this spec | Fix the implementation, ship as v1.x.y |
| Spec ambiguity that allows multiple correct interpretations | Clarify the spec, mark interpretation as preferred, ship as v1.x.y |
| Spec is broken (e.g., consensus-killing edge case) | Protocol amendment to fix the spec; both spec and implementation update at the same governance-activated block |
| Spec is correct but undesirable (e.g., parameter wants tuning) | Protocol amendment, no implementation change needed |

The standard `kern.governance` workflow handles cases 3 and 4 cleanly: the validator network votes, activates, and the change becomes effective at the activation block. No hard fork needed.

---

## Reference

- [`tokenomics.md`](tokenomics.md) — economic spec
- [`governance.md`](governance.md) — governance process spec
- [`staking.md`](staking.md) — staking and delegation spec
- [`multi-frame-evm.md`](multi-frame-evm.md) — KVM spec
- [`architecture.md`](architecture.md) — overall component layout
