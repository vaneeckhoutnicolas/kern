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

**Nesting**: a transaction nests arrays and objects 32 deep at most, itself included, so `params` and `initial_storage` hold 31 levels at most. A deeper transaction is malformed.

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

The bytes signed by the sender's private key are the canonical JSON of the transaction *without* the signature field, with keys sorted alphabetically and no whitespace. This is the function `Transaction._signed_payload()` in [`kern/transaction.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/transaction.py).

**Frozen**: the canonical encoding rule, the choice of fields included, the byte representation.

### 2.3 Block format

```
Block = {
    "header": BlockHeader,
    "transactions": [Transaction, ...],
    "commits": [Commit, ...],      # self-commit of a proposer holding the quorum alone
    "endorsements": [Commit, ...], # endorsement certificate gathered on the wire
    "cert_round": int              # round of that certificate (not hashed)
}

BlockHeader = {
    "level":              int (height, monotonic),
    "payload_round":      int (round at which the payload was first proposed; each level starts at 0),
    "timestamp":          int (unix seconds),
    "parent_hash":        string (hex, 64 chars),
    "state_root":         string (hex, 64 chars),
    "txs_root":           string (hex, 64 chars),
    "proposer":           string (kn1... address),
    "proposer_pubkey":    string (9X... pubkey),
    "signature":          string
}
```

**Frozen**: the field set, types, and serialization order for hashing. Changed once before v1.1 final, in Phase E: the header field `round` became `payload_round` and the body gained `cert_round` (see [consensus-wire.md](consensus-wire.md)).

### 2.4 State-root commitment

The function `state_root_hex(state)` is governance-amendable (the `state_root_function` field in state, with values `"json"` or `"trie"`). For v1.0 mainnet, the default is `"trie"` — the binary Merkle trie implementation in [`kern/trie.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/trie.py).

**Frozen**: the dispatch mechanism (state field → function selection). The trie implementation itself is **stable** — its keying, hashing, and proof format are part of the interoperability contract for any future light client.

### 2.5 Address format

Addresses are `kn1` followed by 33 base58check characters, 36 characters in all, derived as:
```
address = base58check_encode(0x05959b || blake2b(pubkey, digest_size=20, key="kern.addr"))
```

`base58check_encode` appends a checksum, the first 4 bytes of the unkeyed blake2b-256 of the prefixed payload, and writes the result in base58.

**Frozen**: the prefix, the hash, the encoding.

Public keys are 53 characters starting with `9XY`, derived as `base58check_encode(0x0d0f25 || pubkey_32_bytes)`.

Signatures are 98 characters starting with `9XZL`, derived as `base58check_encode(0x09f5cd86 || sig_64_bytes)`.

These values are read from [`kern/crypto.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/crypto.py) and checked by `tests/test_crypto_inventory.py`.

### 2.6 Hash function

All in-protocol hashing uses **blake2b** with **domain-separated keys**. Outputs are 256 bits, except addresses (160 bits) and three identifiers (128 bits). The domains behind the block, transaction and state identities:

| Key | Output | Use |
|---|---|---|
| `kern.tx` | 256 bits | Transaction identity hash: transaction merkle root, mempool key |
| `kern.block` | 256 bits | Block header hash: chain links |
| `kern.merkle` | 256 bits | Merkle tree of the transactions of a block |
| `kern.state` | 256 bits | State commitment in "json" mode (pre-trie state root) |
| `kern.trie.branch` | 256 bits | Trie internal node |
| `kern.trie.leaf` | 256 bits | Trie leaf node |
| `kern.trie.key` | 256 bits | Trie key of an address |
| `kern.storage` | 256 bits | Contract storage, inside a trie leaf |
| `kern.code` | 256 bits | Contract code, inside a trie leaf |
| `kern.addr` | 160 bits | Address derivation (base58check input) |

The complete table, with the domains of rollups, governance, attestations and the Mini-EVM, is in the [cryptographic inventory](cryptographic-inventory.md), section 1.2, and belongs to this frozen surface: an alternative client must reproduce all of them. A test compares both tables with the code.

**Frozen**: blake2b as the hash function, and the keys above. Adding more domains is allowed (no break); changing existing ones is a protocol amendment.

### 2.7 Signature scheme

**Ed25519** for all signatures (transaction, block, endorsement, governance vote).

**Frozen**. A change to a different curve would require a hard fork (validators would need to re-key).

Planned before the freeze takes effect: hybrid signatures, Ed25519 together with the post-quantum ML-DSA, from the genesis of the first network beyond the devnet. The plan and its cost are in the [cryptographic inventory](cryptographic-inventory.md); none of it is in the node, and the formats of sections 2.1 to 2.7 are those of the devnet until it is. The formats that will replace them are written first, in section 9, and reviewed before any of them is implemented.

### 2.8 KVM (EVM rollup) opcode set

The opcodes implemented by [`kern/evm/vm.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/vm.py) and [`kern/evm/frames.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/frames.py) are listed in [`docs/multi-frame-evm.md`](multi-frame-evm.md) (~60 opcodes; the same subset used by Solidity emit at the EVM London hardfork level).

**Stable** (can be extended additively): new opcodes can be added in v1.x via protocol amendment. Existing opcodes' semantics are frozen.

### 2.9 Gas pricing

The Yellow-Paper-equivalent gas costs in [`kern/evm/dynamic_gas.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/dynamic_gas.py).

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

The phases and thresholds in [`kern/governance.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/governance.py):

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
- **Delegation mechanism**: bonded delegation with an unbonding period, no LST derivative. Changed in v1.1-rc Phase D from the earlier liquid, unlocked model, which let consensus weight exist without slashable collateral (see [phase-d-changes.md](phase-d-changes.md)).

### 2.13 Genesis distribution

The 100M KRN distribution per [`tokenomics.md`](tokenomics.md) §4:
- 70% public sale
- 10% founder (4-year vest, 1-year cliff)
- 14% Foundation
- 3% early contributors
- 2% validator bootstrap
- 1% bootstrap validator stake (from the Foundation pool)

**Frozen at genesis ceremony**. Cannot be changed after the genesis block is signed.

---

## 3. Stable surfaces (extensible)

### 3.1 RPC API

The 12 endpoints exposed by [`kern/rpc.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/rpc.py):

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

The Skald lexer, parser, AST, and interpreter as of v1.0. The static type checker in [`kern/skald/typecheck.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/skald/typecheck.py).

**Stable**: existing contract source code that compiles in v1.0 will continue to compile in all v1.x.

### 3.4 Storage schema

The SQLite schema in [`kern/storage.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/storage.py) — blocks, state, mempool tables.

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

## 9. Structure version 1

> **Status.** Draft for review, chapter 1 of three: what is signed and what travels. Nothing in this section is implemented. The node writes the formats of sections 2.1 to 2.7, and no network uses the schemas below.

Structure version 1 is not version 1.0 of the software. It is the value of the field `version` of a block header in release 1.2, the release that implements the [signature profile](hybrid-signatures.md), called the note in this section. The note fixes what every object shares: canonical JSON, the hash function `H`, Merkle trees, the text forms of keys and signatures, addresses. It leaves one thing to this document (its section 4.3): the fields of each object, their types and their bounds, written before any format is implemented, each with its vectors, and reviewed as the note was.

Three chapters, reviewed one after the other:

1. **What is signed and what travels** (this chapter): transactions, consensus messages, certificates, block headers, blocks, the frames peers exchange, the body of an injection request.
2. What is kept: the state, the account of the state trie, the key registry, the genesis.
3. The objects hashed outside blocks: rollup batches, forced inclusion requests, states of the Mini-EVM, verifier keys.

### 9.1 What a schema is

A schema says, for one kind of object, which members it has, what each one may hold and which rules tie them together. An object that is not what its schema says is not an object of structure version 1:

- a node refuses it wherever it receives it, in a frame from a peer or in the body of a request;
- a block that holds a transaction that is not of its schema is not a block, and is invalid. Today a transaction that lacks what its kind needs is included in a block, fails and pays its fee.

A schema checks a form. It needs the network identifier, which is in the checksum of every address, and nothing else: no state, no key. Whether a nonce is the next one, whether a balance covers an amount, whether a signature verifies, whether a signer is a validator of the level are rules of the state and of the consensus, stated in the note and in the pages of the consensus. A transaction of the right form can still fail when it is applied.

Everything below is held three ways. [`tests/schema_reference.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/schema_reference.py) is this section as executable text, written with the Python standard library, and a test compares every table of this section with it. [`tests/vectors/kern/schemas.json`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/vectors/kern/schemas.json) holds objects that are accepted and objects that are refused, each with the rule that refuses it. The Go program kept next to that file checks the same vectors with tables of its own (section 9.11).

### 9.2 Reading the tables

A table lists the fields of an object.

- **required**: the member is always there. **optional**: it is there or not, and the text says when.
- A member that is not in the table is refused. No field has a default value, and none is ever `null`: what has no value is absent (note, section 4.3).
- An empty list or an empty map is a value, not an absence: where a range starts at 0, the member is there, and empty.
- A range includes both its ends. A length is counted in characters where the alphabet is a part of ASCII, and in bytes of UTF-8 where any text is allowed.
- A map is an object whose member names are data: addresses, or the names a contract declares.
- A type written `like this` is defined once, in the table below. Under some tables, sentences state the rules that tie fields together.

#### Types

| Type | JSON | Values |
|---|---|---|
| `level` | integer | 0 to 2^63 - 1 |
| `round` | integer | 0 to 2^32 - 1 |
| `nonce` | integer | 0 to 2^63 - 1 |
| `amount` | integer | 0 to 2^63 - 1, in mukrn |
| `gas` | integer | 0 to 2^63 - 1 |
| `time` | integer | 0 to 2^63 - 1, in seconds since 1 January 1970 |
| `address` | string | 75 characters: an address of this network, with its checksum (note, section 5) |
| `hash` | string | 96 characters: the digits and the letters a to f |
| `key` | string | `kpk1.` and 2,646 characters: the one text form of a public key (note, section 5) |
| `signature` | string | `ksig1.` and 4,498 characters: the one text form of a signature (note, section 5) |
| `network` | string | 64 characters: the digits and the letters a to f |
| `chain` | string | 1 to 64 characters: the letters a to z, the digits and the hyphen, the first one a letter |
| `name` | string | 1 to 64 characters: letters without accent, digits and the underscore, the first one not a digit |
| `schema name` | string | 1 to 128 characters: letters without accent, digits, the full stop, the hyphen and the underscore |
| `subject` | string | 1 to 256 characters: the printable characters of ASCII, U+0020 to U+007E |
| `code` | string | any text of 1 to 65,536 bytes in UTF-8 |
| `memo` | string | any text of 1 to 256 bytes in UTF-8 |
| `value` | integer, boolean or string | an integer from -2^63 to 2^63 - 1, `true` or `false`, or any text of 0 to 4,096 bytes in UTF-8 |
| `claim` | object | any object of canonical JSON whose encoding is at most 16,384 bytes (the protocol does not read it) |
| `fields` | object | map of `name` to `value`, 0 to 256 entries |

- An `address` is an address of the network on which the object is read: the same text fails its checksum on any other. The type says nothing of what the address designates, an account or a contract.
- A `key` and a `signature` are checked as texts. A schema verifies no signature, and does not check that a key passes rule 2 of section 2.5 of the note: that is done when a key is recorded and each time a signature is verified.
- A `value` is what a contract holds in a field of its storage or takes as a parameter. Skald has four types, and an address is written as a string. The same type bounds what a contract stores (chapter 2).
- A `claim` is what an attestation states. The protocol compares two claims and hashes them, and never reads inside one.

### 9.3 Limits

Every text, every list and every map has a bound, and so has every object that travels. These numbers are rules of structure version 1: changing one is another structure version.

#### Limits

| Limit | Value | What it bounds |
|---|---|---|
| `json_nesting` | 64 | Arrays and objects, one inside the other, in any JSON text a node receives |
| `transaction_nesting` | 32 | The same in a transaction, itself included |
| `frame_bytes` | 16,777,216 | A frame between peers |
| `transaction_bytes` | 131,072 | The size of a transaction: its canonical encoding, witness included |
| `block_bytes` | 8,388,608 | The sizes of the transactions of a block, added up |
| `certificate_signatures` | 1,024 | The signatures of a certificate |
| `code_bytes` | 65,536 | The source of a contract |
| `value_bytes` | 4,096 | A text held by a contract |
| `contract_fields` | 256 | The entries of `initial_storage`, and of the `params` of a call |
| `claim_bytes` | 16,384 | The canonical encoding of a claim |
| `recipients` | 64 | The recipients of a treasury proposal |

Where they come from:

- **64 and 32** are the two limits the node applies since November 2026 ([consensus-wire.md](consensus-wire.md)). They become rules of the structure version, the same in every client: the JSON library of Go reads 10,000 levels, so a client in Go measures by itself.
- **16,777,216 bytes** is the cap of a frame today.
- **131,072 bytes per transaction.** A transfer weighs 4,791 bytes, 7,458 when it carries the public key of its account, and a change of key 11,899. The largest example contract of the repository is 14,896 bytes of source.
- **8,388,608 bytes per block** is the largest value the parameter `max_block_bytes` can take, not its default, which is chosen from measurements (note, section 7). It is set so that a block and a certificate always fit in one frame (section 9.8).
- **1,024 signatures per certificate**: a network of structure version 1 has at most 1,024 validators (chapter 2). The note measures up to 100 and projects beyond; this bound is a limit of the format, not a claim about performance.
- **65,536 bytes of code, 4,096 bytes per text, 256 fields.** The example contracts declare 32 fields at most, and their longest name has 39 characters.
- **16,384 bytes per claim, 64 recipients, 256 bytes of memo**: room for what exists, with a margin.

### 9.4 Receiving a text

A node receives bytes from outside in two places: a frame from a peer, and the body of a request that injects a transaction. It checks, in this order:

1. the length: at most 16,777,216 bytes for a frame, and 131,072 for the body of a request, which is one transaction;
2. the nesting, measured on the bytes before anything is decoded: at most 64;
3. the encoding: the bytes are the canonical JSON of the value they decode to (note, section 4.3);
4. the schema.

The nesting of a text is read on its bytes: `[` and `{` open a level, `]` and `}` close one, and what stands between two quotation marks is a string, which opens nothing. Inside a string a reverse solidus takes the character that follows it, so an escaped quotation mark does not end the string. The nesting of a value is 0 for a string, a number or a boolean, and 1 for an array or an object that holds none.

Each schema allows a nesting of its own, which follows from its tables:

#### Nesting

| Object | Levels |
|---|---|
| `transfer` | 1 |
| `originate` | 2 |
| `call` | 2 |
| `governance_propose` | 5 |
| `governance_vote` | 2 |
| `slash_equivocation` | 2 |
| `slash_consensus_equivocation` | 3 |
| `delegate_stake` | 2 |
| `undelegate_stake` | 1 |
| `attest` | 32 |
| `revoke_attestation` | 2 |
| `slash_attestation_equivocation` | 2 |
| `rotate_key` | 2 |
| `vote` | 1 |
| `propose message` | 1 |
| `certificate` | 2 |
| `header` | 1 |
| `block` | 34 |
| `final block` | 35 |
| frame `hello` | 1 |
| frame `proposal` | 35 |
| frame `consensus` | 2 |
| frame `block` | 35 |
| frame `transaction` | 33 |
| frame `get_blocks` | 1 |
| frame `blocks` | 37 |

Only a claim can take a transaction beyond 5 levels: it stands at the third level, inside `params`, and may nest 30 deep. The deepest frame, a reply that carries blocks, adds five levels around a transaction and stays far below 64: what a node admits, it can pass on, and every node reads it.

### 9.5 Transactions

A transaction travels as one object: what its sender signs, and its witness, which is the signature, the public key when the transaction is the first of its account, and a second signature when it changes the key.

#### Fields of every transaction

| Field | Type | Part | Presence | Meaning |
|---|---|---|---|---|
| `kind` | one of the thirteen kinds below | signed | required | What the transaction does |
| `sender` | `address` | signed | required | The account that signs and pays the fee |
| `nonce` | `nonce` | signed | required | The number of transactions of the sender applied before this one: 0 for the first |
| `fee` | `amount` | signed | required | What the sender pays to the proposer of the block |
| `gas_limit` | `gas` | signed | required | The most gas the transaction may use |
| `chain_id` | `chain` | signed | required | The name of the chain, as the genesis gives it |
| `signature` | `signature` | witness | required | The signature of the sender, in the context `kern.tx` |
| `public_key` | `key` | witness | optional | The public key of the sender: carried by the first transaction of an account, and by no other (note, sections 4.5 and 6.1) |
| `second_signature` | `signature` | witness | required in `rotate_key`, absent elsewhere | The signature of the new key, in the context `kern.rotate` (note, section 6.4) |

- Its canonical encoding, which is its size, is at most 131,072 bytes.

**What is signed.** The transaction without its three witness fields, as canonical JSON. The sender signs those bytes in the context `kern.tx`; in a `rotate_key`, the new key signs the same bytes in the context `kern.rotate`. The identifier of the transaction is `H("kern.tx", ...)` of the same bytes (note, section 4.1): it does not depend on the witness.

**Its size.** The number of bytes of the canonical encoding of the whole object, witness included. It is what the fee floor and the size of a block count (note, section 7).

**Its witness leaf.** `H("kern.witness", identifier || flags || [public key] || signature || [second signature])`, with the bytes that the text forms stand for (note, section 6.3). Bit 0 of the flags is set when `public_key` is present, bit 1 when `second_signature` is.

A kind has the fields of its row, and no other: a cell that is empty is a field the kind does not have.

#### Fields by kind

| Kind | `recipient` | `amount` | `code` | `initial_storage` | `entry` | `params` |
|---|---|---|---|---|---|---|
| `transfer` | `address` | `amount` |  |  |  |  |
| `originate` |  |  | `code` | `fields` |  |  |
| `call` | `address` | `amount` |  |  | `name` | `fields` |
| `governance_propose` |  |  |  |  |  | table below |
| `governance_vote` |  |  |  |  |  | table below |
| `slash_equivocation` |  |  |  |  |  | table below |
| `slash_consensus_equivocation` |  |  |  |  |  | table below |
| `delegate_stake` |  | integer, 1 to 2^63 - 1, in mukrn |  |  |  | table below |
| `undelegate_stake` |  |  |  |  |  |  |
| `attest` |  | `amount` |  |  |  | table below |
| `revoke_attestation` |  |  |  |  |  | table below |
| `slash_attestation_equivocation` |  |  |  |  |  | table below |
| `rotate_key` |  |  |  |  |  | table below |

- **`transfer`** moves `amount` to `recipient`.
- **`originate`** creates a contract from its `code`, with the fields of `initial_storage`. A field that is not named takes the default of its type; the map can be empty.
- **`call`** calls the entry point `entry` of the contract at `recipient`, with `params` by name, and moves `amount` to the contract, which can be 0. Parameters are given by name only: the list and the single value that a call may carry today are not forms of structure version 1.
- **`delegate_stake`** bonds `amount` to a validator, and **`undelegate_stake`** ends the delegation of the sender: it has no field of its own.
- **`attest`** records an attestation, with `amount` as its bond, which can be 0.

Which names a contract declares, and what an entry point takes, is for the contract to say: a transaction of the right form whose names do not fit fails when it is applied.

#### `params` of `governance_propose`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `track` | `"protocol"` or `"treasury"` | required | Which of the two tracks the proposal is submitted to |
| `payload` | `protocol payload` or `treasury payload`, as `track` says | required | What the proposal would do |
| `salt` | integer, 0 to 2^63 - 1 | required | Lets one submitter make the same proposal twice, under two identifiers |

The identifier of the proposal is `H("kern.gov.id", ...)` of the canonical JSON of `{"submitter": sender, "payload": payload, "salt": salt}` (note, section 4.1).

#### Protocol payload

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `params` | `parameters` | optional | New values for parameters of the protocol |
| `swap` | `"state_root_function"` | optional | The function to replace |
| `to` | `"json"` or `"trie"` | optional | The function that replaces it |

- `params` or `swap` is present, or both.
- `to` is present exactly when `swap` is.

#### Parameters

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `i_min_ppm` | integer, 0 to 1,000,000 | optional | Issuance at the target staking ratio, in parts per million a year |
| `i_max_ppm` | integer, 0 to 1,000,000 | optional | Issuance when nothing is staked |
| `target_staking_ratio_ppm` | integer, 0 to 1,000,000 | optional | The staking ratio the issuance aims at |
| `target_block_time_ms` | integer, 1 to 3,600,000 | optional | The time between two blocks that the issuance per block assumes, in milliseconds |
| `treasury_share_ppm` | integer, 0 to 1,000,000 | optional | The share of the issuance that goes to the treasury |
| `proposer_bonus_ppm` | integer, 0 to 1,000,000 | optional | The share of the rest that goes to the proposer |
| `fee_floor_enabled` | `true` or `false` | optional | Whether the fee floor applies |
| `fee_floor_base` | integer, 0 to 1,000,000,000,000 | optional | The fixed part of the fee floor, in mukrn |
| `fee_floor_per_byte` | integer, 0 to 1,000,000,000 | optional | Its part per byte of the size of the transaction, in mukrn |
| `max_block_bytes` | integer, 131,072 to 8,388,608 | optional | The most bytes the transactions of a block may add up to |

- At least one parameter is present.

Every parameter is an integer or a boolean. The names that take a fraction today (`i_max` and six others) are not parameters of structure version 1. The smallest block holds the largest transaction, and the largest one fits in a frame with its certificate.

#### Treasury payload

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `recipients` | list of 1 to 64 `recipient` | required | Who would be paid, and how much |
| `memo` | `memo` | optional | A line for the people who vote |

- The amounts add up to 2^63 - 1 at most.

#### Recipient

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `address` | `address` | required | The account or the contract that is paid |
| `amount` | integer, 1 to 2^63 - 1, in mukrn | required | What it receives |

#### `params` of `governance_vote`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `track` | `"protocol"` or `"treasury"` | required | The track of the proposal |
| `proposal_id` | `hash` | required | The identifier of the proposal |
| `vote` | `"yes"`, `"no"` or `"abstain"` | required | The vote of the sender |

#### `params` of `slash_equivocation`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `proposal_id` | `hash` | required | The protocol proposal on which a validator voted twice |
| `equivocator` | `address` | required | That validator |

#### `params` of `slash_consensus_equivocation`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `msg_a` | `vote` | required | A vote of a validator, with its signature |
| `msg_b` | `vote` | required | Another vote of the same validator, of the same kind, for the same level and round, and for another block |

The two votes are objects of the schema `vote` (section 9.6). That they are the two halves of one offence is checked when the transaction is applied, with the key the registry kept for their level (note, section 6.1).

#### `params` of `delegate_stake`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `validator` | `address` | required | The validator the sender delegates to |

#### `params` of `attest`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `schema_id` | `schema name` | required | The kind of statement, as a dotted name |
| `subject` | `subject` | required | What the statement is about |
| `claim` | `claim` | required | The statement |

The identifier of the attestation is `H("kern.attestation.id", ...)` of the canonical JSON of `{"issuer": sender, "schema_id": schema_id, "subject": subject, "claim": claim, "attest_nonce": nonce}` (note, section 4.1). A claim holds no number with a fraction and no integer beyond 64 bits, like any canonical JSON: a larger number, such as a coordinate of a proof, is a string of decimal digits.

#### `params` of `revoke_attestation`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `attestation_id` | `hash` | required | The attestation the sender revokes |

#### `params` of `slash_attestation_equivocation`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `attestation_id_1` | `hash` | required | An attestation of an issuer |
| `attestation_id_2` | `hash` | required | Another one of the same issuer, about the same subject, that states something else |

#### `params` of `rotate_key`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `new_public_key` | `key` | required | The key of the sender from the next level on (note, section 6.4) |

**An example.** The transfer of the vectors of the note, as it travels after the first transaction of its account. What is signed is the object without `signature`; its identifier is the one of the note, `90d56b99...2b6d1d64`, and its size is 4,791 bytes.

```json
{
  "kind": "transfer",
  "sender": "kn1VaZfZoiE4jv99DMc2gQy8ncnFz7gjgtxWTpb5c3u5f4yxcHqpcUEV496Xfag7q9MrPfunnqy",
  "nonce": 1,
  "fee": 1000,
  "gas_limit": 10000,
  "recipient": "kn1VaoeDd1RiNvRjxxNwt6aVbot67RG22Gyc5YtwmJyyZ8SkNPtZppv7HQGEhPyHheHMyKqVrqs",
  "amount": 25,
  "chain_id": "kern-devnet",
  "signature": "ksig1.<4,498 characters>"
}
```

### 9.6 Consensus messages and certificates

A validator makes three statements about a block, each signed in a context of its own: it proposes it, it pre-endorses it, it endorses it. A message carries the address of the validator and never its key, which is read from the registry (note, section 6.1).

#### Vote

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `kind` | `"preendorse"` or `"endorse"` | required | Which of the two votes |
| `level` | `level` | required | The level of the block |
| `round` | `round` | required | The round of the vote |
| `block_hash` | `hash` | required | The hash of the block |
| `validator` | `address` | required | The validator that votes |
| `signature` | `signature` | required | Its signature, in the context `kern.preendorse` or `kern.endorse` |

#### Propose message

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `kind` | `"propose"` | required | A proposal |
| `level` | `level` | required | The level of the block |
| `round` | `round` | required | The round at which the block is proposed |
| `block_hash` | `hash` | required | The hash of the block |
| `validator` | `address` | required | The proposer of that round |
| `valid_round` | `round` | optional | The round whose pre-endorsements justify proposing this block again. Absent when the block is proposed for the first time |
| `signature` | `signature` | required | Its signature, in the context `kern.propose` |

- `valid_round` is lower than `round`.

**What is signed.** The message without `signature`, as canonical JSON, in the context of its kind. Today a new payload is said by a `valid_round` of -1; in structure version 1 the field is absent.

#### Certificate

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `kind` | `"preendorse"` or `"endorse"` | required | The kind of the votes it gathers |
| `level` | `level` | required | Their level |
| `round` | `round` | required | Their round |
| `block_hash` | `hash` | required | The block they are for |
| `signatures` | map of `address` to `signature`, 1 to 1,024 entries | required | For each validator, the signature of its vote |

A certificate is the votes of one kind for one block at one round, without what they have in common. The signature under an address is the one of the `vote` made of the four fields above and of that address as `validator`. An address stands once, since it is the name of a member.

What a schema does not check, and the consensus does: every address is a validator of the level, every signature verifies with the key of its address at that level, and the validators that signed hold more than two thirds of the stake. Which of the valid signatures a certificate holds is not a rule: two nodes can hold two certificates for one block, and nothing is derived from the difference. A node accepts any valid certificate. What it keeps and serves is a certificate from which no signature can be taken away without losing the quorum.

### 9.7 Headers and blocks

#### Header

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `version` | 1 | required | The structure version |
| `level` | `level` | required | The height of the block |
| `payload_round` | `round` | required | The round at which this block was first proposed |
| `timestamp` | `time` | required | When its proposer built it |
| `parent_hash` | `hash` | required | The hash of the block of the level before |
| `state_root` | `hash` | required | The root of the state after the block |
| `txs_root` | `hash` | required | The root of the identifiers of its transactions |
| `witness_root` | `hash` | required | The root of their witness leaves |
| `proposer` | `address` | required | The proposer of the round `payload_round` |
| `signature` | `signature` | required | Its signature, in the context `kern.header` |

**What is signed.** The header without `signature`, which is the nine fields of section 6.3 of the note, as canonical JSON. The hash of the block is `H("kern.block", ...)` of the same bytes.

#### Block

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `header` | `header` | required | The header |
| `transactions` | list of any number of `transaction` | required | The transactions, in the order in which they are applied |

- The sizes of its transactions add up to 8,388,608 bytes at most.
- `txs_root` is the root of the identifiers of its transactions, in the order of the list.
- `witness_root` is the root of their witness leaves, in the same order.

A block is what its header commits to, and nothing else. Both roots are trees of section 4.4 of the note, and are checked by hashing alone, before any signature is verified: a copy of a block in which a signature was replaced, a public key removed or a transaction repeated is not that block. The state lowers the bound on the sizes with its parameter `max_block_bytes`.

The block of level 0 is described with the genesis, in chapter 2.

#### Final block

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `block` | `block` | required | A block |
| `certificate` | `certificate` | required | The endorsements that make it final |

- The certificate is of the kind `endorse`, for the level and the hash of the block, at a round that is not lower than `payload_round`.

The certificate is not in the block and not under its hash: it is gathered after the header is signed, and a block has the same hash whichever certificate travels with it. The fields `commits`, `endorsements` and `cert_round` that a block has today are gone. The round of the certificate is its own field `round`, and the endorsement of a proposer that holds the quorum alone is a signature of the certificate like any other.

### 9.8 Frames

A frame is four bytes that give a length, most significant byte first, then that many bytes: the canonical JSON of one of the seven objects below. Every frame has a member `kind`, which is the name of its table.

#### Frame `hello`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `network_id` | `network` | required | The identifier of the network of the node (note, section 3.1) |
| `level` | `level` | required | The level of its head |

The first frame a node sends on a connection. Two nodes of two networks part at this frame.

#### Frame `proposal`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `block` | `block` | required | The block that is proposed |
| `proposal` | `propose message` | required | The proposal, signed by the proposer of its round |
| `proof` | `certificate` | optional | The pre-endorsements that justify proposing the block again |

- `proposal` names the level and the hash of the block.
- `proof` is present exactly when `proposal` has a `valid_round`.
- Without `valid_round`, `payload_round` is the round of `proposal`.
- With it, `payload_round` is not higher than `valid_round`, and `proof` is of the kind `preendorse`, for the level and the hash of the block, at the round `valid_round`.

#### Frame `consensus`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `msg` | `vote` | required | A vote |

A proposal never travels in this frame: it travels with its block.

#### Frame `block`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `block` | `block` | required | A block |
| `certificate` | `certificate` | required | The endorsements that make it final |

- The certificate is of the kind `endorse`, for the level and the hash of the block, at a round that is not lower than `payload_round`.

#### Frame `transaction`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `tx` | `transaction` | required | A transaction |

#### Frame `get_blocks`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `from` | integer, 1 to 2^63 - 1 | required | The first level asked for |
| `to` | integer, 1 to 2^63 - 1 | required | The last one |

- `to` is not lower than `from`.

#### Frame `blocks`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `blocks` | list of any number of `final block` | required | Final blocks, from the first level asked for |

- The levels of the blocks follow one another, each one more than the one before.

The answer to a `get_blocks`. It holds as many blocks as fit in one frame, from the level `from` upward, and none when the node has none of them: the node that asked asks again from the level after the last one it received. The list has no bound of its own. Its bound is the size of the frame.

**A block always fits.** The heaviest frame that carries one block is a `proposal` whose block holds 8,388,608 bytes of transactions and whose `proof` holds 1,024 signatures: 13,093,853 bytes in the vectors, under the 16,777,216 of a frame. A `block` frame with the same block and a certificate of the same size is lighter by one message. Only a `blocks` frame can reach the bound, and the vectors hold one of 16,777,216 bytes, to the byte.

**The body of an injection request.** `POST /chain/inject_transaction` takes one `transaction`, in its canonical encoding: the body goes through the four checks of section 9.4, like a frame.

### 9.9 What changes from the formats of the devnet

| Subject | Sections 2.1 to 2.7 | Structure version 1 | Why |
|---|---|---|---|
| A field that has no value | `null`, or a default | Absent | Note, 4.3 |
| Public keys | In every transaction, header and vote | `public_key` in the first transaction of an account, and nowhere else | Note, 6.1 |
| Signatures, hashes, addresses | 98, 64 or 32, and 36 characters | 4,504, 96 and 75 characters | Note, 4.2 and 5 |
| `chain_id` | Optional | Required | Note, 3.1 |
| A transaction that lacks what its kind needs, or has more | Included in a block, fails, pays its fee | Not a transaction: refused when received, and the block that holds it is invalid | Note, 4.3: an object has exactly the fields of its schema |
| Parameters of a call | An object by name, a list by position, one value, or `null` | A map of names to values | One form for one call |
| Initial storage | Any JSON, or `null` | A map of names to values, which can be empty | The same |
| What a contract takes and holds | Any JSON | An integer of 64 bits, a boolean or a text | The four types of Skald |
| The size of a transaction | What is signed | The whole transaction, witness included | Note, 7 |
| Parameters of a protocol proposal | Seventeen names, seven of them with a fraction | Ten names, each an integer or a boolean with its range | Note, 4.3: no number with a fraction |
| `salt` of a proposal | Optional, 0 when absent | Required | No default |
| `undelegate_stake` | Empty `params` | No `params` | No placeholder |
| Amount of a delegation | Checked when applied | 1 at least, in the schema | A delegation of nothing is not one |
| `subject` and `schema_id` of an attestation | Any text | A bounded text over a part of ASCII | Names are compared as bytes |
| Header | Eight signed fields | Nine: `version` and `witness_root` come, the key of the proposer goes | Note, 6.3 |
| Body of a block | `commits`, `endorsements`, `cert_round` | Header and transactions; the certificate is an object apart | The certificate is not under the hash of the block |
| Certificate | A list of texts, each an address, a colon and a signature | A map of addresses to signatures | An address stands once by construction |
| A proposal of a new payload | `valid_round` is -1 | `valid_round` is absent | Note, 4.3 |
| Frames | Any spelling of JSON | Canonical JSON only | Note, 4.3 |
| `hello` | The level | The network identifier and the level | Note, 3.1 |
| `blocks` | 512 blocks at most | As many as fit in a frame | The size of a block depends on its certificate |
| `get_blocks` | From level 0 | From level 1 | The genesis has no certificate |
| Nesting | 64 for a frame and 32 for a transaction, limits of the node | The same numbers, rules of the structure version | One verdict in every client |

### 9.10 Another signature scheme, later

This part states no rule.

Structure version 1 has one signature scheme, scheme 1, and refuses everything else: a key written `kpk2.` or a signature written `ksig2.` is refused wherever a key or a signature is expected, and the vectors hold both cases. The note says how another scheme would come: as a new number, introduced by a protocol amendment (its section 2.4).

What structure version 1 already holds for that day:

- the address of an account survives a change of key, since `rotate_key` replaces the key and keeps the address (note, section 6.4);
- the registry keeps every key an address has had, with the level from which it was current, so what was signed before a change can still be verified (note, sections 6.1 and 6.4);
- a key and a signature state their scheme in their text form, and the scheme number enters the derivation of keys and every address (note, sections 3.2 and 5);
- a block states its structure version, and another structure is another number (note, section 6.3).

What it does not hold, and cannot without new rules: `rotate_key` takes a key of scheme 1 only, the witness leaf has fixed lengths, and nothing says from which level a key of another scheme could be recorded, what a key of scheme 1 could still sign afterwards, or how the validators would pass from one scheme to the other. Those rules belong to the amendment that would introduce the scheme, in a new version of the profile, reviewed as this one was.

### 9.11 Vectors

`tests/vectors/kern/schemas.json` is built by [`tests/schema_vectors.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/schema_vectors.py). For this chapter it holds:

- **accepted objects**: every kind of transaction, vote, proposal, certificate, header, block and frame, for every limit an object that reaches it, and for every range an object at each of its ends. Each one is pinned by the length and the start of the SHA3-384 of its canonical encoding, and comes with what the profile computes from it: the identifier and the witness leaf of a transaction, the hash of a header, the text a validator signs and its context, the identifier of a proposal and of an attestation. Four of them are objects of the vectors of the note, and give back its digests;
- **refused objects**, each with the rule that refuses it: a value out of its range, a text outside its alphabet, a field of another kind, a field under its name of today, a bound passed by one, a root that does not match. Each is one to three changes away from an accepted object, so that it is refused for the reason it gives; one stands alone, the two largest blocks in one frame;
- **mutations**: for most accepted objects, every object one change away must be refused, a member removed, a member added, a value of another JSON type, except where the schema says the member is optional;
- **texts as a node receives them**: the canonical encoding of a frame, 64 and 65 arrays one inside the other, the same with objects, strings that hold brackets and escaped quotation marks, a frame and a request body at their longest and one byte beyond, and the spellings that are not canonical.

Keys and signatures are written by rule in the file and are not real ones: no signature in these vectors verifies, since a schema verifies none. The signatures of the profile have vectors of their own (note, section 17).

`tests/test_schema_vectors.py` runs the vectors through `tests/schema_reference.py` and compares the tables of this section with it. `tests/vectors/kern/profile_check.go` runs them with tables written independently, in another order of checks, and the continuous integration runs it on every pull request:

```
go run profile_check.go -schemas schemas.json
```

Neither is the node.

---

## Reference

- [`tokenomics.md`](tokenomics.md) — economic spec
- [`governance.md`](governance.md) — governance process spec
- [`staking.md`](staking.md) — staking and delegation spec
- [`multi-frame-evm.md`](multi-frame-evm.md) — KVM spec
- [`architecture.md`](architecture.md) — overall component layout
