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
- `slash_consensus_equivocation`

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

The function `state_root_hex(state)` is governance-amendable (the `state_root_function` field in state, with values `"json"` or `"trie"`). The node starts with `"json"`; `"trie"`, the binary Merkle trie of [`kern/trie.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/trie.py), is selected by a protocol amendment. Structure version 1 states both again (section 9.13).

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

> **Status.** Draft for review, chapters 1 and 2 of three: what is signed and what travels, and what is kept. Nothing in this section is implemented. The node writes the formats of sections 2.1 to 2.7, and no network uses the schemas below.

Structure version 1 is not version 1.0 of the software. It is the value of the field `version` of a block header in release 1.2, the release that implements the [signature profile](hybrid-signatures.md), called the note in this section. The note fixes what every object shares: canonical JSON, the hash function `H`, Merkle trees, the text forms of keys and signatures, addresses. It leaves one thing to this document (its section 4.3): the fields of each object, their types and their bounds, written before any format is implemented, each with its vectors, and reviewed as the note was.

Three chapters, reviewed one after the other:

1. **What is signed and what travels** (sections 9.2 to 9.11): transactions, consensus messages, certificates, block headers, blocks, the frames peers exchange, the body of an injection request.
2. **What is kept** (sections 9.12 to 9.16): the state, the account of the state trie, the key registry, the genesis and the block of level 0, and what a block does to the state.
3. The objects hashed outside blocks: rollup batches, forced inclusion requests, states of the Mini-EVM, verifier keys.

Structure version 1 migrates nothing. No network beyond the devnet exists, and a network of structure version 1 starts from a genesis of its own (section 9.15): how a state written in the formats of today would be carried over is not defined.

### 9.1 What a schema is

A schema says, for one kind of object, which members it has, what each one may hold and which rules tie them together. An object that is not what its schema says is not an object of structure version 1:

- a node refuses it wherever it receives it, in a frame from a peer or in the body of a request;
- a block that holds a transaction that is not of its schema is not a block, and is invalid. Today a transaction that lacks what its kind needs is included in a block, fails and pays its fee.

A schema checks a form. It needs the network identifier, which is in the checksum of every address, and nothing else: no state, no key. Whether a nonce is the next one, whether a balance covers an amount, whether a signature verifies, whether a signer is a validator of the level are rules of the state and of the consensus, stated in the note and in the pages of the consensus. A transaction of the right form can still fail when it is applied.

Three cases are kept apart, since a block does not treat them alike:

- an object that is not of its schema is not a transaction. A node refuses it, and a block that holds it is invalid, as said above;
- a transaction of the right form whose signature does not verify makes the block that holds it invalid too (note, section 6.3). It is not a transaction that failed: it is not applied, and it pays no fee;
- a transaction of the right form whose signature verifies can still fail when its operation is applied. It is a transaction of its block like the others: it stays there and pays its fee, as it does today.

What a block does with a transaction whose nonce is not the next one, or whose sender cannot pay the fee, is a rule of the state: chapter 2 states it (section 9.16).

Everything below is held three ways. [`tests/schema_reference.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/schema_reference.py) is this section as executable text, written with the Python standard library, and a test compares every table of this section with it. [`tests/vectors/kern/schemas.json`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/vectors/kern/schemas.json) holds objects that are accepted and objects that are refused, each with the rule that refuses it. The Go program kept next to that file checks the same vectors with tables of its own (section 9.11).

### 9.2 Reading the tables

A table lists the fields of an object.

- **required**: the member is always there. **optional**: it is there or not, and the text says when.
- A member that is not in the table is refused. No field has a default value, and none is ever `null`: what has no value is absent (note, section 4.3).
- An empty list or an empty map is a value, not an absence: where a range starts at 0, the member is there, and empty.
- A range includes both its ends. A length is counted in characters where the alphabet is a part of ASCII, and in bytes of UTF-8 where any text is allowed.
- A map is an object whose member names are data: addresses, identifiers, or the names a contract declares.
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
| `positive amount` | integer | 1 to 2^63 - 1, in mukrn |
| `period` | integer | 1 to 2^32 - 1, in blocks |

- An `address` is an address of the network on which the object is read: the same text fails its checksum on any other. The type says nothing of what the address designates, an account or a contract.
- A `key` and a `signature` are checked as texts. A schema verifies no signature, and does not check that a key passes rule 2 of section 2.5 of the note: that is done when a key is recorded and each time a signature is verified.
- A `value` is what a contract holds in a field of its storage or takes as a parameter. Skald has four types, and an address is written as a string. The same type bounds what a contract stores (section 9.12).
- A `claim` is what an attestation states. The protocol compares two claims and hashes them, and never reads inside one.

### 9.3 Limits

Every text has a bound, and so has every object that travels, with every list and every map it holds. What is kept is bounded where this section says so, and grows with the network elsewhere (section 9.12). These numbers are rules of structure version 1: changing one is another structure version.

#### Limits

| Limit | Value | What it bounds |
|---|---|---|
| `json_nesting` | 64 | Arrays and objects, one inside the other, in any JSON text a node receives |
| `transaction_nesting` | 32 | The same in a transaction, itself included |
| `frame_bytes` | 16,777,216 | The canonical JSON of a frame between peers, without the four bytes that announce its length |
| `transaction_bytes` | 131,072 | The size of a transaction: its canonical encoding, witness included |
| `block_bytes` | 8,388,608 | The sizes of the transactions of a block, added up |
| `certificate_signatures` | 1,024 | The signatures of a certificate |
| `code_bytes` | 65,536 | The source of a contract |
| `value_bytes` | 4,096 | A text held by a contract |
| `contract_fields` | 256 | The entries of `initial_storage`, and of the `params` of a call |
| `claim_bytes` | 16,384 | The canonical encoding of a claim |
| `recipients` | 64 | The recipients of a treasury proposal |
| `validators` | 1,024 | The validators of a network |
| `guardians` | 8 | The guardians of its treasury |

Where they come from:

- **64 and 32** are the two limits the node applies since November 2026 ([consensus-wire.md](consensus-wire.md)). They become rules of the structure version, the same in every client: the JSON library of Go reads 10,000 levels, so a client in Go measures by itself.
- **16,777,216 bytes** is the cap of a frame today, counted the same way: on the bytes that follow the four bytes of length, which are not part of it (section 9.8).
- **131,072 bytes per transaction.** A transfer weighs 4,791 bytes, 7,458 when it carries the public key of its account, and a change of key 11,899. The largest example contract of the repository is 14,896 bytes of source.
- **8,388,608 bytes per block** is the largest value the parameter `max_block_bytes` can take, not its default, which is chosen from measurements (note, section 7). It is set so that a block and a certificate always fit in one frame (section 9.8).
- **1,024 signatures per certificate** is a bound of the format of a certificate. That a network of structure version 1 has at most 1,024 validators is another rule, of the validator set, which chapter 2 states (section 9.12): the two go together, and neither follows from the other. The note measures up to 100 validators and projects beyond; these bounds are limits of the format, not a claim about performance.
- **65,536 bytes of code, 4,096 bytes per text, 256 fields.** The example contracts declare 32 fields at most, and their longest name has 39 characters.
- **16,384 bytes per claim, 64 recipients, 256 bytes of memo**: room for what exists, with a margin.

### 9.4 Receiving a text

A node receives bytes from outside in two places: a frame from a peer, and the body of a request that injects a transaction. It checks, in this order:

1. the length: at most 16,777,216 bytes for the canonical JSON of a frame, the four bytes that announce it not counted, and 131,072 for the body of a request, which is one transaction;
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
| `release_payment` | 2 |
| `cancel_payment` | 2 |
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
| `state` | 33 |
| `genesis` | 34 |

Only a claim can take a transaction beyond 5 levels: it stands at the third level, inside `params`, and may nest 30 deep. The deepest frame, a reply that carries blocks, adds five levels around a transaction and stays far below 64: what a node admits, it can pass on, and every node reads it. A state can nest 33 deep and a genesis 34, because an attestation keeps its claim. A genesis holds no attestation, and nests 5 deep.

### 9.5 Transactions

A transaction travels as one object: what its sender signs, and its witness, which is the signature, the public key when the transaction is the first of its account, and a second signature when it changes the key.

#### Fields of every transaction

| Field | Type | Part | Presence | Meaning |
|---|---|---|---|---|
| `kind` | one of the fifteen kinds below | signed | required | What the transaction does |
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
| `release_payment` |  |  |  |  |  | table below |
| `cancel_payment` |  |  |  |  |  | table below |
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
- **`release_payment`** and **`cancel_payment`** are the transactions of a guardian of the treasury: the first releases a payment that waits, the second cancels it (section 9.16).

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

The schema checks each value against its own range. What ties two parameters together, such as an `i_min_ppm` that is not above `i_max_ppm`, is a rule of the state: chapter 2 says which combinations a network refuses, and when (section 9.12).

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

#### `params` of `release_payment`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `proposal_id` | `hash` | required | The identifier of the treasury proposal whose payment is released |

#### `params` of `cancel_payment`

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `proposal_id` | `hash` | required | The identifier of the treasury proposal whose payment is cancelled |

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

The four bytes are a number without a sign, and they give exactly the number of bytes that follow them. The bound of a frame, `frame_bytes`, is on what follows: the four bytes are not counted. The largest frame is 16,777,216 bytes of canonical JSON after the four bytes `01 00 00 00`, and travels as 16,777,220 bytes. A node that reads four bytes that announce more reads no further.

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

The answer to a `get_blocks`. The list has no bound of its own. Its bound is the size of the frame.

#### Answering `get_blocks`

A node answers a `get_blocks` with one `blocks` frame. Four rules tie the answer to the request, which neither schema can state alone:

- When the answer holds blocks, the first one is the block of level `from`.
- It holds no block above `to`.
- It holds every block the node has from `from` upward, in order, as far as the first of three things: a level the node does not hold, the level `to`, or a block that would take the frame beyond its bound. A node never leaves a level out to send a later one.
- An empty list says that the node does not hold the block of level `from`. It says nothing of the levels after it.

The node that asked checks the first two on what it receives, with the rule of the frame itself, that the levels follow one another. An answer that breaks one of them is refused like a frame that is not of its schema: it is not an answer to that request. The last two are what the node that answers does. A frame that holds no block is 29 bytes; each block adds its canonical encoding, and each block after the first adds one byte more, a comma. The answer is the longest run of blocks that starts at `from` and keeps that sum within 16,777,216.

The node that asked asks again from the level after the last one it received, until it has what it asked for or an answer brings no block.

**A block always fits.** The heaviest frame that carries one block is a `proposal` whose block holds 8,388,608 bytes of transactions and whose `proof` holds 1,024 signatures: 13,093,853 bytes in the vectors, under the 16,777,216 of a frame. A `block` frame with the same block and a certificate of the same size is lighter by one message. Only a `blocks` frame can reach the bound, and the vectors hold one of 16,777,216 bytes, to the byte.

**The body of an injection request.** `POST /chain/inject_transaction` takes one `transaction`, in its canonical encoding: the body goes through the four checks of section 9.4, like a frame.

#### One request at a time

A `blocks` frame names no request. Four rules keep an answer with its request:

- A node has one `get_blocks` waiting on a connection at most: it sends no other before the answer comes.
- A `blocks` frame is the answer to the request that waits. A node that receives one while none waits refuses it, as it refuses an answer that breaks one of the two rules it can check.
- A node answers the requests of a connection in the order it receives them.
- A node that reads four bytes that announce more than a frame can hold closes the connection: it reads no further, so it cannot tell where the next frame would start.

With one request waiting at most, the answer to a request is the next `blocks` frame of the connection, and neither frame needs an identifier. How long a node waits for an answer, and whether it keeps a connection on which it refused a frame, is its own choice; the rules say what it does not do, which is to send a second request on a connection on which one waits. The vectors hold exchanges as the node that asks sees them, and what a node sends when two requests reach it.

### 9.9 What changes from the formats of the devnet

| Subject | The devnet | Structure version 1 | Why |
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
| `blocks` | 512 blocks and 8 MiB at most | As many as fit in a frame | The size of a block depends on its certificate |
| `get_blocks` | From level 0 | From level 1 | The genesis has no certificate |
| Nesting | 64 for a frame and 32 for a transaction, limits of the node | The same numbers, rules of the structure version | One verdict in every client |
| The level of a state | `_current_level`, a field the node adds | `level`, a field of the schema | A state says of which level it is |
| A value the genesis does not give | A default, written in the code | Every parameter and every constant has a value in the state | A state leaves nothing to the client that reads it |
| Parameters | `issuance_params` and `fee_params`, each optional | `parameters`: the ten names of a proposal, all required | One table for what a proposal changes |
| Periods, phases and bonds | Three optional fields of the state; for governance, numbers of the code written with each proposal | `constants`, fixed by the genesis | A network chooses them, and a state says them |
| Validators | Addresses, keys and stakes, any number of them, a stake of 0 allowed | Addresses and stakes, 1 to 1,024, a stake of 1 at least | Note, 6.1: keys are in the registry |
| A balance or a nonce of 0 | Written once the address has appeared | Not written | One state, one object |
| Delegations that have ended | A map from a level, written as a text, to a list | A list, each entry with the level at which it is released | A level is an integer |
| Attestations | The records, an index by issuer and subject, and a queue of bonds | The records | What can be computed again is not kept |
| Votes of the consensus already punished | A map whose names are made of four values, kept for ever | A list of objects, each kept while a report of it could still be applied | One value in one member |
| Proposals | A map by identifier, with the history of each one and lists of what was activated and paid | A list in the order of submission, without history | The order is part of the state |
| A proposal that is over | Stays in the state | Leaves it `delegation_unbonding_blocks` levels after it ended | Nothing can be reported about it any more |
| The phase `withdrawn` | A phase no transaction leads to | Not a phase | A schema holds no value that cannot occur |
| Double votes on a proposal | `equivocations`: both votes, the level of the second, and the reporter once punished | `double_votes`: the voter, the phase, the level, and whether it was punished | The state keeps what the next block needs |
| The treasury address | Optional | Required; it has no key, and no transaction is sent by it | Only a payment that was voted and released moves what the treasury holds |
| A treasury proposal whose vote passes | Is paid by the block in which its vote ends | Waits, in the phase `passed`, until a guardian releases it; it is rejected at the end of its wait | A payment needs a vote and a guardian |
| Guardians of the treasury | None | `guardians`: 3 to 8 accounts, fixed by the genesis | They release a payment or cancel it, and can do nothing else |
| What a guardian sends | Nothing | `release_payment` and `cancel_payment`: fifteen kinds of transactions | A guardian acts by a transaction, in a block |
| How long a payment waits | It does not wait | `guardian_delay_blocks` and `treasury_release_blocks`, constants of the network | The first guardian has a time to itself, and a wait has an end |
| Genesis | Settings from which the node builds its first state | The first state itself, with the network, the moment, the version and the scheme | Two clients read the same first state |
| The account of the state trie | `code_hash` and `storage_root` are `null` when there is no contract | Absent | Note, 4.3 |
| The fields of a contract | Any number | 256 at most: an origination that declares more fails | The storage of a contract is of the type `fields` |
| The largest supply | No bound | 2^63 - 1: a reward stops there | Every amount is an integer of 64 bits |
| A transaction a block cannot charge | Stays in the block and changes nothing | The block is invalid | A block holds only transactions it charges |
| `max_block_bytes` | Applies when the fee floor is on | Applies to every block | The size of a block does not depend on its fees |
| Several proposals decided at one level | Judged one after the other, and settled afterwards | Each one settled before the next is judged | One order for everything a decision moves |
| Requests for blocks on a connection | Nothing says how many may wait | One at a time | An answer names no request |

### 9.10 Another signature scheme, later

This part states no rule.

Structure version 1 has one signature scheme, scheme 1, and refuses everything else: a key written `kpk2.` or a signature written `ksig2.` is refused wherever a key or a signature is expected, and the vectors hold both cases. The note says how another scheme would come: as a new number, introduced by a protocol amendment (its section 2.4).

What structure version 1 already holds for that day:

- the address of an account survives a change of key, since `rotate_key` replaces the key and keeps the address (note, section 6.4);
- the registry keeps every key an address has had, with the level from which it was current, so what was signed before a change can still be verified (note, sections 6.1 and 6.4);
- a key and a signature state their scheme in their text form, and the scheme number enters the derivation of keys and every address (note, sections 3.2 and 5);
- a block states its structure version, and another structure is another number (note, section 6.3);
- a genesis names its signature scheme, and one that names another is refused (section 9.15).

What it does not hold, and cannot without new rules: `rotate_key` takes a key of scheme 1 only, the witness leaf has fixed lengths, and nothing says from which level a key of another scheme could be recorded, what a key of scheme 1 could still sign afterwards, or how the validators would pass from one scheme to the other. Those rules belong to the amendment that would introduce the scheme, in a new version of the profile, reviewed as this one was.

### 9.11 Vectors

`tests/vectors/kern/schemas.json` is built by [`tests/schema_vectors.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/schema_vectors.py). For chapter 1 it holds:

- **accepted objects**: every kind of transaction, vote, proposal, certificate, header, block and frame, for every limit an object that reaches it, and for every range an object at each of its ends. Each one is pinned by the length and the start of the SHA3-384 of its canonical encoding, and comes with what the profile computes from it: the identifier and the witness leaf of a transaction, the hash of a header, the text a validator signs and its context, the identifier of a proposal and of an attestation. Four of them are objects of the vectors of the note, and give back its digests;
- **refused objects**, each with the rule that refuses it: a value out of its range, a text outside its alphabet, a field of another kind, a field under its name of today, a bound passed by one, a root that does not match. Each is one to three changes away from an accepted object, so that it is refused for the reason it gives; one stands alone, the two largest blocks in one frame;
- **mutations**: for most accepted objects, every object one change away must be refused, a member removed, a member added, a value of another JSON type, except where the schema says the member is optional;
- **texts as a node receives them**: the canonical encoding of a frame, 64 and 65 arrays one inside the other, the same with objects, strings that hold brackets and escaped quotation marks, a frame and a request body at their longest and one byte beyond, and the spellings that are not canonical;
- **the four bytes of a frame**: what they announce, the largest value a node accepts and the first it refuses, and values that a reader of the least significant byte first, or of a number with a sign, would take for others. Every accepted frame comes with its four bytes;
- **requests for blocks and their answers**: what a node answers, given the blocks it holds and their sizes, among them an answer that fills a frame to the byte and the two highest levels there are; and answers as the node that asked sees them, accepted or refused.

For chapter 2 it holds:

- **states**, accepted: a first state and a state in which every table holds something, each under both functions, a state with 1,024 validators, one with eight guardians, one with payments in every phase a guardian can leave them in, and the lowest and the highest values a state can hold, among them the last level there is and a supply of 2^63 - 1. Each one comes with its state root and the root of its accounts, and one of them with its accounts;
- **states**, refused: a form that is not the one of its table, and, for every rule of sections 9.12 to 9.15, at least one state that breaks that rule and no other. Each of those names the sentence it breaks (`breaks`), and the builder checks that the reference accepts it without that sentence;
- **accounts**, and **genesis** files with the nine fields of their block of level 0 and its hash; a genesis as a text, read like any text and without a bound on its length; refused: a genesis without its moment, under another network, with 1,025 validators, with crossed rates, with a supply that is not the sum of what it gives, with a first state that is not one;
- **what a block charges** (`charges`): a part of a state, a proposer and a block of transfers, with what the block leaves, or the rule that makes it invalid (`block_rules`) and the transaction that breaks it;
- **decisions** (`decisions`): proposals that are decided at one level, each with the outcome of its vote or the end of its wait, and what they do. Several come twice, in one order and in the other;
- **payments** (`payments`): transactions of guardians in one block, on payments that wait, with what each one does or the rule that makes it fail (`guardian_rules`), and what they leave;
- **exchanges** (`exchanges`, `served`): what happens on a connection as the node that asks for blocks sees it, step by step, and what a node sends when two requests reach it.

Keys and signatures are written by rule in the file and are not real ones: no signature in these vectors verifies, since a schema verifies none. The signatures of the profile have vectors of their own (note, section 17).

`tests/test_schema_vectors.py` runs the vectors through `tests/schema_reference.py` and compares the tables of this section with it. `tests/vectors/kern/profile_check.go` runs them with tables written independently, in another order of checks, and the continuous integration runs it on every pull request:

```
go run profile_check.go -schemas schemas.json
```

Neither is the node.

### 9.12 The state

The state is what a network keeps from one block to the next: who holds what, who validates, what is bonded, what is being voted on, and the numbers every rule reads. A block header commits to it through `state_root` (note, section 4.6): after the block of level `n`, every node holds the same state, and the root of that state is in the header of that block.

A schema of chapter 1 checks an object that travels. A state does not travel. Its schema says what a state of structure version 1 is, and nothing of where it came from: the tables below give its form, and the sentences under them the rules that tie its tables together. Every one of those rules can be checked on the state alone, without the blocks that led to it: on a first state (section 9.15), on a copy received from elsewhere, on the output of another client. A state that breaks one is not a state of structure version 1.

The rules are what the steps of section 9.16 keep and rely on: an implementation in which a block leads from a state that keeps them to one that does not has a defect. They do not say that a state can be reached: a state that keeps them all may be one no chain leads to.

Three things hold for the whole state:

- **No default.** Every field is required, and every parameter has a value. A state leaves no value to the client that reads it.
- **Nothing derived, no history.** The state holds what the next block needs. An index that can be computed from another table is not part of it, and neither is the record of what a proposal went through: that history is in the blocks.
- **No zero written.** An address that holds nothing is not in `balances`, and an address that has sent nothing is not in `nonces`. Two states that hold the same things are the same object, whatever led to them.

Section 9.3 bounds every list and every map of an object that travels. A state is bounded where a transaction is (the code and the fields of a contract, a claim) and where the number of validators bounds it (the votes on a proposal). Its tables by address and its lists of proposals grow with the network, and the tables below say `any number`.

#### State

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `level` | `level` | required | The level of the last block applied: 0 in a first state |
| `chain_id` | `chain` | required | The name of the chain, a label (note, section 3.1) |
| `state_root_function` | `"json"` or `"trie"` | required | The function that computes the state root (note, section 4.6) |
| `total_supply` | `amount` | required | Every mukrn that exists |
| `treasury_address` | `address` | required | The address that holds what the protocol sets aside. It has no key: only a payment that was voted and released moves what it holds |
| `guardians` | list of 3 to 8 `address` | required | The guardians of the treasury, the first one first |
| `balances` | map of `address` to `positive amount`, any number of entries | required | What each address holds and can spend |
| `nonces` | map of `address` to integer, 1 to 2^63 - 1, any number of entries | required | For each address, the number of its transactions applied so far |
| `contracts` | map of `address` to `contract`, any number of entries | required | The contracts, by address |
| `keys` | map of `address` to list of 1 or more `key entry`, any number of entries | required | The key registry (section 9.14) |
| `validators` | list of 1 to 1,024 `validator` | required | The validators and their own stakes, in the order of the genesis |
| `consensus_set` | list of 1 to 1,024 `validator` | required | The weight the consensus counts for each validator during the epoch |
| `delegations` | map of `address` to `delegation`, any number of entries | required | What each delegator has bonded to a validator |
| `delegation_unbonding` | list of any number of `unbonding delegation` | required | The delegations that have ended and are not released yet |
| `attestations` | map of `hash` to `attestation`, any number of entries | required | The attestations, by identifier |
| `consensus_slashes` | list of any number of `slashed vote` | required | The votes of the consensus already punished, so that none is punished twice |
| `governance` | `governance` | required | The proposals of the two tracks |
| `parameters` | `state parameters` | required | The ten parameters a protocol proposal can change |
| `constants` | `constants` | required | What the genesis fixes for the life of the network |

- `validators` holds an address once, and `consensus_set` holds the same addresses in the same order.
- The weight of a validator in `consensus_set` is not above its stake plus the amounts delegated to it.
- Every validator has a key in `keys`.
- An address of `contracts` is not in `keys`.
- `treasury_address` is not in `keys`.
- `guardians` holds an address once.
- A guardian is not `treasury_address`, an address of `contracts` or a validator.
- Every address of `nonces` is in `keys`, and every address of `keys` is in `nonces` or is a validator.
- In `keys`, the levels `from` of an address grow, and none is above `level` plus 1.
- The first key of an address is the key whose hash is that address.
- A key stands once in `keys`, and no key of an address has the ML-DSA part or the Ed25519 part of an earlier key of that address.
- `total_supply` is the sum of `balances`, of the stakes of `validators`, of the amounts of `delegations` and of `delegation_unbonding`, of the bonds of `attestations` and of the bonds of the proposals of `governance`.
- A delegation names a validator other than its delegator, and so does a delegation that is unbonding.
- Nothing happened after `level`: the level of a tranche, `unbonding_from`, `issued_at`, `revoked_at`, the level of a slashed vote, `ended_at` and the level of a double vote are not above it.
- A delegation that is unbonding is released `delegation_unbonding_blocks` levels after `unbonding_from`, at a level above `level`, and the list is in the order in which the delegations ended.
- An attestation revoked `attestation_unbonding_blocks` levels before `level`, or earlier, holds no bond.
- No two slashed votes are of the same validator, kind, level and round, and none is `delegation_unbonding_blocks` levels old or more.
- The proposals of a track are in the order of their submission, and no two have the same `proposal_id`.
- The bond of a proposal is `protocol_bond` or `treasury_bond`, as its track says.
- A proposal that is not over is in the phase of its level: that phase started at `level` or before, and ends above it.
- `released_by` is a guardian other than the first.
- When `released_by` is present, the end of `voting` plus `guardian_delay_blocks` is not above `level`.
- A protocol proposal that is over ended when a vote did: at the end of `adoption` if it is activated, of `exploration` or of `adoption` if it is rejected. A treasury proposal that is over ended at the end of `voting` or while it waited: after the end of `voting` if it is executed, and not after the end of `passed`.
- A proposal that is over ended less than `delegation_unbonding_blocks` levels before `level`.
- A vote and a slashed vote are those of a validator.

The rules on `contracts`, `nonces` and `keys` are those of the note for addresses and keys (sections 4.5, 6.1 and 6.4), read on a state: an address is an account or a contract and never both, a key is recorded once, and a rotation takes no part of an earlier key of its address. A contract has no key, and so no nonce, since an address that has sent a transaction has a key. A part of the key of another address is not refused, for the reason the note gives (its section 6.4). A schema reads a key as a text (section 9.2): that its Ed25519 part passes rule 2 of section 2.5 of the note is checked when the key is recorded, by a transaction or from a genesis (section 9.15).

`total_supply` is not a counter kept beside the tables: it is what they add up to. What a block mints enters a balance, what it burns leaves one, and a stake, a delegation or a bond is an amount that left a balance and has not come back. Every amount of a state is therefore a part of its supply, and the supply never passes 2^63 - 1 (section 9.16).

**The treasury.** `treasury_address` holds what the protocol sets aside: its share of each reward, and the half of a lost bond that is not burned. It has no key, and no transaction is sent by it (section 9.16). One thing moves what it holds: a treasury proposal that the validators voted and that a guardian released. It is therefore never a validator, and whoever must sign to spend funds of its own, a foundation for instance, holds another address. It can be the address of a contract, which has no key either, and anyone can send funds to it.

**The guardians.** `guardians` lists three to eight accounts, fixed by the genesis like the validators: no kind of transaction adds one or removes one, and a guardian changes its key with a `rotate_key`, like any account. The first of the list is the first guardian. A guardian does one thing: it releases a payment that the validators voted, or, for the first one, cancels it (section 9.16). It holds nothing of the treasury, pays nothing that was not voted, and names no recipient. A guardian signs, so it is neither the treasury nor a contract; and it is not a validator, whose key stays on a machine that signs at every block.

The rules from the delegations that unbond onward say that a state holds nothing overdue. What is due at a level is done by the block of that level (section 9.16): the state after that block holds no delegation to release, no bond to return, no proposal in a phase that has ended, and neither a proposal nor a slashed vote that nothing can be reported about any more.

#### Contract

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `code` | `code` | required | The source of the contract, as its origination gave it |
| `storage` | `fields` | required | A value for each field the contract declares |

A contract keeps its code and a value for each field it declares. The values are those of the type `value` (section 9.2): the bound of a text and the range of an integer are the same in a transaction and in the state. Two things follow for what a block does. An `originate` whose code declares more than 256 fields fails, since no state could hold its storage. A `call` that would leave in the storage an integer beyond 64 bits or a text of more than 4,096 bytes fails, like a call the contract refuses. The state trie holds the hash of the code and the root of the storage (section 9.13).

#### Validator

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `address` | `address` | required | The validator |
| `stake` | `positive amount` | required | Its own stake in `validators`, its weight in `consensus_set` |

No kind of transaction adds a validator or removes one: the validators of a network are those of its first state, 1,024 at most (section 9.3). The bound of 1,024 signatures of a certificate goes with it.

The stake of a validator is its own. It is 1 mukrn at least, and it goes down only when the validator is slashed: a slash takes a share of it, rounded down, and never the whole ([staking.md](staking.md)). `consensus_set` gives each validator the weight the consensus counts for it during the epoch: its stake and what was delegated to it when the snapshot was taken. A slash or the end of a delegation lowers that weight at once, and nothing raises it before the next snapshot. A weight is therefore never more than what backs it at that moment, and the weights of a state add up to `total_supply` at most. Both lists are in the order of the genesis, which is the order the draw of the proposer follows (note, section 4.1).

#### Delegation

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `validator` | `address` | required | The validator the amount is bonded to |
| `amount` | `positive amount` | required | What is bonded |
| `tranches` | list of 1 or more `tranche` | required | The same amount, by the level at which each part was bonded |

- `amount` is the sum of the amounts of `tranches`, whose levels grow.

#### Tranche

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `level` | `level` | required | The level at which this part was bonded |
| `amount` | `positive amount` | required | The part |

#### Unbonding delegation

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `delegator` | `address` | required | Who gets the amount back |
| `validator` | `address` | required | The validator it was bonded to |
| `amount` | `positive amount` | required | What is still held |
| `tranches` | list of 1 or more `tranche` | required | The same amount, by the level at which each part was bonded |
| `unbonding_from` | `level` | required | The level at which the delegation ended |
| `release_at` | `level` | required | The level whose block returns the amount |

- `amount` is the sum of the amounts of `tranches`, whose levels grow.

A delegator has one delegation, to one validator, and adds to it by delegating again: to delegate to another validator, it ends the first one. A delegation has one tranche for each level at which its delegator delegated. A slash reaches the tranches that were bonded when the offence was committed, and takes a share of each, rounded down. A delegation that ends leaves `delegations` and enters `delegation_unbonding` with its tranches. There it weighs nothing, still answers for the offences committed up to the level at which it ended, and the block of level `release_at` returns what is left of it to the delegator.

#### Attestation

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `issuer` | `address` | required | The account that made the statement |
| `schema_id` | `schema name` | required | The kind of statement |
| `subject` | `subject` | required | What it is about |
| `claim` | `claim` | required | The statement |
| `bond` | `amount` | required | What the attestation still holds |
| `issued_at` | `level` | required | The level of the block that recorded it |
| `revoked_at` | `level` | optional | The level at which its issuer revoked it. Absent while it is not revoked |
| `slashed` | `true` or `false` | required | Whether it was punished as one half of a contradiction |

- `revoked_at` is not lower than `issued_at`.
- An attestation that is slashed holds no bond.

An attestation stays in the state after it is revoked: it can still be one half of a contradiction with an attestation that was issued while it stood. It stays after it is slashed too, and `slashed` is what refuses a second report of it. It stands under the identifier of section 9.5. The bond of a revoked attestation stays held for `attestation_unbonding_blocks` levels, during which a contradiction can still take a share of it. The block of level `revoked_at` plus that period returns it to its issuer, and `bond` is 0 from then on.

#### Slashed vote

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `validator` | `address` | required | The validator that voted twice |
| `kind` | `"preendorse"` or `"endorse"` | required | The kind of its two votes |
| `level` | `level` | required | Their level |
| `round` | `round` | required | Their round |

Two votes of a validator, of the same kind, level and round and for two blocks, are punished once (`slash_consensus_equivocation`, section 9.5), and the entry is what refuses a second report of them. A report of two votes of level `L` is applied at level `L` plus `delegation_unbonding_blocks` at the latest: after that level, the delegations that backed the votes may have been released. The block of that level takes the entry out of the state.

#### Governance

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `protocol` | list of any number of `protocol proposal` | required | The proposals of the protocol track, in the order of their submission |
| `treasury` | list of any number of `treasury proposal` | required | The proposals of the treasury track, in the same order |

The proposals of a track are a list, in the order in which the chain applied the transactions that submitted them. That order is part of the state, and so under its root: when several proposals are decided at one level, they are decided in that order (section 9.16). A proposal is found by its `proposal_id`. A `governance_propose` whose identifier is that of a proposal of its track that is still in the state fails; `salt` lets a submitter make the same proposal again (section 9.5).

#### Protocol proposal

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `proposal_id` | `hash` | required | Its identifier (section 9.5) |
| `submitter` | `address` | required | The validator that submitted it and posted its bond |
| `payload` | `protocol payload` | required | What it would do |
| `submitted_at` | `level` | required | The level of the block that recorded it |
| `phase` | `"submitted"`, `"exploration"`, `"cooldown"`, `"adoption"`, `"activated"` or `"rejected"` | required | Where it stands |
| `ended_at` | `level` | optional | The level at which it was activated or rejected |
| `exploration_votes` | map of `address` to `"yes"`, `"no"` or `"abstain"`, 0 to 1,024 entries | required | The first vote, by validator |
| `adoption_votes` | map of `address` to `"yes"`, `"no"` or `"abstain"`, 0 to 1,024 entries | required | The second vote, by validator |
| `double_votes` | list of 0 to 2,048 `double vote` | required | The validators that voted two ways in a phase |
| `bond` | `amount` | optional | What it holds until it is over |

- `ended_at` is present exactly when `phase` is `activated` or `rejected`, and `bond` exactly when it is not.
- A voter has one double vote in a phase at most, and a vote in that phase.

#### Double vote

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `voter` | `address` | required | The validator |
| `phase` | `"exploration"` or `"adoption"` | required | The phase in which it voted two ways |
| `level` | `level` | required | The level of the vote that contradicted its first one |
| `punished` | `true` or `false` | required | Whether a `slash_equivocation` has punished it |

#### Treasury proposal

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `proposal_id` | `hash` | required | Its identifier (section 9.5) |
| `submitter` | `address` | required | The account that submitted it and posted its bond |
| `payload` | `treasury payload` | required | Who it would pay, and how much |
| `submitted_at` | `level` | required | The level of the block that recorded it |
| `phase` | `"submitted"`, `"voting"`, `"passed"`, `"executed"` or `"rejected"` | required | Where it stands |
| `ended_at` | `level` | optional | The level at which it was executed or rejected |
| `votes` | map of `address` to `"yes"`, `"no"` or `"abstain"`, 0 to 1,024 entries | required | The vote, by validator |
| `released_by` | `address` | optional | The guardian, other than the first, that has released it. Absent while none has |
| `bond` | `amount` | optional | What it holds until it is over |

- `ended_at` is present exactly when `phase` is `executed` or `rejected`, and `bond` exactly when it is not.
- `released_by` is present only when `phase` is `passed`.

A protocol proposal waits, is voted on, rests, and is voted on again. A treasury proposal waits, is voted on once and, when its vote passes, waits again, for a guardian: it is then a payment that waits, in the phase `passed`. The length of each phase is a constant of the network, and a phase ends at a level:

#### Ends of phases

| Track | Phase | Ends at |
|---|---|---|
| protocol | `submitted` | `submitted_at` plus `protocol_proposal_blocks` |
| protocol | `exploration` | the end of `submitted` plus `protocol_exploration_blocks` |
| protocol | `cooldown` | the end of `exploration` plus `protocol_cooldown_blocks` |
| protocol | `adoption` | the end of `cooldown` plus `protocol_adoption_blocks` |
| treasury | `submitted` | `submitted_at` plus `treasury_proposal_blocks` |
| treasury | `voting` | the end of `submitted` plus `treasury_vote_blocks` |
| treasury | `passed` | the end of `voting` plus `treasury_release_blocks` |

The block of the level at which a phase ends moves the proposal on. A proposal that is not over is therefore in the phase of its level. A protocol proposal that is over ended when a vote did. So did a treasury proposal that its vote rejected; one whose vote passed ended in a later block, when a guardian released it or cancelled it, or at the end of `passed`, when none had.

**Votes.** Only a validator votes, `yes`, `no` or `abstain`, and only while a vote of the proposal is open. On the protocol track its first vote of a phase stands. A later vote of that validator in that phase that says something else does not replace it: it is recorded as a double vote, once for that validator and that phase, with the level of the block that holds it, and a `slash_equivocation` (section 9.5) punishes it, once. A later vote that says the same thing changes nothing. A double vote is therefore that of a validator that has a vote in the same phase. On the treasury track a later vote replaces the earlier one.

**Bonds.** A proposal holds the bond of its track from its submission until it is over; section 9.16 says where the bond goes then.

**Leaving.** A proposal that is over stays in the state for `delegation_unbonding_blocks` levels, so that a double vote of its last phase can be reported for as long as two votes of the consensus can, and leaves with the block of level `ended_at` plus `delegation_unbonding_blocks`. A `slash_equivocation` names a proposal that is in the state: once the proposal has left, it fails. The devnet has a phase `withdrawn`; no transaction withdraws a proposal, and structure version 1 has no such phase.

#### State parameters

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `i_min_ppm` | integer, 0 to 1,000,000 | required | Issuance at the target staking ratio, in parts per million a year |
| `i_max_ppm` | integer, 0 to 1,000,000 | required | Issuance when nothing is staked |
| `target_staking_ratio_ppm` | integer, 0 to 1,000,000 | required | The staking ratio the issuance aims at |
| `target_block_time_ms` | integer, 1 to 3,600,000 | required | The time between two blocks that the issuance per block assumes, in milliseconds |
| `treasury_share_ppm` | integer, 0 to 1,000,000 | required | The share of the issuance that goes to the treasury |
| `proposer_bonus_ppm` | integer, 0 to 1,000,000 | required | The share of the rest that goes to the proposer |
| `fee_floor_enabled` | `true` or `false` | required | Whether the fee floor applies |
| `fee_floor_base` | integer, 0 to 1,000,000,000,000 | required | The fixed part of the fee floor, in mukrn |
| `fee_floor_per_byte` | integer, 0 to 1,000,000,000 | required | Its part per byte of the size of the transaction, in mukrn |
| `max_block_bytes` | integer, 131,072 to 8,388,608 | required | The most bytes the transactions of a block may add up to |

- `i_min_ppm` is not above `i_max_ppm`.

These are the ten parameters of section 9.5, each in the range it has there. A protocol proposal that is activated replaces the values it names. The two rates of issuance are tied: a state never holds a lowest rate above the highest. This is the rule that section 9.5 announced, and a network applies it at three moments. A genesis whose rates are crossed is refused. A `governance_propose` whose `params` hold both rates, crossed, fails when it is applied. A proposal that holds one of them is judged when it would be activated, on the parameters of that moment (section 9.16).

#### Constants

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `epoch_blocks` | `period` | required | The length of an epoch: `consensus_set` is taken again at each level that is a multiple of it |
| `delegation_unbonding_blocks` | `period` | required | How long a delegation that has ended stays held, and how long an offence can be reported |
| `attestation_unbonding_blocks` | integer, 0 to 2^32 - 1, in blocks | required | How long the bond of a revoked attestation stays held |
| `protocol_proposal_blocks` | `period` | required | How long a protocol proposal waits before its first vote |
| `protocol_exploration_blocks` | `period` | required | The length of its first vote |
| `protocol_cooldown_blocks` | `period` | required | The pause between its two votes |
| `protocol_adoption_blocks` | `period` | required | The length of its second vote |
| `treasury_proposal_blocks` | `period` | required | How long a treasury proposal waits before its vote |
| `treasury_vote_blocks` | `period` | required | The length of that vote |
| `guardian_delay_blocks` | `period` | required | How long a payment that passed waits before a guardian other than the first can release it |
| `treasury_release_blocks` | `period` | required | How long a payment that passed waits to be released: at the end it is rejected |
| `protocol_bond` | `amount` | required | What a protocol proposal holds while it is not over |
| `treasury_bond` | `amount` | required | The same for a treasury proposal |

- `delegation_unbonding_blocks` is not lower than `epoch_blocks`.
- `guardian_delay_blocks` is not above `treasury_release_blocks`.

A network fixes these numbers at its genesis and never changes them: no proposal of structure version 1 can. The node of today reads the first three from its genesis, with a default, and has eight others in its code. It does not have the two that time a payment: it pays when a vote passes.

`guardian_delay_blocks` is how long after a vote only the first guardian can release a payment, and `treasury_release_blocks` the whole wait of that payment. The first is not above the second: past the delay the other guardians can release, in the last block of the wait at the latest.

`delegation_unbonding_blocks` is the period the others lean on: a delegation that has ended stays held that long, an offence can be reported that long, and a proposal that is over stays in the state that long. It is never shorter than an epoch ([staking.md](staking.md)).

The sharing of a reward, the weights and the thresholds of a vote and the rates of a slash are not in the state. They are rules, written in [adaptive-issuance.md](adaptive-issuance.md), [governance.md](governance.md) and [staking.md](staking.md). This chapter states the order in which a block applies them and the form of what they read and write, not their arithmetic.

### 9.13 Accounts and the state trie

With the function `trie`, the three tables keyed by address leave the object that is hashed, and one hash stands for them: `accounts_root`, the root of the state trie (note, section 4.6). Every other field of the state is hashed as it is, with both functions: the key registry, the validators, the proposals, the parameters and the constants are under the root whichever function computes it.

The trie holds one account for each address that is in `balances`, in `nonces` or in `contracts`:

#### Account

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `balance` | `amount` | required | What the address holds: 0 when it is not in `balances` |
| `nonce` | `nonce` | required | Its nonce: 0 when it is not in `nonces` |
| `code_hash` | `hash` | optional | `H("kern.code", ...)` of the code of the contract, as text |
| `storage_root` | `hash` | optional | `H("kern.storage", ...)` of the canonical JSON of its storage |

- `code_hash` and `storage_root` are present together.

The value of a leaf is the canonical JSON of that object. An address that holds nothing, has sent nothing and is not a contract has no account: with no zero written in the state, the accounts of a state depend on what it holds and not on its history. An address can have a key and no account: a validator that has everything staked and has sent nothing.

The name `accounts_root` is reserved (note, section 4.6): the state has no field of that name.

The vectors of the note fix the two computations on small examples of six or seven fields, one of which writes a balance of 0. They show how a state is hashed, whatever it holds; they are not states of this schema. The vectors of this chapter give the root of complete states, with both functions, and the accounts of one of them.

### 9.14 The key registry

`keys` holds, for each address that has a key, the keys it has had, the oldest first. The examples of the note already have that shape:

#### Key entry

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `from` | `level` | required | The level from which the key is current |
| `public_key` | `key` | required | The key |

The key that is current at a level is the last one whose `from` is not above that level. A signature made for level `n` is verified with the key that was current at level `n` (note, section 6.1): the key of the block for what the block holds, an earlier one for a vote quoted as evidence.

A key enters the registry in three ways:

1. The genesis records the key of each validator, from level 0.
2. The first transaction of an account carries its key, whose hash is the address. The key is recorded from the level of that block, and it is the key that transaction is verified with.
3. A `rotate_key` in the block of level `H` records the new key from level `H` + 1 (note, section 6.4).

A key is checked before it is recorded (note, section 4.5, rule 4), and nothing ever leaves the registry. The rules of section 9.12 are those of the note, read on a state: the first key of an address is the one whose hash is the address; a key stands once in the whole registry; a key of an address takes no part of an earlier key of that address; and since one rotation of an address takes effect in a block, the last `from` of an address is `level` plus 1 at most.

**A rotation that fails.** A `rotate_key` fails, and pays its fee, when its new key is or has been the key of an address, when it takes a part of an earlier key of its sender, or when a rotation of its sender is already due at the next level. It records nothing, and the first rotation of an address that succeeds in a block is the one that is applied (note, section 6.4). A `rotate_key` whose second signature does not verify is another matter: the block that holds it is invalid (section 9.16).

### 9.15 The genesis and the block of level 0

A genesis is the first state of a network, and four values that are not in the state:

#### Genesis

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `version` | 1 | required | The structure version |
| `scheme` | 1 | required | The signature scheme (note, sections 2.4 and 5) |
| `network_id` | `network` | required | The identifier of the network, drawn when the genesis is built (note, section 3.1) |
| `timestamp` | `time` | required | The moment the network starts: the `timestamp` of the block of level 0 |
| `state` | `state` | required | The first state |

- The `level` of `state` is 0.
- `nonces`, `contracts`, `delegations`, `delegation_unbonding`, `attestations`, `consensus_slashes` and the two lists of `governance` are empty.
- Each validator has one key, current from level 0.
- `consensus_set` is `validators`.

**The first state is given, not computed.** A node does not build its first state from settings: it reads it. Every balance, every parameter and every constant is written in `state`, which is of the schema of section 9.12 and keeps all its rules. A genesis with 1,025 validators, with two guardians, with rates of issuance that are crossed, with a validator that has no key or with a supply that is not the sum of what it gives is refused.

**Read on the network it names.** A node reads a genesis as it receives a text (section 9.4), without a bound on its length: the nesting is measured on the bytes, the encoding is canonical, and the object is of its schema on the network its `network_id` names. That identifier is in the checksum of every address of the state, so a genesis under another identifier is refused: none of its addresses is an address of that network. One genesis is one sequence of bytes, which two operators can compare.

**What a first state holds.** Balances, the validators with their stakes and their keys, the treasury address, which has no key, its guardians, the parameters and the constants. Nobody has sent a transaction: there is no nonce, no contract, no delegation, no attestation, no proposal. An account that the genesis funds has no key in it, and its first transaction brings one (note, section 4.5, rule 5); the same goes for a guardian. The key of each validator is in `keys`; a schema reads it as a text, and a node checks it as rule 4 of that section says before it starts. Rule 1 of that section lets a genesis list contracts beside its accounts. A genesis of structure version 1 lists none: the address of a contract is made from the identifier of the transaction that originates it (note, section 4.1).

**The block of level 0.** It has no transaction, nobody signs it, it has no certificate and it never travels: `get_blocks` starts at level 1 (section 9.8). A node computes it from its genesis. Its hash is `H("kern.block", ...)` of the canonical JSON of the nine fields a header has without its signature (section 9.7):

#### Block of level 0

| Field | Value |
|---|---|
| `version` | 1 |
| `level` | 0 |
| `payload_round` | 0 |
| `timestamp` | the `timestamp` of the genesis |
| `parent_hash` | 96 zeros |
| `state_root` | the root of the first state |
| `txs_root` | the root of a tree with no item |
| `witness_root` | the same root |
| `proposer` | the first address of `validators` |

The block of level 0 commits to the whole first state through `state_root`, to the moment through `timestamp`, and to the network through `H`, which hashes the network identifier with everything (note, section 4.1). Its hash is the `parent_hash` of the block of level 1, so every block of a network leads back to its genesis. `proposer` names the first validator so that the nine fields are all there: that validator proposes nothing, and the block of level 0 mints nothing.

A genesis names its structure version and its signature scheme, and one that names others is refused. So is a genesis without a `timestamp`, as today: nothing takes the time of the machine in its place.

### 9.16 What a block does to the state

A block of level `n` takes the state of level `n` - 1 to the state of level `n`. This section says in what order, and states what the forms cannot: what a block must be able to charge, in what order proposals are decided, what a guardian does, and what leaves the state.

The steps of a block, in this order:

1. `level` becomes the level of the block. Its transactions see that level.
2. The transactions are applied, in the order of the block.
3. The reward of the block is minted and shared ([adaptive-issuance.md](adaptive-issuance.md)).
4. The bonds of the attestations revoked `attestation_unbonding_blocks` levels earlier return to their issuers.
5. The delegations whose `release_at` is the level of the block return to their delegators.
6. The proposals whose phase ends at this level move on, as said below.
7. What nothing can be reported about any more leaves the state: a proposal that ended `delegation_unbonding_blocks` levels earlier, and a slashed vote that old.
8. When the level is a multiple of `epoch_blocks`, `consensus_set` is taken again: for each validator, its stake and what is delegated to it at that moment.

**The ends of the ranges.** No state holds a number outside its range, so no block writes one. A reward never takes `total_supply` beyond 2^63 - 1: where the full reward would, the block mints what is left under that bound. A sender whose nonce is 2^63 - 1 sends nothing more (below). An operation that would have to write a level above 2^63 - 1, the release of a delegation that ends at one of the last levels for instance, fails. No network reaches these numbers. They are stated so that two clients do the same thing with the same state, whatever it holds.

#### What a block charges

A block holds only transactions it charges. It is valid only if all of the following hold, each transaction being looked at in the order of the block, on the state as the transactions before it left it:

- The sizes of its transactions add up to `max_block_bytes` at most.
- When `fee_floor_enabled` is `true`, the fee of each transaction is at least `fee_floor_base` plus `fee_floor_per_byte` times its size.
- The `chain_id` of each transaction is the `chain_id` of the state.
- The `nonce` of each transaction is the nonce of its sender when its turn comes: the number of transactions of that sender applied before it. A sender whose nonce is 2^63 - 1 sends nothing more: its nonce could not go up.
- The sender of each transaction holds its `fee` when its turn comes.
- No transaction is sent by `treasury_address`.
- The sender of each transaction has a key: the one `keys` holds for it, in which case the transaction carries no `public_key`, or the one the transaction carries, whose hash is the sender and which no address has had.
- Every signature verifies: `signature` with the key of the sender, and in a `rotate_key` `second_signature` with the new key.

A block that breaks one of them is invalid: this is the rule that section 9.1 announced. Today a transaction that cannot be charged stays in its block and changes nothing. In structure version 1 it has no place there, so every transaction of a block has paid its fee. The proposer of the node already builds its blocks that way.

Once these hold for a transaction, its fee moves from its sender to the proposer, the nonce of its sender goes up by one, the key it carries is recorded from the level of the block, and its operation is applied. The operation succeeds, or it fails and changes nothing else (section 9.1): a transfer whose sender does not hold the amount, a call that the contract refuses, a rotation to a key that was recorded before.

`max_block_bytes` bounds every block, whether the fee floor is on or not. A schema verifies no signature, so the vectors hold the first six rules, on blocks of transfers: what each block leaves, or the rule that makes it invalid and the transaction that breaks it. The last two are those of the note (sections 4.5, 6.3 and 6.4), and their tests come with the implementation.

#### Deciding proposals

The block of level `n` moves on every proposal whose phase ends at `n`. A proposal that waited or rested enters its next phase, and so does a protocol proposal whose first vote passes: it rests, and its bond stays held. Every other proposal whose vote ends is decided, and so is a payment whose wait ends:

- The proposals of the protocol track come first, then those of the treasury track; in each track they are taken in the order of the list.
- Each proposal is decided, and everything that follows from the decision is done, before the next one is looked at.
- A proposal whose vote does not pass is rejected.
- A protocol proposal whose second vote passes is activated: its `params` replace the parameters of those names, and its `swap` sets `state_root_function`. It is rejected instead when its `params` would leave `i_min_ppm` above `i_max_ppm`.
- A treasury proposal whose vote passes is not paid: it waits, in the phase `passed`, and its bond stays held.
- A payment that still waits at the end of `passed` is rejected.
- The bond of a proposal that is activated returns to its submitter. Half the bond of a proposal that is rejected is burned, rounded down, and `total_supply` is lowered by it; the rest goes to the treasury.

Whether a vote passes is a rule of [governance.md](governance.md): the weights, the quorum and the majorities are not restated here. The vectors give each proposal the outcome of its vote and hold what follows. Several come twice, in one order and in the other, and give two results.

Decisions are settled one at a time: the half of a bond that the treasury keeps is there before the next proposal is looked at. No decision pays anything: a payment is made by a guardian.

#### What a guardian does

A treasury proposal whose vote passed is a payment that waits. Two kinds of transactions act on it, a `release_payment` and a `cancel_payment`, each of which names it by its `proposal_id` (section 9.5). The first guardian releases a payment alone, from the block that follows the end of its vote. Two other guardians release it together, once `guardian_delay_blocks` levels have passed since the end of that vote: the release of the first of them is recorded in `released_by`, and the release of a second one makes the payment. The first guardian, and no other, cancels a payment that waits.

A payment that is made is executed in the transaction that releases it: each recipient is paid, the treasury itself when it is one of them, its bond returns to its submitter, and `ended_at` is the level of the block. A payment that is cancelled is rejected in the transaction that cancels it, and its bond goes where the bond of a rejected proposal goes. Such a transaction is charged like any other, and its operation fails, changing nothing else, unless all of the following hold:

- Its sender is a guardian.
- It names a proposal of the treasury track whose `phase` is `passed`.
- Only the first guardian cancels.
- A guardian other than the first releases a payment in a block whose level is the end of `voting` plus `guardian_delay_blocks`, or higher.
- A guardian other than the first releases a payment once.
- A release that pays finds the sum of the amounts of the payment in the treasury. Otherwise it fails, and the payment goes on waiting.

A payment needs both a vote and a guardian. Until a guardian releases it, a payment that the validators voted moves nothing, and at the end of `passed` it is rejected like a proposal whose vote failed. A guardian, for its part, releases what was voted, to the recipients and for the amounts of the proposal: it cannot name another payment, and without a vote that passed its transaction fails. Until `guardian_delay_blocks` levels have passed since the end of the vote, the first guardian alone can release, and it has the whole wait in which to cancel. Past that delay two others can release without it, so that a payment does not hang on one key.

The block of the level at which a vote ends applies its transactions before it decides that vote (step 2, then step 6): for them the proposal is still in its vote, and the first block in which a guardian can act is the next one. In the block of the level at which the wait ends, a payment can still be released: the transactions come before the decision that would reject it. A release that would pay more than the treasury holds fails, and can be sent again later in the wait. The vectors hold transactions of guardians in one block, with what each one does or the rule that makes it fail, and what they leave; several come twice, in one order and in the other. An operation that breaks several rules fails all the same, and leaves the same state whichever rule is named: the vectors name the first one, in the order of the list.

---

## Reference

- [`tokenomics.md`](tokenomics.md) — economic spec
- [`governance.md`](governance.md) — governance process spec
- [`staking.md`](staking.md) — staking and delegation spec
- [`multi-frame-evm.md`](multi-frame-evm.md) — KVM spec
- [`architecture.md`](architecture.md) — overall component layout
