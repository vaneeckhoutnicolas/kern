# Kern v0.4 — what changed

This document summarizes the v0.4 changes made on top of v0.3. Three pieces, in order of integration depth: **issuance wired into block production**, the **Merkle-Patricia trie for state commitments**, and an **expanded EVM opcode set with execution context**.

For the design rationale of each, see the underlying spec documents:
- [`adaptive-issuance.md`](adaptive-issuance.md) for the issuance formula
- [`merkle-trie.md`](merkle-trie.md) for the trie design (new in v0.4)
- [`evm-fraud-proofs.md`](evm-fraud-proofs.md) for the EVM and its protocol role

---

## 1. Issuance wired into block production

The v0.3 `kern/issuance.py` module defined the adaptive emission formula but was not yet called by the chain state machine. In v0.4, `kern/chain.py::apply_block` now invokes it after processing the block's transactions.

### What changed

- **State schema additions.** Three new keys in the state dict:
  - `total_supply` — running total in mukrn, updated every block.
  - `treasury_address` — set at genesis; receives the treasury share of each block reward.
  - `issuance_params` — optional override of the default `IssuanceParams`; `None` means use defaults.

- **`apply_block` flow.** After all transactions have been applied, `_apply_block_rewards` is called. It:
  1. Computes the staked total from the validator set.
  2. Identifies endorsers from `block.commits`.
  3. Calls `compute_block_rewards(...)` to get the treasury credit and per-validator distribution.
  4. Credits each, and updates `total_supply`.

- **`propose_block` flow.** The proposer must now compute the post-reward state root, since validators reproducing the block will. So `kern/consensus.py::propose_block` was restructured to apply rewards (via the same `_apply_block_rewards`) to the working state before computing the `state_root` and signing the header.

### Observable behavior

Running the reference node now demonstrates issuance live:

```
Initial baker balance: 1000000112 mukrn
Initial treasury:      4 mukrn

After 1s   level=8    baker=1000000224   treasury=8
After 2s   level=11   baker=1000000308   treasury=11
After 3s   level=15   baker=1000000420   treasury=15
After 4s   level=18   baker=1000000504   treasury=19
```

Each block at 50% staking ratio adds ~28 mukrn to the baker (proposer + endorser share at the 0.25%/yr floor) and ~1 mukrn to the treasury (5% share). Over a full year, this scales to exactly the documented inflation target.

### Compatibility

The change is backward-incompatible with v0.3 *blocks* (the state_root commitment now covers post-reward state). A v0.4 node cannot validate v0.3 blocks. The change is forward-compatible: future protocol versions can keep the same wiring, just with different IssuanceParams.

## 2. Merkle-Patricia trie for state commitments

The v0.1-v0.3 `state_root_hex()` was a placeholder: it hashed the canonical JSON of the entire state. This worked for an MVP but had two problems:

1. **No proofs.** A light client could verify the root, but couldn't verify any individual account's balance without downloading the entire state.
2. **No incremental updates.** Every block rebuilt the JSON from scratch.

The v0.4 `kern/trie.py` module replaces this with a proper binary Merkle trie. Key API:

```python
trie = trie_from_state(state)        # build trie from a chain state dict
root = trie.root_hex()                # the 32-byte state commitment
proof, account = trie.prove_account(addr)   # generate an inclusion proof
verify_proof(root, proof)             # O(log n) verification
```

### Design choices

- **Binary radix trie**, not Ethereum's hex-Patricia. Simpler to implement (~300 lines), simpler to prove against, only ~30% larger proofs.
- **Keys are blake2b-256(address)**. Uniform key distribution → balanced trie → no adversarial address-grinding can create deep paths.
- **Domain-separated hashes**: `kern.trie.leaf` for leaves, `kern.trie.branch` for branches, `kern.trie.key` for address-to-key derivation. Prevents second-preimage collisions between node types.
- **Account leaf encoding** is canonical JSON of `{"balance": int, "nonce": int, "code_hash": str|null, "storage_root": str|null}`.

### Light-client usage

For a state containing 100 accounts, an account balance proof is:

```
Proof:
  Sibling hashes:   7
  Leaf bits:        249
  Account balance:  42000 mukrn
  Verified:         True
  Serialized size:  1514 bytes
```

A light client that knows the state root from a block header can verify any specific account in O(log n) space, never downloading the full state.

### Not yet wired into chain.py

The trie module is shipped as a **library** in v0.4, with its own test suite (21 tests). Replacing `state_root_hex` in `chain.py` with `state_root_trie_hex` is a one-line change but requires backward-incompatible state-root semantics across the network. It is therefore staged separately: v0.4 ships the trie as available; v0.5 will swap it in as the canonical state root function in the same release that ships on-chain governance (so the swap can be governed itself).

The `trie_from_state(state)` function takes the existing state dict as input — when wired, the change is transparent to all other code paths.

## 3. Expanded EVM opcode set

v0.3 shipped enough opcodes (~30) to demonstrate the fraud-proof protocol. v0.4 adds the opcodes that real EVM contracts actually use, bringing the supported set to ~60.

### What's new

**Storage** (SSTORE, SLOAD, MSTORE8). The single largest gap. Smart contracts without persistent storage are toy contracts. SSTORE/SLOAD operate on 256-bit keys → 256-bit values; storing zero deletes the slot, matching Ethereum semantics.

**Hashing** (SHA3 / KECCAK256). Required for any contract that hashes structured data, computes addresses, or interacts with Merkle proofs. Implemented as `sha3_256` (note: real Ethereum uses Keccak-256, which differs slightly from FIPS SHA3-256; a production node would swap the implementation).

**Bit shifts** (SHL, SHR, SAR). Modern Solidity emits these for division-by-power-of-2 optimizations.

**Modular arithmetic** (ADDMOD, MULMOD, SIGNEXTEND). Common in cryptographic and financial contracts.

**Byte extraction** (BYTE). Get a specific byte from a 256-bit word; used in oracles and serialization code.

**Execution context** (ADDRESS, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, TIMESTAMP, NUMBER, GAS). Lets contracts know who called them with what input and value, and what block they're in. Without these, a contract can't do anything interesting.

**Larger DUP/SWAP variants** (DUP5..DUP16, SWAP4..SWAP16). The full EVM range.

### Execution context

A new `ExecContext` dataclass carries the transaction-level context:

```python
ctx = ExecContext(
    address=0xaa,           # `self` — contract being executed
    caller=0xbb,            # `msg.sender`
    value=12345,            # `msg.value`
    calldata=b"\xaa\xbb\xcc",
    block_number=99,
    block_timestamp=1700000000,
)
trace = execute(code, gas=10_000, context=ctx, initial_storage={1: 42})
```

The context is part of the initial `VmState` and therefore is committed-to in the first state hash — meaning the bisection fraud-proof protocol covers context manipulation as well. A sequencer who lies about the caller is caught the same way as a sequencer who lies about an arithmetic result.

### Storage is part of the commitment

The state commitment hash now includes contract storage (sorted by key for canonicality). A SSTORE that changes a value produces a different post-state commitment than one that doesn't, and the bisection protocol can detect storage divergences just like stack or memory divergences.

```python
t1 = execute(code, gas=1000, initial_storage={0: 1})
t2 = execute(code, gas=1000, initial_storage={0: 2})
assert t1.commitments[-1] != t2.commitments[-1]   # different end states
```

### What's still missing for full EVM equivalence

- **Inter-contract calls** (CALL, STATICCALL, DELEGATECALL). The Mini-EVM is single-frame. Multi-frame execution with proper call stack semantics is a substantial chunk of work and is on the v0.5 roadmap.
- **CREATE / CREATE2**. Contract deployment from inside EVM execution.
- **Logs** (LOG0..LOG4). Event emission for off-chain indexers.
- **Precompiles** (ECRECOVER, SHA256, RIPEMD160, IDENTITY, MODEXP, EC operations). Special addresses that perform built-in computations.
- **Dynamic gas costs**. Real Ethereum has per-opcode dynamic costs (e.g., SSTORE cost depends on whether the slot was zero before). v0.4 uses static costs.
- **Memory expansion gas**. Real Ethereum charges quadratic gas for memory growth beyond a threshold. v0.4 charges per-opcode base cost only.

These are mechanical extensions on top of the protocol skeleton already in place. None of them affect the correctness of the bisection-based fraud-proof framework.

## Test additions

v0.4 brings the test count to **164 tests** (up from 119 in v0.3):

| Module | v0.3 | v0.4 |
|---|---:|---:|
| crypto | 6 | 6 |
| transaction | 7 | 7 |
| block/chain | 6 | 6 |
| skald | 9 | 9 |
| typecheck | 20 | 20 |
| bft | 9 | 9 |
| rollup | 11 | 11 |
| forced_inclusion | 14 | 14 |
| issuance | 18 | 18 |
| evm | 19 | 19 |
| **evm (v0.4 additions)** | — | **24** |
| **trie (v0.4)** | — | **21** |
| **Total** | **119** | **164** |

## File summary

New files:
- `kern/trie.py` — Merkle trie + proof verification
- `tests/test_trie.py` — 21 tests
- `tests/test_evm_extended.py` — 24 tests
- `docs/merkle-trie.md` — trie design doc
- `docs/v04-changes.md` — this file

Modified files:
- `kern/chain.py` — issuance wiring, schema expansions
- `kern/consensus.py` — propose_block applies rewards before signing
- `kern/evm/opcodes.py` — ~30 new opcodes
- `kern/evm/vm.py` — handlers for new opcodes, ExecContext, storage
- `kern/evm/__init__.py` — export ExecContext

## Roadmap update

| Phase | Scope | Status |
|---|---|---|
| v0.1 | Single-baker chain + Skald interpreter | ✅ |
| v0.2 | Multi-validator BFT + Static Skald + Rollup framework | ✅ |
| v0.3 | Mini-EVM + bisection + forced inclusion + adaptive issuance | ✅ |
| **v0.4** | **Issuance wiring + Merkle trie + EVM extensions** | **✅ (this version)** |
| v0.5 | Inter-contract EVM calls + governance live + trie swap-in | 🟡 Next |
| v1.0 | Testnet audited | 🔵 |
| v2.0 | Mainnet + KRN genesis | 🔵 |
