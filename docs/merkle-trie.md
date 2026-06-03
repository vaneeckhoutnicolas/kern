# Merkle-Patricia Trie — state commitments with proofs

This document describes Kern's binary Merkle trie, implemented in [`kern/trie.py`](../kern/trie.py). It is the v0.4 piece that replaces the placeholder "hash the JSON of the state" with a real state commitment scheme that supports light-client proofs.

---

## The problem

A blockchain's `state_root` is a hash that commits to every account balance, every contract storage slot, every validator, at a given block. The simplest implementation — `hash(canonical_json(state))` — works in the sense that all honest nodes converge on the same root, but it has two limitations:

1. **No proofs.** A light client (a wallet, an explorer, an oracle) that only follows block headers has no way to *verify* "account A has balance B at state root R" without downloading the entire state.
2. **No incremental updates.** Every block rebuilds the root from scratch by re-canonicalizing and re-hashing the full state.

Real blockchains solve this with a Merkle trie keyed by account. Ethereum's hex-Patricia trie is the canonical reference; Kern's design is a deliberately simpler binary variant.

## Why a binary trie

Ethereum's Merkle-Patricia trie is **hex** (4-bit nibbles, 17-element branch nodes) for historical compatibility with RLP encoding. The simpler choice is a **binary** radix trie (1-bit branching, 2-element branch nodes). Properties:

| Property | Binary trie | Hex Patricia |
|---|---|---|
| Implementation complexity | ~300 lines | ~1500 lines |
| Proof size | ~30% larger | smaller |
| Cryptographic safety | identical (both use blake2b/keccak) | identical |
| Lookup time | O(log₂ n) | O(log₁₆ n) |
| Insertion logic | clean (binary tree) | complex (path compression + nibble alignment) |

Kern picks the binary variant: the protocol's value is in the *property* (any state read can be proved), not in matching Ethereum's specific layout. The 30% size difference is a cheap price for a much simpler implementation and audit surface.

## Design

### Keys

Account addresses are arbitrary-length strings. The trie keys are uniformly 32 bytes (256 bits), derived by hashing:

```
trie_key = blake2b256("kern.trie.key", address.encode("utf-8"))
```

Uniformly-distributed keys mean the trie stays roughly balanced — no adversary can craft an address that creates a degenerate deep path. Lookup time is `O(log n)` where n is the number of accounts.

### Node structure

A node is one of two kinds:

- **Leaf.** Holds the *residual key bits* (the part of the 256-bit key not absorbed by the path from root) and the *value* (the canonical account state encoding).
- **Branch.** Holds two child pointers, `left` (bit 0) and `right` (bit 1). Either or both may be empty (None), which hashes to `0x00...00`.

### Hashing

Domain-separated blake2b-256:

```
leaf_hash(key_bits, value)     = blake2b256(key="kern.trie.leaf",
                                            len(key_bits) || key_bits ||
                                            len(value) || value)

branch_hash(left, right)        = blake2b256(key="kern.trie.branch", left || right)

empty subtree hash              = 0x00...00 (32 zero bytes)
```

Domain separation prevents a leaf from being confused with a branch — without it, an adversary might construct a leaf whose hash equals a branch hash, creating proof ambiguity. The keyed-blake2b approach is structurally similar to BLAKE2's tree hashing mode.

### Account encoding

A leaf's value is the canonical JSON encoding of an account state dict:

```json
{
  "balance":      <int>,
  "nonce":        <int>,
  "code_hash":    <hex string or null>,
  "storage_root": <hex string or null>
}
```

Sorted keys, no whitespace, UTF-8. Deterministic across implementations.

For contract accounts, `code_hash` is the blake2b-256 of the canonical Skald source, and `storage_root` is (currently) a hash of the contract's storage dict. A future version will replace `storage_root` with a per-contract Merkle trie root, giving proofs of individual storage slots — the same architecture, one level down.

## API

```python
from kern.trie import (
    MerkleTrie, Proof,
    address_to_key, make_account, encode_account, decode_account,
    verify_proof, trie_from_state, state_root_trie_hex,
)

# Build a trie from scratch
trie = MerkleTrie()
trie.set_account("kn1alice", make_account(balance=1000, nonce=3))
trie.set_account("kn1bob",   make_account(balance=2000))
root = trie.root_hex()

# Generate a proof
proof, account = trie.prove_account("kn1alice")
assert account["balance"] == 1000

# Verify independently
assert verify_proof(root, proof)

# Build from a chain state dict
state = {"balances": {...}, "nonces": {...}, "contracts": {...}}
root = state_root_trie_hex(state)
```

## Proofs

An inclusion proof for an account is:

```python
@dataclass
class Proof:
    key:                bytes           # 32-byte trie key
    value:              bytes           # account leaf value
    leaf_residual_bits: List[int]       # bits of the key not in branch path
    siblings:           List[bytes]     # sibling hash at each branch level
    bits_taken:         List[int]       # 0=went left, 1=went right at each level
```

Verification:

```python
def verify_proof(root_hex, proof):
    # 1. Check that bits_taken + leaf_residual_bits reconstitute the full key.
    # 2. Hash the leaf with leaf_residual_bits and value.
    # 3. Walk up the tree, combining with each sibling per the recorded direction.
    # 4. Compare reconstructed root to root_hex.
```

The verifier only needs:
- The `root_hex` (from a block header)
- The `Proof` object

That's enough to verify "the chain state at this root contains an account at this address with this balance and nonce". No need to trust the node that produced the proof; no need to download the rest of the state.

### Proof sizes

For a chain with N accounts, a proof contains:
- 32-byte key
- ~50-byte value (typical account)
- ~256 leaf residual bits (32 bytes)
- ~log₂(N) sibling hashes (32 bytes each)

For 100 accounts: ~7 siblings × 32 bytes = ~224 bytes of siblings, plus the leaf + key ≈ 350 bytes raw. Serialized as JSON-hex: ~1.5 KB.

For 1 million accounts: ~20 siblings × 32 bytes = ~640 bytes of siblings, similar overhead. The proof grows logarithmically — even at billion-account scale, proofs stay under 2 KB.

## Performance characteristics

| Operation | Cost |
|---|---|
| `set(key, value)` | O(log n) hash operations |
| `get(key)` | O(log n) lookups |
| `root_hex()` | O(n) if recomputed from scratch (TODO: incremental hashing in v0.5) |
| `prove(key)` | O(log n) |
| `verify_proof(root, proof)` | O(log n) hashes |

The current implementation rebuilds the trie from scratch on each call (immutable persistent structure). A v0.5 optimization will cache subtree hashes and only re-hash the path from the modified leaf to the root.

## Why not wire it into chain.py yet?

The v0.4 release ships the trie as an importable module with full tests, but does **not** swap it into `chain.py::state_root_hex()`. The reason is that the state_root commitment is part of the block header signed by the proposer; changing the function changes the state_root values, which is a backward-incompatible network change.

The swap is staged for v0.5, alongside the launch of on-chain governance, so that the migration itself can be governed: the protocol-amendment cycle votes on the trie swap before it activates. This is what governance is for.

The current `kern/trie.py::state_root_trie_hex(state)` is a drop-in replacement for `kern/chain.py::state_root_hex(state)`. When the swap happens, it is a one-line change in `chain.py`.

## Comparison with other chains

| Chain | State commitment | Proof type | Proof size for typical chain state |
|---|---|---|---|
| Bitcoin | UTXO set (no Merkle proofs for state) | — | n/a |
| Ethereum | Merkle-Patricia (hex) | Branch + leaf | ~1.5 KB |
| Cosmos / Tendermint | IAVL+ tree | AVL-style | ~1 KB |
| Tezos | Skiplist / Sparse Merkle | Sparse Merkle | ~1 KB |
| **Kern (v0.4)** | **Binary Merkle radix** | **Binary inclusion** | **~1.5 KB** |

Kern's binary Merkle trie has the same security and verifiability properties as Ethereum's hex Patricia, with substantially smaller implementation complexity. It is in the same family as Cosmos's IAVL+ and Tezos's sparse Merkle, with the difference being the specific tree shape and hashing scheme.

## Reference

[`kern/trie.py`](../kern/trie.py) (~300 lines) provides the full implementation. [`tests/test_trie.py`](../tests/test_trie.py) (21 tests) covers:

- Empty trie root determinism
- Set/get round-trips, single and at scale
- Get of missing keys returns None
- Overwrite replaces value
- Root depends on contents
- Root is independent of insertion order (a critical invariant)
- 100-entry insertion + lookup correctness
- Proof generation + verification, single and at scale
- Proof rejects tampered values and tampered siblings
- Proof serialization round-trip (for off-chain use)
- Proof for missing key raises
- Account-helper convenience API
- `trie_from_state` builds a trie from a chain state dict
- End-to-end light-client verification scenario
- 32-byte root length sanity
