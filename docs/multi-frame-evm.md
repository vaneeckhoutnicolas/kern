# Multi-frame EVM

This document describes Kern's multi-frame EVM execution model, implemented in [`kern/evm/frames.py`](../kern/evm/frames.py). It extends the single-frame Mini-EVM from [`evm-fraud-proofs.md`](evm-fraud-proofs.md) to support inter-contract calls (CALL / STATICCALL / DELEGATECALL), contract deployment (CREATE / CREATE2), and precompiles.

---

## Single-frame vs multi-frame

The v0.3 Mini-EVM in [`kern/evm/vm.py`](../kern/evm/vm.py) handles **one** EVM execution context — a single contract, called once, with its own stack/memory/storage/gas. That's enough to demonstrate the bisection fraud-proof protocol with real EVM semantics, but it's not enough for real EVM applications: any non-trivial DApp involves multiple contracts calling each other.

The v0.5 multi-frame layer adds:

- **WorldState**: the global EVM state — account balances, code, storage, nonces — keyed by address.
- **Frames**: recursive execution contexts. A CALL opcode pushes a frame; RETURN/STOP/REVERT pops it.
- **CALL / STATICCALL / DELEGATECALL**: the three call variants with their different semantics.
- **CREATE / CREATE2**: contract deployment from inside EVM execution.
- **Precompiles**: built-in functions at addresses 0x01..0x09 (ECRECOVER, SHA256, IDENTITY).
- **Snapshot / revert**: atomic rollback when a sub-call REVERTs.

## World state

```python
@dataclass
class Account:
    balance: int = 0
    code: bytes = b""
    storage: Dict[int, int] = field(default_factory=dict)
    nonce: int = 0

@dataclass
class WorldState:
    accounts: Dict[int, Account] = field(default_factory=dict)
```

The world state is the EVM's global ledger. It's the EVM analogue of Kern L1's `state` dict, restricted to the EVM execution domain (the rollup's state, not the L1 state).

Two key operations:

- `transfer(from, to, amount)` — atomic value transfer, returns False on insufficient balance.
- `snapshot()` / `revert_to(snap)` — take an immutable snapshot for atomic rollback.

## Call variants

The three CALL opcodes have different semantics — getting this right is one of the most-bug-prone parts of EVM implementation:

| Opcode | Storage modified | `msg.sender` | `msg.value` | State mutation allowed |
|---|---|---|---|---|
| `CALL` | Callee's | Caller | Specified by caller | Yes |
| `STATICCALL` | (none) | Caller | Always 0 | **No** — any SSTORE reverts |
| `DELEGATECALL` | Caller's | Outer caller (preserved) | Outer value (preserved) | Yes |

### CALL — ordinary call

```python
result = call_contract(world, kind=FrameKind.CALL,
                       caller=0x10, address=0x100,
                       value=1000, calldata=b"...", gas=100_000)
```

- Value is transferred from caller to callee.
- The callee runs with its own storage, its own context (`msg.sender = caller`, `msg.value = 1000`, `address = 0x100`).
- If the callee REVERTs, all changes (value transfer, storage writes) are atomically rolled back.

### STATICCALL — read-only call

Used for view functions. Has identical semantics to CALL but:
- `value` must be 0 (enforced; positive value → call fails).
- The `is_static` flag propagates to all sub-calls; any SSTORE while static reverts the call.

### DELEGATECALL — library pattern

This is the EVM's "use someone else's code with my state" primitive. Critical for the library pattern:
- The callee's code is executed.
- But the storage that gets mutated is the **caller's**, not the callee's.
- And `msg.sender` / `msg.value` are preserved from the outer call.

A typical use: a "Vault" contract uses DELEGATECALL to invoke shared library code that mutates the Vault's own storage. This is also the foundation of upgradeable-proxy patterns (the proxy DELEGATECALLs to an implementation contract).

## Atomic semantics

Every call goes through a snapshot:

```python
snap = world.snapshot()
try:
    # value transfer + execution
    ...
    if reverted:
        world.revert_to(snap)
except:
    world.revert_to(snap)
```

The snapshot is a deep copy of the entire `accounts` dict. If the call succeeds, the snapshot is discarded. If it REVERTs, the world is restored.

This is what makes calls atomic: a REVERT inside a deeply-nested call chain undoes *exactly that sub-call's effects*, not the whole transaction.

## Contract creation

CREATE and CREATE2 deploy new contracts by running `init_code` and storing whatever bytes it RETURNs as the new contract's code.

```python
addr, result = create_contract(
    world, creator=0xabc, init_code=init_bytecode,
    value=0, gas=100_000,
)
```

### CREATE

Address = `blake2b(creator || nonce)[12:32]`. The creator's nonce is bumped (regardless of whether init_code succeeds — matches Ethereum), making each CREATE produce a fresh address.

### CREATE2

Address = `blake2b(creator || salt || hash(init_code))[12:32]`. The salt lets the deployer **pick** the address: same salt + same init_code → same address. Enables counterfactual deployment patterns where you can interact with a contract before it's been deployed (since you know its future address).

The reference implementation uses blake2b for address derivation; real Ethereum uses keccak256 with RLP encoding. The choice doesn't change the deterministic-address property.

## Precompiles

Precompiles are functions at fixed low addresses (0x01..0x09) that are *not* EVM contracts but get invoked through the normal CALL flow. They're the EVM's way of exposing cryptographic primitives that would be prohibitively expensive to implement as EVM bytecode.

v0.5 implements three:

### 0x01 — ECRECOVER

Recovers an address from a signature. Kern uses **Ed25519** instead of Ethereum's secp256k1 — this is a deliberate divergence to match the rest of the Kern protocol (validator keys, transaction signatures, etc., all use Ed25519). Calldata layout:

```
[ 32-byte message hash | 32-byte public key | 64-byte signature ]
```

Returns the 20-byte address (= blake2b-160 of the pubkey, matching Kern's address derivation), left-padded to 32 bytes. On bad signature: returns 32 zero bytes.

### 0x02 — SHA256

Standard SHA-256 of the input. No special semantics; output is the 32-byte hash.

### 0x04 — IDENTITY

Returns calldata unchanged. EVM contracts use this as a `memcpy` primitive — CALL with `output_size = input_size` and the precompile address copies bytes between memory regions cheaply.

### Not yet implemented

| Address | Function | Status |
|---|---|---|
| 0x03 | RIPEMD160 | Stub — easy to add |
| 0x05 | MODEXP | Stub — long-tail use |
| 0x06 | BN_ADD (BN254 point addition) | Stub |
| 0x07 | BN_MUL (BN254 scalar mul) | Stub |
| 0x08 | BN_PAIRING (BN254 pairing) | Stub — needed for zkSNARK verification |
| 0x09 | BLAKE2F | Stub |

Adding any of these is a single function in `kern/evm/frames.py`. The control-plane (gas accounting, calldata extraction, return-data packaging) is already in place.

## Address derivation

Addresses in the multi-frame EVM are 256-bit integers (matching the EVM's word size), not the `kn1...` base58 strings used at L1. This is correct for EVM compatibility: existing Solidity tools expect 20-byte addresses formatted as 0x-prefixed hex.

The bridge between the two address spaces happens at the rollup bridge contract (see [`rollups.md`](rollups.md)): an L1 `kn1...` address that deposits funds into the rollup gets a corresponding EVM 256-bit address derived deterministically.

## Fraud proofs across frames

The bisection fraud-proof protocol from [`evm-fraud-proofs.md`](evm-fraud-proofs.md) extends naturally to multi-frame execution:

- Each frame produces its own sequence of `VmState` commitments via the step-wise VM.
- The frame stack itself is part of the state hashed at each step.
- A divergence in *any* frame at *any* step is detectable via the same `O(log n)` bisection.
- The single-step verifier re-runs one EVM instruction in the disputed frame, with the disputed pre-state, and decides who's right.

The single-frame protocol covers single contract execution; the multi-frame extension covers contract-calls-contract execution. No new protocol primitives are needed.

## Gas accounting

CALL-family opcodes have a base cost (700 gas) plus the cost of the sub-call's actual execution. The sub-call's gas budget is the *forwarded* gas (a parameter on the stack), which can be less than the caller's remaining gas. Unused gas is returned to the caller.

CREATE costs 32 000 gas plus the cost of executing `init_code`. The deployed contract's storage and code stay around perpetually, justifying the high base cost.

LOG0..LOG4 cost 375 + 375 × N gas (where N is the number of indexed topics). Logs themselves don't return data; they're emitted as side-effect events for off-chain indexing.

These costs match the Ethereum Yellow Paper rough orders of magnitude. Dynamic gas (e.g., SSTORE's cost depending on the previous slot value) is simplified to static costs in v0.5; matching real Ethereum's dynamic gas is a v0.6 refinement.

## What multi-frame enables in real applications

This is the layer that makes the rollup useful. With single-frame EVM, you could prove arithmetic correctness; with multi-frame, you can run real DeFi:

- **AMMs**: a `Router` contract that CALLs an `LP` contract to swap, which CALLs the underlying `ERC20` tokens to transfer.
- **Lending**: a `Comptroller` that STATICCALLs price oracles, then CALLs collateral handlers, then CALLs the liability ledger.
- **Upgradeable contracts**: a thin Proxy contract that DELEGATECALLs to an Implementation, where the Implementation can be replaced via governance.
- **Cross-contract composability**: any DApp built from multiple contracts that interact.

None of these patterns work without multi-frame execution. v0.5 brings them in.

## Reference

[`kern/evm/frames.py`](../kern/evm/frames.py) (~330 lines) provides:

- `Account`, `WorldState` — global state
- `Frame`, `FrameKind`, `CallResult` — frame abstractions
- `call_contract(...)` — top-level CALL / STATICCALL / DELEGATECALL dispatch
- `create_contract(...)` — CREATE / CREATE2 deployment
- `derive_create_address`, `derive_create2_address` — deterministic address derivation
- Precompiles dict, `is_precompile`, `execute_precompile`

Tested in [`tests/test_evm_frames.py`](../tests/test_evm_frames.py) (25 tests) covering:

- World state ops (get/transfer/snapshot/revert)
- Precompile dispatch (SHA256, IDENTITY, ECRECOVER with valid Ed25519 sig)
- CALL with value transfer, return data, revert rollback
- CALL persists storage on success
- STATICCALL allows pure views, rejects value, rejects SSTORE
- DELEGATECALL mutates caller's storage
- CREATE / CREATE2 deterministic addresses, init_code execution, nonce bumping
