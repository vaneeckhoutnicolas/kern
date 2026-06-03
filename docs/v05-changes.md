# Kern v0.5 — what changed

This document summarizes the v0.5 changes made on top of v0.4. Three pieces, in order of impact: **on-chain governance live**, the **state-root function swap via governance**, and the **multi-frame EVM**.

For the design rationale and full specifications, see:
- [`governance.md`](governance.md) for the two governance tracks
- [`multi-frame-evm.md`](multi-frame-evm.md) for CALL/STATICCALL/DELEGATECALL/CREATE
- [`merkle-trie.md`](merkle-trie.md) for the trie now in active production use

---

## 1. On-chain governance live

The v0.5 release brings governance from spec to working code. Both tracks — protocol amendments and treasury allocations — now run as actual state machines that walk proposals through phases, tally validator-stake-weighted votes, and apply activated changes to the chain.

### What changed

- **New module** [`kern/governance.py`](../kern/governance.py) (~450 lines):
  - `ProtocolGovernance` state machine — 5-phase cycle (Submitted, Exploration, Cooldown, Adoption, Activated)
  - `TreasuryGovernance` state machine — 2-phase cycle (Submitted, Voting)
  - Stake-weighted tallying with quorum (25%) and supermajority (80%) thresholds for protocol; simple majority (50%) for treasury
  - Payload validation for both tracks
  - Two on-chain Skald contracts: `ProtocolGovernance` and `Treasury`

- **Payload kinds**:
  - `{"params": {...}}` — change one or more protocol parameters (issuance, block time, etc.)
  - `{"swap": "<target>", "to": "<value>"}` — replace a core protocol function (used for the trie swap-in demo)
  - Treasury: `{"recipients": [{"address": ..., "amount": ...}, ...], "memo": ...}`

### Observable behavior

The integration test in [`tests/test_state_root_swap.py`](../tests/test_state_root_swap.py) drives a full 5-phase protocol amendment that swaps the state-root function. From submission to activation: 4 transitions (advance_phases) plus 2 voting rounds (unanimous yes both times). The chain's `state_root_hex(state)` returns different values before and after activation — same state, different commitment, governed by the chain's own rules.

### What's not yet wired

- The governance state machines exist as Python; they are **not yet automatically called** from `apply_block`. Doing so requires deciding where the governance state lives (in the chain state dict? in dedicated contracts?). v0.6 will make this decision and wire it. For now, governance is invoked manually by node operators and demonstrated in integration tests.
- Vote messages over the network: validators currently call `gov.vote(...)` directly. v0.6 will define a `GovernanceVote` message kind exchanged via the P2P layer, with the same signature/equivocation rules as BFT consensus messages.

## 2. State-root function swap via governance

The v0.4 release shipped the binary Merkle trie as an importable module but did not swap it into `chain.py::state_root_hex()`. The v0.5 release wires the swap, **under governance control**.

### What changed

- `chain.py::state_root_hex(state)` now dispatches based on the state's `state_root_function` field:
  - `"json"` (default for backward compatibility) → JSON-hash commitment, as in v0.1-v0.4.
  - `"trie"` → binary Merkle trie commitment from `kern.trie.state_root_trie_hex`.
- The dispatch field is **set by governance activation**: when a `{"swap": "state_root_function", "to": "trie"}` proposal reaches ACTIVATED, the runtime updates the state's `state_root_function` field. From the activation block onward, all blocks use the trie commitment.
- `empty_state()` initializes `state_root_function = "json"` for backward compatibility.

### Why this matters

This is the v0.5 proof point. The chain replaces a **core function of itself** through its own governance rails. No hard fork. No off-chain coordination. The community votes; the chain respects the vote. The light-client proof system (already shipped in v0.4) becomes active for any block produced after the activation.

This is the architectural claim made in the executive summary made concrete: "on-chain self-amendment" is not aspirational — it works, and the v0.5 release demonstrates it.

## 3. Multi-frame EVM

The v0.3 Mini-EVM handled single-contract execution. v0.5 adds the call-frame layer that real applications need.

### What changed

- **New module** [`kern/evm/frames.py`](../kern/evm/frames.py) (~330 lines):
  - `WorldState` and `Account` for global EVM state
  - `call_contract()` — top-level dispatch for CALL / STATICCALL / DELEGATECALL
  - `create_contract()` — CREATE and CREATE2 deployment
  - Snapshot/revert semantics for atomic rollback
  - Precompiles at addresses 0x01..0x09 (ECRECOVER, SHA256, IDENTITY implemented; others stubbed)

- **Opcode set expansion** in `kern/evm/opcodes.py`:
  - CALL (0xf1), STATICCALL (0xfa), DELEGATECALL (0xf4), CALLCODE (0xf2)
  - CREATE (0xf0), CREATE2 (0xf5)
  - LOG0..LOG4 (0xa0..0xa4)
  - INVALID (0xfe)
  - Gas costs declared per opcode

### Call semantics

The three CALL variants are correctly distinguished:

| Opcode | Storage modified | `msg.sender` | `msg.value` | State mutation allowed |
|---|---|---|---|---|
| CALL | Callee's | Caller | Specified by caller | Yes |
| STATICCALL | (none) | Caller | Always 0 | No (any SSTORE reverts) |
| DELEGATECALL | Caller's | Outer caller (preserved) | Outer value (preserved) | Yes |

DELEGATECALL is what makes the library pattern (and upgradeable-proxy patterns) work. STATICCALL is what lets view functions be called from other contracts without risk of mutation.

### Atomic rollback

Every call is wrapped in a `world.snapshot()`. If the inner execution REVERTs, the snapshot restores the world atomically — value transfers undone, storage writes undone, even nested sub-call effects undone. This is what makes EVM contracts safe to compose: a failure deep in a call chain doesn't corrupt the outer caller's state.

### Precompile choice: Ed25519 for ECRECOVER

Kern's address space, validator keys, and transaction signatures all use Ed25519. To keep the EVM consistent with the rest of the protocol, the ECRECOVER precompile (address 0x01) uses Ed25519 — not the secp256k1 used by Ethereum.

Calldata layout: `[ 32-byte msg hash | 32-byte pubkey | 64-byte sig ]`. On valid signature: returns the 20-byte address (blake2b-160 of the pubkey, matching Kern's L1 address derivation), left-padded to 32 bytes. On invalid: returns 32 zero bytes.

This is a deliberate divergence from Ethereum that lets Kern's cryptographic identity stack be uniform top to bottom. Solidity contracts that explicitly invoke ECRECOVER will need to switch to Ed25519 signature inputs — a one-line change in any contract that previously called it.

## Tests

v0.5 brings the test count to **221 tests** (up from 192 in v0.4):

| Module | v0.4 | v0.5 |
|---|---:|---:|
| crypto, transaction, block/chain | 19 | 19 |
| skald + typecheck | 29 | 29 |
| bft, rollup, forced_inclusion | 34 | 34 |
| issuance | 18 | 18 |
| evm (v0.3 + v0.4 extensions) | 43 | 43 |
| trie | 21 | 21 |
| **governance** | — | **28** |
| **state_root_swap (integration)** | — | **4** |
| **evm_frames (multi-frame)** | — | **25** |
| **Total** | **192** | **221** |

## File summary

**New files**:
- `kern/governance.py` — protocol amendment + treasury state machines
- `kern/evm/frames.py` — multi-frame execution, CALL variants, CREATE, precompiles
- `tests/test_governance.py` — 28 tests
- `tests/test_state_root_swap.py` — 4 integration tests
- `tests/test_evm_frames.py` — 25 tests
- `docs/governance.md` — full governance specification
- `docs/multi-frame-evm.md` — multi-frame EVM doc
- `docs/v05-changes.md` — this file

**Modified files**:
- `kern/chain.py` — `state_root_hex` dispatches on `state_root_function`; new state key
- `kern/evm/opcodes.py` — CALL/CREATE/LOG opcodes + gas costs
- `kern/evm/__init__.py` — exports frames API

## Roadmap update

| Phase | Scope | Status |
|---|---|---|
| v0.1 | Single-baker chain + Skald interpreter | ✅ |
| v0.2 | Multi-validator BFT + Static Skald + Rollup framework | ✅ |
| v0.3 | Mini-EVM + bisection + forced inclusion + adaptive issuance | ✅ |
| v0.4 | Issuance wiring + Merkle trie + EVM extensions | ✅ |
| **v0.5** | **Governance live + trie swap-in + multi-frame EVM** | **✅ (this version)** |
| v0.6 | Governance auto-wire into apply_block; vote messages over P2P; quadratic treasury; remaining precompiles; dynamic gas | 🟡 Next |
| v1.0 | Testnet audited | 🔵 |
| v2.0 | Mainnet + KRN genesis | 🔵 |
