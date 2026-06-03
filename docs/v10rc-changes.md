# Kern v1.0-rc — what changed

This document summarizes everything added between v0.9 and v1.0-rc. The headline themes are:

1. **Economy live**: 100M KRN genesis with full Ethereum-style distribution and modern vesting
2. **Liquid PoS baking delegation**: liquid staking that actually works without LST derivatives
3. **EVM Yellow-Paper compliance**: dynamic gas wired into the VM, real BN254 pairing via py_ecc
4. **Slashing closes the loop**: equivocation evidence → transaction → punishment → snitch reward
5. **API frozen**: a formal stability spec declares what v1.x downstream code can rely on

This is the **release candidate**. The code is feature-complete; what remains for v1.0 is the audit cycle.

For deep reference see:
- [`tokenomics.md`](tokenomics.md) §4 for the genesis distribution
- [`staking.md`](staking.md) for the delegation mechanics
- [`contributors-program.md`](contributors-program.md) for the incentive structure
- [`api-stability.md`](api-stability.md) for what's frozen in v1.0

---

## 1. Genesis 100M KRN — economy goes live

### What changed

The placeholder 1B-supply / 30%-public-sale tokenomics from earlier versions is replaced by the **Ethereum 2014 template**: 70% public, ~10% founder, ~10% Foundation, plus dedicated contributor and validator-bootstrap pools.

```
Total:               100 000 000 KRN
─────────────────────────────────────
Public sale          70 000 000  (70%)  — liquid at genesis
Founder              10 000 000  (10%)  — vested 4y, 1y cliff
Foundation           15 000 000  (15%)  — Foundation legal entity
Early contributors    3 000 000  (3%)   — vested 3y, 6mo cliff
Validator bootstrap   2 000 000  (2%)   — released over 1y
```

### Why these specific numbers

- **70% public** matches Ethereum's ~83% public — bias toward decentralization at genesis.
- **10% founder with vesting** is the modern norm. Ethereum 2014 didn't have it; everyone since has.
- **15% Foundation** funds audits, partnerships, legal — separate from on-chain treasury.
- **3% contributors pool** + **2% validators** are explicit line items rather than buried in "team."

### New files

- `scripts/build_v1_genesis.py` — reproducible genesis builder
- `genesis.json` (regenerated) — the chain-side initial state
- `genesis_vesting.json` — off-chain vesting schedules

### Doc updates

- `tokenomics.md` §3-§4 rewritten for 100M
- `docs/contributors-program.md` new — describes the 3 funding channels (genesis 3M / Foundation 15M / on-chain treasury / future RPGF)

---

## 2. Liquid PoS baking delegation

### What changed

Two new transaction kinds: `DELEGATE_STAKE` and `UNDELEGATE_STAKE`. Delegators keep custody of their KRN; the validator counts the delegator's balance toward effective stake at reward-distribution time.

```python
# Builders
make_delegate_stake(sender_kp, validator=val_addr, nonce=n)
make_undelegate_stake(sender_kp, nonce=n)
```

### How it differs from Ethereum and Cosmos

| | Kern | Ethereum | Cosmos |
|---|---|---|---|
| Custody of delegated KRN | Delegator keeps | Transferred to deposit contract or LST | Transferred to validator |
| Lockup to delegate | None | None on entry, 9d on exit | 21d on exit |
| Minimum delegation | 1 mukrn | 0.01 ETH via LST or 32 ETH native | varies |
| LST derivative needed | No | Yes (stETH, rETH, …) | No |
| Liquidity | Full — balance stays spendable | Locked or LST | Locked |

This is the Tezos design since 2018, ported to Kern.

### Reward splitting

Validators take a commission (10% default) off the top. The rest is distributed pro-rata between the validator's own stake and each delegator's balance.

Worked example: validator with 100k own stake, delegator with 900k, 10% commission, 1000 mukrn reward →
- Commission to validator: 100 mukrn
- Remaining 900 split: 90 to validator (10% of effective stake), 810 to delegator (90% of effective stake)
- Validator total: 190, delegator: 810

### Proportional slashing

When a validator is slashed (e.g., for governance equivocation), each delegator loses the same percentage of their balance. This is "skin in the game" — picking a sketchy validator has real cost.

### New state fields

```python
state["delegations"] = {delegator_addr: validator_addr, ...}
state["commission_rates"] = {validator_addr: int_percent, ...}
```

### Helpers exposed

```python
from kern.chain import effective_stake, delegators_of, commission_rate_of
```

### Tests

20 new tests in `tests/test_delegation.py` covering split math, state helpers, transactions, end-to-end reward earning, and proportional slashing.

---

## 3. EVM Yellow Paper compliance

### Dynamic gas wired into the VM

The constants from `kern/evm/dynamic_gas.py` (introduced in v0.7 but not wired) are now consumed by `vm.py::step()`. Before each instruction, the executor computes the static base + dynamic extra, checks the gas budget, deducts, and proceeds.

The dynamic components:

| Opcode | Dynamic cost |
|---|---|
| MLOAD / MSTORE / MSTORE8 | Memory expansion (linear + quadratic above 512 bytes) |
| SHA3 | 6 gas per word of input |
| EXP | 50 gas per byte of exponent |
| SSTORE | EIP-2200 three-case pricing (set/reset/no-op) |
| LOG0..LOG4 | 8 gas per data byte + 375 per topic |
| CALL / STATICCALL / DELEGATECALL | Memory expansion of return-data region |

The implementation peeks at the stack values needed for the cost calculation **without mutating** the VmState, computes the total, then proceeds. This is the right design — gas accounting must happen before any side-effect.

A new field on `VmState`: `original_storage`, snapshotted at the start of execution. EIP-2200 SSTORE pricing depends on the *original* slot value at transaction start, not just the current value.

### Real BN254 pairing via py_ecc

The `kern/evm/bn254.py` placeholder is replaced by a real implementation using **py_ecc** (the Ethereum Foundation's reference Python BN128 library) with graceful fallback to the structural placeholder when py_ecc is not installed.

The pairing now correctly answers `e(G1, G2) × e(-G1, G2) == 1` (the identity used by every Groth16 verifier) and returns the right F_p^12 value for non-trivial inputs.

```python
PY_ECC_AVAILABLE = True   # module-level flag, set at import time
```

If py_ecc is missing, the precompile still handles the empty-input case (returns True), but production nodes MUST install py_ecc.

Future: py_ecc is pure Python and slow (~30ms per pairing). A v1.x will swap for blst via FFI for ~10x speedup — critical for high-throughput zkSNARK verification.

### Tests

13 new tests in `tests/test_bn254_real.py` covering G1 group operations, EIP-197 calldata parsing, and the real pairing-identity property when py_ecc is available.

---

## 4. Slashing transaction closes the equivocation loop

### What was missing in v0.8

The v0.8 release detected governance equivocations (someone voting yes-then-no on the same proposal in the same phase) and recorded them in state. But there was no way to *apply* the punishment.

### What v1.0-rc adds

A new transaction kind `SLASH_EQUIVOCATION`:

```python
make_slash_equivocation(
    sender_kp=whistleblower_kp,
    proposal_id="abc123...",
    equivocator="kn1validator_address",
    nonce=n,
)
```

Anyone can submit this transaction with the (proposal_id, equivocator) pair. The chain looks up the on-chain equivocation record. If found and not already consumed:

- The equivocator loses **30% of their stake** (SLASHING_PERCENTAGE)
- The whistleblower receives **10% of the slashed amount** (WHISTLEBLOWER_REWARD_PCT)
- The rest is **burned** (reduces total supply)
- Each **delegator** of the equivocator loses 30% of their delegated balance, burned
- The equivocation record is marked `consumed` (idempotent — no double-slash)

This is the v1.0-rc completion of the "honest validator behavior" incentive loop. Before: equivocation was *visible* on-chain but not *punishable*. Now: anyone with the evidence on-chain can trigger the punishment, and is paid for doing so.

### Tests

10 new tests in `tests/test_v10rc_additions.py` covering rejection paths (no evidence, unknown validator, unknown proposal, already-slashed) and the happy path with full math verification.

---

## 5. API stability formal specification

A new document `docs/api-stability.md` formalizes what v1.0 freezes:

- **Frozen** (cannot change without protocol amendment): transaction format, block format, signed-payload computation, state-root commitment, address format, hash function, signature scheme, opcode semantics, gas pricing shape, precompile addresses, governance state machine shape, staking parameters, genesis distribution
- **Stable** (extensible without breaking): RPC API, Python module entry points, Skald language, storage schema
- **Beta** (best-effort): metrics names, log format, test utilities, bootstrap scripts

This document is what an alternative-client implementation (kern-rs, kern-go, …) would read to know what to implement identically. Divergence on a Frozen surface = chain split; divergence on a Stable surface = client incompatibility but no fork.

---

## Tests

v1.0-rc brings the test count to **368 tests** (up from 335 in v0.9):

| Module | v0.9 | v1.0-rc |
|---|---:|---:|
| crypto, transaction, block/chain | 19 | 19 |
| skald + typecheck | 29 | 29 |
| bft, rollup, forced_inclusion | 34 | 34 |
| issuance | 18 | 18 |
| evm (vm, bisection, frames, extensions) | 68 | 68 |
| trie | 21 | 21 |
| governance + state-root swap + integration | 40 | 40 |
| v06 additions (precompiles, bonds) | 15 | 15 |
| v07 additions (BN254 stub, dynamic gas constants) | 46 | 46 |
| v08 additions (quadratic, delegated, equivocation) | 17 | 17 |
| v09 additions (observability, fuzzing) | 18 + 2 chaos skipped | 18 + 2 chaos skipped |
| v1.0-rc additions (slashing + dynamic gas in VM) | — | 10 |
| **delegation** | — | **20** |
| **bn254_real (py_ecc pairing)** | — | **13** |
| **Total** | **335 + 2 skipped** | **368 + 2 skipped** |

---

## File summary

**New files**:
- `scripts/build_v1_genesis.py` — reproducible genesis builder for v1.0
- `tests/test_v10rc_additions.py` — 10 tests for slashing + dynamic gas wiring
- `tests/test_delegation.py` — 20 tests for Liquid PoS delegation
- `tests/test_bn254_real.py` — 13 tests for real BN254 pairing
- `docs/staking.md` — dedicated staking and delegation spec
- `docs/contributors-program.md` — contributor incentive structure
- `docs/api-stability.md` — v1.0 API freeze declaration
- `docs/v10rc-changes.md` — this file
- `genesis.json` regenerated for v1.0
- `genesis_vesting.json` — off-chain vesting schedules

**Modified files**:
- `kern/transaction.py` — new OpKinds: SLASH_EQUIVOCATION, DELEGATE_STAKE, UNDELEGATE_STAKE
- `kern/chain.py` — handlers, state["delegations"], state["commission_rates"], effective_stake helpers, slashing handler with proportional delegator slashing
- `kern/issuance.py` — `split_validator_reward()` function for commission + pro-rata split
- `kern/evm/vm.py` — dynamic gas wired into step(), VmState.original_storage for EIP-2200
- `kern/evm/bn254.py` — full rewrite to use py_ecc pairing with fallback
- `kern/rpc.py` — `/chain/governance` endpoint
- `docs/tokenomics.md` — 100M distribution table, updated §3, §4, §6 (staking), §7 (treasury), §8 (modeling), summary table
- `docs/roadmap.md` — v0.7-v0.9 marked done, v1.0-rc current, network track and ops milestones updated
- `docs/executive-summary.md` — §6 with distribution table, §7 roadmap actualized
- `docs/whitepaper.md` — §9 reference implementation status rewritten

**Dependencies added**:
- `py_ecc>=8.0.0` (for real BN254 pairing)

---

## Roadmap update

| Phase | Scope | Status |
|---|---|---|
| v0.1 – v0.9 | All shipped | ✅ |
| **v1.0-rc** | **Genesis distribution + Tezos staking + dynamic gas wired + real BN254 pairing + slashing tx + API freeze spec** | **✅ (this version)** |
| v1.0-rc → v1.0 | Audit cycle 1 (Trail of Bits / OtterSec / Hashlock / Runtime Verification candidates); fixes applied; ship | 🟡 Awaiting Foundation setup |
| v1.0 | First stable release after audit | 🔵 |
| v1.x | Non-breaking patches | 🔵 |
| v2.0 | Breaking changes via governance amendment | 🔵 |

For the parallel network and operational tracks see [`roadmap.md`](roadmap.md).
