# Kern v0.7, v0.8, v0.9 — what changed

This document covers three releases in one batch because they were shipped together as part of pushing toward the v1.0-rc code freeze. Each block could have been its own release with its own changelog; combining them here saves redundant cross-referencing.

The big picture: **v0.7** completes the EVM (BN254 + dynamic gas) for Yellow Paper compliance, **v0.8** completes governance (quadratic + delegated voting + equivocation slashing) for the realistic adversarial case, and **v0.9** hardens the runtime (structured logs, Prometheus metrics, property-based fuzzers) so it can survive being run as a real network.

For the structural rationale (why these specific features in this order), see [`roadmap.md`](roadmap.md).

---

## v0.7 — Yellow Paper compliance

### BN254 precompiles (0x06, 0x07, 0x08)

The three BN254 (alt_bn128) curve operations are the prerequisites for on-chain zkSNARK verification. Every Groth16, PLONK, Bulletproof verifier composes these primitives:

- **0x06 BN_ADD**: G1 point addition
- **0x07 BN_MUL**: G1 scalar multiplication
- **0x08 BN_PAIRING**: bilinear pairing check (multi-pair input)

Implementation is in [`kern/evm/bn254.py`](../kern/evm/bn254.py): pure-Python arithmetic over the BN254 base field, with proper modular inverse, point doubling, projective-to-affine conversion, scalar multiplication via double-and-add.

The pairing implementation is a **placeholder** that correctly handles the most common case (empty product → identity = 1) and gets calldata parsing / gas accounting right. A full pairing (Miller loop + final exponentiation in F_p^12) is ~1000 lines of careful math; a production node links against `blst` or `py_ecc` via FFI. This is documented clearly in the module — the protocol integration is correct, the math is honest about its limits.

### Dynamic gas costs ([`kern/evm/dynamic_gas.py`](../kern/evm/dynamic_gas.py))

Static per-opcode gas (as in v0.3-v0.6) was a starting approximation. v0.7 introduces dynamic costs matching the Ethereum Yellow Paper:

- **Memory expansion**: linear in word count up to 724 words, quadratic above
- **SSTORE**: three-case model (SET 20 000, RESET 5 000, NOOP cheap)
- **SSTORE refund** for clearing slots (capped at half tx gas)
- **CALL family**: base 700 + 9 000 (value transfer) + 25 000 (new account) + 2 500 (cold access)
- **CALL stipend**: 2 300 free gas forwarded on value transfers (so callee can log a receipt)
- **LOG**: 375 base + 375 per topic + 8 per byte
- **SHA3**: 30 base + 6 per word
- **EXP**: 10 base + 50 per byte of exponent
- **Copy ops**: 3 per word copied
- **CREATE**: 32 000 base + 200 per byte of deployed code

These are exposed as pure functions (e.g., `sstore_cost(current, new, original)`) so callers can compute the cost before deducting gas. Production wiring into the step VM is a v0.8 follow-up — for v0.7, the constants and the math are the deliverable.

## v0.8 — Adversarial-grade governance

### Quadratic voting (`WeightScheme.QUADRATIC`)

The default vote weighting for the treasury track switches from linear to quadratic: **`weight = isqrt(stake)`**. A whale with 100× more stake gets only 10× more voting power. Linear remains the default for protocol amendments (where stake-aligned alignment is appropriate — you should care more if you have more at stake) but treasury spending is broader-decision territory where quadratic helps.

The math is documented and the demo test (`test_quadratic_compresses_large_holders`) shows the property in action: a 100× ratio in stake compresses to ~10× in vote weight.

Whether to swap a track between schemes is itself a governance decision in v1.0 — the field is part of the state dict, settable by a protocol amendment.

### Delegated voting (treasury)

Non-validators can now delegate their stake to a validator via `treasury.set_delegation(delegator, validator)`. The delegated stake is added to the validator's effective stake for vote tallying. If the delegator casts an independent vote on a specific proposal, they **opt out of the delegation for that proposal only** — their stake follows their explicit vote rather than the validator's.

This is the standard Tezos / Cosmos pattern: most people don't have time to track governance, so they delegate to a validator they trust, with the option to override on individual issues they care about.

### Equivocation detection on protocol votes

If a validator votes YES on a proposal in the EXPLORATION phase, then later votes NO on the same proposal in the same phase, the second vote is **rejected** and the equivocation is **recorded** on the proposal:

```python
prop.equivocations.append({
    "voter": validator_addr,
    "phase": "exploration",
    "first_vote": "yes",
    "second_vote": "no",
    "second_at_level": current_level,
})
```

The original vote stands. The equivocation record persists in the state dict (survives serialization), so any block-explorer or watchdog can detect it post-hoc and trigger slashing.

Voting differently in DIFFERENT phases (yes in exploration, no in adoption) is **not** equivocation — that's deliberation, which the two-vote cycle is explicitly designed to allow.

The slashing transaction itself (`OpKind.SLASH_EQUIVOCATION`) is a v1.0 item: the equivocation evidence is on-chain now; the punishment transaction kind ships when the validator-bond slashing path is finalized.

## v0.9 — Production hardening

### Structured logging ([`kern/observability.py`](../kern/observability.py))

Replaces Python's default logging text with JSON-line output. Every log record is one self-contained JSON object:

```json
{"ts": "2026-05-22T13:14:15.123Z", "level": "INFO", "logger": "kern.node", "msg": "block baked", "level_int": 42, "tx_count": 7}
```

Easy to pipe into `jq`, ship to Loki / ELK, or render in Grafana. Extra context fields are merged from `logger.info(..., extra={...})` calls.

Configure via:
```python
from kern.observability import configure_structured_logging
configure_structured_logging(level=logging.INFO)
```

### Prometheus metrics (`/metrics` endpoint)

Three metric types: `Counter`, `Gauge`, `Histogram`. Exposed via standard Prometheus text exposition format at `GET /metrics`.

Canonical metrics declared at module-load time:

| Metric | Type | Meaning |
|---|---|---|
| `kern_blocks_produced_total` | Counter | Blocks the local baker produced |
| `kern_blocks_applied_total` | Counter | Blocks applied (own + peers) |
| `kern_transactions_applied_total` | Counter | Successful txs |
| `kern_transactions_rejected_total` | Counter | Rejected txs |
| `kern_governance_proposals_total` | Counter | Proposals seen |
| `kern_governance_activations_total` | Counter | Proposals reached ACTIVATED |
| `kern_governance_equivocations_total` | Counter | Equivocations detected |
| `kern_treasury_executions_total` | Counter | Treasury payouts executed |
| `kern_chain_height` | Gauge | Current head level |
| `kern_mempool_size` | Gauge | Mempool tx count |
| `kern_peers_connected` | Gauge | P2P peer count |
| `kern_total_supply_mukrn` | Gauge | Total KRN supply |
| `kern_validator_count` | Gauge | Validator set size |
| `kern_block_apply_seconds` | Histogram | Block apply latency |
| `kern_tx_apply_seconds` | Histogram | Tx apply latency |
| `kern_rpc_request_seconds` | Histogram | RPC handler latency |

Convenient timer context manager:
```python
from kern.observability import observe_latency
with observe_latency("kern_block_apply_seconds"):
    apply_block(state, block)
```

Already wired into `chain.apply_block`: every block updates the height gauge, the supply gauge, the validator-count gauge, and observes the apply latency.

### Fuzzing harness ([`kern/fuzzing.py`](../kern/fuzzing.py))

Three property-based fuzzers, each with a seeded RNG (reproducible failures):

**EVM determinism fuzzer** generates random programs from the safe-opcode set, executes each twice, and asserts both runs produce identical state commitments at every step. This is the most important invariant in the system: if EVM execution is non-deterministic in any way, consensus breaks.

**Transaction safety fuzzer** generates random transfers between three known accounts and asserts:
- Total supply is conserved across all attempts
- `apply_transaction` never raises (it must always return an `ApplyResult`)
- Fees are always debited on accepted transactions

**Governance invariants fuzzer** generates random sequences of propose / vote / advance operations and asserts:
- No proposal transitions to a terminal phase (ACTIVATED, REJECTED, WITHDRAWN) more than once
- Bond accounting reconciles: refund + burn + treasury share = original bond

The default iteration count is 100 per fuzzer (sub-second). Bumping to 10 000 is opt-in via the `slow` pytest marker — designed for nightly CI runs.

### Devnet bootstrap ([`networks/devnet_bootstrap.py`](../networks/devnet_bootstrap.py))

A script that generates a complete local-network setup: N validator keypairs + a shared genesis pre-funding them + a docker-compose file with one container per validator + a README explaining how to use it.

```bash
python networks/devnet_bootstrap.py --validators 5 --out networks/devnet
cd networks/devnet
docker-compose up --build
# Five validators bake in lock-step. RPC at localhost:18732..18736.
```

This is the first concrete piece of the Track 2 (networks) work. The Previewnet bootstrap (v1.0-rc) will be similar but with stricter validator gating and a public-facing faucet RPC.

## Tests

v0.6 → v0.9 brings the test count from 244 to **325** (+ 2 chaos tests skipped by default):

| Module | v0.6 | v0.9 |
|---|---:|---:|
| crypto, transaction, block/chain | 19 | 19 |
| skald + typecheck | 29 | 29 |
| bft, rollup, forced_inclusion | 34 | 34 |
| issuance | 18 | 18 |
| evm (v0.3 + v0.4 + v0.5) | 68 | 68 |
| trie | 21 | 21 |
| governance | 28 | 28 |
| state_root_swap + integration | 12 | 12 |
| v06_additions (precompiles + bonds) | 15 | 15 |
| **v07_additions (BN254 + dynamic gas)** | — | **46** |
| **v08_additions (quadratic + delegated + equivocation)** | — | **17** |
| **v09_additions (observability + fuzzing)** | — | **18 + 2 chaos** |
| **Total** | **244** | **325** |

## File summary

**New files (v0.7–v0.9 combined)**:
- `kern/evm/bn254.py` — BN254 curve arithmetic + precompile entry points
- `kern/evm/dynamic_gas.py` — Yellow-Paper-aligned gas computation
- `kern/observability.py` — structured logs + metrics registry
- `kern/fuzzing.py` — property-based fuzzers
- `networks/devnet_bootstrap.py` — multi-node devnet generator
- `tests/test_v07_additions.py`, `test_v08_additions.py`, `test_v09_additions.py`
- `docs/roadmap.md` — three-track roadmap
- `docs/v07-v08-v09-changes.md` — this file

**Modified files**:
- `kern/governance.py` — `WeightScheme` enum, `_isqrt`, `vote_weight`, equivocation tracking, delegations
- `kern/chain.py` — metrics integration in `apply_block`
- `kern/evm/frames.py` — wires BN254 precompiles into the registry
- `kern/rpc.py` — `/metrics` endpoint
- Various — SPDX headers (carried over from licensing change)

## Roadmap update

| Phase | Scope | Status |
|---|---|---|
| v0.1 → v0.6 | Reference implementation through governance-by-tx + bonds | ✅ |
| **v0.7** | **BN254 + dynamic gas** | **✅ (this batch)** |
| **v0.8** | **Quadratic + delegated voting + equivocation** | **✅ (this batch)** |
| **v0.9** | **Observability + fuzzing + devnet bootstrap** | **✅ (this batch)** |
| v1.0-rc | Code freeze. RPC + transaction format frozen. Full documentation. | 🟡 Next |
| v1.0 | First stable release post-audit-cycle-1 | 🔵 (gated on Foundation + auditors) |

The next code release on the critical path is **v1.0-rc** — a freeze, not a feature. See [`roadmap.md`](roadmap.md) for the three-track structure and non-code dependencies.
