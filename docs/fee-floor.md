# L1 fee floor & block size cap (optional, governance-gated)

The Kern L1 charges a flat, sender-chosen `tx.fee` and does not meter compute
(it relies on Skald being loop-free and non-recursive to terminate by
construction — see [`skald-language.md`](skald-language.md)). That is safe
against compute-DoS but provides no *compute-proportional* fee and no per-block
spam bound. This document describes an **optional** mechanism that adds both,
and that is **off by default**.

## Why this is a consensus rule (and therefore not a local flag)

The fee floor and the block size cap decide whether a block is **valid**. If two
validators disagreed on the threshold, they would accept different blocks and the
chain would **fork**. So the parameters cannot be a per-node environment variable
or CLI flag. They are resolved from **chain state** (`state["fee_params"]`), which
every node shares by construction, and they can be set in exactly two consensus-safe
ways:

1. **At genesis** — bake `fee_params` into the genesis file. Every node that
   starts from that genesis applies the identical rule from block 1.
2. **On a live chain — via protocol governance.** The four parameter names are on
   the protocol-amendment whitelist (`ALLOWED_PARAMS` in `governance.py`), so a
   `GOVERNANCE_PROPOSE` on the `protocol` track can turn the feature on or retune
   it. Activation lands through the normal five-phase governance cycle, so the
   change point is itself agreed by validator vote — not flipped unilaterally.

This is the "secured feature flag": a parameter under genesis/governance control,
**disabled by default**, never a local toggle.

## Parameters

Stored under `state["fee_params"]` (a dedicated bucket — kept separate from
`issuance_params`, which is consumed by a strict dataclass):

| Key | Meaning | Proposed default |
|---|---:|---:|
| `fee_floor_enabled` | master switch (the whole feature) | `false` |
| `fee_floor_base` | fixed per-tx anti-spam base (mukrn) | `100` |
| `fee_floor_per_byte` | charge per canonical-encoded byte (mukrn) | `2` |
| `max_block_bytes` | per-block total encoded-size cap (bytes) | `1048576` (1 MiB) |

**Minimum acceptable fee** for a transaction is

```
min_fee(tx) = fee_floor_base + fee_floor_per_byte × tx.encoded_size()
```

where `encoded_size()` is the length of the canonical signed payload (deterministic
across nodes). A block is invalid if any transaction pays below its `min_fee`, or
if the sum of transaction sizes exceeds `max_block_bytes`.

## Why these default values

Transactions measure ~320–350 bytes (transfer ≈ 321, call ≈ 336, origination ≈ 348
plus contract code). With `base = 100`, `per_byte = 2`:

- a 321-byte transfer has a floor of `100 + 2×321 = 742` mukrn — **below** the
  current 1000-mukrn default transfer fee, so legitimate traffic is not priced out;
- filling a 1 MiB block (~3,200 transfers) costs **≥ ~2.4 KRN per block** in fees,
  making sustained block-stuffing expensive while keeping a single honest tx cheap;
- the per-byte term makes data-heavy transactions (large contract code, big params)
  pay proportionally, which is the property the flat fee lacks.

These are conservative starting points. Tune them via governance for the economic
profile you want; raising `fee_floor_per_byte` increases spam cost (and legitimate
cost) roughly linearly, and `max_block_bytes` trades throughput against
propagation/validation load per block.

## Enabling it

**Genesis** (`fee_params` block):

```json
{
  "fee_params": {
    "fee_floor_enabled": true,
    "fee_floor_base": 100,
    "fee_floor_per_byte": 2,
    "max_block_bytes": 1048576
  }
}
```

**Governance** (protocol track) payload:

```json
{ "params": { "fee_floor_enabled": true, "fee_floor_base": 100,
              "fee_floor_per_byte": 2, "max_block_bytes": 1048576 } }
```

A block proposer should filter its mempool with the same rule
(`kern.chain.check_fee_rules`) so it never builds a block that validators will
reject; honest validators enforce it in `validate_block` regardless.

## What it does *not* do

This is a fee floor and a size cap, not a full gas market. It does not meter
per-opcode compute on the L1 (the rollup Mini-EVM does that — see
[`rollups.md`](rollups.md) and `kern/evm/`) and it does not implement dynamic,
demand-responsive base-fee adjustment (EIP-1559-style). Those remain possible
future work; the parameter plumbing here is the foundation they would build on.
