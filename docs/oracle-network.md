# Oracle Network on Kern

This document describes how Kern's slashable attestation primitive composes into a **decentralized oracle network** — one that can deliver DeFi prices, energy market data, telco usage metrics, identity status, supply-chain provenance, weather, and IoT readings, all with cryptoeconomic slashing-on-equivocation as the primary trust mechanism.

The thesis: **oracle networks should not be a separate protocol layer with their own token, governance, and economic security**. The L1 already has all of these. A correctly-designed L1 primitive (slashable attestation) lets oracles inherit the L1's security at native cost. Chainlink's $11B+ market cap is paid by users to a separate network when the same function could be provided by an L1 primitive at orders-of-magnitude lower cost.

Kern provides this as a built-in capability in v1.1-rc.

This document covers:

- §1 — The architecture: feeders, aggregator, consumers, slashing
- §2 — The four shipped Skald templates
- §3 — Use cases beyond DeFi prices: energy, telco, identity, public goods
- §4 — Schema marketplace and verifier-key registry
- §5 — ZK-claims: privacy-preserving attestations
- §6 — Economic model: who pays whom, why this beats Chainlink
- §7 — Limitations and v1.2 roadmap

---

## 1. Architecture

Every Kern oracle has four roles:

```
┌──────────────┐
│  Feeder 1    │  ┐
├──────────────┤  │  Each feeder reads off-chain data and
│  Feeder 2    │  │  posts ATTEST tx with bond:
├──────────────┤  ├─►  schema_id = "<oracle>.feed"
│  Feeder 3    │  │   subject    = "<observable>"
├──────────────┤  │   claim      = {value, timestamp, ...}
│   ...        │  │   bond       = K mukrn (slashable)
├──────────────┤  │
│  Feeder N    │  ┘
└──────┬───────┘
       │
       ▼
┌──────────────────────────────┐
│  Aggregator                  │
│  - Reads attestations off-   │
│    chain via RPC             │
│  - Computes median /         │
│    consensus value           │
│  - Verifies feeders within   │
│    tolerance band            │
│  - Calls oracle contract's   │
│    finalize_round entry      │
│  - Itself posts a slashable  │
│    attestation: "median for  │
│    round N was X"            │
└──────┬───────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│  Oracle contract             │
│  (Skald)                     │
│  - Stores finalized value    │
│  - Tracks staleness          │
│  - Enforces circuit breakers │
│  - Exposes consumer views    │
└──────┬───────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│  Consumer contract (any      │
│  Skald or rollup contract)   │
│  Reads via view function.    │
└──────────────────────────────┘
```

### Trust assumptions

The network is secure if:

1. At least one honest feeder exists (to anchor truthful readings)
2. The aggregator is incentivized to honestly compute the median (or is itself slashable on equivocation)
3. Consumers verify staleness and circuit-breaker status before using values

**No single feeder, no single aggregator, no single consumer needs to be trusted in isolation.** Equivocation by any participant is detected by anyone else and slashed via the SLASH_ATTESTATION_EQUIVOCATION transaction.

### Why this is more secure than existing oracles

Chainlink, Pyth, and other established oracles rely on **reputational** punishment: a node that publishes wrong values loses business over time. This is slow (months to weeks) and depends on the existence of buyers who care.

Kern's slashing is **immediate** and **financially provable**:

- The feeder's bond is locked at the time of attestation
- Equivocation evidence (two contradicting attestations for the same subject) is a single transaction submission, anyone can do it
- The slashing happens at the next block, no waiting period
- 30% of bond is destroyed and 10% of slash is paid to the reporter

The economic incentive to report equivocation is symmetric: every honest participant has reason to monitor and report.

---

## 2. The four shipped Skald templates

| Template | Purpose | Use case |
|---|---|---|
| [`generic-data-oracle.skald`](../kern/skald/examples/generic-data-oracle.skald) | Any data type | Energy, telco, weather, IoT, identity, supply chain |
| [`defi-price-oracle.skald`](../kern/skald/examples/defi-price-oracle.skald) | Prices specifically | DeFi consumers (lending, DEXs, derivatives) |
| [`schema-marketplace.skald`](../kern/skald/examples/schema-marketplace.skald) | Registry of schemas + minimum bonds | Foundation, validators, application devs |
| [`quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald) (from §5.3) | Uses oracle for personhood proofs | Public goods funding rounds |

### Generic data oracle features

- **Feeder set** with k-of-n threshold (default 7 of 10)
- **Tolerance band** between feeders (default 0.5%)
- **Anomaly tracking** for out-of-tolerance readings
- **Round-by-round operation** with explicit open / record / finalize lifecycle
- **Stale-round abort**: if quorum can't be reached, anyone can abort to surface the stale state
- **Pause** by network admin (emergency stop)
- **Network health score** (feeders × 100 − anomalies − failed rounds × 10) for consumer visibility

### DeFi price oracle features (in addition)

- **Decimals normalization** (8 by default, like Chainlink)
- **Circuit breaker**: max % change per round (default 10%) prevents flash-loan manipulation propagation
- **Heartbeat**: max time between updates (default 600 levels / 10 min)
- **Previous price snapshot** (for derivatives that need both current and previous)
- **First-round bypass** of circuit breaker (no baseline to compare)

### Schema marketplace features

- **Per-schema minimum bond** enforced by application logic
- **Recognized issuer registry** with quality scoring
- **Version monotonic** (bump_version for schema evolution)
- **Deprecation flag** (consumers see it; historical attestations remain valid)
- **Slashing history** per schema (Foundation can identify problematic schemas)

---

## 3. Use cases beyond DeFi prices

This is where Kern differentiates from Chainlink-as-Ethereum-oracle. Chainlink optimized for DeFi prices on Ethereum. Kern's oracle primitive serves **regulated industrial data** which is a much larger market and is under-served.

### 3.1 Energy market data

**The problem**: European energy markets (EPEX SPOT, Nord Pool, GME) settle inter-utility transactions every 15 minutes. Settlement requires consensus on grid frequency, regional supply, demand, and clearing prices. Currently coordinated through bilateral agreements, ENTSO-E publications, and a multi-step verification process.

**Kern primitive**:

```
schema_id   = "energy.grid-frequency-hz"
subject     = "EU-grid-region-CWE"   (Central Western Europe)
claim       = {"frequency_hz": 49998, "timestamp": 1730000000, "measurement_window_seconds": 60}
bond        = 10_000 KRN per attestation
```

Each grid operator (Elia, RTE, TenneT, Amprion, Swissgrid, etc.) attests their measurements with bond. If two operators contradict for the same subject at the same window, slashing follows. This replaces hours of post-hoc reconciliation with continuous mathematical verification.

**Economic case**: a single Belgian grid operator (Elia) handles ~€100M/year in settlement reconciliation cost. Replacing 30% of this with Kern attestations = €30M/year savings, of which a few % flow to the L1 as fees.

### 3.2 Telco settlement

**The problem**: inter-operator billing for roaming, MVNO settlement, wholesale traffic. Currently coordinated via the GSMA Billing & Charging Evolution (BCE) framework and periodic reconciliation.

**Kern primitive**:

```
schema_id = "telco.subscriber-count"
subject   = "FR-metro-orange"
claim     = {"count": 18_000_000, "as_of": 1730000000, "service_type": "mobile-broadband"}
bond      = 5 000 KRN
```

Plus:
```
schema_id = "telco.roaming-minutes"
subject   = "<operator-pair>:<destination>:<period>"
claim     = {"minutes": int, "data_mb": int}
bond      = 1 000 KRN
```

Each operator attests its data with bond. Equivocation is provable — a single operator can't claim 18M subscribers in one settlement window and 22M in an adjacent one.

**Industry relevance**: a tier-1 EU telecom operator typically handles on the order of ~€10M/year in settlement reconciliation with EU peers. Kern's primitive moves this to continuous verification at marginal cost.

### 3.3 Identity attestations (KYC, personhood, accreditation)

Already covered in [`sto-mica.md`](sto-mica.md) and [`public-goods-funding.md`](public-goods-funding.md) — KYC providers attest user status with bonds, used by STO contracts and QF rounds.

The privacy concern (revealing DOB or address publicly) is addressed by ZK-claims (§5 below).

### 3.4 Supply chain provenance

**The problem**: Pharmaceuticals (anti-counterfeiting), luxury goods (anti-forgery), food (origin verification — wine, cheese, organic certification) need verifiable provenance from producer through wholesale to retail.

**Kern primitive**:

```
schema_id = "provenance.physical-handoff"
subject   = "<product_serial_number>"
claim     = {"from": "kn1producer", "to": "kn1distributor", "timestamp": ..., "location_hash": ...}
bond      = 100-10_000 KRN depending on product value
```

Each handoff is attested by both parties (producer + distributor sign jointly via a separate aggregation contract). Equivocation by anyone in the chain — claiming two distributors received the same serial — is automatically detected.

### 3.5 Weather and parametric insurance

**The problem**: Parametric insurance contracts (e.g., farm insurance that pays out if rainfall in a region drops below threshold) need objective, verifiable weather data.

**Kern primitive**:

```
schema_id = "weather.rainfall-mm-monthly"
subject   = "FR-rhone-region"
claim     = {"rainfall_mm": 45, "month_yyyymm": 202610}
bond      = 1 000 KRN per attestation
```

Multiple weather services (Météo France, ECMWF re-analysis, satellite providers) attest independently. The insurance contract reads the median via a Skald oracle template.

### 3.6 ESG and sustainability data

**The problem**: Carbon credits, sustainability metrics, biodiversity offsets — currently rife with double-counting and unverifiable claims.

**Kern primitive**:

```
schema_id = "esg.carbon-offset-tonnes-co2eq"
subject   = "<project_id>:<vintage_year>"
claim     = {"tonnes_co2eq": 10_000, "verifier": "Verra-VCS-001", "issued_at": ...}
bond      = 50_000 KRN (high — counterfeiting carbon credits is a $100M+ problem)
```

Two verifiers attesting different tonnage for the same project = automatic slashing. Replaces multi-year audits with continuous attestation chains.

---

## 4. Schema marketplace and verifier-key registry

The protocol-level attestation primitive doesn't gate schemas — anyone can use any `schema_id` string. The application-level **schema marketplace** (Skald template) lets a curator (the Foundation, or a sector consortium) publish:

- Canonical schema definitions (hash → off-chain JSON schema)
- Minimum bond requirements per schema
- Recognized issuer list per schema
- Deprecation status
- Slashing statistics

Multiple marketplaces can coexist. Examples:

- **Foundation canonical marketplace**: covers general-purpose schemas (price, KYC, identity)
- **Energy industry marketplace**: operated by ENTSO-E or similar, covers energy-specific schemas
- **Telco industry marketplace**: operated by GSMA or industry consortium
- **National regulatory marketplace**: FSMA in Belgium publishes the schemas it relies on for STO compliance

Consumers choose which marketplace(s) to trust. The protocol does not pick winners.

### Verifier-key registry pattern

For ZK-claim schemas (§5), the marketplace contract additionally publishes the **verifier key hash** for the circuit. Without this, a consumer reading a ZK attestation cannot know which circuit's verifier key to use.

The schema-marketplace contract field `schema_hash` can carry the verifier-key hash for ZK schemas. Off-chain, the full verifier key bytes are published at the URL in `documentation_url`.

---

## 5. ZK-claims: privacy-preserving attestations

### The privacy problem

The plain attestation format reveals the full claim to everyone reading the chain. For many use cases this is fine (prices are public). For others it's a deal-breaker:

| Schema | Sensitive data |
|---|---|
| `kyc.aml-screening` | Status reveals: "user passed AML" or "failed" — fine, but linking address to identity over time is bad |
| `identity.date-of-birth` | DOB is sensitive |
| `compliance.income-tier` | Income tier is sensitive |
| `kyc.source-of-funds` | Source category is sensitive |
| `account-ownership.proof` | Linking accounts compromises privacy |

### ZK-claim format

A ZK-claim payload (see [`kern/zk_claims.py`](../kern/zk_claims.py)):

```python
{
    "proof_system":      "groth16-bn254",
    "verifier_key_hash": "<32-byte hex>",
    "public_inputs":     [<int>, ...],
    "proof": {
        "a": [<x>, <y>],         # G1 point
        "b": [[<x_r>, <x_i>], [<y_r>, <y_i>]],  # G2 point
        "c": [<x>, <y>],         # G1 point
    },
    "predicate_summary": "user is over 18 years old"
}
```

This is posted via `make_attest` exactly like a plain claim, but consumers (a Skald contract, an off-chain verifier, the regulator) **first verify the ZK proof** before trusting the claim's logical content.

### The Kern BN254 primitive

Kern already has BN254 (alt_bn128) precompiles (since v0.7) via `kern.evm.bn254`. The precompile `bn_pairing_precompile` evaluates the Groth16 pairing check that constitutes the core of proof verification. With py_ecc backing (v1.0-rc), this is a real verifier.

The v1.1-rc `kern.zk_claims` module provides:

- `build_zk_claim(...)`: canonical payload constructor
- `is_zk_claim(claim)`: detection of ZK payloads
- `derive_verifier_key_hash(vk_bytes)`: deterministic ID for a verifier key
- `verify_zk_claim(claim, verifier_key_registry)`: structural + cryptographic verification

In v1.1-rc, the cryptographic verification is a STUB — it does structural checks but does not perform the actual pairing (requires application-specific verifier key + circuit). Production deployments plug in the real verifier for their specific circuit.

### Reference circuits

Four reference circuits are described (not implemented in Python — they would be Circom or Cairo) for the most common predicates:

1. **age_threshold_v1** — "DOB + min_age_seconds ≤ now"
2. **value_threshold_v1** — "value ≥ public_threshold"
3. **account_ownership_v1** — "prover knows sk such that pubkey(sk) = public_addr"
4. **set_membership_v1** — "prover knows Merkle path proving leaf is in tree"

These cover ~80% of real-world ZK-claim use cases in the EU regulatory context. Foundation-funded work to ship implementations of these circuits + trusted-setup ceremonies is in the v1.2 roadmap.

### Production deployment workflow

1. **Circuit author** writes the Circom (or Cairo, Noir) circuit for their predicate
2. **Trusted setup** ceremony generates the proving and verifying keys (MPC ceremony, multi-party)
3. **Foundation** registers the verifying key hash in the schema marketplace under the chosen `schema_id`
4. **Provers** (the issuers — KYC providers, custodians, etc.) use the proving key to generate proofs
5. **Issuers** post attestations with ZK-claim payloads referencing the registered verifier key
6. **Consumers** read the attestation, look up the verifier key, run the Kern BN254 verifier to check the proof

The Foundation's role is to operate the trusted setup ceremonies. The protocol's role is to make verification on-chain efficient.

---

## 6. Economic model

### Who pays what

| Actor | Pays | Receives |
|---|---|---|
| Feeder | Bond (locked while attestation active), tx fee | Compensation from oracle consumers (set off-chain) |
| Aggregator | Bond on median attestations, tx fees for finalize_round | Compensation from oracle consumers |
| Whistleblower | tx fee on SLASH_ATTESTATION_EQUIVOCATION | 10% of slashed bond when equivocation proven |
| Consumer | Compensation paid to feeders/aggregator (off-chain or via Skald contract) | Data access |
| Schema marketplace operator | tx fees on schema lifecycle | Reputation; potentially a small per-attestation fee from consumers |
| Issuer of slashed attestation | 30% of bond lost (90% burned, 10% to whistleblower) | — |

The Foundation may operate the canonical schema marketplace for free as a public service (funded from the Foundation pool). Sector marketplaces (energy, telco) charge for inclusion in their curated lists.

### Why this beats Chainlink

Chainlink charges ~50-200 USD per oracle update for major DeFi pairs. A Lending Market reading ETH/USD every minute spends ~$1500-6000/month per pair.

Kern oracle costs:
- Aggregator finalize_round tx: ~10 000 mukrn = ~€0.01 per round
- Per-feeder attestation: ~5 000 mukrn = ~€0.005 per attestation
- For a 10-feeder oracle updating every minute: ~€0.06/minute = ~€2600/month

That's roughly the same order of magnitude as Chainlink. But Chainlink's cost is paid in LINK (a separate token), whereas Kern's is paid in KRN (the L1 token), keeping value circulation within the protocol. And the slashing-based security model is provably stronger than Chainlink's reputation-based model.

The much bigger competitive moat is **non-DeFi data** (energy, telco, supply chain, identity), where Chainlink has limited footprint and where Kern's privacy + slashing + regulator-readability combination is uniquely positioned.

---

## 7. Limitations and v1.2 roadmap

| Limitation (v1.1-rc) | v1.2 fix |
|---|---|
| Skald has no mapping types; feeder set tracked by count, not by address | v1.2 mapping support → per-feeder bond and reputation in-contract |
| Aggregator computes median off-chain | v1.2 Skald median builtin on sorted arrays |
| ZK verification is a stub | v1.2 ships at least 2 production circuits (age_threshold, value_threshold) with trusted setup |
| No per-feeder reputation scoring | v1.2 adds reputation contract that consumes slashing history |
| Cross-contract reads not yet supported | v1.2 adds `call_view(contract, entry, params)` for Skald |
| ZK trusted setups require Foundation coordination | v2.0 considers transparent SNARKs (STARK, etc.) to remove trusted setup |

These are real limitations but not blocking. The v1.1-rc model is operationally usable for production oracles today, with v1.2 enhancements making the developer experience smoother.

---

## 8. Reference

- **Skald templates**: [`generic-data-oracle.skald`](../kern/skald/examples/generic-data-oracle.skald), [`defi-price-oracle.skald`](../kern/skald/examples/defi-price-oracle.skald), [`schema-marketplace.skald`](../kern/skald/examples/schema-marketplace.skald)
- **Python module**: [`kern/zk_claims.py`](../kern/zk_claims.py)
- **Attestation primitive**: [`attestations.md`](attestations.md)
- **BN254 precompiles**: see `kern/evm/bn254.py` (py_ecc-backed pairing)
- **Tests**: [`tests/test_oracle_and_zk.py`](../tests/test_oracle_and_zk.py)
- **Use case integrations**: [`sto-mica.md`](sto-mica.md), [`public-goods-funding.md`](public-goods-funding.md)
