# Kern v1.1-rc — Compliance, Public Goods, and Oracles

This document consolidates the four verticals introduced in Kern v1.1-rc:

1. **Slashable attestations** (the protocol primitive)
2. **STO securities compliance** (the regulated finance vertical)
3. **Public goods funding** (the institutional grant-making vertical)
4. **Oracle network + ZK-claims** (the data infrastructure vertical)

Plus, also shipped in the v1.1-rc cycle:

5. **Heimdall** — the official block explorer and monitoring stack that surfaces the four verticals above. See [`setup-heimdall-operator.md`](setup-heimdall-operator.md) for installation, configuration, and the Prometheus metric surface. Heimdall is a separate Python sub-package (`kern_explorer`), built on FastAPI + SQLite + Jinja2 + Tailwind, with 69 tests and 13 HTML pages including dedicated views for the attestation registry, contract template classification (auto-detecting STO / PGF / oracle templates), and per-vertical statistics. Sessions 2-4 of the Heimdall delivery plan will add per-vertical drill-down dashboards, Grafana dashboards JSON for the monitoring stack, alerting rules, and production-grade UI polish.

6. **Licence migration — LGPL-3.0-or-later → Apache-2.0 for the reference implementation.** Earlier v1.0-rc shipped under LGPL-3.0-or-later. v1.1-rc relicenses the reference implementation under Apache-2.0 — a permissive licence aligned with the broader L1 ecosystem (Solana, Cosmos SDK) — to remove copyleft friction for institutional adoption and to obtain Apache-2.0's express patent grant, which is meaningful protection for an L1 protocol. Documentation, whitepaper, and manifesto remain under CC-BY-SA-4.0 (see [`LICENSE-DOCS.md`](../LICENSE-DOCS.md)). The author's moral rights under Belgian law (Code of Economic Law, Art. XI.165) are preserved independently of the licence change, as noted in [`NOTICE`](../NOTICE).

Together, these define Kern's positioning: **the L1 protocol where compliance, accountability, and verifiable data are first-class citizens** — not features bolted on top.

For change details vs. v1.0, see [`v10rc-changes.md`](v10rc-changes.md) for v1.0-rc, and the per-section docs below for v1.1-rc.

---

## 1. The thesis in one paragraph

Most L1 protocols position themselves around **scaling** (throughput, latency) or **composability** (smart contract languages, developer tooling). These compete in dimensions where the marginal improvement is small and the competitors are well-funded.

Kern positions itself around a different dimension: **institutional legibility**. A protocol where:

- A regulator (FSMA, AMF, CSSF, BaFin) can READ the smart contract's invariants directly and confirm securities compliance (MiFID II / Prospectus Regulation / AIFMD — security tokens are excluded from MiCA by Art. 2(4)), with no auditor as middleman
- A foundation (UNESCO, EU, Wikimedia) can ALLOCATE grants via mathematically explicit Quadratic Funding or Retroactive PGF, with no committee opacity
- An industry data network (energy grids, telcos, supply chains) can PUBLISH measurements with slashing-on-equivocation, replacing post-hoc reconciliation with continuous verification
- A user with sensitive data (KYC, age, income) can PROVE properties without revealing raw values via on-chain-verifiable zk-SNARKs

These four dimensions are not addressable on Ethereum (Solidity doesn't support declared invariants), not addressable on Tezos (no EVM-friendly developer ecosystem), not addressable on Solana (no on-chain governance primitive), and not addressable on Cosmos (no native equivocation slashing at the application layer).

**The combination is the moat.** Each individual feature exists somewhere else. Putting them in one protocol, with a coherent design, is what Kern provides.

---

## 2. The four verticals

### 2.1 Slashable attestations (the primitive)

**What it is**: Any address can post a signed claim about any subject under any schema, with an optional KRN bond. If the same address signs CONTRADICTORY claims for the same (schema_id, subject) pair, anyone can submit slashing evidence and the issuer loses 30% of their bond (10% to the prover, rest burned).

**Why it matters**: Most "oracle" and "attestation" systems use reputational punishment (off-chain, slow). Kern moves punishment on-chain and immediate.

**API surface added to v1.1**: 3 new OpKinds (ATTEST, REVOKE_ATTESTATION, SLASH_ATTESTATION_EQUIVOCATION), declared as additive in [api-stability.md](api-stability.md).

**Spec**: [`attestations.md`](attestations.md)
**Code**: [`kern/attestation.py`](../kern/attestation.py)
**Tests**: [`tests/test_attestations.py`](../tests/test_attestations.py) — 25 tests

### 2.2 STO securities compliance

**What it is**: Three Skald templates that encode the EU securities regime — Prospectus Regulation (whitepaper/prospectus), MiFID II Art. 16 & 24 and AIFMD Art. 18, 21, 22 (segregation, depositary independence, diversification), and MAR (market-abuse blackout) — as runtime-enforced invariants. (Earlier drafts cited MiCA Articles 14/50/88; security tokens are financial instruments excluded from MiCA by Art. 2(4). See the correction box in [`sto-mica.md`](sto-mica.md).)

**Why it matters**: Continuous verification supplements annual audits. The Belgian FSMA (or any EU regulator) can read the invariants directly to confirm compliance under the applicable securities framework.

**Spec**: [`sto-mica.md`](sto-mica.md)
**Templates**:
- [`sto-startup-equity.skald`](../kern/skald/examples/sto-startup-equity.skald) — €5M-50M raises
- [`sto-institutional-fund.skald`](../kern/skald/examples/sto-institutional-fund.skald) — €50M-500M AUM
- [`sto-real-estate.skald`](../kern/skald/examples/sto-real-estate.skald) — €10M-100M property deals

**Tests**: [`tests/test_sto_templates.py`](../tests/test_sto_templates.py) — 13 tests

### 2.3 Public goods funding

**What it is**: Two Skald templates implementing Quadratic Funding (the matching-pool model from Buterin/Hitzig/Weyl 2018) and Retroactive Public Goods Funding (the Optimism model where impact is funded retrospectively).

**Why it matters**: A €multi-billion annual market in foundations, supranational bodies, and corporate ESG that currently wastes ~15% on administrative overhead and selection bias. Kern's mechanisms collapse this to ~2%.

**Spec**: [`public-goods-funding.md`](public-goods-funding.md)
**Templates**:
- [`quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald)
- [`retroactive-pgf.skald`](../kern/skald/examples/retroactive-pgf.skald)

**Tests**: [`tests/test_pgf_templates.py`](../tests/test_pgf_templates.py) — 21 tests

### 2.4 Oracle network + ZK-claims

**What it is**: Three Skald templates (generic data oracle, DeFi price oracle, schema marketplace) plus a Python module for ZK-claim payload construction. Built on the attestation primitive, with circuit breakers, heartbeats, tolerance bands, and a schema registry.

**Why it matters**: Replaces Chainlink-style separate oracle networks with an L1 primitive at a fraction of the cost. Extends to non-DeFi data (energy, telco, supply chain, weather, ESG) where existing oracle infrastructure is weak. ZK-claims enable privacy-preserving compliance attestations.

**Spec**: [`oracle-network.md`](oracle-network.md)
**Templates**:
- [`generic-data-oracle.skald`](../kern/skald/examples/generic-data-oracle.skald)
- [`defi-price-oracle.skald`](../kern/skald/examples/defi-price-oracle.skald)
- [`schema-marketplace.skald`](../kern/skald/examples/schema-marketplace.skald)

**Code**: [`kern/zk_claims.py`](../kern/zk_claims.py)
**Tests**: [`tests/test_oracle_and_zk.py`](../tests/test_oracle_and_zk.py) — 29 tests

---

## 3. How the four verticals compose

The four verticals are not independent — they reinforce each other:

```
        ┌─────────────────────────┐
        │  Attestation primitive  │
        │  (the L1 protocol)      │
        └────────────┬────────────┘
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
  ┌─────────┐  ┌─────────┐  ┌─────────────┐
  │  STO    │  │  Oracle │  │ Public goods│
  │  (sec.) │◀─┤ network │  │  funding    │
  │ (Skald) │  │ (Skald) │  │  (Skald)    │
  └─────────┘  └────┬────┘  └──────┬──────┘
                    │              │
                    ├──────────────┤
                    ▼              ▼
            ┌────────────┐  ┌──────────────┐
            │ ZK-claims  │  │  Schema      │
            │ (privacy)  │  │  marketplace │
            └────────────┘  └──────────────┘
```

Concrete composition examples:

### Example A: STO with KYC attestations + ZK-proof of age

A regulated equity token offering uses:

1. **STO securities template** for the issuance contract
2. **KYC provider attestations** (via attestation primitive) for AML screening
3. **Age threshold ZK-claim** (via zk_claims module) to prove "investor is over 18" without revealing DOB
4. **Schema marketplace entry** confirming the KYC provider is recognized
5. **DeFi price oracle** for the live KRN/EUR rate used in price-stable tranches
6. **Equivocation slashing** punishes any KYC provider that contradicts itself

### Example B: UNESCO heritage funding round with verified impact

A €10M public goods round uses:

1. **Quadratic Funding template** for the project contracts
2. **Personhood attestations** (via attestation primitive) for Sybil resistance
3. **RPGF templates** for the retroactive round at year-end
4. **Generic data oracle** for usage metrics from beneficiary sites
5. **ZK-claim** of "received funding meets matching threshold" for project audit
6. **Schema marketplace** publishes the canonical schemas used

### Example C: Energy market settlement

EU grid operators run inter-utility reconciliation via:

1. **Generic data oracle** for grid frequency, regional demand/supply, clearing prices
2. **Schema marketplace** operated by ENTSO-E for the canonical schemas
3. **Attestation primitive** with bonds proportional to settlement value (typically €10k-100k bonds)
4. **Equivocation slashing** when a grid operator's measurements conflict between settlement windows

---

## 4. The bigger picture — Kern's positioning vs other L1s

| Dimension | Ethereum | Tezos | Solana | Cosmos | **Kern (v1.1-rc)** |
|---|---|---|---|---|---|
| EVM compat (via rollup or native) | Native | No | Limited | No | **Via rollup** |
| On-chain governance | No (off-chain forks) | Self-amending | No | Limited | **Dual-track + slashing** |
| Declared contract invariants | No (Solidity) | Limited (LIGO) | No (Rust) | No | **Native (Skald)** |
| Liquid PoS without LST | No (requires Lido) | Yes | No (locked) | No (locked) | **Yes (Liquid PoS)** |
| BN254 ZK precompiles | Yes | No | Limited | No | **Yes (py_ecc-backed)** |
| Slashable attestations as L1 primitive | No | No | No | No | **Yes** |
| Multi-channel public goods funding | Add-on (Gitcoin) | No | No | No | **Native (QF + RPGF)** |
| Tokenized-securities STO templates (MiFID II/AIFMD) | Solidity only, no invariants | LIGO contracts | None | None | **3 templates, type-checked** |

Kern doesn't dominate any single dimension. Kern dominates the **combination**. No competitor has all six rows.

---

## 5. Test counts

| Vertical | New tests |
|---|---|
| Attestation primitive | 25 |
| STO securities templates | 13 |
| Public goods funding templates | 21 |
| Oracle network + ZK-claims | 29 |
| **Total v1.1-rc additions** | **88** |
| **Cumulative test count** | **466** (was 378 in v1.0-rc) |

Two chaos tests remain intentionally skipped.

---

## 6. v1.2 roadmap (what comes after audit cycle 1)

The v1.1-rc demonstrators expose a clear set of v1.2 enhancements that, taken together, take the protocol from "principle demonstrator" to "production-grade":

**Skald language features**:
- Mapping types (`map<address, int>`) — unlocks per-investor balances, per-feeder reputation, multi-project rounds
- Math primitives (`isqrt`, `min`, `max`) — unlocks on-chain QF matching computation
- Cross-contract calls (`call_view(contract, entry, params)`) — unlocks composition between STO contracts, oracles, governance
- Native attestation reads from contracts — `attestation_latest(issuer, schema, subject)` builtin

**Application-level**:
- Production ZK circuits for age_threshold + value_threshold with multi-party trusted setup
- Multi-currency denomination registry (EUR, USD, GBP as first-class)
- Native vesting enforcement (currently off-chain via multisig)
- MiFID II execution venue integration

**Operational**:
- Foundation incorporated (Estonian Foundation (Sihtasutus) per [setup-foundation.md](setup-foundation.md))
- Audit cycle 1 conducted on v1.1-rc
- Yggdrasil testnet launched

The v1.1-rc release is **the input to audit cycle 1**. What ships in v1.2 depends on what audit findings require.

---

## 7. Reference

The full library of v1.1-rc documentation:

- This document — index
- [`attestations.md`](attestations.md) — slashable attestation primitive spec
- [`sto-mica.md`](sto-mica.md) — STO securities compliance spec (corrected: MiFID II/AIFMD, not MiCA)
- [`public-goods-funding.md`](public-goods-funding.md) — QF + RPGF spec
- [`oracle-network.md`](oracle-network.md) — oracle + schema marketplace + ZK-claims spec
- [`setup-heimdall-operator.md`](setup-heimdall-operator.md) — Heimdall (explorer + monitoring) operator guide
- [`v10rc-changes.md`](v10rc-changes.md) — v1.0-rc changes (genesis economy, Tezos delegation, BN254)
- [`api-stability.md`](api-stability.md) — API surface declared frozen / stable / beta
- [`tokenomics.md`](tokenomics.md) — KRN token economy
- [`roadmap.md`](roadmap.md) — code / network / operational roadmap
- [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) — gating items before Midgard launch
- [`originality-and-attribution.md`](originality-and-attribution.md) — founder attribution and Belgian moral rights
