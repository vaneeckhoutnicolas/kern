# Tokenized Securities on Kern — Compliance-by-Construction for the EU Securities Regime

> ## ⚠ Regulatory scope correction (read first)
>
> **An earlier draft of this document was titled "MiCA-Compliant by Construction" and framed the three STO templates as MiCA instruments. That framing was wrong on the law and is corrected here.**
>
> Tokenized **equity, fund units, and real-estate fund interests are *financial instruments* within the meaning of MiFID II** (Directive 2014/65/EU). **MiCA Article 2(4) explicitly excludes crypto-assets that qualify as financial instruments from MiCA's scope.** A security token is therefore **out of scope of MiCA** and is governed by the *existing* EU securities framework:
>
> | Instrument (template) | Governing regime — **not MiCA** |
> |---|---|
> | Startup equity (`sto-startup-equity`) | MiFID II + **Prospectus Regulation** (EU 2017/1129) + **MAR** (Market Abuse Regulation, EU 596/2014) + national company/securities law |
> | Institutional fund (`sto-institutional-fund`) | **AIFMD** (2011/61/EU) — or UCITS if applicable — + MiFID II + MAR |
> | Real-estate fund (`sto-real-estate`) | **AIFMD** (typically, as an AIF) + MiFID II + national real-estate/fund law |
> | The on-chain market-infrastructure layer | **DLT Pilot Regime** (EU 2022/858) where a trading/settlement venue is involved |
>
> Concretely, in the article mapping below: the "market abuse / blackout" logic is grounded in **MAR**, not MiCA Art. 88; the "custody / asset-segregation" logic tracks **MiFID II Art. 16(8)–(9) and the depositary duties under AIFMD Art. 21**, not MiCA Art. 50 (which addresses *crypto-asset service providers*). MiCA becomes relevant only for an *ancillary* utility/payment token that is genuinely **not** a financial instrument — for example KRN-as-gas, or a non-security loyalty point — and even then a case-by-case ESMA-guidelines classification is required.
>
> The compliance-by-construction *thesis* (encode obligations as runtime-enforced invariants a supervisor can read directly) is unchanged and, if anything, fits the securities regime *better* than MiCA. Only the named statute changes. **This remains a design discussion, not legal advice or a compliance assurance — see [`disclaimer.md`](disclaimer.md). Engage licensed counsel and your competent authority (FSMA, AMF, CSSF, BaFin, CONSOB…) before any deployment.**

This document describes how Kern's Skald language and slashable attestation primitive combine to make **regulatory compliance machine-enforced** for Security Token Offerings (STOs) in the European Union.

The thesis: **the regulator (FSMA, AMF, CSSF, BaFin, CONSOB, etc.) can read the contract's invariants directly to verify compliance, rather than waiting for an annual audit report from a third party**. Conformance is continuous and cryptographically verifiable, not retrospective and trust-based.

This document is the design rationale and integration guide for the three Skald templates shipped in `kern/skald/examples/`:

- [`sto-startup-equity.skald`](../kern/skald/examples/sto-startup-equity.skald) — startup equity tokenization (€5M-50M raises)
- [`sto-institutional-fund.skald`](../kern/skald/examples/sto-institutional-fund.skald) — institutional fund tokenization (€50M-500M AUM)
- [`sto-real-estate.skald`](../kern/skald/examples/sto-real-estate.skald) — real estate fund tokenization (€10M-100M deals)

---

## 1. The compliance gap that Skald closes

In current EU practice, MiCA compliance is enforced through:

1. **Pre-launch white paper review** by a competent authority (FSMA in Belgium, AMF in France, etc.)
2. **Annual audit** by an external auditor (Big 4 typically) confirming ongoing compliance with the prospectus and applicable regulations
3. **Periodic disclosure** of NAV, holdings, material events
4. **Reactive enforcement** if violations are discovered (fines, license revocation)

This model has three structural weaknesses:

| Weakness | Consequence |
|---|---|
| Annual audits are retrospective | A breach in Q1 may not surface until Q4 of the following year |
| Audits are sampled | Auditors cannot verify 100% of transactions; they spot-check |
| Compliance is parsed by humans | Disagreement between issuer/auditor/regulator on interpretation |

What Skald changes:

1. **Compliance rules are encoded as invariants** in the contract itself
2. **Runtime enforces every invariant on every state change** — there is no "let me check next time"
3. **The regulator can read the invariants directly** — no auditor as middleman for the rules themselves
4. **Slashable attestations from independent oracles** (KYC providers, custodians, notaries, appraisers) provide the off-chain data the regulator needs

Skald doesn't replace auditors entirely — they still verify that the contract correctly maps to the issuer's intended business reality. But the auditor's role moves from "find any violations" to "confirm the encoded invariants are the right ones." This is a much smaller, faster, more targeted job.

---

## 2. Regulatory articles encoded as Skald invariants

> **Note (per the scope correction above):** the article *numbers* in this section were written against MiCA in an earlier draft. For a security token the substantive obligation is real but the citation should read against the securities regime — e.g. market-abuse/blackout → **MAR**, asset segregation → **MiFID II Art. 16 / AIFMD Art. 21**, prospectus/whitepaper → **Prospectus Regulation**. The invariant *mechanics* below are unchanged; treat the statute labels as illustrative pending counsel review.


### MiCA Article 14 — Whitepaper / prospectus requirements

> *Issuers of asset-referenced tokens or e-money tokens must publish a crypto-asset white paper before offering tokens to the public, and that white paper must be reviewed by the competent authority.*

**Skald encoding:**

```skald
storage {
    whitepaper_registered: bool,
    whitepaper_hash:       string,
    ...
}

invariant prospectus_whitepaper_before_issuance {
    total_supply_issued == 0 || whitepaper_registered
}

entry buy_tokens(token_amount: int) {
    require whitepaper_registered with "whitepaper not registered (MiCA Art. 14)";
    ...
}
```

The invariant guarantees that the *total state of the chain* cannot evolve such that tokens are issued without a registered whitepaper. Every state transition is checked. The regulator reads the invariant and knows it cannot be violated.

The pre-condition on the entry point is technically redundant given the invariant (any violation would revert the transaction), but it gives a better error message to a non-compliant caller.

### MiCA Article 50 — Segregation of client assets

> *Crypto-asset service providers must hold client crypto-assets and funds segregated from their own crypto-assets and funds. They must ensure that client assets cannot be used for the provider's own account.*

**Skald encoding:**

```skald
storage {
    funds_raised_mukrn:           int,    // total invested by subscribers
    funds_released_to_issuer:     int,    // released ONLY with regulatory authorization
    regulatory_release_authorized: bool,
}

invariant mifid_art16_custody_segregation {
    funds_released_to_issuer <= funds_raised_mukrn
}

invariant mifid_art16_release_requires_authorization {
    funds_released_to_issuer == 0 || regulatory_release_authorized
}
```

The issuer cannot drain investor funds. The path from `funds_raised_mukrn` to the issuer's working capital goes through a regulator-authorized release event. The custodian role is the only address that can execute the release.

### MiCA Article 88 — Market abuse prevention

> *Persons in possession of inside information about asset-referenced tokens or e-money tokens shall not unlawfully disclose that information or use it to acquire or dispose of such tokens.*

**Skald encoding:**

```skald
storage {
    blackout_active: bool,
}

entry attempt_transfer(token_amount: int, current_level: int) {
    require !blackout_active with "transfer blocked: blackout window (MiCA Art. 88)";
    ...
}
```

When the issuer (or the compliance oracle that monitors them) declares a blackout window (e.g., before earnings, during pending material event), the contract refuses transfers. This isn't a soft policy — it's a hard runtime constraint.

The blackout signal comes from an off-chain compliance oracle that reads attestations from the issuer's filings. See §4.

### AIFMD Article 21 — Depositary independence

For institutional fund tokenization. The depositary must be a distinct legal entity from the AIFM (the fund manager).

**Skald encoding:**

```skald
storage {
    aifm:       address,
    depositary: address,
}

invariant aifmd_art21_depositary_independence {
    aifm != depositary
}
```

A single-line invariant that cannot be violated. The regulator reads it once and knows the depositary structure is sound.

### AIFMD Article 18 — Risk concentration limits

> *AIFMs must ensure that AIFs they manage maintain adequate risk diversification.*

```skald
storage {
    largest_position_pct:    int,
    concentration_cap_pct:   int,
}

invariant aifmd_art18_concentration_limit {
    largest_position_pct <= concentration_cap_pct
}
```

The compliance oracle updates `largest_position_pct` periodically from off-chain portfolio data. If a trade would push it above the cap, the trade reverts.

### AIFMD Article 22 — NAV staleness

> *AIFMs must ensure that the net asset value per unit of AIFs is calculated and disclosed periodically.*

```skald
storage {
    nav_per_token_mukrn:     int,
    nav_published_at_level:  int,
    nav_max_staleness_levels: int,
}

entry request_redemption(token_amount: int, current_level: int) {
    require current_level - nav_published_at_level <= nav_max_staleness_levels
        with "NAV too stale (AIFMD Art. 22)";
    ...
}
```

If the AIFM fails to publish a fresh NAV within the required window, redemptions auto-pause until a new one is published. The protocol enforces the publication SLA.

### MiFID II Article 24 — Best execution

For institutional fund tokenization specifically. Every trade executed by the AIFM must have a best-execution attestation.

```skald
storage {
    trades_with_best_exec_attestation_count: int,
    total_trades_count:                       int,
}

view best_execution_coverage_pct() -> int {
    trades_with_best_exec_attestation_count * 100 / total_trades_count
}
```

The compliance oracle reads off-chain trade execution reports, verifies the best-exec attestations posted by the execution venue (via the attestation registry), and updates the counters. A regulator query of `best_execution_coverage_pct()` gives an instant compliance metric.

---

## 3. How the templates differ

| Aspect | sto-startup-equity | sto-institutional-fund | sto-real-estate |
|---|---|---|---|
| **Target deal size** | €5M-50M | €50M-500M | €10M-100M |
| **Issuer profile** | Tech scale-up | Established financial institution | Real estate fund / SPV |
| **Compliance frameworks** | MiCA only | MiCA + AIFMD + MiFID II | MiCA + national real estate law |
| **NAV publishing** | Not required | Required, with staleness SLA | Annual valuation required |
| **Redemption** | Lock-up + exit event | Per-NAV redemption | Secondary market or property sale |
| **Custody** | Issuer-multisig or third-party | Independent depositary mandatory | Depositary + notary (for title) |
| **Risk limits** | None | Concentration cap (Art. 18) | Property-specific |
| **Rental/yield distribution** | N/A | Via redemption | Periodic distribution from rent |
| **Lock-up** | Typical 12 months | Per redemption mechanics | Mandatory 12+ months |
| **Terminal event** | Buyback or IPO | Indefinite (open-ended) | Property sale → wind-down |

Each template is fully type-checked by the Skald static type system (see [`typecheck.md`](typecheck.md)) and is ready to deploy on the Kern devnet for testing.

---

## 4. The off-chain orchestration: compliance oracles + attestations

The contract IS NOT self-sufficient — by design. Compliance requires off-chain data that the chain cannot directly observe:

- KYC/AML status of investors (collected by a regulated entity)
- Best-execution proof of a trade (from the execution venue)
- Notary attestation of title transfer (from a public notary)
- NAV calculation (from the AIFM)
- Property valuation (from a licensed appraiser)

Kern integrates these via the **slashable attestation registry** introduced in v1.1-rc (see [`attestations.md`](attestations.md)).

The integration pattern:

```
┌──────────────────────────────┐
│ Off-chain regulated entity   │
│ (KYC provider, notary,       │
│  appraiser, depositary)      │
└──────────────┬───────────────┘
               │ posts ATTEST transactions
               │ (with KRN bond)
               ▼
┌──────────────────────────────┐
│ Kern chain — attestation     │
│ registry                     │
│  - schema_id                 │
│  - subject                   │
│  - claim (JSON)              │
│  - bond (slashable)          │
└──────────────┬───────────────┘
               │ off-chain compliance oracle
               │ reads via RPC
               ▼
┌──────────────────────────────┐
│ Off-chain compliance oracle  │
│ (a Foundation-operated or    │
│  client-operated service)    │
│  Verifies attestations meet  │
│  threshold (e.g., bond > X)  │
└──────────────┬───────────────┘
               │ calls STO contract's
               │ "register_X" entries
               ▼
┌──────────────────────────────┐
│ STO Skald contract           │
│ Updates: whitepaper_         │
│ registered, nav_per_token,   │
│ blackout_active, etc.        │
└──────────────────────────────┘
```

**Why this indirection?** The Skald contract is a runtime-enforced state machine — it must always make the same decision given the same input. The "should I trust this attestation?" question is a policy decision that varies by deal (different STOs trust different KYC providers; different funds use different appraisers).

By splitting the responsibilities:

- The **contract** enforces compliance invariants atomically
- The **compliance oracle** decides which off-chain attestations to trust
- The **attestation registry** holds the cryptographic evidence with slashing-on-equivocation

Each layer has the simplest possible job. The regulator can audit each layer independently.

---

## 5. Conventional attestation schemas for STOs

Issuers can use any schema names; these are conventions for interoperability:

| Schema ID | Subject | Claim shape | Posted by |
|---|---|---|---|
| `kyc.aml-screening` | investor address | `{"status": "passed"\|"failed", "level": "individual"\|"corporate", "completed_at": int}` | KYC provider (regulated) |
| `kyc.accredited-investor` | investor address | `{"is_accredited": bool, "jurisdiction": str, "verified_at": int}` | Regulated investment firm |
| `kyc.source-of-funds` | investor address | `{"declared": bool, "category": str}` | KYC provider |
| `compliance.whitepaper-registered` | contract address | `{"hash": str, "approved_by": str, "approved_at": int}` | Competent authority's oracle |
| `compliance.blackout-event` | contract address | `{"started_at": int, "reason": str}` | Issuer or oracle |
| `realestate.title-registered` | property_id | `{"spv": str, "notary": str, "registered_at": int}` | Notary |
| `realestate.valuation` | property_id | `{"value_mukrn": int, "appraiser_license": str}` | Licensed appraiser |
| `fund.nav-publication` | fund address | `{"nav_per_token": int, "as_of_level": int, "depositary_signed": bool}` | AIFM (co-signed by depositary) |
| `tradevenue.best-execution` | trade_id | `{"venue": str, "spread": int, "verified_at": int}` | Execution venue |

Each posted with a bond proportional to the consequence of equivocation. A KYC provider attesting a fraudulent ID is exposed to slashing if the equivocation is later proved (the same provider attesting different statuses for the same investor).

---

## 6. The regulator's read interface

A regulator does NOT need to read every transaction. They have three integration points:

### Point 1 — Read contract storage directly

```bash
curl -s $KERN_RPC/chain/contract/$STO_CONTRACT | jq '.storage'
```

The storage layout names the invariants explicitly (`prospectus_whitepaper_before_issuance`, etc.). The regulator reads the storage state once and confirms the invariants are encoded.

### Point 2 — Use the contract's view functions

```bash
# Is the STO compliant right now?
curl -s $KERN_RPC/chain/view/$STO_CONTRACT/is_mica_compliant
# {"result": true}

# How much has been raised? Distributed? Released?
curl -s $KERN_RPC/chain/view/$STO_CONTRACT/raise_progress_percent
# {"result": 67}
```

(The /chain/view RPC endpoint executes a pure view function against the current state and returns the result. Implementation in v1.2; for v1.1-rc, the regulator queries storage directly via /chain/contract.)

### Point 3 — Subscribe to attestation registry events

```bash
# All attestations the contract relies on
curl -s "$KERN_RPC/chain/attestations?schema=compliance.blackout-event&subject=$STO_CONTRACT" | jq

# All attestations from a specific KYC provider
curl -s "$KERN_RPC/chain/attestations?issuer=kn1kyc_provider" | jq
```

If anomalies appear (e.g., the KYC provider issued equivocating attestations), the regulator can investigate and the slashing mechanism punishes the misbehavior automatically.

---

## 7. Why this is defensible to a regulator

A regulator (e.g., FSMA in Belgium) reviewing whether to approve an STO on Kern can be presented with:

1. **The Skald source file** (one PDF, 200-300 lines, human-readable)
2. **A mapping table** (5 lines) from MiCA articles to the contract's `invariant` declarations
3. **A test suite** demonstrating that the type checker accepts the contract
4. **An attestation policy** describing which oracles provide which attestations and with what bonds

Total review surface: probably under 50 pages, far less than a typical prospectus (which can run to 500+ pages of legalese).

The regulator's review focuses on two questions:

- **Are the encoded invariants the right ones?** (Domain expertise applied to a small, focused document.)
- **Is the off-chain attestation policy sound?** (Are the KYC providers and oracles licensed and bonded appropriately?)

Compare to current practice:

- 500-page prospectus
- Multiple legal opinions
- Annual auditor's report (after the fact)
- Regulatory inspection if anomalies are reported

The Skald model doesn't replace the regulator's judgment — but it makes that judgment scalable, repeatable, and continuously verified.

---

## 8. Limitations of the v1.1-rc demonstrators

These templates demonstrate the pattern but have known limitations to be lifted in subsequent versions:

| Limitation | Why | Future fix |
|---|---|---|
| No per-investor token balances tracked inside the contract | Skald v1.1 lacks `mapping<address, int>` types | v1.2 Skald adds mapping support |
| Cross-contract reads not implemented | Skald v1.1 contracts are isolated | v1.2 adds `call_view(contract, entry, params)` |
| Off-chain compliance oracle is not part of the contract | Skald cannot directly read the attestation registry yet | v1.2 adds `attestation_latest(...)` builtin |
| No bridge to MiFID II execution venues | Out of scope | v2.0 — add EIP-712-style execution attestation schema |
| No multi-currency (EUR-denominated NAV) | All amounts in mukrn | v2.0 — denomination registry primitive |

These templates are deployable today on Kern devnet and demonstrate the compliance-by-construction thesis. Production deployment requires the v1.2 features above, which are the natural next iteration.

---

## 9. Reference

- **Templates**: [`kern/skald/examples/sto-startup-equity.skald`](../kern/skald/examples/sto-startup-equity.skald), [`sto-institutional-fund.skald`](../kern/skald/examples/sto-institutional-fund.skald), [`sto-real-estate.skald`](../kern/skald/examples/sto-real-estate.skald)
- **Slashable attestations**: [`attestations.md`](attestations.md)
- **Skald language**: [`skald-language.md`](skald-language.md), [`typecheck.md`](typecheck.md)
- **MiCA full text**: Regulation (EU) 2023/1114 — <https://eur-lex.europa.eu/eli/reg/2023/1114>
- **AIFMD full text**: Directive 2011/61/EU
- **MiFID II full text**: Directive 2014/65/EU
- **Belgian context**: FSMA (`fsma.be`), Code of Economic Law Book XI
