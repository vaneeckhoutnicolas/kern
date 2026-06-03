# Post-Code Roadmap — From v1.1-rc to Midgard Mainnet

Kern v1.1-rc is code-complete. **What remains is execution work that cannot be solved by writing more code.** This document is the roadmap for that work.

It is the canonical reference for:
- The 6 phases that bring Kern from "audited reference implementation" to "Midgard mainnet live"
- The dependencies between phases (what blocks what)
- Indicative budgets and timelines
- Decision points where execution choices need to be made

**Owner**: Nicolas Van Eeckhout (founder) until Foundation incorporation, then jointly with the Foundation board.

---

## Overview

```
v1.1-rc (today)
  │
  ▼
┌────────────────────────────────────────┐
│ Phase 1: Foundation incorporation       │  ~3 months   €40-60k
│ (Estonian Foundation (Sihtasutus) recommended)             │
└──────────────┬─────────────────────────┘
               │ unlocks everything below
               │
        ┌──────┴──────────────┐
        ▼                     ▼
┌──────────────────┐  ┌─────────────────────┐
│ Phase 2: Audit 1 │  │ Phase 3: Yggdrasil  │   parallel
│ ~2-3 months      │  │ testnet launch       │   tracks
│ €100-200k        │  │ ~2 months  €15-30k   │
└────────┬─────────┘  └─────────┬───────────┘
         │                       │
         ▼                       │
┌──────────────────┐              │
│ Phase 4: Audit   │              │
│ remediation + 2  │              │
│ ~2 months €50-80k│              │
└────────┬─────────┘              │
         │                       │
         └─────────┬─────────────┘
                   │
                   ▼
        ┌────────────────────┐
        │ Phase 5: Public    │  ~1 month   €30-50k
        │ sale + treasury    │
        │ provisioning       │
        └─────────┬──────────┘
                  │
                  ▼
        ┌────────────────────┐
        │ Phase 6: Midgard   │  Day 0
        │ mainnet genesis    │
        └────────────────────┘
```

**Realistic total**: 9-12 months from v1.1-rc to Midgard live.

**Total indicative budget**: €240-420k over the period.

Numbers are estimates based on comparable EU L1 launches (Tezos Foundation 2018, IOTA Foundation 2017, Aleph Zero Foundation 2021). Actuals depend on the audit firm selected, the legal jurisdiction, and the public sale design.

---

## Phase 1 — Foundation incorporation (Estonian Foundation / Sihtasutus recommended)

### Why first

The Foundation is the legal entity that holds the KRN allocation, signs the genesis ceremony, contracts with auditors, and represents Kern in regulatory dialogue. Until it exists, every other phase is blocked from execution because:

- Audit firms require a contracting entity (not an individual)
- A public sale requires a regulated legal vehicle
- Validators are reluctant to commit to an unregistered project
- Regulators (FSMA, AMF, Finantsinspektsioon, BaFin, etc.) want a counterparty to interact with

### Recommended jurisdiction

**Estonian Foundation (Sihtasutus)** is the recommended structure because:

1. It is a non-profit form natively recognized across the EU under freedom-of-establishment
2. Estonia has the most established crypto-friendly legal framework in the EU, with Finantsinspektsioon precedent on MiCA implementation
3. e-Residency enables remote operation from Brussels with no physical relocation
4. ~3x lower annual cost than Belgian or Swiss alternatives — more budget for security audits
5. Belgian moral rights law (Art. XI.165) continues to protect founder attribution regardless of Foundation jurisdiction

Alternatives considered:

| Form | Pros | Cons |
|---|---|---|
| **Estonian Foundation / Sihtasutus** (recommended) | EU native; lowest annual cost; e-Residency-friendly; established crypto-precedent | Founder must obtain e-Residency for remote operation (≈1 month) |
| Belgian AISBL | Brussels-proximity; FSMA dialogue easier if STO templates approved there first | Higher annual cost; slower notary processes |
| Swiss Stiftung (Zug) | Strongest crypto-precedent (Ethereum, Solana) | Outside EU; subject to FINMA's stricter line on token issuance post-2022; significantly more expensive |
| Cayman Foundation | Tax-efficient | Reputational baggage; EU institutions less receptive |

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Obtain Estonian e-Residency for Nicolas (https://www.e-resident.gov.ee/) | Founder | €100 application fee | 3-5 weeks |
| Engage Estonian foundation counsel (COBALT, Sorainen, Triniti, or specialised boutique) | Founder | €3-8k retainer | 2 weeks |
| Identify board members (3-5 people, no nationality requirement) | Founder | — | 4-6 weeks |
| Draft foundation deed + statutes (põhikiri) in Estonian + English | Counsel + Founder | €5-15k | 3 weeks |
| Digital notarisation via e-Notary | Counsel | €500-1 500 | 1 week |
| Registration with Estonian Business Register (Äriregister) | Counsel | (included) | 1 week |
| Open Foundation bank account (LHV Pank, SEB, or alternative) | Foundation | €0 | 2-4 weeks |
| Engage statutory auditor (Estonian Auditors Association member) | Foundation | €5-12k/year | 2 weeks |
| Generate Foundation multisig keys (3-of-5) | Foundation board | — | 1 day |
| Generate founder allocation multisig (2-of-3) | Founder | — | 1 day |
| Adopt internal policies (conflict of interest, whistleblower, document retention) | Foundation board | €3-7k | 4 weeks |
| **Phase 1 total** | | **€20-40k** | **~2-3 months** |

### Deliverables

- Sihtasutus incorporated and registered with Estonian Business Register (registry code obtained)
- Statutory auditor engaged
- Foundation bank account operational
- Multisigs generated for: Foundation pool (3-of-5), founder vesting (2-of-3), contributors pool (3-of-5), validator bootstrap pool (2-of-3)
- Initial capital deposited (≥ €50k equivalent)
- Internal policies adopted

### Key decision points

- **Initial Foundation board composition**: who has the credibility and time to serve? Recommended composition: 2 from Belgium, 1 from Germany, 1 from France, 1 from a Nordic country. Mix of legal, technical, and economic backgrounds.
- **Foundation operating budget for year 1**: typical ranges are €300k-800k including audit costs, staffing, infrastructure, and reserve. Founder contribution vs early treasury vs delayed funding through public sale.
- **Foundation logo, brand, website**: outsourced or in-house? Budget €5-15k for a clean web presence.

---

## Phase 2 — Audit cycle 1

### What it is

A specialized smart-contract security firm reviews the full Kern v1.1-rc codebase over 6-12 weeks. The output is a public audit report classifying findings as Critical / High / Medium / Low / Informational, with a description of each issue and the recommended remediation.

The findings from this audit drive the work in Phase 4.

### Candidate firms

| Firm | Strengths | Comparable past work | Indicative cost (12 weeks) |
|---|---|---|---|
| Trail of Bits | Strong on cryptographic constructions, formal verification | Compound, MakerDAO, Solana | €150-250k |
| OtterSec | Strong on consensus/economic security | Aptos, Sui, Solana | €100-180k |
| Hashlock | EU-located, growing reputation | Bitfinex, Curve | €80-150k |
| Runtime Verification | Formal verification specialists | Ethereum, IOHK Cardano | €120-200k |
| ChainSec | EU-based, lighter scope | Polkadot, Acala | €80-130k |
| Certik | Largest but commodity-tier | Many; quality varies | €60-100k |

### Recommendation

**Start with two RFPs**: Trail of Bits (cycle 1 reputational anchor) and Hashlock (EU proximity, lower cost). Compare scope, methodology, and team CVs. Pick whichever offers the highest quality team for the budget.

For Kern's positioning (institutional, EU, regulator-readable), **Trail of Bits' reputation** is worth the premium. They are the firm regulators recognize.

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Prepare audit RFP (scope, code repo access, deliverables, timeline) | Foundation + Founder | €0 | 2 weeks |
| Send RFP to 3-5 firms | Foundation | €0 | 1 week |
| Compare proposals, interview teams, select firm | Foundation board | €0 | 2-3 weeks |
| Engagement letter signed | Foundation + Auditor | (included) | 1 week |
| Kickoff meeting | Both | (included) | 1 day |
| Audit execution | Auditor | €100-200k | 8-12 weeks |
| Findings report (preliminary) | Auditor | (included) | (within audit) |
| **Phase 2 total** | | **€100-200k** | **~2-3 months** |

### Deliverables

- Signed engagement letter
- Public audit report (PDF) with all findings
- Findings categorized by severity
- Recommended remediations for each
- Originality and authorship attestation (auditor confirms Kern code is original; relevant for moral rights protection)

### What this internal security review prepared

The internal review documented in [`security-review-v11rc.md`](security-review-v11rc.md) already surfaced and fixed 7 findings (2 critical, 2 major, 2 medium, 1 minor). This is **what the audit team won't have to find for us** — saving roughly 1-2 weeks of their time. Don't expect this to halve the audit cost; it improves the quality of what the audit catches.

---

## Phase 3 — Yggdrasil testnet launch (in parallel with audit)

### What it is

A public testnet that mirrors the planned Midgard mainnet topology. Validators and users interact with real Kern code under real-world conditions. Issues that don't surface in unit tests (network partitions, mempool DoS, edge cases in BFT under load) emerge here.

This phase can and SHOULD run in parallel with the audit. Audit findings might prompt code changes; the testnet provides a place to validate those changes before mainnet.

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Genesis design for Yggdrasil (validator set, faucet allocation, initial token distribution) | Founder | — | 1 week |
| Recruit 5-10 initial validators (Foundation contacts) | Foundation | €0 | 4 weeks |
| Validator hardware/cloud setup (each runs ~€100-500/month) | Validators | (their cost) | 2 weeks |
| Faucet contract + frontend | Community / Founder | €5-10k | 2 weeks |
| Block explorer (Heimdall — already shipped; needs deployment + ops) | Foundation | €5-15k (hosting + Grafana) | 1 week to deploy |
| Yggdrasil launch event | Foundation | €0 | 1 day |
| Monitoring and incident response | Foundation + validators | ongoing | continuous |
| 60-day stability validation | Foundation | €0 | 2 months |
| **Phase 3 total** | | **€15-30k** | **~2 months** |

### Deliverables

- Yggdrasil testnet operational with 5-10 validators
- Faucet operational (users can request testnet KRN)
- Block explorer operational (the official **Heimdall** explorer + monitoring stack, see [setup-heimdall-operator.md](setup-heimdall-operator.md))
- 60 days of stability data (uptime, no consensus halts > 5 min)
- Public testnet stress test report (1M+ tx without consensus issues)
- At least one rollup deployment on testnet (demo of EVM-via-rollup)

### Key decision points

- **Validator selection**: who are the initial 5-10? Recommended: 2-3 Foundation-operated, 5-7 community/professional validators (Staked, P2P, Chainflow, etc.). The Foundation pays them validator subsidies for the testnet duration.
- **Faucet limits**: how much KRN per request? Recommended: 100 KRN per address per day, with global rate limiting.

---

## Phase 4 — Audit remediation + cycle 2

### What it is

Apply the fixes for Audit 1 findings, then run a second (shorter) audit to verify the fixes work and didn't introduce new issues.

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Fix all Critical findings | Founder + audit firm review | — | 2-4 weeks |
| Fix all High findings | Founder | — | 2-3 weeks |
| Address Medium findings (fix or document acceptance) | Founder | — | 1-2 weeks |
| Update test suite | Founder | — | 1 week |
| Re-deploy to testnet for re-validation | Validators | (covered in P3) | 1 week |
| Audit cycle 2 (re-audit of fixes only) | Audit firm (same or different) | €30-50k | 3-5 weeks |
| Cycle 2 report | Auditor | — | 1 week |
| **Phase 4 total** | | **€50-80k** | **~2 months** |

### Deliverables

- All Critical and High findings remediated
- Medium findings either fixed or documented with acceptance rationale
- Cycle 2 audit report (public)
- Code tagged as `v1.1.0` (or `v1.0.0` if the Foundation chooses to ship v1.0 first then add v1.1 features incrementally)

### Decision point — what tag for mainnet?

Two options:

1. **Ship v1.1.0** (recommended) — mainnet launches with all 4 verticals (attestations, STO securities, public goods funding, oracles) live from day 1. Maximizes initial utility but increases audit scope.
2. **Ship v1.0.0 then v1.1.0** — mainnet starts with v1.0 features only; v1.1 ships post-launch via governance amendment. Smaller initial audit scope; the v1.1 features get separate audit later.

Recommendation depends on the audit findings — if v1.1-rc emerges with few changes, ship v1.1.0. If audit cycle 1 surfaces deep issues in the v1.1 verticals specifically, ship v1.0 first.

---

## Phase 5 — Public sale + treasury provisioning

### What it is

The genesis distribution allocates 70% of KRN supply to public buyers. This phase designs and executes that distribution.

This is **the highest-regulatory-risk phase** of the entire roadmap. MiCA crypto-asset distribution rules apply. Engage securities counsel BEFORE designing the mechanism.

### Sale mechanism options

| Mechanism | How it works | Pros | Cons | Typical use |
|---|---|---|---|---|
| ICO (fixed price) | Buyers send KRN at announced rate over a window | Simple, well-understood | Lottery dynamics; bot domination | Pre-2018 model |
| Dutch auction | Price starts high, drops until clears | Market-clearing price | Complex to communicate | MakerDAO, Foundation Devices |
| LBP (Liquidity Bootstrapping Pool) | Continuous price discovery via Balancer-style pool | Smooth distribution | Requires DEX infrastructure | Many recent launches |
| Staged sale (private → strategic → public) | Tiered access with KYC and lockups | Allows institutional participation | Regulator-friendly but slower | Aleph Zero, recent EU launches |
| Genesis airdrop (no sale) | Allocation by community participation criteria | No "sale" = MiCA-light | Limited treasury runway | Some L2 launches |

### Recommendation

**Staged sale: Private (institutional) → Strategic (community) → Public (open)**. Each stage with:

- KYC and AML screening (via the attestation infrastructure we've built — eat our own dogfood)
- Jurisdictional geofencing (no US persons during Reg S window; no Cuba/Iran/etc.)
- Lockups: Private 18-month vesting, Strategic 12-month vesting, Public 6-month vesting (smooth supply increase)

The Kern Foundation (Estonian Sihtasutus) contracts with a securities-licensed entity in an EU MiCA jurisdiction (e.g., Estonia, Luxembourg, or Liechtenstein) to operate the sale, so the regulatory burden is on a specialist.

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Engage securities counsel (Sorainen, Loyens Loeff Luxembourg, Allen & Overy LX, or equivalent EU MiCA-experienced firm) | Foundation | €30-60k | 2 weeks |
| Design sale mechanism + legal opinion | Foundation + counsel | (included) | 4 weeks |
| Select sale platform (Tokeny, ConsenSys Codefi, in-house) | Foundation | €20-50k setup | 4 weeks |
| Marketing and community outreach | Foundation | €10-30k | continuous |
| KYC/AML provider integration | Foundation | €5-15k | 2 weeks |
| Sale execution | Foundation | (operational) | 2-4 weeks |
| Treasury provisioning to Foundation pool (15% of supply) | Foundation | (zero) | 1 day |
| Founder allocation provisioning (10%, 4-year vest) | Foundation + Founder | (zero) | 1 day |
| **Phase 5 total** | | **€30-50k** (excl. counsel) | **~1 month execution** |

### Deliverables

- Securities legal opinion (private and confidential)
- Sale mechanism documentation (public)
- Sale platform live
- KYC/AML screening operational (using Kern attestation infrastructure)
- Sale executed; treasury and allocations provisioned
- Genesis allocations file finalized

### Key decision points

- **Token price**: discovered by mechanism (auction) or set by Foundation (ICO)? Recommended: **let the auction discover**, with a floor price tied to development costs.
- **Total raised vs. number of holders**: optimize for *number* of holders (broader distribution) over *amount raised* (vanity metric). 10 000 small holders > 100 whales.

---

## Phase 6 — Midgard mainnet launch

### What it is

The genesis ceremony where the Foundation board, with the founder, signs the final `genesis.json` and the validator network begins producing blocks.

This is the irreversible event. Once block 1 is produced, the chain is live and the KRN tokens have economic value.

### Steps and budget

| Step | Owner | Indicative cost | Indicative time |
|---|---|---:|---|
| Final genesis.json construction (final addresses, balances, validators) | Founder + Foundation | — | 1 week |
| Foundation board convenes for genesis ceremony | Foundation | (logistics ~€5k) | 1 day |
| Each board member signs hash with personal GPG key | Foundation board | — | 1 day |
| Genesis pinned to IPFS, archived to archive.org | Foundation | €100 | 1 day |
| 7-day public verification window | Public | €0 | 7 days |
| Validators boot Midgard nodes | Validators | (their infra cost) | 1 day |
| Block 1 produced | Validators | — | (event) |
| Mainnet announcement | Foundation | €5-10k PR | 1 day |
| KRN distribution to sale participants | Foundation | — | 1-3 days |
| Public RPC endpoint, block explorer go live | Community | €5-20k/month | 1 day |
| **Phase 6 total** | | **€10-30k** | **~2 weeks execution** |

### Deliverables

- Midgard mainnet live (block 1 produced)
- 5-10+ validators operating
- Public RPC, **Heimdall explorer**, wallet UI all functional
- KRN distributed to sale participants
- Founder + Foundation + contributors + validator-bootstrap allocations live with respective vesting schedules
- Mainnet announcement published

---

## Cumulative budget summary

| Phase | Indicative cost |
|---|---:|
| Phase 1 — Foundation incorporation | €40-60k |
| Phase 2 — Audit cycle 1 | €100-200k |
| Phase 3 — Yggdrasil testnet | €15-30k |
| Phase 4 — Remediation + audit cycle 2 | €50-80k |
| Phase 5 — Public sale | €30-50k (excl. counsel ≈ €30-60k) |
| Phase 6 — Mainnet launch | €10-30k |
| **Cumulative total (low)** | **€275k** |
| **Cumulative total (high)** | **€510k** |

This is operational spend. The Foundation must also reserve operating budget for year 1 post-launch (incident response, ongoing audits, community support): €300-600k typical.

**Total Foundation runway needed at start of Phase 1**: ~€600k-1M (conservative) or ~€300k-500k (lean).

---

## Funding the runway

Three options for funding the €600k-1M:

1. **Founder bootstrap**: Nicolas + co-founders provide capital, Foundation reimburses via treasury post-launch
2. **Strategic backers**: angel investors / EU-aligned crypto funds provide capital in exchange for early KRN allocation (subject to MiCA Art. 14 prospectus rules)
3. **Foundation grant**: a partner foundation (Ethereum Foundation, Web3 Foundation grants) — competitive, slow, but reputationally beneficial

The realistic answer is probably a mix: **founder bootstrap + 1-2 strategic backers + Belgian government innovation grant (VLAIO, BEFin, ...)**. Belgian innovation funding is non-trivial; a Brussels-based protocol with EU positioning is a strong applicant.

---

## Critical-path summary

```
Month 0:  v1.1-rc shipped (today)
Month 1:  Foundation counsel engaged, board recruited
Month 2:  Foundation board first meeting; audit RFPs out
Month 3:  Foundation incorporated (Moniteur publication)
          Audit firm selected; audit cycle 1 kickoff
Month 4:  Yggdrasil testnet launched
          Audit cycle 1 in progress
Month 6:  Audit cycle 1 report received
          Yggdrasil 60-day stability validated
Month 7:  Audit findings remediation
Month 8:  Audit cycle 2 in progress
          Public sale legal design complete
Month 9:  Audit cycle 2 complete
          Public sale launched
Month 10: Public sale concludes
          Genesis ceremony preparation
Month 11: Genesis ceremony
          Mainnet announcement
Month 12: Midgard live; v1.1.0 (or v1.0.0) tagged
```

This is the **aggressive** path. Realistic path with normal delays: **12-15 months**.

---

## What's NOT in this roadmap

Several activities run in parallel and are not gated by these phases:

- **Documentation translation** (French, German, Dutch, Spanish) — community-driven
- **Skald developer tooling** (IDE integration, debugger, simulator) — community + Foundation grants
- **EVM compatibility maturation** — rollup framework improvements continue
- **External integrations** (wallets, exchanges, on-ramps) — engaged when audit is complete

---

## Reference

- [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) — itemized list of every gate (the source of truth)
- [`setup-foundation.md`](setup-foundation.md) — operational steps for Foundation incorporation
- [`setup-auditor.md`](setup-auditor.md) — auditor engagement workflow
- [`setup-validator.md`](setup-validator.md) — validator setup
- [`tokenomics.md`](tokenomics.md) — KRN economic design
- [`security-review-v11rc.md`](security-review-v11rc.md) — internal security review input to audit
