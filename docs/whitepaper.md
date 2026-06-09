# Kern — A Layer-1 Protocol for Institutional Legibility

*Whitepaper, v1.1-rc*

*Nicolas Van Eeckhout (founder) and Kern contributors*

*Published as part of the Kern v1.1-rc release. License: CC-BY-SA-4.0 for this document; Apache-2.0 for the reference implementation.*

---

## Abstract

We present Kern, a Layer-1 blockchain protocol designed around a specific thesis we call **institutional legibility**: the property that the rules an institution must follow — whether regulatory (MiCA, AIFMD, MiFID II), procedural (grant-making, funding allocation), or evidentiary (oracle attestations, supply chain provenance) — are encoded as protocol-enforced invariants that regulators, auditors, and counterparties can read directly, without trusting any intermediary.

Kern combines five primitives that together support this thesis. None of them is individually novel; the combination has not previously been delivered by any production Layer-1 protocol. Those primitives are: (1) a four-phase BFT consensus protocol with Liquid Proof-of-Stake delegation; (2) the Skald contract language with first-class runtime-enforced invariants and a static type system; (3) dual-track on-chain governance with equivocation slashing; (4) the slashable attestation primitive — generalized equivocation detection for any signed claim about the world; (5) BN254 zk-SNARK verification precompiles enabling privacy-preserving compliance attestations.

We describe the protocol architecture, the four application verticals it enables (compliance-by-construction Security Token Offerings, public goods funding, generic data oracle networks, and ZK-claims-based identity), and the operational path from the v1.1-rc reference implementation to the Midgard mainnet. We are explicit about what Kern is not, what audits are required before launch, and which design decisions are deliberate trade-offs.

The reference implementation is open-source under Apache-2.0 and ships with 483 passing tests. A professional security audit by a specialized firm is mandatory before Midgard mainnet launch; we have conducted an internal review that surfaced and fixed seven vulnerabilities prior to engaging the professional audit.

### Table of contents

1. **Ambition** — Why, How, What
2. **Motivation** — the structural gap in existing L1s
3. **Use cases envisioned** — nine personae across compliance, public goods, oracles, identity
4. **The core thesis: institutional legibility** — what Kern provides that other L1s don't (5 rows)
5. **Consensus** — four-phase BFT finality with LPoS, validator economics, slashing
6. **Skald and the KVM** — first-class invariants, static typing, deterministic interpreter
7. **EVM compatibility via Optimistic Smart Rollups** — Solidity gets a home without compromising L1 design
8. **The slashable attestation primitive** — the new L1 primitive in v1.1-rc
9. **ZK-claims: privacy-preserving attestations** — Groth16+BN254, four reference circuits
10. **On-chain governance** — dual-track (protocol + treasury), equivocation slashing
11. **Token economy** — 100M KRN, distribution, issuance, slashing economy
12. **Security review and audit path** — internal review done, professional audit mandatory
13. **From whitepaper to running node** — technical entry points (9 setup guides per role)
14. **v1.2 roadmap** — what comes next
15. **The position Kern occupies** — the institutional market this targets
16. **Reference implementation** — stats, how to run locally
17. **Acknowledgments**
18. **License**

---

## 1. Ambition

This section states the project's ambition in the simplest terms we can. We follow the Why → How → What ordering popularized by Simon Sinek's *Start With Why*, which we find clarifying for protocol design as much as for product design.

### 1.1 WHY — the conviction that drives Kern

We are building Kern because we believe the next decade of blockchain adoption will not be won by the protocol that maximizes transactions per second, the protocol that lists on the most exchanges, or the protocol that builds the most aggressive growth incentives. It will be won by the protocol that **institutions can adopt without lying to their regulators, auditors, or beneficiaries**.

The institutional gap is concrete. Today:

- A European bank cannot tokenize a financial product on a public chain without inheriting a regulatory burden so vast that the cost-benefit is negative. So they don't.
- A regulator cannot verify a smart contract's compliance with MiFID II Art. 16(9) (custody segregation) without commissioning an audit from a Big Four firm, reading the audit report, and trusting the auditor. So they don't approve the contract until the audit is done — a 6-12 month cycle that kills most launches.
- An NGO cannot run a public-goods funding round on-chain without one of two outcomes: either Sybil attacks drain the matching pool, or the manual sybil-detection process drives administrative cost above 15% of the disbursement.
- An identity service cannot attest a user's age without revealing the user's date of birth — and revealing the DOB creates GDPR exposure that the service can't carry.

All four of these gaps exist not because the underlying problems are unsolvable, but because **no production Layer-1 has assembled the right primitives in one place**. Each gap requires a specific combination: declared invariants + privacy-preserving proofs + slashable attestations + on-chain governance + a regulator-readable contract language.

The why is: **institutions deserve infrastructure that lets them remain institutions while using blockchain rails**. Not "DeFi for everyone" — DeFi for those who choose it. Beyond DeFi, **accountable infrastructure for the institutions that make collective life work**: banks, foundations, public bodies, regulators, NGOs, industry consortia.

This conviction predates Kern; the Tezos community has been articulating something close to it since 2018. What's new is the convergence of a maturing EU regulatory perimeter (MiCA for crypto-assets; MiFID II, the Prospectus Regulation and AIFMD for financial instruments), zk-SNARKs reaching production maturity (Groth16 + BN254 is now standard), and the slashing primitive design (proven at consensus layer, generalizable to off-chain claims).

### 1.2 HOW — the design principles that constrain Kern

Five design principles constrain every protocol decision in Kern. They are not aspirations; they are constraints we test every PR against.

**(1) Determinism over throughput.** A predictable 2-second finality is preferred over peak TPS. Applications that need 50,000 TPS live in rollups; the L1 is a settlement and governance layer. This principle directly chooses against the Solana model.

**(2) Formal properties over expressive convenience.** Skald deliberately omits language features that make static analysis intractable. No dynamic dispatch in the EVM sense; no unbounded recursion; no implicit state mutation; every contract declares its invariants; the runtime checks them on every entry call. This principle directly chooses against the Solidity model.

**(3) On-chain evolution over off-chain coordination.** Protocol changes — including consensus parameters, gas pricing, treasury allocations, and changes to Skald itself — are proposed, voted on, and activated on-chain. Hard forks remain physically possible but are not the intended evolution path. This principle inherits from Tezos and extends it with dual-track governance.

**(4) Cryptoeconomic accountability over reputation.** Misbehavior — by validators (consensus equivocation), by governance participants (vote equivocation), or by off-chain claim issuers (attestation equivocation) — is detected on-chain by anyone and punished automatically through slashing. Reputation systems are slow, contestable, and depend on social consensus; slashing is immediate, mathematical, and provable. This principle is what produces the slashable attestation primitive in v1.1-rc.

**(5) Compatibility over purity.** Existing Ethereum developers and existing Ethereum assets need a path into Kern. Optimistic Smart Rollups, with EVM-compatible execution settling to Kern, provide that path without compromising L1 design properties. This principle is what justifies running EVM via rollup instead of natively.

These five constraints, in conjunction, produce the rest of the protocol mechanically. There is little optionality left once you commit to all five.

### 1.3 WHAT — the deliverables

What Kern ships, concretely:

1. A **Layer-1 blockchain protocol** with the design above, running with Python reference implementation (Apache-2.0, ~33,000 LOC, 483 passing tests).
2. **KRN**, the native token, with a 100M genesis supply distributed per the Ethereum 2014 template.
3. **Skald**, a contract language with first-class runtime-enforced invariants, plus a static type system, plus a deterministic interpreter (the Kern Virtual Machine).
4. **A dual-track governance system** (protocol amendments + treasury) with equivocation slashing.
5. **A slashable attestation registry** as a protocol primitive, generalizing equivocation accountability beyond consensus to any signed claim.
6. **A ZK-claims infrastructure** built on BN254 pairing precompiles for privacy-preserving compliance attestations, with four reference circuits described.
7. **An Optimistic Smart Rollup framework** with multi-frame EVM, bisection-based fraud proofs, and forced inclusion.
8. **Ten reference Skald contracts** spanning compliance-by-construction STOs (3 templates), public goods funding (QF + RPGF), oracle networks (generic + DeFi prices + schema marketplace), and didactic examples (vault, counter).
9. **A complete documentation set** of 51 markdown files, including this whitepaper, nine role-specific setup guides (see §13), the four vertical specification documents, the API stability specification, the tokenomics specification, the governance specification, and the operational roadmap to mainnet.
10. **An internal security review** documenting seven findings (two Critical, two Major, two Medium, one Minor) all fixed prior to engaging the mandatory professional audit.

The deliverables are reference-implementation-grade. Production deployment requires the professional audit (Phase 2 in the post-code roadmap), the Foundation incorporation (Phase 1), and the public testnet stability validation (Phase 3). See §12 for the security path and the [post-code roadmap](post-code-roadmap.md) for the full operational timeline.

---

## 2. Motivation

### 2.1 The structural gap in existing Layer-1 protocols

The blockchain ecosystem has produced two dominant Layer-1 families.

**The developer-gravity family** (Ethereum and its many descendants — Polygon, Optimism, Arbitrum, Base, Avalanche, BNB Chain, Solana) optimizes for attracting builders. Their core asset is the size and depth of the developer ecosystem and tooling. Their characteristic weaknesses are: contract languages (Solidity, Move, Cairo, Rust) that make formal reasoning intractable in practice; governance that depends on off-chain social coordination and hard forks; and a primary application domain (decentralized finance speculation) that is poorly aligned with regulatory expectations.

**The protocol-rigor family** (Tezos, Cardano, Algorand, Polkadot to some extent) optimizes for formally-tractable protocols and self-amendment. Their characteristic weaknesses are: smaller developer ecosystems; contract languages (Michelson, Plutus) that have steep learning curves; and limited compatibility with the EVM-centric tooling ecosystem.

Neither family addresses a third concern that has become acute in 2024-2026: **regulatory legibility**. The European Union's Markets in Crypto-Assets Regulation (MiCA) entered into force in 2024. The Digital Operational Resilience Act (DORA) entered into force in January 2025. Together these create a substantial compliance perimeter for any protocol or application interacting with EU users, EU funds, or EU regulated entities.

The current state of compliance in DeFi is: a Solidity contract is audited once (or several times), the auditor's report is read by a compliance officer, the compliance officer writes a memo, and the memo is reviewed by the regulator. Each layer is a translation; each translation introduces interpretive risk; the regulator never directly verifies anything mechanically.

We submit that this is not the necessary state of affairs. With the right primitives, the regulator can READ THE CONTRACT'S INVARIANTS DIRECTLY and have machine-checkable assurance that the rules are followed. This is what we mean by institutional legibility, and it is the design thesis of Kern.

### 2.2 What this thesis implies

If institutional legibility is the design goal, then the protocol must provide:

**(a) A contract language whose static semantics admit human-readable invariants.** Not "we have formal verification tools you can run on Solidity": a language where invariants are part of the contract's text, are enforced by the runtime, and a regulator without formal verification training can read them.

**(b) Cryptoeconomically secured attestations of off-chain facts.** Regulators care about real-world facts (an investor is over 18; a counterparty is a licensed depositary; this trade was best-executed; this property's title is registered). The protocol must let off-chain authorities sign these claims with skin in the game.

**(c) Privacy-preserving attestations.** Regulators want PROOF that compliance holds; users want NOT TO REVEAL the underlying data. Zero-knowledge proofs solve this; the protocol must verify them efficiently on-chain.

**(d) Equivocation slashing as a protocol primitive, not an off-chain reputation system.** Reputation is slow, contestable, and depends on social consensus. Slashing is immediate, mathematical, and depends on signatures.

**(e) Dual-track governance** — one for protocol evolution (the rules of the rules), one for treasury allocation (the spending of common funds). Each operates under its own constraints; they should not interfere.

**(f) Native EVM compatibility (via rollups), not native EVM emulation.** The L1 is optimized for clarity and finality; high-throughput dApp execution belongs in rollups that settle to it. This preserves L1 design properties while accessing the developer ecosystem.

Kern's reference implementation provides (a) through (f) as a coherent design. The four application verticals — compliance-by-construction STOs, public goods funding, decentralized oracle networks, and ZK-claims identity — are not bolted on; they are direct consequences of the primitives.

### 2.3 What Kern is and is not

**Kern is**:
- A new Layer-1 protocol with native KRN token
- A four-phase BFT consensus engine
- A Liquid Proof-of-Stake delegation model (no LSTs, no lockups)
- The Skald contract language with declared, runtime-enforced invariants
- An optimistic-rollup framework with EVM compatibility for application developers
- A slashable attestation registry as a protocol primitive
- A schema marketplace and ZK-claims infrastructure built on (5)
- An on-chain governance system with dual tracks and equivocation slashing
- 100,000,000 KRN genesis supply, distributed per the Ethereum 2014 template (70% public sale / 10% founder vested 4y / 15% Foundation / 3% contributors / 2% validator bootstrap)

**Kern is not**:
- A general-purpose high-throughput chain. The L1 is throughput-limited in service of finality and verifiability. High-throughput applications live in rollups.
- A privacy-by-default protocol. ZK-claims allow attestations to be privacy-preserving; bare transfers are visible on-chain.
- A drop-in Ethereum competitor. Solidity contracts run on Kern's EVM rollup, not the L1. Native Kern contracts are written in Skald.
- Audited yet. The reference implementation has had an internal security review only. Professional audit is mandatory before Midgard mainnet launch — see §12.
- Production-ready for value custody. Until Midgard launches, Kern remains a reference implementation.

---

## 3. Use cases envisioned

Before describing the protocol architecture, we describe **who we are building for and what they would do with Kern**. Architecture without target users is design fiction. Each persona below corresponds to a realistic actor we have either talked to, observed publicly tendering for blockchain infrastructure in the last 24 months, or whose operational profile we know from professional context.

### 3.1 Persona A — A Belgian fintech tokenizing private equity

**The actor**: a Brussels-headquartered B2B fintech with ~50 employees raising a €15M Series B. They want to tokenize approximately 20% of their post-money equity (€3M) so secondary trading by employees and early backers becomes possible without an IPO.

**Current state**: they cannot do this because (a) the Prospectus Regulation requires a registered prospectus, (b) MiFID II Art. 16(9) requires custody segregation, and (c) MAR requires market-abuse controls. To address all three in Solidity would require a custom contract whose audit alone costs €80-150k and whose regulatory approval (from FSMA) is unpredictable because there is no template the regulator has previously approved.

**With Kern**: they deploy [`sto-startup-equity.skald`](../kern/skald/examples/sto-startup-equity.skald), the canonical template encoding the EU securities regime (Prospectus Regulation, MiFID II, MAR) as Skald invariants — note security tokens are excluded from MiCA by Art. 2(4). The FSMA approval cycle may compress materially because the regulator reads the invariants directly. The audit perimeter shrinks (auditor only verifies that the deployment matches the template, not that the template itself is correct). Total cost to launch: ~€25-40k vs ~€150-300k via custom Solidity.

**Why this is unique to Kern**: no other production L1 has runtime-enforced invariants + a regulator-readable contract language + a community of templates a regulator can accumulate familiarity with over time.

### 3.2 Persona B — An EU institutional fund tokenizing a private-debt strategy

**The actor**: a Luxembourg-domiciled alternative investment fund (€200M AUM) tokenizing access to a private-debt portfolio. The fund manager (AIFM) is a regulated entity; the depositary is an independent bank.

**Current state**: AIFMD compliance has them publishing NAV quarterly via reports, with depositary co-signing. Token holders cannot redeem outside the quarterly NAV window. The operational cycle is heavy: NAV calculation, depositary validation, distribution document, regulator notice.

**With Kern**: they deploy [`sto-institutional-fund.skald`](../kern/skald/examples/sto-institutional-fund.skald). The contract encodes:
- AIFMD Art. 21 (depositary independence) as the invariant `aifm != depositary` — single-line, regulator-checkable
- AIFMD Art. 22 (NAV staleness) as `current_level - nav_published_at_level <= nav_max_staleness_levels`, runtime-enforced
- AIFMD Art. 18 (concentration limits) as `largest_position_pct <= concentration_cap_pct`
- MiFID II Art. 24 (best execution) as a per-trade attestation read from the attestation registry

The depositary publishes signed NAV attestations on-chain; the AIFM cannot publish NAVs unilaterally. Redemptions become continuous (not quarterly) because the NAV freshness gate auto-enforces the publication SLA. Operational cost drops by ~40%; investor experience improves dramatically (real-time NAV, instant redemption when NAV is fresh).

**Why this is unique to Kern**: the combination of (a) regulator-readable invariants for AIFMD compliance, (b) slashable attestations for the depositary co-sign requirement, and (c) on-chain best-execution tracking is not assembled elsewhere.

### 3.3 Persona C — A French SCPI (real estate investment vehicle)

**The actor**: a Paris-based real estate fund (SCPI) with €80M deployed across 12 commercial properties. Investors are mostly French retail (3,000+ holders), with secondary trading currently going through a paper-based broker process at quarterly intervals.

**Current state**: secondary liquidity is bad. Investors who need to exit before the quarterly window take significant haircuts. Acquisitions are slow (notary-attested title transfers take weeks). Tax distributions require manual reconciliation per investor jurisdiction.

**With Kern**: they deploy [`sto-real-estate.skald`](../kern/skald/examples/sto-real-estate.skald). Key features:
- Notary attestations (`schema_id = "realestate.title-registered"`) — the notary signs once, the SPV's title is provable on-chain forever
- The invariant `rental_income_distributed <= rental_income_received` prevents any Ponzi-style behavior (a distribution can only happen if rent was actually collected); read directly by the AMF
- Secondary market with floor price set by the compliance oracle, auto-paused if valuation staleness exceeds threshold
- Lock-up of 12 months enforced as a hard invariant

**Why this is unique to Kern**: the notary-attestation pattern (a tangible-asset trust anchor not naturally expressible in pure DeFi protocols) plus the anti-Ponzi invariant plus the lock-up + secondary-market staleness gates are all specific to the regulatory and operational pattern of European real-estate tokenization. Kern provides them as a deployable template; nowhere else are they pre-assembled.

### 3.4 Persona D — UNESCO regional office running heritage preservation grants

**The actor**: a UNESCO regional office (Africa or South Asia, for example) with a €10M annual budget for digital heritage preservation projects. The current grant process: applications submitted, expert committee reviews, allocations decided, disbursements made through traditional banking. Administrative overhead: ~15% of the budget.

**Current state**: the committee process is slow (6+ months from application to disbursement), opaque (no community signal on which projects matter most), and the administrative cost is significant relative to small grants (€10-50k size).

**With Kern**: they deploy quarterly Quadratic Funding rounds ([`quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald)) for small grants and an annual Retroactive Public Goods Funding round ([`retroactive-pgf.skald`](../kern/skald/examples/retroactive-pgf.skald)) for proven-impact larger grants. Contributors include: affected communities, individual academics, partner foundations. Sybil resistance comes from `identity.proof-of-personhood` attestations (the UNESCO office signs these for verified individuals, with slashing). Administrative cost drops to ~2% (server infrastructure + badge-holder honoraria for RPGF).

**Why this is unique to Kern**: Gitcoin demonstrates QF works at small scale, but suffers persistent Sybil attacks; Optimism demonstrates RPGF works but is a closed-ecosystem distribution. Kern provides both as native primitives with cryptoeconomic Sybil resistance (via slashable personhood attestations) as a first-class capability.

### 3.5 Persona E — An EU TSO (Transmission System Operator) for energy settlement

**The actor**: a national electricity grid operator (e.g., Elia in Belgium, RTE in France, TenneT in the Netherlands) participating in inter-TSO settlement under the EU Central Western Europe (CWE) market coupling. Settlement requires consensus on grid frequency, regional supply/demand, and clearing prices, computed every 15 minutes across the 7 CWE member states.

**Current state**: settlement reconciliation between TSOs takes weeks. Disputes arise from measurement timing differences, methodology variations, and the absence of a single source of truth. A national TSO spends an estimated €30-100M/year on reconciliation, dispute resolution, and the back-office staff supporting them.

**With Kern**: each TSO posts grid-frequency measurements as attestations (`schema_id = "energy.grid-frequency-hz"`, subject = grid region, bond = ~10,000 KRN per attestation). Inter-TSO consensus on a 15-minute window is computed by aggregating attestations; equivocation (the same TSO posting different frequencies for the same window) is slashable. ENTSO-E operates the schema marketplace, publishing canonical schemas and recognized issuer lists.

**Why this is unique to Kern**: general-purpose oracle networks today (Chainlink, Pyth, and similar) primarily focus on DeFi price feeds and data delivery patterns; they are not architecturally optimised for the institutional structure of regulated industrial data networks. Kern's slashable attestation primitive plus the schema marketplace pattern together fit the institutional structure of ENTSO-E precisely. This is also one of two verticals (the other being telco settlement, Persona F) where Kern aligns directly with regulated-industry data exchange — EU telcos and grid operators face this exact reconciliation problem.

### 3.6 Persona F — An EU telco settling inter-operator roaming and wholesale traffic

**The actor**: a tier-1 European telco (Deutsche Telekom, Vodafone, Telefónica, and peers) settling roaming agreements with hundreds of counterparts globally, plus MVNO settlement, plus wholesale traffic exchange. The volume is in the hundreds of millions of euros per year per major telco.

**Current state**: GSMA's Billing & Charging Evolution (BCE) framework is the industry standard; bilateral reconciliation happens monthly or quarterly. Disputes resolve over weeks via mutual auditor engagement.

**With Kern**: operators post subscriber-count attestations (`schema_id = "telco.subscriber-count"`) and roaming-minute attestations (`schema_id = "telco.roaming-minutes"`) with bonds. Equivocation between settlement windows is detectable and slashable. GSMA operates the canonical schema marketplace. The result: settlement reconciliation moves from monthly batch to continuous attestation; back-office cost drops; disputes drop because the cryptographic proof replaces the dispute.

**Why this is unique to Kern**: this is the same argument as the energy case — no oracle network today targets regulated industrial data exchange. The institutional fit + the slashing primitive + the EU regulatory context together are what Kern provides that no competitor does.

### 3.7 Persona G — A pharma supply chain anti-counterfeiting program

**The actor**: a global pharmaceutical company subject to the EU Falsified Medicines Directive (FMD) and US Drug Supply Chain Security Act (DSCSA). Anti-counterfeiting requires unit-level serialization, with provenance verifiable from producer through distribution to dispensing pharmacy.

**Current state**: each handoff in the supply chain is recorded in a central database operated by a country-level repository (the FMD model). The integrity of the database depends on the trusted operator; cross-border verification is slow.

**With Kern**: handoff attestations (`schema_id = "provenance.physical-handoff"`, subject = serial number) co-signed by sending and receiving parties. Equivocation (claiming the same serial was delivered to two distinct distributors) is automatically detectable. The schema marketplace publishes the canonical schemas; national repositories continue to exist as schema operators rather than as single points of trust.

**Why this is unique to Kern**: no current pharma supply chain blockchain (MediLedger, TruTrace, etc.) uses cryptoeconomic slashing as the primary trust mechanism; they use permissioned-consortium governance which has lower trust-loss-cost than equivocation slashing.

### 3.8 Persona H — A parametric insurance product (weather-based farm insurance)

**The actor**: a European insurer underwriting parametric crop insurance — payouts triggered automatically when measured rainfall in a region falls below a threshold over a period.

**Current state**: oracle data is procured from satellite providers (e.g., ECMWF re-analysis) and national meteorological services (Météo France, DWD) under bilateral contracts. Disputes resolve through arbitration if the insurer and the policyholder disagree on the measurement.

**With Kern**: multiple meteorological services attest rainfall measurements (`schema_id = "weather.rainfall-mm-monthly"`). The insurance contract reads the median across attestations. If one service equivocates (different rainfall numbers for the same region/month), they are slashed. The contract auto-disburses without arbitration.

**Why this is unique to Kern**: parametric insurance is a known use case for oracles, but the typical implementation (Chainlink + a smart contract) has trust assumptions that pushed insurers away. Kern's slashable attestation model gives insurers a stronger guarantee at lower cost.

### 3.9 Persona I — A carbon-credit registry tracking offset issuance and retirement

**The actor**: a carbon-credit certification body (Verra-VCS, Gold Standard) issuing offset certificates and tracking their retirement. The industry has been plagued by double-counting (the same offset claimed by multiple buyers) and questionable issuance (offsets for projects whose additionality is disputed).

**Current state**: each registry is a centralized database. Cross-registry linkage requires bilateral integration. Double-counting still happens.

**With Kern**: each issuance is a high-bond attestation (`schema_id = "esg.carbon-offset-tonnes-co2eq"`, subject = project + vintage, bond = €50,000+). The bond size makes issuance equivocation prohibitively expensive. Each retirement is also an attestation; double-retirement (claiming the same credit twice) is structurally impossible because the registry is content-addressed.

**Why this is unique to Kern**: this is the canonical "high-stakes verifiable claims" use case. No existing protocol combines the bond size + slashing immediacy + cross-registry interoperability needed for the carbon market specifically.

### 3.10 What this catalog establishes

These nine personae are not aspirational — each maps to a real institutional process happening today, in Europe, with operational pain points that Kern's primitives directly address. The total addressable market across these nine is **in the tens of billions of euros annually** in administrative cost, settlement cost, and forgone economic activity due to current frictions.

Kern doesn't have to capture all nine to be economically meaningful. Capturing the operational pain in **two or three** would justify the protocol's existence. The point of presenting nine is to demonstrate that the design isn't tuned to a single use case — the primitives are general enough to serve many institutional patterns.

---

## 4. The core thesis: institutional legibility

We claim that institutional legibility is **structurally different** from the design goals of existing Layer-1 protocols, and that it carves out a defensible position.

### 4.1 What Kern provides that other L1s don't — five rows

The comparison table below lists five dimensions critical to institutional legibility. For each dimension we describe **(a) what other L1s offer**, **(b) what Kern offers differently**, and **(c) what consequence that has for an institutional user**. The point is not to win every row — Kern wins few rows on raw throughput or developer-count metrics. The point is to win the **combination** when an institutional user needs all five simultaneously.

#### Row 1 — Contract invariants enforced at runtime

| L1 | What they offer | Gap for institutions |
|---|---|---|
| Ethereum | Solidity has `require`/`assert` — per-call checks but no "this property must always hold" | Auditor + regulator must reconstruct invariants by reading code; no machine-checked guarantee |
| Tezos | Michelson (low-level) and LIGO (high-level) admit some formal verification; not invariant-declarative | Verification is a separate workflow, not part of the contract; expertise-gated |
| Solana | Rust — full Turing-complete; verification tools exist but are not standard | Audit-as-the-only-mechanism, same as Solidity |
| Cosmos | Cosmwasm in Rust — same posture as Solana | Same |
| **Kern** | **Skald: invariants are first-class. `invariant name { expr }` is checked AFTER every entry call by the runtime. A violating transaction reverts.** | **Regulator reads invariants directly; machine guarantees the property holds in every reachable state. Audit time shrinks because the auditor's job becomes "verify invariants match intent," not "find ways the contract could violate intent."** |

**Significance**: The cost of regulatory approval for a tokenized financial product drops from 6-12 months (custom contract + audit + regulator interpretation) to 2-3 months (deploy canonical template + thin audit + regulator reads invariants).

#### Row 2 — On-chain governance (rules AND treasury)

| L1 | What they offer | Gap |
|---|---|---|
| Ethereum | None — protocol changes via off-chain social coordination → hard forks | Slow, contestable, splits the community |
| Tezos | Single-track on-chain governance for protocol amendments | Treasury allocations require separate off-chain governance (Tezos Foundation) |
| Solana | None on-chain | Same as Ethereum, even more centralized in practice |
| Cosmos | Cosmos Hub has governance for hub parameters; sovereign chains each have their own | Fragmented; treasury vs protocol mixed in one track |
| **Kern** | **Dual-track governance: protocol amendments (long cycle, validator-supermajority) and treasury allocations (short cycle, quadratic + stake) running in parallel. Equivocation between YES and NO votes is slashable at the protocol level.** | **Foundations and consortia get a treasury they govern transparently; the protocol can evolve without forking; bad-faith voting is automatically punished.** |

**Significance**: A foundation operating Kern treasury can allocate €millions/year through transparent on-chain proposals without ever requiring an off-chain committee. The protocol can adopt new features through governance without forking, which is the property that lets the protocol evolve over decade-plus time horizons.

#### Row 3 — Liquid Proof-of-Stake without Liquid Staking Tokens

| L1 | What they offer | Gap |
|---|---|---|
| Ethereum | Validator stake is locked; delegators use LSTs (Lido, RocketPool) which introduce LST risk | Lido controls ~30% of all staked ETH; systemic risk |
| Tezos | Native LPoS with delegation; delegator keeps custody | Operationally smooth; no LST risk |
| Solana | Validator stake locked; delegation requires lockup with cooldown | Capital inefficiency; same UX issues as ETH |
| Cosmos | Similar to Solana — delegated stake with cooldown | Capital inefficiency |
| **Kern** | **Liquid PoS LPoS: delegators keep custody of KRN, the delegation is a pointer. No LSTs, no rehypothecation, no Lido equivalent. EVM compatibility via rollups, so this protocol-level property is preserved even when EVM applications run on top.** | **Institutional staking participants (insurance funds, pensions) can stake KRN without introducing a third-party LST counterparty. Custodians can offer staking-as-a-service without rehypothecation risk.** |

**Significance**: Insurance regulators in many EU jurisdictions cannot approve staking products that rely on LSTs (counterparty risk too opaque). Kern's LPoS model is the only design where regulated insurance balance sheets can stake at scale.

#### Row 4 — Slashable attestations as L1 primitive

| L1 | What they offer | Gap |
|---|---|---|
| Ethereum | EAS (Ethereum Attestation Service) — attestations are stored on-chain, no slashing on equivocation | Reputational punishment only; slow and contestable |
| Tezos | None as a native primitive | Application-layer only |
| Solana | None | Application-layer only |
| Cosmos | None | Application-layer only |
| **Kern** | **Native protocol-level OpKinds: ATTEST, REVOKE_ATTESTATION, SLASH_ATTESTATION_EQUIVOCATION. Any signed claim with a bond can be slashed on equivocation by anyone, with 10% whistleblower reward and the rest burned.** | **Off-chain authorities (KYC providers, custodians, notaries, oracle feeders) have cryptoeconomic skin in the game. The "should I trust this attestation" question reduces to "is the bond sufficient and was it not slashed?" — a mechanical check.** |

**Significance**: Replaces the reputation/social-trust layer underpinning oracles, KYC providers, and compliance attestors with mathematical enforcement. Oracle networks built on Kern operate at roughly an order of magnitude lower cost than Chainlink while offering stronger guarantees. Compliance attestation networks become viable where they currently aren't (e.g., for industries that can't tolerate reputational lag).

#### Row 5 — ZK-claim infrastructure (BN254 + reference circuits)

| L1 | What they offer | Gap |
|---|---|---|
| Ethereum | BN254 precompile available; circuits and verifier keys are per-application work | High barrier for application teams; no reference circuits commonly available |
| Tezos | No BN254 precompile | Cannot verify Groth16 proofs on-chain at reasonable cost |
| Solana | Limited; runtime BN254 ops via syscalls but not standard | High friction |
| Cosmos | None | None |
| **Kern** | **BN254 precompile (py_ecc-backed, since v1.0-rc), `kern.zk_claims` Python module with canonical claim payload format, four reference circuits described (age threshold, value threshold, account ownership, set membership), and the schema marketplace pattern for registering verifier keys.** | **A KYC provider can build a "user is over 18" attestation in days, not months. The trusted setup ceremony is run once (by the Foundation) and reused across applications.** |

**Significance**: Privacy-preserving compliance becomes deployable in weeks not years. GDPR-compatible KYC attestations become a default, not an exotic feature.

### 4.2 What no competitor has

Each row above is individually attainable on some other protocol by writing application-layer code. **No competitor has all five rows simultaneously as protocol primitives.**

This is the moat. An institution evaluating Kern vs Ethereum-L2 isn't choosing between equivalent options. On Ethereum-L2 they would need to combine: (1) third-party invariant verification tooling (and re-verify on every upgrade), (2) a foundation governance off-chain, (3) Lido or equivalent LST exposure, (4) EAS without slashing or a custom slashable attestation contract they audit themselves, (5) custom ZK circuit + trusted setup work.

On Kern, all five come as protocol primitives with one cohesive design. The total engineering cost difference is measured in **person-years**, not person-months.

### 4.2 The four application verticals

The five rows directly enable four application verticals, each of which we ship as Skald templates and specification documents in v1.1-rc:

**Vertical 1 — Compliance-by-construction tokenized securities.** Three templates (`sto-startup-equity.skald`, `sto-institutional-fund.skald`, `sto-real-estate.skald`) encode the EU securities regime as Skald invariants: the Prospectus Regulation (whitepaper/prospectus), MiFID II Art. 16 & 24 and AIFMD Art. 18, 21, 22 (asset segregation, depositary independence, diversification), and MAR (market-abuse blackout). Note that security tokens are *financial instruments* and are therefore **excluded from MiCA** under Art. 2(4); the applicable framework is securities law, not MiCA. A regulator reads the invariants and confirms compliance directly, supplementing rather than replacing the audit cycle.

**Vertical 2 — Public goods funding.** Two templates (`quadratic-funding.skald`, `retroactive-pgf.skald`) implement the Buterin/Hitzig/Weyl Quadratic Funding mechanism and the Optimism Collective's Retroactive Public Goods Funding. These collapse the typical 15% administrative overhead of foundation grant-making to roughly 2%, while making the selection mechanism mathematically explicit and auditable.

**Vertical 3 — Decentralized data oracles.** Three templates (`generic-data-oracle.skald`, `defi-price-oracle.skald`, `schema-marketplace.skald`) implement an oracle network with k-of-n consensus among feeders, tolerance bands, circuit breakers, heartbeats, and a schema marketplace for issuer recognition. The slashable attestation primitive is the security mechanism; equivocation by any feeder is immediately slashable. Cost is roughly an order of magnitude below Chainlink for equivalent guarantees; extends to non-DeFi data (energy, telco, supply chain, weather, ESG) where existing oracle infrastructure is weak.

**Vertical 4 — Privacy-preserving identity and compliance.** The `kern.zk_claims` Python module and four reference circuits (age threshold, value threshold, account ownership, set membership) enable attestations whose underlying data is hidden but whose properties are publicly verifiable. A KYC provider attests "this user is over 18" without revealing the date of birth. A custodian attests "the fund's holdings exceed €X" without revealing the exact balance.

### 4.3 How the verticals compose

The verticals reinforce each other:

- A regulated STO uses the oracle vertical for live price discovery and KYC attestation reading
- A public goods round uses the attestation primitive for personhood verification, with ZK-claims for privacy
- An oracle network uses the schema marketplace to publish accepted feeder schemas with minimum bond requirements
- The compliance vertical can read price oracles for tokens denominated in fiat-pegged values

This composition is not coincidental — it falls out naturally from having the right primitives. The unified design is what creates the network effect.

---

## 5. Consensus

Kern's consensus engine is a Python implementation of a BFT finality protocol in the four-phase family (propose → prevote → precommit → commit) with Liquid Proof-of-Stake delegation.

### 3.1 Design goals

The consensus engine optimizes for:

- **Deterministic finality**: a block is final within 2 blocks (~2 seconds at 1-second block cadence) and cannot be rolled back without a long-range attack.
- **Liveness under partial synchrony**: the protocol makes progress as long as a supermajority (greater than two-thirds) of validator-weighted stake is honest and reachable.
- **Equivocation accountability**: every double-baking and double-endorsing is provable on-chain and slashable.
- **Validator accessibility**: validators delegate operationally (run nodes, sign blocks) but operationally the burden is comparable to running a validator on any BFT proof-of-stake network.

### 3.2 Validator economics

Validators (Kern calls them *bakers*) stake KRN to participate. Delegators can lend their stake without giving up custody — the KRN remains in the delegator's account; the delegation is a pointer to a validator that the validator's effective stake includes. This is **Liquid Proof-of-Stake without Liquid Staking Tokens**: no Lido equivalent, no rehypothecation, no LST risk.

Block rewards come from two sources: newly issued KRN per the adaptive issuance schedule, and transaction fees. The split between validator and delegators is determined by a per-validator commission rate (default 10%).

Slashing applies to:
- Double-baking (signing two distinct blocks at the same level): -100% of bond
- Double-endorsing (signing two distinct endorsements for the same block at the same round): -50% of bond
- Governance equivocation (voting both sides of the same proposal in the same phase): -30% of bond

The slashing math is consistent across all surfaces: 30% slash, 10% whistleblower reward, 60% burn (see attestation primitive in §8 for the same numbers applied to off-chain claims).

### 5.3 The block lifecycle, step by step

A block is produced in a four-move round. Most blocks settle in round 0; rounds 1, 2, … are fallbacks if a proposer fails.

```
  PROPOSE            PRE-ENDORSE          ENDORSE              FINAL
  (proposer)         (all validators)     (all validators)     (the chain)
     │                    │                    │                   │
  assemble block     sign block hash      once >2/3 stake     next endorsed
  from mempool,  ──►  to signal       ──► pre-endorsed,   ──►  block builds
  broadcast          commitment           broadcast            on top → level
  candidate                               endorsement          is irreversible
     │                    │                    │                   │
   t = 0s            gather >2/3          >2/3 quorum         ~2s after creation
                     of stake             = endorsed
```

The **>2/3 stake** quorum is what makes finality deterministic: as long as fewer than one-third of validators are malicious or offline, an endorsed block cannot be reverted. A failed round (proposer offline, or block fails to reach quorum within `1 + n` seconds) hands off to the next proposer, selected via a round-incremented seed.

### 5.4 The block reward, and where it goes

Each finalized block mints a fresh reward (the issuance — see §11) and splits it deterministically:

```
  Newly minted reward (100%)
  ├── 5%   → Treasury (on-chain protocol treasury)
  └── 95%  → Baker pool
             ├── 10% of pool → Proposer (fixed bonus, higher overhead)
             └── 90% of pool → Endorsers, pro-rata by stake
```

At the 50% target staking ratio, the reward is ~0.079 KRN/block (79 220 mukrn). The proposer additionally keeps the *fees* of every successful transaction it includes; failed-transaction fees are burned. Delegators share their baker's rewards via the per-validator commission (Liquid PoS — custody stays with the delegator).

The L1 transaction fee is a flat sender-chosen `tx.fee` paid in mukrn (Skald executes loop-free and non-recursive, so termination is structural and per-tx compute metering is not required at the L1 layer; the Yellow Paper-compliant gas metering applies inside the rollup Mini-EVM, §7). An **optional, governance-gated fee floor and per-block size cap** can be activated to add a compute-proportional fee component and a spam bound; it is off by default and detailed in [`fee-floor.md`](fee-floor.md).

> An interactive, animated walk-through of the block lifecycle, the gas/fee flow, the reward split, the adaptive-issuance curve, and the attestation lifecycle is published at **kern_site/how-it-works.html**.

---

## 6. Skald and the KVM

### 4.1 The language

Skald is the contract language native to Kern. A Skald contract is a self-contained module declaring storage, invariants, and entry points.

```skald
contract Vault {
    storage {
        owner: address,
        deposited: int,
        withdrawn: int,
    }

    invariant accounting {
        deposited >= withdrawn
    }

    invariant nonneg {
        deposited >= 0
    }

    entry deposit() {
        require amount > 0 with "must attach a positive amount";
        deposited = deposited + amount;
    }

    entry withdraw(n: int) {
        require sender == owner with "only owner can withdraw";
        require n > 0 with "amount must be positive";
        require deposited - withdrawn >= n with "insufficient escrow";
        withdrawn = withdrawn + n;
    }
}
```

The language has four types in v1.1-rc: `int` (arbitrary precision), `bool`, `string`, `address`. Mappings and lists arrive in v1.2 (see §14).

### 4.2 Why invariants are first-class

Most contract languages relegate invariants to documentation. Solidity has `assert` and `require`, but these are checks at specific points — there is no general "this contract must maintain X across all state transitions." Skald inverts this: an `invariant name { expr }` declaration is checked AFTER every entry call. A call that would leave storage in a state violating any invariant is rejected and the storage is rolled back.

The runtime guarantee is what makes invariants useful for compliance encoding. A securities invariant like `total_supply_issued == 0 || whitepaper_registered` is not a documentation comment; it is a constraint that cannot be violated by any execution path. The regulator reads the invariant and knows it holds for every possible state of the contract.

Compared to the languages a team would realistically evaluate, this is Skald's distinguishing property:

| Language | Invariants | Reentrancy | Turing-complete | Legibility for non-engineers |
|---|---|---|---|---|
| Solidity (Ethereum) | Manual / external tools | Footgun | Yes | Low |
| Vyper (Ethereum) | Manual asserts | Reduced | Yes | Medium |
| Rust + Anchor (Solana) | Manual checks | Possible | Yes | Low |
| Move (Aptos / Sui) | Move Prover (compile-time, opt-in) | Hard by design | Yes | Medium |
| Clarity (Stacks) | Asserts + decidability | Impossible | No (decidable) | Medium-high |
| **Skald (Kern)** | **First-class, runtime-enforced** | **Impossible** | **No (bounded)** | **High** |

Skald borrows decidability and no-reentrancy from Clarity, the make-bugs-unrepresentable philosophy from Move, and the small-surface discipline from Vyper. Its one original contribution is making the invariant a first-class language construct that the runtime enforces unconditionally — so the compliance statement and the protocol enforcement are the same artifact. The full comparison, including Skald's honest limitations (runtime enforcement is not formal proof; bounded expressiveness is a real cost; no ecosystem yet), is in [`skald-language.md`](skald-language.md).

### 4.3 Static typing

The Skald type checker validates contracts before deployment. Type-incorrect contracts cannot be originated. This catches most low-hanging Solidity-style bugs (integer overflow misuse, type confusion, accidental shadowing) at deployment, not at runtime.

### 4.4 The KVM

The Kern Virtual Machine is the deterministic execution environment. It maintains a stack-based evaluator over the Skald AST. Gas accounting tracks every operation; gas-exhausted execution reverts.

The KVM is intentionally narrow: no dynamic dispatch in the EVM sense, no implicit cross-contract reads in v1.1-rc (added in v1.2), no implicit state mutation. Every state change goes through an entry point of the owning contract.

---

## 7. EVM compatibility via Optimistic Smart Rollups

Kern does not natively run Solidity contracts on L1. The L1 runs Skald, optimized for the institutional-legibility properties described above. Solidity contracts run on **Optimistic Smart Rollups** whose state commitments are posted to Kern as data.

The rollup framework supports:

- A multi-frame EVM execution layer (CALL, STATICCALL, DELEGATECALL, CREATE, CREATE2 frames)
- Bisection-based fraud proofs (the classical Arbitrum-style mechanism, simplified)
- Forced inclusion (anti-censorship), so users can submit transactions directly to L1 if the rollup operator censors them
- 6 EVM precompiles (ECRECOVER, SHA256, RIPEMD160, IDENTITY, MODEXP, BLAKE2F) plus BN254 pairing

Developers use Hardhat, Foundry, MetaMask, and existing Ethereum toolchains. The rollup's bridge handles asset and message passing in both directions. Settlement to L1 (with fraud-proof challenge windows) brings Kern's finality and BFT properties to EVM applications without compromising the L1's design.

This is architecturally the same pattern Tezos uses with Etherlink. The pattern works.

---

## 8. The slashable attestation primitive

This is the single most distinctive primitive introduced in v1.1-rc.

### 6.1 The problem

Most "oracle" systems and identity attestations today rely on **reputational** punishment: a node or attestation issuer that lies loses business over time as customers route around them. This works at the limit but is slow (months), expensive (operators must be paid handsomely to maintain reputation), and coordinative-failure-prone (a coalition can attack short-term).

The principal alternative — full on-chain consensus for every oracle update — is computationally expensive and gas-prohibitive at scale.

### 6.2 The Kern primitive

Kern provides three new operation kinds at the protocol level:

- **ATTEST**: a signed claim by an issuer about a subject under a schema, with an optional KRN bond. The bond is debited from the issuer at the time of attestation.
- **REVOKE_ATTESTATION**: marks a previously issued attestation as revoked and returns the bond to the issuer. Revocation does NOT remove the historical record.
- **SLASH_ATTESTATION_EQUIVOCATION**: anyone can submit two contradicting attestations by the same issuer for the same (schema, subject) tuple with overlapping validity windows. The runtime verifies the contradiction; the issuer's bond is slashed (30% of bond by default, of which 10% is paid to the prover and the rest burned); the remaining 70% is refunded to the issuer.

The protocol does not validate the content of claims — anyone can attest under any schema identifier. Schema marketplaces (an application-layer contract) provide curation: which schemas are recognized, what minimum bonds apply, which issuers are recognized.

### 6.3 Why this matters

The economic incentive to report equivocation is symmetric: every observer has reason to monitor and submit slashing evidence. Combined with the on-chain bond at the time of attestation, this makes equivocation **automatically expensive** in a way that doesn't depend on reputation timing or social consensus.

The lifecycle of an attestation, and the two paths it can take:

```
  ATTEST                  ┌──► REVOKE_ATTESTATION  (honest path)
  issuer signs            │     claim no longer holds; issuer revokes;
  (schema, subject,  ─────┤     bond returned in full ↩
   claim) + locks bond    │
  🔒 e.g. 1 KRN           └──► SLASH_ATTESTATION_EQUIVOCATION  (dishonest path)
                                issuer signed two contradictory claims;
                                anyone submits both as evidence ⚔
                                       │
                                       ▼
                           bond slashed 30%  →  0.30 KRN
                              ├── 10% of slash → whistleblower   (0.03 KRN)
                              └── rest         → burned          (0.27 KRN)
                           both attestations marked consumed (no double-slash)
```

The math is the protocol's standard slashing split (consistent with §5.2). On a 1 KRN bond: 0.30 KRN slashed, of which 0.03 KRN rewards the prover and 0.27 KRN is burned; the remaining 0.70 KRN of the bond is unaffected.

For oracle networks specifically, this allows Kern oracles to operate at roughly an order of magnitude lower cost than reputation-based systems (Chainlink, Pyth) while providing cryptoeconomically stronger guarantees.

### 6.4 Composition with other verticals

The attestation primitive is the foundation for:
- KYC and AML screening attestations posted by regulated providers (Vertical 1)
- Notary attestations of property title transfer (Vertical 1, real estate)
- NAV and best-execution attestations from depositaries (Vertical 1, institutional fund)
- Personhood attestations for Sybil resistance in QF rounds (Vertical 2)
- Evidence attestations for RPGF rounds (Vertical 2)
- Feeder readings and aggregator medians in oracle networks (Vertical 3)
- ZK-claim payloads for privacy-preserving identity proofs (Vertical 4)

---

## 9. ZK-claims: privacy-preserving attestations

The plain attestation format reveals the full claim to anyone reading the chain. For high-stakes regulated use (KYC, accreditation, source of funds), the consumer needs PROOF that a property holds without learning the underlying data.

### 7.1 The format

A ZK-claim attestation carries a Groth16 (BN254-pairing-based) proof in the claim field:

```json
{
    "proof_system": "groth16-bn254",
    "verifier_key_hash": "<32-byte hex>",
    "public_inputs": [...],
    "proof": {"a": [...], "b": [[...], [...]], "c": [...]},
    "predicate_summary": "user is over 18 years old"
}
```

### 7.2 Verification on-chain

Kern's BN254 precompile (since v0.7, real py_ecc-backed pairing since v1.0-rc) performs the Groth16 pairing check that constitutes the core of proof verification. The verifier key for each circuit is registered in the schema marketplace; consumers look up the key by hash and run the verifier.

### 7.3 Reference circuits

Four reference circuits are described (with implementations to be shipped in v1.2 with proper trusted setup ceremonies):

- **age_threshold_v1**: "DOB + min_age_seconds ≤ now"
- **value_threshold_v1**: "value ≥ public_threshold"
- **account_ownership_v1**: "prover knows sk such that pubkey(sk) = public_addr"
- **set_membership_v1**: "prover knows Merkle path proving leaf is in tree"

These four cover roughly 80% of real-world ZK-claim use cases in the EU regulatory context.

### 7.4 Production deployment workflow

1. Circuit author writes the predicate in Circom (or equivalent)
2. Trusted setup ceremony (MPC, multi-party) generates proving and verifying keys
3. Foundation registers the verifying key hash in the schema marketplace
4. Provers (KYC providers, custodians) use the proving key to generate proofs
5. Issuers post attestations referencing the registered verifying key
6. Consumers run the verifier on-chain via the BN254 precompile

---

## 10. On-chain governance

Two governance tracks run in parallel on-chain, each with its own cycle and parameters.

### 8.1 Protocol amendment track

For changes to consensus rules, gas pricing, the KVM, Skald itself, or any other protocol parameter. Follows a four-phase Liquid PoS cycle (Proposal → Exploration → Cooldown → Adoption) over approximately 25 days. Activation requires 80% supermajority of validator-weighted stake and 25% quorum.

The protocol amendment can swap function implementations (the on-chain code is upgradable via a coordinated vote), change gas pricing constants, and modify any documented governance-amendable parameter.

### 8.2 Treasury track

For disbursements from the protocol treasury (funded by a small fraction of block rewards plus optional founder contributions) to ecosystem projects. Follows a simpler cycle (Submission → Voting → Execution) over approximately 7 days. Voting uses **quadratic voting with stake weighting**: a voter's effective vote is proportional to the square root of their stake. This favors broad participation over plutocracy.

### 8.3 Equivocation slashing

Validators who vote both YES and NO on the same proposal in the same phase are slashable. The proof is the two on-chain votes; the slashing is processed via a SLASH_EQUIVOCATION transaction (this is structurally analogous to the slashable attestation primitive in §8).

### 8.4 Why dual track

A single governance track would force the chain to choose between "fund this development team" and "amend the consensus rules" as competing priorities. The two operate at different speeds (protocol amendments are once-in-quarters; treasury disbursements are weekly) and require different voter pools (protocol amendments need expert-level voter understanding; treasury allocations need community sentiment). Separating them lets each operate under its own constraints.

---

## 11. Token economy

The native token is **KRN**. The smallest unit is the **mukrn** (Tezos homage): 1 KRN = 10^6 mukrn.

### 9.1 Genesis distribution

100,000,000 KRN at genesis, distributed per the Ethereum 2014 template:

| Allocation | Share | Purpose |
|---|---:|---|
| Public sale | 70% | Sold to the public at genesis (staged distribution; see §12) |
| Founder | 10% | Vested 4 years, 1-year cliff |
| Foundation | 15% | Treasury for ecosystem grants, audits, infrastructure |
| Contributors | 3% | Retroactive grants for v0.1-v1.0 contributors |
| Validator bootstrap | 2% | Initial subsidy pool for testnet and mainnet validators |

### 9.2 Issuance

Block rewards come from KRN issuance per the adaptive issuance schedule (see [`adaptive-issuance.md`](adaptive-issuance.md)). Target initial annual issuance: ~5-7% of supply, decreasing as stake participation rises. Issuance is governance-amendable.

### 9.3 Slashing economy

The slashing of equivocators (consensus, governance, or attestation) reduces total supply via the burn portion (60-90% of slashed amounts). The reward portion (10%) provides whistleblower incentives. Together these create a deflationary pressure on misbehavior.

### 9.4 On speculation, memecoins, and "fair launch" mythology

KRN is the native utility token of an institutional L1, not a speculative asset. We do not market it as a memecoin, do not run aggressive growth campaigns, do not airdrop retroactively, and do not court the audience that drives short-cycle token price action. The two markets — institutional adoption and memecoin speculation — are mutually exclusive, and Kern picks institutions.

For the full reasoning (why no memecoin positioning, why no "fair launch" theatre, why no aggressive marketing, what the founder's relationship to token price actually is), see [`tokenomics.md`](tokenomics.md) §11, and the founder's [`manifesto.md`](manifesto.md) §V.

---

## 12. Security review and audit path

### 10.1 Internal review (completed)

The v1.1-rc release ships with an internal security review (see [`security-review-v11rc.md`](security-review-v11rc.md)) that surfaced and fixed seven vulnerabilities:

| Severity | Count | Examples |
|---|---:|---|
| Critical | 2 | Negative-fee baker drain; negative-amount theft from named recipient |
| Major | 2 | No cross-network replay protection; slash handler locked unslashed bond |
| Medium | 2 | Index key collision via separator characters; lax ZK-claim type checks |
| Minor | 1 | No range checks on gas_limit and nonce |

All findings have regression tests (`tests/test_security_v11rc.py`). This review is INPUT to the professional audit, not a substitute.

### 10.2 Mandatory professional audit

A professional smart-contract audit by a specialized firm — recommended: Trail of Bits, OtterSec, Hashlock, Runtime Verification, or ChainSec — is mandatory before Midgard mainnet launch.

Indicative scope: 6-12 weeks per cycle, €100-200k per audit, two cycles recommended.

The Foundation contracts directly with the audit firm. See [`setup-auditor.md`](setup-auditor.md) for the engagement workflow.

### 10.3 The full operational path

See [`post-code-roadmap.md`](post-code-roadmap.md) for the detailed phase-by-phase plan. Summary:

| Phase | What | Indicative time | Indicative cost |
|---|---|---|---:|
| 1 | Foundation incorporation (legal entity, board, multisigs) | ~3 months | €40-60k |
| 2 | Audit cycle 1 | 2-3 months | €100-200k |
| 3 | Yggdrasil testnet launch (parallel) | ~2 months | €15-30k |
| 4 | Audit remediation + cycle 2 | ~2 months | €50-80k |
| 5 | Public sale | ~1 month | €30-50k |
| 6 | Midgard mainnet genesis | ~2 weeks | €10-30k |
| **Total** | | **9-15 months** | **~€275-510k** |

---

## 13. From whitepaper to running node — technical entry points

This whitepaper is intentionally vulgarized: it explains Kern's thesis and verticals in language a non-engineer institutional reader can follow. But Kern is a working reference implementation, not a position paper. If you want to **actually run, build on, integrate, audit, or operate Kern**, this section is your map.

Nine **setup guides** live in `docs/setup-*.md`. Each is role-targeted and assumes only the prerequisites needed for that role. They are linked from a single index — [`setup-guides.md`](setup-guides.md) — and each is operationally exhaustive (copy-paste commands, exact version numbers, file paths). They are the technical vertical complementing the conceptual vertical of this whitepaper.

### 13.1 Which guide is for me?

| If you are... | Read | What it covers |
|---|---|---|
| A protocol contributor or someone reading the code | [`setup-developer.md`](setup-developer.md) | Clone, install dependencies, run tests, navigate the codebase, run a local devnet, modify Skald, build the docs site |
| A KRN holder wanting to earn baking yield without running a node | [`setup-delegator.md`](setup-delegator.md) | Wallet setup, choosing a validator, delegating with no lockup, monitoring rewards, undelegating |
| Someone planning to operate a validator on Yggdrasil testnet or Midgard mainnet | [`setup-validator.md`](setup-validator.md) | Hardware requirements, key management (hot vs cold), node setup, monitoring, slashing avoidance, commission rate setup |
| A dApp developer building on Kern (native Skald or EVM via rollup) | [`setup-dapp-developer.md`](setup-dapp-developer.md) | Toolchain (Hardhat/Foundry for EVM rollup; Skald CLI for native), local testing, deploying to devnet/testnet, frontend integration |
| A team running an Optimistic Smart Rollup on Kern | [`setup-rollup-operator.md`](setup-rollup-operator.md) | Rollup framework, sequencer setup, state commitment posting, fraud proof bisection, forced inclusion handling |
| Someone running a block explorer, indexer, or chain data service | [`setup-explorer-ops.md`](setup-explorer-ops.md) | RPC endpoints, archival node setup, indexing patterns, public-facing APIs |
| Someone running **Heimdall** (the official Kern explorer + monitoring stack) | [`setup-heimdall-operator.md`](setup-heimdall-operator.md) | Heimdall installation, env vars, Prometheus scraping, vertical-specific dashboards |
| A founding board member of the (to-be-incorporated) Kern Foundation | [`setup-foundation.md`](setup-foundation.md) | Foundation legal setup, multisig key generation (3-of-5 / 2-of-3), genesis ceremony, treasury operations, regulatory dialogue |
| A security auditor engaged by the Foundation for audit cycle 1 | [`setup-auditor.md`](setup-auditor.md) | Codebase walkthrough, threat model, where to focus (BFT, attestation, EVM, governance), reporting format, originality attestation |
| Looking for the navigation index across all the above | [`setup-guides.md`](setup-guides.md) | One-page overview of each guide with a "start here" recommendation by role |

### 13.2 Spec documents (the protocol details)

Beyond the setup guides, the protocol's full specification is split across topic-specific documents. These are the source of truth that the setup guides reference :

**Architecture & consensus**
- [`architecture.md`](architecture.md) — component layout, module boundaries, data flow
- [`consensus.md`](consensus.md) — BFT protocol detail, finality conditions, view changes
- [`bft.md`](bft.md) — multi-validator BFT implementation specifics
- [`staking.md`](staking.md) — Liquid PoS LPoS delegation mechanics

**Smart contracts**
- [`skald-language.md`](skald-language.md) — Skald language reference (grammar, types, semantics)
- [`typecheck.md`](typecheck.md) — static type system rules

**v1.1-rc verticals** (the institutional applications)
- [`attestations.md`](attestations.md) — slashable attestation primitive
- [`sto-mica.md`](sto-mica.md) — STO compliance vertical
- [`public-goods-funding.md`](public-goods-funding.md) — QF + RPGF vertical
- [`oracle-network.md`](oracle-network.md) — oracle network + schema marketplace + ZK-claims vertical
- [`v11rc-changes.md`](v11rc-changes.md) — consolidated v1.1-rc release notes

**Tooling shipping with v1.1-rc**
- [`setup-heimdall-operator.md`](setup-heimdall-operator.md) — Heimdall, the official block explorer + monitoring stack (FastAPI + SQLite indexer + Prometheus metrics, dedicated per-vertical pages)

**Governance & economy**
- [`governance.md`](governance.md) — dual-track on-chain governance spec
- [`tokenomics.md`](tokenomics.md) — KRN supply, distribution, sinks
- [`contributors-program.md`](contributors-program.md) — contributor allocation policy
- [`adaptive-issuance.md`](adaptive-issuance.md) — issuance schedule that responds to participation

**API & integration**
- [`api-stability.md`](api-stability.md) — frozen / stable / beta surface declarations per version
- [`api.md`](api.md) — JSON-RPC endpoint reference
- [`merkle-trie.md`](merkle-trie.md) — state trie format for light clients

**Operations**
- [`post-code-roadmap.md`](post-code-roadmap.md) — Foundation → Audit → Sale → Mainnet operational plan
- [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) — gating items before Midgard launch
- [`release-tagging.md`](release-tagging.md) — versioning policy and tag conventions
- [`security-review-v11rc.md`](security-review-v11rc.md) — internal security review (input to professional audit)

**Originality & legal**
- [`originality-and-attribution.md`](originality-and-attribution.md) — founder attribution policy + Belgian moral rights anchor

### 13.3 Start here, for each common scenario

If you are a regulator (FSMA, AMF, BaFin, CSSF, CONSOB, equivalent) asked to assess Kern:

1. Read this whitepaper §3 (use cases) and §4 (thesis)
2. Read [`sto-mica.md`](sto-mica.md) section "The compliance gap that Skald closes"
3. Read one of the STO templates ([`kern/skald/examples/sto-startup-equity.skald`](../kern/skald/examples/sto-startup-equity.skald) is the smallest; ~225 lines) noting the `invariant` blocks
4. Read [`security-review-v11rc.md`](security-review-v11rc.md) to see the security posture honestly stated

This should give you, in roughly 4 hours of reading, a defensible position on whether Kern's compliance model is sound for your jurisdiction.

If you are a foundation or institution evaluating Kern for a public-goods funding program:

1. This whitepaper §1 (ambition) and §3 (use case D — UNESCO heritage preservation)
2. [`public-goods-funding.md`](public-goods-funding.md) end-to-end
3. The two PGF templates ([`quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald), [`retroactive-pgf.skald`](../kern/skald/examples/retroactive-pgf.skald))
4. [`setup-foundation.md`](setup-foundation.md) for the operational pattern of running a Foundation that operates Kern-based rounds

If you are an institutional investor or compliance officer at a financial institution evaluating Kern for asset tokenization:

1. This whitepaper §1 (ambition), §3.1-3.3 (your persona is likely one of A/B/C), §4 (what Kern provides)
2. [`sto-mica.md`](sto-mica.md) end-to-end
3. The relevant STO template
4. [`security-review-v11rc.md`](security-review-v11rc.md) + the post-code-roadmap §10-§12

If you are a software engineer about to write code on Kern:

1. [`setup-developer.md`](setup-developer.md) → get the chain running locally
2. [`setup-dapp-developer.md`](setup-dapp-developer.md) → deploy your first contract
3. [`skald-language.md`](skald-language.md) → language reference (or [`setup-rollup-operator.md`](setup-rollup-operator.md) if you're staying in EVM)
4. The example contracts in [`kern/skald/examples/`](../kern/skald/examples/) as templates

### 13.4 The reference implementation

Quick start to run Kern locally:

```bash
git clone https://github.com/vaneeckhoutnicolas/kern    # exact URL TBD post-Foundation
cd kern
pip install -e ".[dev,explorer,docs]"
pytest tests/                # 692 tests should pass in ~20 seconds
python networks/devnet_bootstrap.py    # local 3-validator devnet
python scripts/kern_wallet.py keygen --out ~/.kern/my-wallet.json
```

In a second terminal, start **Heimdall** — the official explorer + monitoring stack — pointing at your local devnet :

```bash
heimdall    # web UI on http://127.0.0.1:8800, /metrics, /health
```

Open `http://127.0.0.1:8800` to inspect the live chain: blocks, transactions, validators, originated contracts (auto-classified by detected Skald template), the slashable attestation registry, and the governance state. The `/metrics` endpoint is Prometheus text-format for scraping into your monitoring stack.

From there, every setup guide walks you through your role-specific next steps.

The reference implementation runs in Python for clarity and auditability. A production-performance implementation in Rust or Go is anticipated post-Midgard as a v2.x effort — but the Python reference will remain the canonical specification (the implementation is the spec).

---

## 14. v1.2 roadmap

The v1.1-rc release is feature-complete for its scope but exposes several v1.2 enhancements:

**Skald language**:
- Mapping types (`map<address, int>`) — enables per-investor balances, per-feeder bonds, multi-project rounds
- Math primitives (`isqrt`, `min`, `max`) — enables on-chain QF matching computation
- Cross-contract reads (`call_view(contract, entry, params)`) — enables composition between STO contracts, oracles, governance
- Direct attestation reads from Skald (`attestation_latest(...)` builtin)

**Application-level**:
- Production ZK circuits for `age_threshold_v1` and `value_threshold_v1` with multi-party trusted setup ceremonies
- Multi-currency denomination registry (EUR, USD, GBP as first-class)
- Native vesting enforcement
- MiFID II execution venue integration via standardized best-execution attestation schema

The v1.2 features are not blocking for an initial Midgard launch. The v1.1-rc primitives are operationally usable today.

---

## 15. The position Kern occupies

We do not claim Kern dominates any single dimension on which existing protocols compete. Ethereum has more developers. Solana has higher throughput. Tezos has longer governance track record. Cosmos has more sovereign chains.

We claim Kern dominates a specific combination of dimensions that, when combined, are uniquely suited to **institutional users for whom legibility and accountability are more valuable than throughput or speculation**. Specifically:

- **EU regulators** evaluating which protocols they can recognize for MiCA/AIFMD/MiFID II purposes
- **Foundations and supranational bodies** (UNESCO, EU public sector, World Bank, Wikimedia) running grant-making programs
- **Regulated financial institutions** tokenizing financial instruments under MiFID II / the Prospectus Regulation
- **Industrial data networks** (energy, telco, supply chain) replacing post-hoc reconciliation with continuous attestation
- **Researchers and developers** of identity infrastructure with privacy guarantees

This is not a venture-scale market in the sense of "10 billion users" — it is a market of perhaps **thousands of institutional actors** controlling collectively hundreds of billions of euros in deployed capital and regulatory authority. The product-market fit is precise rather than broad.

That precision is what gives Kern a defensible position despite the competitive density of the L1 space.

---

## 16. Reference implementation

The Kern reference implementation is open-source under Apache-2.0. As of v1.1-rc:

- ~32,000 lines of code, documentation, and configuration
- 63 Python modules
- 49 markdown specifications
- 10 Skald example contracts (vault, counter, 3 STOs, QF, RPGF, 3 oracle/marketplace)
- **483 passing tests**, 2 chaos tests intentionally skipped
- 4 internal originality checks pass (no copied code, all files SPDX-licensed, founder attribution on all modules)

The repository is at https://github.com/vaneeckhoutnicolas/kern (or wherever the Foundation chooses to host it post-incorporation).

Run the test suite:
```bash
git clone https://github.com/vaneeckhoutnicolas/kern
cd kern
pip install -e ".[dev]"
pytest tests/
```

Bootstrap a local devnet:
```bash
python networks/devnet_bootstrap.py
```

---

## 17. Acknowledgments

This work draws on, and explicitly acknowledges, intellectual debt to:

- **Tezos** for the LPoS delegation model, on-chain self-amendment, and Tenderbake consensus design
- **Ethereum** for the BN254 precompiles, the rollup architecture pattern, the foundational ideas of "decentralized applications," and the Yellow Paper that we use for EVM compatibility
- **Optimism** for the Retroactive Public Goods Funding mechanism and the trusted-setup approach to ZK infrastructure
- **Vitalik Buterin, Zoë Hitzig, and Glen Weyl** for Quadratic Funding (Liberal Radicalism, 2018)
- **The Gitcoin team** for demonstrating QF works in practice
- **The EU Commission, EBA, and ESMA** for the EU regulatory frameworks whose precision makes encoding them as Skald invariants tractable
- **The pre-Belgian and Belgian moral rights tradition** (Code de droit économique, Livre XI) for the legal recognition of founder authorship

Kern's block-production and finality mechanism is adapted from the Tenderbake family of BFT consensus algorithms. The author (Nicolas Van Eeckhout) is founder of [Cogarius](https://www.cogarius.com), [contributor to the Tezos ecosystem](https://github.com/tezos-checker/checker-ui), and co-founder of the [Meetup Blockchain-Ethereum group in Brussels](https://www.meetup.com/meetup-blockchain-ethereum-bruxelles/).

---

## 18. License

This document is published under **CC-BY-SA-4.0** (Creative Commons Attribution-ShareAlike 4.0 International). Derivative documents must credit Nicolas Van Eeckhout and Kern contributors as authors.

The reference implementation is published under **Apache-2.0** (the Apache License, Version 2.0). See [`LICENSE`](../LICENSE) for the full terms.

The Kern name, the "kn1" address prefix, and the Skald language name are reserved as marks of authenticity by the project; they are not transferable to forks. Forks must use distinct names. See [`originality-and-attribution.md`](originality-and-attribution.md) for the full attribution and forking policy.

## 19. Disclaimer

The reference implementation, the Skald language, the Heimdall explorer, the documentation, this whitepaper, and all related artifacts are provided **"AS IS," without warranty of any kind**. The author and contributors accept **no liability** for any direct, indirect, or consequential damages arising from use, misuse, or inability to use the Software, including any financial loss, regulatory consequence, or third-party claim. Discussion of EU regulation (MiCA, AIFMD, MiFID II, DORA) is **informational, not a compliance assurance**; no regulator has approved, endorsed, or certified the Software. The reference implementation is **pre-audit** as of this writing and unsuitable for production with material value at stake.

Read the full disclaimer at [`disclaimer.md`](disclaimer.md) — by using the Software in any way, you accept it.

---

*This whitepaper accompanies the v1.1-rc reference implementation release. It will be revised for v1.0 (after audit cycle 1) and again at Midgard mainnet launch. The canonical version is at `docs/whitepaper.md` in the Kern repository.*

*The full technical specification — including the nine role-specific setup guides, the four vertical specifications, the API stability declaration, the tokenomics document, and the operational roadmap — is indexed in §13 above. Start at [`setup-guides.md`](setup-guides.md) for role-based navigation.*
