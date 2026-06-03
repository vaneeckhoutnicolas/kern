# Public Goods Funding on Kern

This document describes how Kern positions itself as **the protocol for community-governed funding of public goods**, and the two mechanisms it ships as native Skald primitives in v1.1-rc:

- **Quadratic Funding (QF)** — matching pool amplifies the signal from many small donors
- **Retroactive Public Goods Funding (RPGF)** — fund shipped impact rather than predicted impact

The thesis: a multi-billion-euro annual market in foundations, ONGs, supranational bodies (UNESCO, World Bank, EU public sector, Wikimedia), municipal innovation funds, and corporate ESG programs is currently spent on grants administered through opaque selection processes, with high administrative overhead and significant selection bias. Kern's primitives make the selection mechanism mathematically explicit, the votes verifiable, and the disbursement automatic — collapsing administrative cost and replacing political judgment with cryptoeconomically secured collective preference.

This document is the design rationale and integration guide for:

- [`quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald) — QF round, one contract per project
- [`retroactive-pgf.skald`](../kern/skald/examples/retroactive-pgf.skald) — RPGF nomination, one contract per nomination

---

## 1. Why public goods are under-funded

The classic economics problem: public goods are non-rival and non-excludable. Anyone benefits, no one is forced to pay. The free-rider equilibrium leads to underprovision.

Existing mechanisms to fix this:

| Mechanism | Limitation |
|---|---|
| Government taxation + budget allocation | Slow, captured by political interests, doesn't respond to community signal |
| Foundation grants (e.g., Gates, Ford) | One donor's preferences set the agenda; insulated from beneficiary feedback |
| Crowdfunding (Kickstarter) | Plutocratic — wealthier backers dominate; no signal amplification |
| Government matching schemes | Limited, jurisdictionally bound, opaque selection criteria |
| Corporate ESG | Often greenwashing or PR-driven; not impact-driven |

**Quadratic Funding** addresses the plutocracy problem mathematically — it amplifies the *number* of supporters over the *amount* given.

**Retroactive PGF** addresses the prediction problem — it's far easier to identify what *has worked* than what *will work*, and routing capital to proven impact closes the feedback loop.

Together, these two mechanisms cover most of the meaningful public-goods funding flows. Kern provides them as native, composable, on-chain primitives.

---

## 2. Quadratic Funding — the math and the politics

### The formula

For a project with direct contributions $c_1, c_2, \ldots, c_n$ from $n$ unique contributors, the **matching share** allocated from the pool is proportional to:

$$
\left( \sum_{i=1}^{n} \sqrt{c_i} \right)^2
$$

This means: 100 people each giving €1 generates a matching coefficient of $(100 \times \sqrt{1})^2 = 10\,000$, while 1 person giving €100 generates $(\sqrt{100})^2 = 100$.

The same total contribution, 100× the matching power.

**Why this is the right shape**: under reasonable economic assumptions (Buterin et al., 2018), the QF formula produces the optimal allocation when individual preferences are independent. Many small donors = strong signal that the project provides value to many people = should be matched heavily. One large donor = signal that one person values it = match modestly.

### The plutocracy-resistance

A single donor with €1M cannot dominate a QF round. Their matching coefficient on a single project would be $\sqrt{10^6}^2 = 10^6$, but splitting that same €1M across 1000 different projects gives $1000 \times \sqrt{1000}^2 = 10^9$ — except they can't, because they're a single contributor; the formula counts unique contributors.

### The sybil problem — and why Kern solves it differently

The QF formula is trivially gameable by sybils: create 1000 fake accounts, each donates €1, and now you control €1000 of "many small donors" matching power.

Existing QF systems (Gitcoin) address sybils with hybrid solutions: BrightID, Gitcoin Passport, manual reviews. Effectiveness varies; sybil attacks remain ongoing.

**Kern's solution**: the contribution itself is two-stepped, and the operator must record a separate attestation for each contributor's eligibility. The operator's attestation is **slashable on equivocation** — if the operator double-counts the same person under different identities, anyone can prove it on-chain and slash the operator's bond.

The verification chain:

1. Each contributor must hold an `identity.proof-of-personhood` attestation from a trusted issuer (e.g., Worldcoin orb, BrightID, government KYC)
2. The operator reads these attestations off-chain and records the contribution's sqrt share via `record_sqrt_share`
3. If the operator equivocates (records the same person twice under different addresses), the proof-of-personhood attestations themselves expose the duplicate, and anyone can submit `SLASH_ATTESTATION_EQUIVOCATION` against the operator's reporting attestation

The operator has skin in the game. Sybil prevention becomes an economic deterrent, not a hope.

### The Skald template constraint

Skald v1.1 has no `mapping<address, int>` type and no `sqrt()` builtin. So the QF contract:

- Tracks ONE project per origination
- The operator (off-chain) computes `sqrt(c_i)` for each contribution and records it via `record_sqrt_share`
- A separate "round coordinator" contract (not modeled in v1.1) closes the round and allocates the matching pool across all project contracts

v1.2 Skald will add map types and computable sqrt, allowing a single multi-project round contract.

---

## 3. Retroactive Public Goods Funding — the model

### The thesis (Optimism, 2021)

> *It is much easier to identify what has provided value to a system than to predict what will provide value.*

Funding decisions are typically made *prospectively*: an applicant pitches a project, a panel evaluates the pitch, money is disbursed if approved. This has known failure modes:

- Selection bias toward articulate pitchers
- Selection bias toward connected applicants
- High administrative overhead (the panel must evaluate every application)
- Inability to verify outcomes against promises
- No accountability if a funded project fails

RPGF inverts this:

1. The round publishes an *eligibility window* (e.g., "any public good shipped in 2026 H1")
2. Anyone can nominate a project that shipped within that window
3. Evidence of impact is collected (downloads, citations, beneficiary testimonials, usage metrics — all posted as attestations to the chain)
4. A panel of **badge-holders** (Foundation board + recognized contributors with track records of fair judgment) scores each nomination
5. The matching pool is distributed proportional to median or trimmed-mean scores

### Why median, not sum

A single bad-faith voter scoring a project either 0 or 100 cannot move the median significantly. Trimmed-mean (drop top and bottom 10%) is even more robust. This protects against both bribery and grudges.

### Why badge-holders, not stake-weighted

QF measures "preference signal from many people." RPGF measures "expert judgment of impact." These need different voter pools:

- For QF, anyone whose preferences are independent is a valid signal
- For RPGF, you need people who can credibly evaluate "did this project ship value to its declared beneficiaries"

The Foundation curates the badge-holder list and recognizes new badge-holders over time, gradually decentralizing the panel.

### Anti-collusion

If a badge-holder votes consistently for projects they have undisclosed interest in, an outside party can submit attestations exposing the conflict, leading the Foundation to revoke the badge.

In v1.1, badge revocation is a Foundation governance decision (off-chain). In v1.2+, this could be automated via slashable attestations on badge-holder behavior.

### The Skald template constraint

Same as QF: one nomination per contract. The "round coordinator" off-chain process aggregates votes across all nomination contracts and computes the final distribution.

---

## 4. How the two mechanisms compose

QF and RPGF are not competitors — they cover complementary moments in a project's lifecycle:

| Project stage | Best-fit mechanism |
|---|---|
| Idea, no traction yet | QF — let many small backers signal demand |
| Early shipped product | QF for growth funding |
| Mature product with usage data | RPGF — score based on demonstrated impact |
| Public-good libraries (e.g., dev tooling) | RPGF heavily, occasional QF for major upgrades |
| Single-event public goods (e.g., conferences) | QF (preference signal) |
| Ongoing maintenance | RPGF rounds with recurring eligibility |

A typical Foundation might run:

- **Quarterly QF rounds** — 100k EUR matching pool, project signups during a 2-week window
- **Semi-annual RPGF rounds** — 1M EUR pool, eligibility window covers last 6-24 months of shipped work
- **Continuous attestation registry** — beneficiaries publish impact evidence asynchronously between rounds

---

## 5. Use case: UNESCO heritage preservation

Hypothetical concrete example:

- UNESCO sets up a Kern-based public goods funding system
- 10M EUR annual budget for African heritage digitization projects
- Run as 4 quarterly QF rounds (250k EUR each) + 1 annual RPGF round (9M EUR)
- Eligible projects: open-source digitization tools, archive metadata standards, public training materials, community-led documentation efforts
- Contributors include: museums, universities, the affected communities themselves, individual cultural advocates
- Badge-holders: UNESCO regional experts + recognized academic peers in African heritage studies

What changes vs. current UNESCO grant model:

- Selection is **mathematically explicit** (the QF/RPGF formulas)
- Selection is **continuously auditable** (every vote and contribution on-chain)
- Administrative cost drops from ~15% of grant size (typical for international foundations) to ~2% (server costs + badge-holder honoraria)
- The community being served gets direct say (via QF participation)
- Bad-faith votes become slashable

UNESCO's brand value and convening power remain. What changes is the *mechanism* of allocation, made transparent and automated.

---

## 6. Use case: EU Digital Decade 2030 alignment

EU's Digital Decade 2030 strategy has a stated objective of "75% of EU enterprises adopting AI, cloud, big data." Currently funded via Horizon Europe (~95 billion EUR through 2027), administered through grant calls with months-long evaluation cycles.

If a small fraction (e.g., 1%, or ~950M EUR) were allocated through Kern's primitives:

- Quarterly QF rounds for small-team R&D projects (€500k-2M)
- Annual RPGF rounds for shipped open-source tools and frameworks used across EU industry
- Attestations of usage by the targeted enterprises (with bonds — equivocation is slashable)
- Cross-border coordination automatic (no per-member-state administration)

The political feasibility of this is non-trivial. But the technical feasibility is now demonstrated, and EU's interest in digital-sovereignty-aligned protocols (post-MiCA) creates an opening.

---

## 7. Use case: Wikimedia chapter funding

The Wikimedia Foundation distributes ~$15M per year to national Wikimedia chapters for community programs. Currently allocated by the WMF Affiliations Committee through annual budget requests.

Replace with Kern primitives:

- Each chapter submits an RPGF nomination annually (impact: # of edits, # of new editors, # of partnerships, # of educational events, etc.)
- Evidence: attestations from Wikipedia analytics, partner institutions, editor surveys (all with bonds)
- Voters: a global panel of Wikimedia stewards + meta-committee members
- Distribution: proportional to trimmed-mean impact score

Chapters with consistent high-impact delivery get more; chapters with low impact get less. The signal is mechanical and undebatable.

---

## 8. Why this is defensible for Kern as a Foundation strategy

Three reasons this positioning is durable for Kern:

### 8.1 Network effect

Once one major foundation (UNESCO, Wikimedia, an EU agency) uses Kern's primitives, others observe the operational efficiency and follow. This is the same pattern as Ethereum's adoption among DeFi: once Uniswap was on Ethereum, every other DEX team chose Ethereum.

### 8.2 Foundation-foundation alignment

Foundations *like* protocols that make their grant-making more accountable and efficient. Foundations *strongly dislike* protocols that primarily speculate (Bitcoin, Solana). Kern as "the protocol for grant-making" puts it in the small set of crypto projects that foundations can openly support.

### 8.3 Brussels-friendly positioning

Brussels (EU institutions, the parliament, the Commission) is currently negotiating MiCA implementation and watching the crypto space cautiously. A protocol positioned as "compliance-by-construction + public goods funding" is *the* example Brussels would want to point to as the "good crypto" answer.

This positioning is natural for an EU-based project. Kern doesn't compete with Solana on TPS or with Ethereum on developer mindshare; it provides what neither can: *institutionally legible* public-purpose blockchain infrastructure.

---

## 9. Operating a round end-to-end

### Pre-round (weeks -4 to 0)

1. **Foundation announces the round** — type (QF or RPGF), pool size, eligibility window, timeline
2. **Eligible projects nominate themselves** — for QF: register before contribution window opens; for RPGF: submit nominations with evidence
3. **Round operator role assigned** — typically the Foundation, sometimes a delegate
4. **Matching pool funded** — KRN transferred to `matching_pool_address`
5. **Per-project / per-nomination contract originations** — one Skald contract per project/nomination, all referencing the same `round_id`

### During round

**For QF (contributions phase, typically 2-4 weeks):**

- Contributors send KRN to each project's `contribute()` entry
- Round operator verifies sybil-resistance attestations for each contributor (off-chain)
- Operator calls `record_sqrt_share` for each verified contribution
- Operator posts a slashable attestation for each operator decision (`qf.contribution-verified`, subject = contributor address, claim = `{c, sqrt_c}`)
- Anyone can monitor and challenge by submitting `SLASH_ATTESTATION_EQUIVOCATION`

**For RPGF (voting phase, typically 4-8 weeks):**

- Evidence collection: anyone can post attestations supporting a nomination
- Badge-holders review and submit votes via the operator
- Operator posts attestations for badge-holder votes (`rpgf.vote-recorded`, subject = `{nomination_id, voter}`, claim = `{score}`)
- Badge-holder list itself is publicly known (badges issued as on-chain attestations by the Foundation)

### Post-round

For QF:

1. Operator calls `close_round(current_level)` on each project contract
2. Off-chain coordinator computes each project's matching share:
   `matching_i = pool × (sum_sqrt_i)² / Σ (sum_sqrt_j)²`
3. Matching pool transfers calculated shares to each project via `receive_matching_share`
4. Recipients withdraw via `withdraw_to_recipient`

For RPGF:

1. Operator records each nomination's median score via `record_median_and_share`
2. Off-chain coordinator computes shares proportional to median scores
3. Matching pool transfers shares; recipients withdraw

### Audit trail

Every contribution, vote, attestation, slashing event, and payout is on-chain. The complete audit trail of a round can be reconstructed by anyone, at any time, indefinitely.

---

## 10. Limitations and v1.2 roadmap

| Limitation in v1.1-rc | v1.2 fix |
|---|---|
| One project per Skald contract | Skald mapping types → single multi-project round contract |
| sqrt computed off-chain by operator | Skald math primitives (`isqrt(int) → int`) |
| Badge-holder votes "one per voter" enforced off-chain | Skald sets/mappings → on-chain enforcement |
| Round coordinator off-chain | Skald cross-contract calls → on-chain coordinator |
| Operator can equivocate (slashable but reactive) | Attestation-of-attestation: any single vote requires a counter-signature from a second badge-holder |

These limitations are real but not blocking — the v1.1 model is operationally usable, just less elegant than v1.2 will be.

---

## 11. Reference

- **Templates**: [`kern/skald/examples/quadratic-funding.skald`](../kern/skald/examples/quadratic-funding.skald), [`kern/skald/examples/retroactive-pgf.skald`](../kern/skald/examples/retroactive-pgf.skald)
- **Slashable attestations**: [`attestations.md`](attestations.md)
- **Contributors program** (Kern's own use of RPGF): [`contributors-program.md`](contributors-program.md)
- **Skald language**: [`skald-language.md`](skald-language.md)
- **Original QF paper**: Buterin, Hitzig, Weyl, "Liberal Radicalism: Formal Rules for a Society Neutral among Communities" (2018)
- **Original RPGF announcement**: Optimism Collective, "Retroactive Public Goods Funding" (2021)
