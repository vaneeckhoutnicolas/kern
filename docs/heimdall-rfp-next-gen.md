# RFP — Next-generation Kern explorer

**Document status**: Draft for community / vendor input. Not yet open for proposals.
**Owner**: Foundation, post-establishment.
**Audience**: external teams interested in building or operating the canonical public-facing Kern block explorer.
**Maintainer**: Nicolas Van Eeckhout (founder).

---

## Why an RFP

Heimdall (kern_explorer in this repo) is the reference explorer and monitoring stack shipped with the Kern v1.1-rc reference implementation. It is intentionally minimal: a 4-session build delivering a FastAPI app, a SQLite indexer, Jinja2 + Tailwind UI, and Prometheus instrumentation, totalling ~2,200 lines of Python and 18 HTML templates.

Heimdall is **enough for**: devnet, Yggdrasil testnet operations, the Foundation's own monitoring of Midgard mainnet, and any organization that wants self-hosted chain introspection.

Heimdall is **not enough for**: the public-facing canonical explorer at `explorer.kern.protocol` that a token holder, dApp developer, or regulator would visit. That product needs the polish, performance, and feature breadth of an Etherscan or a Tzkt — built and operated by a dedicated team with a multi-year mandate.

This RFP defines what the Foundation will eventually solicit for that next-generation explorer.

---

## Timing

This RFP will be **opened after Yggdrasil testnet launch** (Phase 3 of [`post-code-roadmap.md`](post-code-roadmap.md)), and target a vendor selection before Midgard mainnet (Phase 6).

Before then, Heimdall covers the gap. Public visibility on Yggdrasil traffic via a Foundation-operated Heimdall instance is the prerequisite for issuing this RFP — without it, prospective vendors have no traffic patterns to size against.

---

## What Heimdall already provides (and the next-gen explorer can build on)

Vendors should expect to reuse — or interoperate with — these existing artefacts :

- **The indexer schema** (SQLite or Postgres per [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md)) is documented and stable. A next-gen explorer can either re-index from RPC or read directly from the same Postgres.
- **The Skald template detection rules** (`kern_explorer/indexer.py:TEMPLATE_PATTERNS`) classify originated contracts as STO / PGF / oracle / other. These have to be maintained as new templates ship; today there are 10.
- **The vertical summary heuristics** (`compute_vertical_summary()`) derive securities compliance, oracle health, etc. from storage. The same logic applies to a next-gen UI.
- **The Prometheus metrics surface** (`kern_explorer/metrics.py`) is the canonical source for Heimdall operational telemetry. A next-gen explorer should emit at least a superset, never a strict subset.
- **The Grafana dashboards** (`kern_explorer/monitoring/grafana/`) are reusable as-is by any system using the same metrics.
- **The alerting rules and ops runbook** define what "abnormal" looks like across the chain.
- **The API surface** documented in [`setup-heimdall-operator.md`](setup-heimdall-operator.md) section "Programmatic access". A next-gen explorer should provide at least an equivalent set.

---

## Functional requirements

The next-generation explorer should provide all of the following.

### Must have

1. **Real-time chain inspection** — blocks, transactions, accounts, validators, contracts. Refresh latency ≤ 5 seconds from RPC.
2. **All Heimdall vertical dashboards, at parity or better** — attestations, STO compliance, public goods, oracles. The dashboards should be at least as informative as Heimdall's, ideally with richer drill-downs (e.g. per-issuer reputation across schemas, per-feeder anomaly history with confidence intervals).
3. **Search**: by block level, block hash, transaction hash, account address, attestation ID, schema ID, contract address, contract name. Fuzzy match where appropriate.
4. **API**: public REST and/or GraphQL, documented with OpenAPI/GraphQL schema, with rate-limited free tier and authenticated paid tier.
5. **Wallet integrations**: show holdings, delegations, attestations for any kn1 address. "What does this address do?" should answer in one click.
6. **Verified contracts**: a community-driven mechanism for issuers to verify their Skald source matches an originated contract's bytecode, plus display of the verified source.
7. **Internationalization**: at minimum English + French (Belgium's official languages, Founder's native context). Ideally also German + Dutch + Spanish + Italian for EU coverage.
8. **Mobile**: fully responsive. Critical pages (account, tx, block) usable on phone.
9. **Accessibility**: WCAG 2.1 AA conformance.
10. **HTTPS, secure headers, CSP** — production web hygiene.
11. **Public availability commitment**: ≥ 99.5% monthly uptime SLA.
12. **Multi-network**: one product handles devnet + Yggdrasil + Midgard with a network selector.

### Should have

13. **Historical analytics**: charts of validator performance, governance participation, network growth, KRN holder distribution.
14. **Notifications**: subscribe to address activity, attestation issuance/slashing, contract events, validator status changes (email, webhook, browser push).
15. **Schema marketplace browser**: discoverable list of recognized schemas with their issuers, bonds, attestation counts, slashing history.
16. **Rollup explorer**: when rollups are deployed, second-level views into L2 state with reference back to L1 settlement.
17. **EVM compatibility view**: when EVM rollups are live, decode known ERC-20/721/1155 events for known token contracts.
18. **MEV transparency**: when MEV becomes relevant, surface ordering anomalies and proposer behavior.

### Could have (post-v1)

19. **Wallet integration adapters** (Ledger, Metamask Snap, mobile wallets) baked into the explorer for transaction submission and signing.
20. **Decentralized notification network** using attestations.
21. **An on-chain-paid premium tier** (Kern as the substrate for its own product economy).

### Won't have (out of scope)

- Building new contract templates — that's the Skald language team's domain
- Block production or validation — out of scope; the explorer is read-only with respect to consensus
- Running validators — see [`setup-validator.md`](setup-validator.md) for that

---

## Non-functional requirements

### Performance

- **Index lag**: ≤ 10 seconds behind the chain head on Midgard at 1s block time
- **Page load (cached)**: ≤ 500 ms p95 from a major EU datacenter
- **API response (single record by primary key)**: ≤ 100 ms p95
- **Concurrent users**: design for 10k concurrent / 100k req/min sustained at Midgard launch, with linear scale-out

### Operational

- **Open source**: the explorer software must be open-source under a permissive license (Apache-2.0 like Kern itself is preferred). The Foundation will fund development; the community gets the artifact.
- **Self-hostable**: any third party should be able to run their own instance from public source + a Kern RPC endpoint. Vendor lock-in to the SaaS instance is a disqualifying property.
- **Cloud-portable**: deployable on at least 3 of {AWS, GCP, Azure, Hetzner, OVH, on-prem k8s}. No proprietary BaaS dependencies.
- **Reproducible builds**: deployment artifacts produced from a tagged source revision with verifiable checksums.

### Security

- Standard web security baseline (CSP, HSTS, SameSite cookies, anti-CSRF on any state-changing endpoint)
- Annual third-party penetration test
- Coordinated vulnerability disclosure program
- No private keys handled by the explorer ever — wallet integration must be via standard signing flows (eip-1193-equivalent for Kern)

### Independence

- The explorer must remain **independent of the Foundation in operations**: the Foundation may fund and contract it, but it must not be the sole instance. At minimum, two community-operated alternative instances should exist by Midgard year 2.

---

## Vendor evaluation criteria

Bids will be evaluated on :

1. **Demonstrated capability**: prior delivery of an explorer for an analogous chain (Etherscan, Tzkt, Blockscout, Subscan teams are exemplars)
2. **Architecture clarity**: how does the proposed system scale to mainnet load; what are the bottlenecks; what's the indexing pipeline
3. **Open-source commitment**: license terms, governance of the codebase, contribution model
4. **Team continuity**: not just for v1 build but for years of operation
5. **Cost transparency**: hosting costs, on-call costs, feature roadmap costs broken down
6. **Cultural fit**: Belgian / EU-rooted teams have a comparative advantage given Kern's regulatory positioning, but are not required
7. **Independence from Kern Foundation**: no equity, no insider relationships — vendor selection by open RFP

### Cost expectations (indicative, not binding)

For a 24-month build + first-year operation contract :
- Build: €600k–€1.2M (depending on scope of must-haves + should-haves chosen)
- Annual operation: €150k–€400k (hosting + on-call + feature development)

These are budget estimates for the Foundation, not a price ceiling. Vendors are expected to propose their actual costs.

---

## Submission

When this RFP opens (post-Yggdrasil), interested vendors will submit :

1. **Cover letter** (≤ 1 page)
2. **Team bios** with relevant prior projects
3. **Technical proposal** (≤ 20 pages) covering: architecture, indexing strategy, API design, deployment topology, monitoring, security
4. **Open-source commitment** statement
5. **Cost breakdown**
6. **References** from prior similar work

Submission via the Foundation's email (TBD). The Foundation will publish a shortlist within 6 weeks, conduct technical interviews, and announce a selection.

---

## See also

- [`setup-heimdall-operator.md`](setup-heimdall-operator.md) — the existing explorer (this RFP defines what comes after it)
- [`heimdall-ops-runbook.md`](heimdall-ops-runbook.md) — the operational requirements a successor must meet
- [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md) — the data layer a successor may inherit
- [`post-code-roadmap.md`](post-code-roadmap.md) — the network rollout phases this RFP fits within
- [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) — explorer presence is gated by this checklist
- [`setup-foundation.md`](setup-foundation.md) — the entity that will issue this RFP

---

*This RFP draft is part of the Heimdall delivery (Session 4/4). It defines what success looks like beyond the reference implementation, so the community has a north star.*

*Founder: Nicolas Van Eeckhout. License: Apache-2.0.*
