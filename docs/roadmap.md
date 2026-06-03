# Kern Roadmap

This document is the canonical plan for getting Kern from its current state (v0.6, reference implementation) to a production mainnet. It is organized in **three parallel tracks** because code versions, network instances, and operational milestones progress at different rates and with different constraints.

The naming throughout follows the Norse-mythology thread established by **Kern** (kernel/core) and **Skald** (court poet): networks are named after the realms of Norse cosmology — **Yggdrasil** (the world-tree, our testnet linking realms) and **Midgard** (the realm of humans, our mainnet).

---

## Track 1 — Code releases (semantic versioning)

Code is what you `git pull`. Versions follow semver: `0.x` is pre-stable, `1.x` is stable, `2.x` is a breaking-protocol-change cycle.

| Version | Scope | "Done" criterion | Status |
|---|---|---|---|
| v0.1 | Single-baker chain + Skald interpreter | Block production + transfers working | ✅ |
| v0.2 | Multi-validator BFT + Static Skald + Rollup framework | 3-node consensus + typed Skald + bridge contract | ✅ |
| v0.3 | Mini-EVM + bisection + forced inclusion + adaptive issuance | EVM fraud proof end-to-end demo | ✅ |
| v0.4 | Issuance live in production + Merkle trie + EVM extensions | Block rewards crediting, light-client proofs available | ✅ |
| v0.5 | Governance live + trie swap-in + multi-frame EVM | CALL family + on-chain state-root function swap | ✅ |
| v0.6 | Governance via transactions + apply_block wiring + bonds + more precompiles | Proposals injectable through RPC, settle via governance tick | ✅ |
| v0.7 | BN254 precompiles + dynamic gas costs (Yellow Paper compliance) | Pass ethereum/tests opcode subset; zkSNARK verification working | ✅ |
| v0.8 | Voting refinements: quadratic + delegated; GovernanceVote over P2P with equivocation slashing | Multi-validator votes via gossip; slashing detected from history | ✅ |
| v0.9 | Hardening: structured logs, Prometheus metrics, fuzzing harness, devnet bootstrap | No crashes, no consensus stalls under fuzz | ✅ |
| **v1.0-rc** | **Genesis distribution (100M KRN) + Liquid PoS stake delegation + slashing tx + dynamic gas wired into VM** | **Code freeze. RPC API frozen. Documentation complete.** | **🟡 In progress (this iteration)** |
| v1.0 | First stable release after audit-cycle-1 fixes applied | External audit report public | 🔵 Planned |
| v1.x | Non-breaking patches and features (governance-amendable only) | Backward-compatible with v1.0 | 🔵 |
| v2.0 | Breaking protocol changes activated via on-chain governance | Approved by ≥ 80% supermajority vote | 🔵 |

The jump from "all features written" (v0.9) to "first stable" (v1.0) goes through an external security audit cycle. That's months of human time even for a finished codebase. v1.0 is *not* the day the code freezes — it's the day the audit report says "ship it" and the fixes are in.

## Track 2 — Networks (live instances)

Networks are what you connect to. They progress more slowly than code because each network bootstrap has a tail of monitoring, operator coordination, and stability validation.

| Network | Code at launch | Audience | Tokens have value? | Reset policy | Lifetime |
|---|---|---|---|---|---|
| **Devnet** | v0.9 ✅ launched | Contributors only (3–5 nodes via `networks/devnet_bootstrap.py`) | No | Free reset, anytime | Until interest fades |
| **Previewnet** | v1.0-rc 🟡 | Application-gated (~30 validators) | No | Reset on critical bugs, announced | Until audit-cycle-2 |
| **Yggdrasil (testnet)** | v1.0 🔵 | Public, permissionless validation, faucet-funded KRN-test | No | Reset only on consensus-killing bugs | Continues after mainnet (used for DApp dev forever) |
| **Midgard (mainnet)** | v1.0 + audit ✅ + Foundation 🔵 | Public, permissionless | **Yes** — real KRN | **Never** | Forever |

Yggdrasil and Midgard are intentionally named: anyone working on a Kern DApp will spin up on Yggdrasil, the same way Ethereum devs use Sepolia. Midgard is the home where real value lives.

Bootstrapping scripts for each network ship alongside the code release that launches it — see [`networks/`](../networks/) for the genesis files, seed-peer lists, and faucet credentials.

## Track 3 — Operational milestones (not code)

These are the non-code items that have to happen for Kern to be a *real* chain rather than a research artifact. They're listed here because forgetting one would block mainnet just as effectively as a missing feature.

| Milestone | What it is | Blocking which network? |
|---|---|---|
| Foundation entity setup | Legal vehicle for the protocol — Sihtasutus (Estonian Foundation, recommended), AISBL (Belgian), or Stiftung (Swiss). Holds the brand, the IP, the multisig keys, the legal posture. Receives the 15M KRN Foundation pool at genesis. | Midgard |
| Validator program | Hardware spec, ops runbook, slashing-insurance options, stake-delegation interface. Distributes the 2M KRN validator bootstrap pool to selected early validators. | Yggdrasil |
| Bug bounty program | Public bounty rules + budget. Recommended platforms: Immunefi (DeFi-focused), Cantina, or self-hosted via Foundation. | Yggdrasil |
| Audit cycle 1 | Independent security audit of v0.9 / v1.0-rc. Candidate firms: Trail of Bits, OtterSec, Hashlock, Runtime Verification, ChainSecurity. Funded from Foundation pool. | v1.0 |
| Audit cycle 2 | Re-audit of v1.0 + fixes, before mainnet KRN distribution. | Midgard |
| Wallet integration | At least one wallet supporting Kern's address format and signing. Either: build one (Kern Wallet, ~3 months), or get Ledger app + Metamask Snap. | Yggdrasil (testnet UX) |
| Block explorer | **DONE in v1.1-rc**: [Heimdall](setup-heimdall-operator.md) ships as the official Kern explorer — FastAPI + SQLite indexer + Prometheus metrics + 13 HTML pages with dedicated views for the v1.1-rc verticals (attestations, STO compliance, oracle health). Sessions 2-4 of the Heimdall plan add per-vertical drill-downs, Grafana dashboards, and production polish. | v1.1-rc → ongoing |
| Public sale design | Mechanism for the 70% public allocation (70M KRN). Options: time-bounded ICO (Ethereum 2014 style), Dutch auction, LBP via existing AMMs, or staged distribution. Selected by Foundation. | Midgard |
| Genesis ceremony | Distribute the 100M KRN per [`tokenomics.md`](tokenomics.md) §4. Multisig signing of the genesis file. IPFS-pinned + checksum-published. | Midgard |
| Contributor registry | Public log of pre-mainnet contributions and their KRN allocations from the 3M contributors pool. See [`contributors-program.md`](contributors-program.md). | Midgard |
| Documentation site | Beyond this repo: hosted at `docs.kern.protocol` (or similar). Source can stay in repo; rendering via mkdocs / docusaurus. | Yggdrasil |

The Foundation setup, in particular, is *the* gating item that the rest depends on. Audits are commissioned by a legal entity; bounties pay out from a legal entity; the Foundation also holds the validator registry and signs the genesis ceremony.

## Cross-track timing (realistic if pursued seriously)

Assuming a small focused team and a serious commitment to the audit-driven path:

```
Month  0     3     6     9     12    15    18    21
       │     │     │     │     │     │     │     │
Code:  v0.7──v0.8──v0.9──v1.0-rc────────v1.0──────v1.1
                       │
Net:                   Devnet (private)
                              Previewnet ──────────┐
                                                Yggdrasil ──── (continues forever)
                                                         Midgard (mainnet)
Ops:   Foundation setup ──────┐
                        Bug bounty ────────────────
                              Audit cycle 1 ─────┐
                                                 Audit cycle 2 ─┐
                                                       Wallet ──────
                                                       Explorer ────
                                                                Genesis ceremony
```

A solo developer realistically extends this to 24-36 months. A funded team with 5-10 engineers can compress to 12-15 months.

## Why this structure

The point of separating tracks is honesty. Saying "v1.0 = audited testnet" buries the actual work: choosing auditors, raising the budget to pay them, scheduling the engagement, fixing what they find, getting them to re-validate. That's calendar work, not just engineering work.

Saying "v2.0 = mainnet + KRN genesis" similarly compresses launching a legal entity, signing 1B KRN of tokenomics into a multisig, coordinating exchange listings (or not), and a launch ceremony.

The three-track structure makes it visible that progress on one track doesn't automatically advance another. A finished v0.9 doesn't launch Yggdrasil; a launched Previewnet doesn't pass an audit. Each cell of the matrix is its own work item with its own owner.

## Status as of this commit

- **Code**: v0.9 ✅ shipped. v1.0-rc 🟡 in progress (genesis distribution + stake delegation + slashing tx + dynamic gas wiring done; remaining: BN254 real pairing, API freeze spec, mkdocs site).
- **Networks**: Devnet bootstrap script ships in `networks/devnet_bootstrap.py`. Previewnet design pending.
- **Ops**: All blocked on Foundation setup, which is a real-world action no codebase can take by itself. Genesis distribution table is finalized — see [`tokenomics.md`](tokenomics.md) §4 and [`contributors-program.md`](contributors-program.md).
