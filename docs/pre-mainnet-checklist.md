# Pre-Mainnet Checklist

This document is the canonical checklist for everything that must be complete before Kern launches the **Midgard mainnet**. It exists so that no critical item is forgotten under deadline pressure.

**Owner**: Nicolas Van Eeckhout (founder) and the Foundation board (once incorporated).

**Source of truth**: this file. If a step is missing here, it does not block mainnet — but if you're about to add a new milestone, add it here first so it can be tracked.

---

## Status legend

- ✅ Done
- 🟡 In progress
- 🔵 Planned (not started)
- ⛔ Blocked
- N/A Not applicable to v1.0

---

## A. Code readiness

| Item | Owner | Status |
|---|---|---|
| All v1.0-rc features implemented per [v10rc-changes.md](v10rc-changes.md) | Founder | ✅ |
| 368 tests passing, 2 chaos tests intentionally skipped | Founder | ✅ |
| Real BN254 pairing via py_ecc functional | Founder | ✅ |
| All 55 Python files carry SPDX-License-Identifier: Apache-2.0 | Founder | ✅ |
| All 55 Python files credit Nicolas Van Eeckhout (founder) | Founder | ✅ |
| Originality audit passed (no copied code) | Founder | ✅ |
| AUTHORS file at repo root naming Nicolas as founder | Founder | ✅ |
| API stability spec frozen: [api-stability.md](api-stability.md) | Founder | ✅ |
| Sample wallet CLI (`scripts/kern_wallet.py`) operational | Founder | ✅ |
| Reference genesis builder reproducible: `scripts/build_v1_genesis.py` | Founder | ✅ |
| Devnet bootstrap script: `networks/devnet_bootstrap.py` | Founder | ✅ |
| All markdown internal links resolve | Founder | ✅ |
| mkdocs site builds without errors | Founder | ✅ |
| v1.0.0rc1 git tag created and signed | Founder | 🟡 (do at end of this step) |

---

## B. Documentation

| Item | Owner | Status |
|---|---|---|
| Whitepaper updated for v1.0: [whitepaper.md](whitepaper.md) | Founder | ✅ |
| Executive summary published: [executive-summary.md](executive-summary.md) | Founder | ✅ |
| Tokenomics finalized: [tokenomics.md](tokenomics.md) | Founder | ✅ |
| Staking + delegation spec: [staking.md](staking.md) | Founder | ✅ |
| Contributors program spec: [contributors-program.md](contributors-program.md) | Founder | ✅ |
| All 9 setup guides published: [setup-guides.md](setup-guides.md) | Founder | ✅ |
| Originality and attribution doc: [originality-and-attribution.md](originality-and-attribution.md) | Founder | ✅ |
| API reference complete: [api.md](api.md) | Founder | ✅ |
| Roadmap actualized: [roadmap.md](roadmap.md) | Founder | ✅ |
| Governance spec complete: [governance.md](governance.md) | Founder | ✅ |
| Documentation site deployed to docs.kern.protocol | Foundation | 🔵 |
| Documentation site has search, dark mode, mobile responsive | Foundation | ✅ (mkdocs ready) |
| Translations to French (Nicolas's native language) | Community | 🔵 |

---

## C. Foundation legal setup

Per [setup-foundation.md](setup-foundation.md):

| Item | Owner | Status |
|---|---|---|
| Jurisdiction decided (recommended: Estonian Foundation (Sihtasutus)) | Founder | 🔵 |
| Initial board members identified and recruited (5 people, 2 from different EU countries) | Founder | 🔵 |
| Legal counsel engaged (Belgian non-profit specialist) | Founder | 🔵 |
| Auditor engaged (Big 4 or mid-tier mid for AISBL) | Foundation | 🔵 |
| Foundation statutes drafted and notarized | Foundation + counsel | 🔵 |
| Foundation registered with Estonian Business Register (or alternative jurisdiction registry) | Counsel | 🔵 |
| Foundation registry code obtained | Counsel | 🔵 |
| Foundation bank account opened | Foundation | 🔵 |
| Foundation bylaws (rules of procedure) approved by board | Foundation board | 🔵 |
| Foundation GPG key generated and published | Foundation | 🔵 |
| Conflict-of-interest policy adopted | Foundation board | 🔵 |
| Whistleblower policy adopted | Foundation board | 🔵 |
| Initial capital deposited (≥ 50 000 EUR equivalent) | Founder | 🔵 |
| Founder allocation multisig (2-of-3) generated and tested | Founder | 🔵 |
| Foundation pool multisig (3-of-5) generated and tested | Foundation board | 🔵 |
| Contributors pool multisig (3-of-5) generated and tested | Foundation board | 🔵 |
| Validator bootstrap pool multisig (2-of-3) generated and tested | Foundation board | 🔵 |

---

## D. Audits

| Item | Owner | Status |
|---|---|---|
| Audit cycle 1 firm engaged (Trail of Bits / OtterSec / Hashlock / RV / ChainSec) | Foundation | 🔵 |
| Audit cycle 1 engagement letter signed | Foundation + auditor | 🔵 |
| Audit cycle 1 kickoff meeting completed | Foundation + auditor | 🔵 |
| Audit cycle 1 report received | Auditor | 🔵 |
| Audit cycle 1 findings: Critical fixed | Founder | 🔵 |
| Audit cycle 1 findings: High fixed | Founder | 🔵 |
| Audit cycle 1 findings: Medium addressed (fixed or accepted) | Founder | 🔵 |
| Audit cycle 2 firm engaged (re-audit of fixes) | Foundation | 🔵 |
| Audit cycle 2 report received | Auditor | 🔵 |
| Audit cycle 2 findings: any remaining Critical/High fixed | Founder | 🔵 |
| Public audit reports published on docs.kern.protocol/audits | Foundation | 🔵 |
| Originality attestation included in each audit report | Auditor | 🔵 |
| Code-version tags: v1.0.0 (post-audit) | Founder | 🔵 |

---

## E. Networks

| Item | Owner | Status |
|---|---|---|
| Devnet operational (3-validator local network) | Founder | ✅ |
| Previewnet design finalized (~30 validators application-gated) | Foundation | 🔵 |
| Previewnet launched | Foundation | 🔵 |
| Previewnet stability validated (30 days uptime, no consensus stalls) | Foundation | 🔵 |
| Yggdrasil testnet design finalized | Foundation | 🔵 |
| Yggdrasil testnet genesis prepared | Founder | 🔵 |
| Yggdrasil testnet validators recruited (5-10 initial) | Foundation | 🔵 |
| Yggdrasil testnet launched | Foundation | 🔵 |
| Yggdrasil testnet faucet operational | Community / Foundation | 🔵 |
| Yggdrasil testnet stability validated (60 days uptime) | Foundation | 🔵 |
| Yggdrasil testnet block explorer deployed (**Heimdall** ships in v1.1-rc; needs deployment) | Foundation | 🟡 |
| Yggdrasil testnet wallet integration (Ledger app OR Metamask Snap OR Kern Wallet) | Community / Foundation | 🔵 |
| Public testnet stress test: 1M tx without consensus issues | Community + Foundation | 🔵 |
| Public testnet rollup demo deployed | Founder / Community | 🔵 |

---

## F. Economy

| Item | Owner | Status |
|---|---|---|
| Genesis distribution finalized (100M KRN, 70/10/14/3/2 + 1% bootstrap baker; matches `genesis.json` as source of truth) | Founder + Foundation board | ✅ |
| Founder vesting schedule documented (4y, 1y cliff) | Founder + Foundation | ✅ |
| Contributors pool allocation policy: [contributors-program.md](contributors-program.md) | Founder + Foundation | ✅ |
| **Foundation pool and on-chain treasury separated into distinct addresses** (currently share one address in `genesis.json` — must be split for clean accounting and audit) | Founder + Foundation | 🟡 |
| **Bootstrap baker single-point-of-control mitigated** (the 1M genesis validator stake is the only baker at launch; bring independent validators in as early as possible per [setup-validator.md](setup-validator.md)) | Founder + Foundation | 🟡 |
| Initial contributor grants identified | Foundation | 🔵 |
| Public sale mechanism decided (ICO / Dutch auction / LBP / staged) | Foundation board | 🔵 |
| Public sale legal review complete (securities classification under MiFID II / Prospectus Regulation per jurisdiction; MiCA only for genuinely non-financial-instrument ancillary tokens) | Securities counsel | 🔵 |
| Public sale jurisdictional restrictions documented (KYC + IP geofence) | Foundation | 🔵 |
| Public sale platform selected | Foundation | 🔵 |
| Public sale runbook published | Foundation | 🔵 |
| Validator bootstrap pool distribution rules finalized | Foundation | 🔵 |
| KRN ticker reserved on relevant exchanges (CoinGecko, CMC) | Foundation | 🔵 |

---

## G. Operational infrastructure

| Item | Owner | Status |
|---|---|---|
| Foundation operations runbook | Foundation | 🔵 |
| Validator operations runbook: [setup-validator.md](setup-validator.md) | Founder | ✅ |
| Incident response playbook (consensus halt, exploit, slashing event) | Foundation + Founder | 🔵 |
| Bug bounty program designed | Foundation | 🔵 |
| Bug bounty program funded (target: 5-10% of Foundation pool reserved) | Foundation | 🔵 |
| Bug bounty platform selected (Immunefi / Cantina / self-hosted) | Foundation | 🔵 |
| Security disclosure policy published | Foundation | 🔵 |
| Security GPG keys published on Foundation site | Foundation | 🔵 |
| Public communication channels established (forum, Twitter, Discord/Matrix) | Foundation | 🔵 |
| Crisis communication plan (e.g., "what to say if chain halts for 1 hour") | Foundation | 🔵 |

---

## H. Genesis ceremony preparation

Per [setup-foundation.md](setup-foundation.md) Step 8:

| Item | Owner | Status |
|---|---|---|
| Final pool addresses confirmed (replacing placeholder seeds) | Foundation | 🔵 |
| Final genesis.json generated and reviewed | Foundation + Founder | 🔵 |
| Final genesis_vesting.json generated and reviewed | Foundation | 🔵 |
| Foundation board members convene (in-person or secure video) | Foundation board | 🔵 |
| SHA-256 of genesis.json computed | Founder | 🔵 |
| Each board member signs hash with personal GPG key | Foundation board | 🔵 |
| Foundation GPG key signs genesis.json | Foundation | 🔵 |
| Genesis pinned to IPFS (CID recorded) | Founder | 🔵 |
| Genesis published to GitHub release tag `midgard-genesis` | Founder | 🔵 |
| Genesis published to Foundation website with SHA-256 + IPFS CID + signature | Foundation | 🔵 |
| Genesis archived to Internet Archive (`archive.org`) | Foundation | 🔵 |
| Notarized printout in Foundation records | Foundation + notary | 🔵 |
| Community verification window: 7 days minimum | Public | 🔵 |
| Public announcement of Midgard launch date | Foundation | 🔵 |

---

## I. Day-of-launch

| Item | Owner | Status |
|---|---|---|
| Initial validator set ready (5-10 validators with hardware, keys, monitoring) | Foundation + validators | 🔵 |
| Initial validators on-call for first 72 hours | Validators | 🔵 |
| Foundation board on standby for incident response | Foundation board | 🔵 |
| First block produced from agreed genesis (level 1) | Validators | 🔵 |
| Mainnet announcement (Twitter, blog, press) | Foundation | 🔵 |
| Public RPC endpoint live (rpc.midgard.kern.protocol) | Community / Foundation | 🔵 |
| Block explorer live (**Heimdall** at canonical Foundation-operated URL) | Foundation | 🔵 |
| KRN distribution to public sale participants (post-genesis) | Foundation | 🔵 |
| Foundation vesting starts (founder + contributors clocks running) | Foundation | 🔵 |

---

## J. Post-launch (first 30 days)

| Item | Owner | Status |
|---|---|---|
| 99%+ uptime achieved (no consensus halt > 5 min) | Validators | 🔵 |
| First governance proposal submitted and processed end-to-end | Community | 🔵 |
| First treasury proposal submitted and processed | Community | 🔵 |
| Bug bounty program live and accepting reports | Foundation | 🔵 |
| First quarterly financial report (Foundation pool spending) | Foundation | 🔵 |
| Validator set grows from initial 5-10 to 15+ via permissionless registration | Network | 🔵 |
| First rollup deployed on Midgard | Community | 🔵 |
| Public retrospective published (what went well, what didn't) | Foundation | 🔵 |

---

## Critical path summary

The shortest realistic critical path from v1.0-rc to Midgard live:

```
v1.0-rc (today)
  │
  ├─→ Foundation incorporation             [3 months]
  │   ├─→ Audit cycle 1 engagement
  │   └─→ Public sale planning
  │
  ├─→ Audit cycle 1 conducted              [2 months]
  │
  ├─→ Audit findings remediation            [1 month]
  │
  ├─→ Audit cycle 2                         [1 month]
  │
  ├─→ Yggdrasil testnet stability validation [2 months in parallel]
  │
  ├─→ Public sale conducted                 [1 month, can parallel with audit cycle 2]
  │
  ├─→ Genesis ceremony preparation          [2 weeks]
  │
  └─→ Midgard launch                        Day 0
```

Total: **9-12 months** of focused execution. Realistic for a small team; longer for a solo founder.

---

## Sign-off

When all items in sections A through H are ✅, and the Foundation has formally voted to proceed:

- **Founder signature**: Nicolas Van Eeckhout, dated _______
- **Foundation board signatures**: collected at the launch-authorization meeting, dated _______
- **Audit firm attestation**: cycle 2 final report received, dated _______

Mainnet launch is authorized upon these three signatures.

---

## Reference

- [setup-foundation.md](setup-foundation.md) — Foundation incorporation steps
- [setup-auditor.md](setup-auditor.md) — Audit engagement workflow
- [setup-validator.md](setup-validator.md) — Validator setup
- [tokenomics.md](tokenomics.md) — Economic design
- [roadmap.md](roadmap.md) — Three-track roadmap (code / networks / operations)
