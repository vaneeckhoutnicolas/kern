# Setup Guides — Index

This directory contains step-by-step setup guides for each role and audience that interacts with Kern. Every guide is **precise and executable** — concrete commands you can copy-paste, file paths, version numbers, port numbers, and verification steps.

If you don't know where to start, find your role below and jump to the corresponding guide.

---

## Who should read what

| If you are... | Read this guide |
|---|---|
| **Cloning the repo to contribute code, tests, or docs** | [setup-developer.md](setup-developer.md) |
| **Holding KRN and wanting yield without running a node** | [setup-delegator.md](setup-delegator.md) |
| **Running a validator node (baker) on Yggdrasil or Midgard** | [setup-validator.md](setup-validator.md) |
| **Writing and deploying Skald smart contracts** | [setup-dapp-developer.md](setup-dapp-developer.md) |
| **Running an EVM rollup sequencer on Kern** | [setup-rollup-operator.md](setup-rollup-operator.md) |
| **Building public infrastructure (block explorer, wallet, public RPC)** | [setup-explorer-ops.md](setup-explorer-ops.md) |
| **Running Heimdall** (Kern's official explorer + monitoring stack) | [setup-heimdall-operator.md](setup-heimdall-operator.md) |
| **Nicolas Van Eeckhout (founder), setting up the Foundation** | [setup-foundation.md](setup-foundation.md) |
| **External security auditor (Trail of Bits, OtterSec, etc.)** | [setup-auditor.md](setup-auditor.md) |

---

## Order of operations across the project

These guides depend on each other. Here is the canonical execution order for getting from "v1.0-rc reference implementation" to "Midgard mainnet live":

```
                                                  ┌──────────────────────────┐
1. Founder identity established  ──────────────►  │ setup-foundation.md      │
   (this repo, signed commits)                    │ (Estonian Sihtasutus —   │
                                                  │  or AISBL/Stiftung)      │
                                                  └────────────┬─────────────┘
                                                               │
                  ┌────────────────────────────────────────────┤
                  ▼                                            ▼
       ┌──────────────────────┐                    ┌──────────────────────┐
   2.  │ setup-developer.md   │                3.  │ setup-auditor.md     │
       │ (contributors clone, │                    │ (audit cycle 1       │
       │ test, develop)       │                    │  engagement)         │
       └──────────┬───────────┘                    └──────────┬───────────┘
                  │                                           │
                  └────────────────────┬──────────────────────┘
                                       │
                                       ▼
                          ┌────────────────────────────┐
                      4.  │ setup-validator.md         │
                          │ (Yggdrasil testnet         │
                          │  bootstrap validators)     │
                          └──────────┬─────────────────┘
                                     │
                  ┌──────────────────┼─────────────────────┐
                  ▼                  ▼                     ▼
       ┌──────────────────────┐  ┌───────────────────┐ ┌─────────────────────┐
   5a. │ setup-delegator.md   │5b│ setup-dapp-       │5c│ setup-explorer-     │
       │ (Yggdrasil users     │  │ developer.md      │  │ ops.md (community   │
       │  delegate KRN-test)  │  │ (testnet DApps)   │  │  infra on Yggdrasil)│
       └──────────────────────┘  └───────────────────┘ └─────────────────────┘
                                     │
                                     ▼
                          ┌────────────────────────────┐
                      6.  │ setup-rollup-operator.md   │
                          │ (rollup sequencers on      │
                          │  Yggdrasil → Midgard)      │
                          └──────────┬─────────────────┘
                                     │
                                     ▼
                          ┌────────────────────────────┐
                      7.  │ Audit cycle 2 (setup-      │
                          │  auditor.md again)         │
                          └──────────┬─────────────────┘
                                     │
                                     ▼
                          ┌────────────────────────────┐
                      8.  │ Genesis ceremony →         │
                          │  Midgard mainnet launch    │
                          │  (in setup-foundation.md)  │
                          └────────────────────────────┘
```

---

## What's NOT in these guides

- **Protocol design rationale** — see [whitepaper.md](whitepaper.md), [tokenomics.md](tokenomics.md), [governance.md](governance.md).
- **API reference** — see [api.md](api.md) and [api-stability.md](api-stability.md).
- **Change history** — see [v10rc-changes.md](v10rc-changes.md) and the per-version change docs.
- **Quick conceptual overview** — see [executive-summary.md](executive-summary.md).

The setup guides are operational only. They assume you've decided to do the thing; they tell you how.

---

## Format conventions across all guides

Every guide follows this structure:

1. **Audience** — who specifically this guide is for
2. **Prerequisites** — skills, hardware, accounts, KRN balance, etc.
3. **What this guide covers** — a one-paragraph scope
4. **Step-by-step instructions** — numbered sections with copy-pasteable commands
5. **Verification at each step** — how to confirm the step worked
6. **Common issues** — troubleshooting table
7. **Next steps** — what to read or do after this guide

Commands are shown in bash blocks unless otherwise noted. File paths are absolute where ambiguity exists. Versions are pinned where it matters.

---

## Maintainer

These guides are maintained by **Nicolas Van Eeckhout** (founder) and accept pull requests through the standard contributor process. See [AUTHORS](../AUTHORS) and [contributors-program.md](contributors-program.md).
