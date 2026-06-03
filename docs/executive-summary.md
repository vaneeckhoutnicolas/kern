# Kern — Executive Summary

**One-line:** A Layer-1 blockchain that combines Ethereum's developer ecosystem with Tezos's on-chain governance and formal verifiability, optimized to be a *settlement and registry layer* rather than an execution-throughput layer.

---

## 1. The problem Kern solves

The L1 landscape today forces a choice between two trade-offs:

- **Ethereum-family chains** (Ethereum, BNB, Polygon, Avalanche, …) win on developer gravity and tooling, but evolve through contentious hard forks, and their dominant contract language (Solidity) makes properties like solvency, supply caps, and ownership constraints hard to *prove* — they remain assertions in audits, not protocol-enforced guarantees.
- **Formal-methods-first chains** (Tezos, Cardano, Algorand to a degree) win on protocol rigor — on-chain governance, formally verifiable contracts, deterministic finality — but lack the developer mass that makes Ethereum a default choice.

The result is a structural gap: institutions that need provable guarantees and predictable evolution — central banks, regulated financial protocols, government registries, high-value settlement systems — find Ethereum culturally unfit and the rigorous chains under-resourced.

Kern is designed to close that gap, not by being a "better Ethereum" or a "more popular Tezos", but by being a deliberately specialized **settlement and registry layer** that delegates execution to rollups.

## 2. What Kern is, in five points

1. **A Layer-1 with deterministic finality.** Tenderbake-style BFT consensus, ~1-second block time, ~2-second finality. No probabilistic reorganizations.
2. **A Liquid Proof-of-Stake validator economy.** Anyone can delegate without giving up custody. Validators stake KRN; rewards adjust adaptively to participation.
3. **A contract language built for verification.** Skald is small, statically typed, and enforces declared invariants at runtime. A lending market literally cannot enter an insolvent state.
4. **An on-chain evolution path.** Protocol amendments — including consensus parameters, gas pricing, and Skald itself — go through an on-chain governance cycle. No hard forks.
5. **EVM compatibility via Optimistic Rollups.** Existing Ethereum applications run on a Kern-anchored rollup with Hardhat/Foundry/MetaMask working unchanged. Kern itself stays narrow and verifiable.

Plus, shipping in v1.1-rc:

- **A slashable attestation primitive** generalizing equivocation accountability beyond consensus to any signed off-chain claim — KYC, oracle prices, NAV, notary attestations, ESG data.
- **Heimdall, the official block explorer + monitoring stack** (FastAPI + SQLite indexer + Prometheus metrics), with dedicated views that surface what other explorers cannot: the attestation registry, STO compliance dashboards, oracle health, public-goods funding rounds. See [setup-heimdall-operator.md](setup-heimdall-operator.md).

## 3. What makes Kern *different* from existing chains

| Property                          | Ethereum L1   | Tezos         | Solana        | **Kern**     |
|-----------------------------------|---------------|---------------|---------------|--------------|
| Finality                          | Probabilistic (~12 min) | Deterministic (~30s) | Deterministic (~12s) | **Deterministic (~2s)** |
| Consensus                         | PoS (Casper)  | Tenderbake    | PoH + PoS     | **Tenderbake-lite + LPoS** |
| Block time                        | 12 s          | 8–15 s        | 0.4 s         | **1 s**      |
| On-chain governance               | No            | Yes           | No            | **Yes (dual track)** |
| Contract language verifiability   | Hard (Solidity) | Strong (Michelson) | Hard (Rust + BPF) | **Strong (Skald + declared invariants)** |
| EVM compatibility                 | Native        | Via Etherlink rollup | No            | **Via Optimistic Rollup** |
| Account abstraction at L1         | EIP-4337 (opt-in) | No (planned) | No            | **Native (no EOA/contract split)** |
| Native token utility              | Gas + staking | Gas + staking + governance | Gas + staking | **Gas + staking + governance + storage rent + treasury** |

**The clearest differentiators:**

- **Invariants as first-class language constructs.** No other major L1's contract language enforces declared invariants automatically. In Solidity, an invariant is a comment; in Skald, it's machine-checked on every state mutation.
- **Dual-track on-chain governance.** Tezos has a single track; Kern splits protocol amendments from treasury allocations so funding doesn't bottleneck protocol evolution.
- **Native account abstraction.** Every account is potentially programmable; there is no EOA-vs-contract distinction. This simplifies wallet UX, multi-sig, social recovery, and gas sponsorship without retrofitting (the source of EIP-4337's complexity on Ethereum).
- **Deliberate narrowness at L1.** Kern doesn't pretend to be a high-throughput execution layer. Execution goes to rollups. L1 stays small, slow-by-design, verifiable, and governable.

## 4. Why use Kern — the institutional value proposition

The value of Kern is concentrated in five properties that institutions ask for and that most chains struggle to deliver simultaneously:

**1. Predictable finality, not probabilistic.** A settlement made on Kern at second T is final at second T+2. No reorganization rollback. Banking-grade auditability.

**2. Provable correctness, not asserted.** A Kern contract's declared invariants are protocol-enforced. "This pool is always solvent" stops being an audit promise and becomes a runtime guarantee.

**3. Documented evolution path, not coordination crisis.** Every protocol change goes through a multi-week voting cycle visible to all stakeholders. When the chain upgrades, the path that got it there is on-chain and auditable.

**4. Compatibility without compromise.** Existing EVM tooling works against the Kern rollup. Existing teams don't retrain. Existing assets bridge in. But the *settlement* — the canonical "who owns what" — has Kern's properties.

**5. Specialized, not general-purpose.** Kern is honest about what it's for. High-frequency consumer apps live on rollups. The L1 itself does what only an L1 can do: settle, govern, attest, register.

## 5. Concrete use cases (in priority order)

### 5.1 Sovereign stablecoins and CBDC pilots

A central bank or sovereign issuer deploys a stablecoin contract on Kern where:
- Issuance authority is held by a multisig governed by the issuing institution.
- Per-address holding caps are declared as Skald invariants.
- Redemption mechanics (reserve attestation, settlement window) are encoded as entry points.
- Monetary parameters (cap level, issuance rate) are amendable through on-chain governance with the institution as the sole proposer.

**Why Kern specifically:** ~2-second finality matches payment expectations. Invariants give the central bank machine-enforced policy rules. On-chain governance gives a documented amendment path that's friendlier to regulators than off-chain hard forks.

### 5.2 Regulated DeFi (institutional money markets, RWAs)

A money-market protocol declares `invariant solvent { total_assets >= total_liabilities }`. The runtime rejects any transaction that would breach it — including price-feed manipulations and flash-loan attacks. The protocol's parameters (LTVs, liquidation thresholds, oracle sources) are upgradeable through governance, with KRN holders or a designated subset voting.

**Why Kern specifically:** Solvency stops being an off-chain audit and becomes an on-chain property. Upgrades don't require user funds to migrate. Real-world asset issuers get a settlement layer they can credibly tell auditors about.

### 5.3 Government and public-sector registries

Land titles, civil registers, professional licensing, public procurement. The semantics — who can transfer, what conditions must be met, what records persist — are encoded in Skald. Parameter changes go through governance. Records are queryable by light clients.

**Why Kern specifically:** Predictable finality (no notary needs to explain probabilistic reorgs). On-chain governance (the registry's evolution is itself part of the public record). Skald invariants (the rules of who owns what are protocol-enforced, not platform-enforced).

### 5.4 Cross-chain settlement layer for EVM rollups

Multiple EVM rollups (DeFi-focused, gaming-focused, enterprise-focused) post their state commitments to Kern. Kern acts as the settlement hub: cross-rollup transfers settle through it; bridge contracts use Skald invariants to enforce accounting; rollup upgrades are themselves governed through Kern.

**Why Kern specifically:** The chains that need to be settlement layers should not be the chains optimized for execution. Kern's narrowness is the feature.

### 5.5 Verifiable AI inference and computational markets

A buyer commits to inference terms (model hash, input hash, latency budget) in a Skald contract. A provider posts an attestation with the result. Payment is released only when the attestation passes the contract's invariants. The whole interaction is auditable on-chain.

**Why Kern specifically:** Invariants make computational guarantees enforceable, not advisory. The settlement is fast (2s finality) so inference latency budgets are not blocked by chain confirmation. Governance gives the marketplace a path to evolve attestation standards.

### 5.6 Treasury management for DAOs and foundations

A foundation's treasury is held by a Skald contract with declared spending invariants (annual cap, multi-sig thresholds, vesting schedules). Treasury votes are on-chain. Funding decisions are auditable and reversible only through the same governance path that authorized them.

**Why Kern specifically:** A foundation that pretends to be transparent should actually be transparent. Skald makes the spending rules machine-enforced. The dual-track governance separates protocol-level treasury (KRN ecosystem fund) from application-level treasuries (each DAO's own).

## 6. The KRN token — economic design

Kern has a native token, **KRN**, because the protocol genuinely needs one:

- **Gas / fees.** Every transaction pays a fee in KRN to the producing baker.
- **Staking collateral.** Validators stake KRN; delegators delegate it Liquid PoS — balances stay liquid and in the holder's custody, no LST derivative, no lockup.
- **Governance weight.** Voting on protocol amendments and treasury allocations is weighted by stake; quadratic weighting on treasury votes to dampen whales.
- **Storage rent.** Originating a contract and growing its storage consumes KRN, preventing state bloat.
- **Treasury funding.** A fraction of block rewards (default 5%) flows to the on-chain treasury for ecosystem grants.

**Genesis distribution** (100 000 000 KRN total, Ethereum-style with modern vesting):

| | % | Amount | Vesting |
|---|---:|---:|---|
| Public sale | 70% | 70M KRN | Liquid at genesis |
| Founder (Nicolas Van Eeckhout) | 10% | 10M KRN | 1-year cliff + 4-year linear |
| Foundation | 15% | 15M KRN | Strategic ops, legal entity multisig |
| Early contributors pool | 3% | 3M KRN | 6-month cliff + 3-year linear, individual grants |
| Validator bootstrap | 2% | 2M KRN | Released over 1 year |

The full tokenomics — supply, distribution, vesting, sinks, faucets, adaptive issuance formula, staking and delegation mechanics, slashing — is specified in [`tokenomics.md`](tokenomics.md) and [`staking.md`](staking.md). The contributor incentive structure is detailed in [`contributors-program.md`](contributors-program.md).

## 7. Roadmap

| Phase                      | Scope                                                                                    | Status     |
|----------------------------|------------------------------------------------------------------------------------------|------------|
| v0.1 — Reference node      | Single-baker chain, Skald interpreter, RPC, P2P, persistence, end-to-end transfer + call | ✅ Done     |
| v0.2 — Multi-validator BFT | Pre-endorsement + endorsement messages, signature aggregation, slashing primitives       | ✅ Done     |
| v0.2 — Static Skald        | Compile-time type checker wired into origination                                          | ✅ Done     |
| v0.2 — Optimistic Rollup   | Rollup state machine + bridge contract + batch challenges                                 | ✅ Done     |
| v0.3 — Mini-EVM            | Step-wise EVM subset with state commitments                                              | ✅ Done     |
| v0.3 — Bisection protocol  | Interactive O(log n) fraud-proof bisection + single-step verifier                        | ✅ Done     |
| v0.3 — Forced inclusion    | L1 mailbox with deadline-based force-include and slashing                                 | ✅ Done     |
| v0.3 — Adaptive issuance   | Self-stabilizing emission formula + per-block reward distribution                        | ✅ Done     |
| v0.4 — Issuance live       | Issuance wired into block production; supply grows per block                              | ✅ Done     |
| v0.4 — Merkle trie         | Binary Merkle trie + O(log n) light-client inclusion proofs                              | ✅ Done     |
| v0.4 — EVM extensions      | SSTORE/SLOAD, SHA3, shifts, environment opcodes, ExecContext                              | ✅ Done     |
| v0.5 — Governance live     | Protocol amendment + treasury state machines; Skald contracts                            | ✅ Done     |
| v0.5 — Trie swap-in        | `state_root_hex` dispatches on governance-set `state_root_function`                       | ✅ Done     |
| v0.5 — Multi-frame EVM     | CALL/STATICCALL/DELEGATECALL/CREATE/CREATE2 + LOG + precompiles                          | ✅ Done     |
| v0.6 — Governance via tx   | GOVERNANCE_PROPOSE and GOVERNANCE_VOTE are first-class transactions                       | ✅ Done     |
| v0.6 — apply_block wiring  | Governance phases advance per block; activations applied to state automatically           | ✅ Done     |
| v0.6 — Proposal bonds      | Anti-spam economics: refund on success, 50/50 burn/treasury on rejection                  | ✅ Done     |
| v0.6 — More precompiles    | RIPEMD160, MODEXP, BLAKE2F (in addition to ECRECOVER, SHA256, IDENTITY)                   | ✅ Done     |
| v0.7 — BN254 precompiles   | Point addition, scalar mul, pairing entry-points — basis for on-chain zkSNARK verification | ✅ Done     |
| v0.7 — Dynamic gas         | EVM dynamic gas costs matching Ethereum Yellow Paper                                       | ✅ Done     |
| v0.8 — Quadratic voting    | Treasury voting now sqrt(stake) by default, dampening whales                              | ✅ Done     |
| v0.8 — Delegated voting    | Non-validators delegate stake to validators with per-proposal override                    | ✅ Done     |
| v0.8 — Equivocation        | Double-voting in same phase detected, recorded for slashing                               | ✅ Done     |
| v0.9 — Observability       | JSON-line structured logs + Prometheus metrics with /metrics endpoint                     | ✅ Done     |
| v0.9 — Fuzzing harness     | Property-based fuzzers for EVM determinism, tx safety, governance invariants              | ✅ Done     |
| v0.9 — Devnet bootstrap    | One-command multi-validator local network generator                                       | ✅ Done     |
| v1.0-rc — Dynamic gas wiring | EIP-2200 SSTORE pricing wired into VM step(); SHA3/EXP/memory expansion costs live | ✅ Done |
| v1.0-rc — Slashing tx | OpKind.SLASH_EQUIVOCATION transaction; proportional delegator slashing | ✅ Done |
| v1.0-rc — Delegated staking | Liquid PoS: DELEGATE_STAKE / UNDELEGATE_STAKE; commission split; effective_stake | ✅ Done |
| v1.0-rc — Genesis 100M | Ethereum-style distribution: 70% public / 10% founder vested 4y / 15% Foundation / 3% contributors / 2% validator bootstrap | ✅ Done |
| v1.0-rc — Code freeze | Final RPC API + transaction format + state schema freeze. Full documentation site. | 🟡 Remaining |
| v1.0 — Audit cycle 1 | First external security audit (candidates: Trail of Bits, OtterSec, Hashlock) | 🔵 Planned |
| Yggdrasil (testnet) | Public testnet, permissionless validators | 🔵 Planned |
| Midgard (mainnet) | Production launch with 100M KRN genesis distribution | 🔵 Planned |

## 8. What this repository is, what it is not

**This is** a working reference implementation: ~4 400 lines of Python that demonstrate every layer of the protocol end-to-end. You can clone it, generate keys, build a genesis, and watch blocks finalize in real time.

**This is not** production software. It is for protocol research, education, prototyping rollup applications against a stable settlement abstraction, and as the starting point of a serious testnet effort. Do not secure real value with it.

---

*See [`whitepaper.md`](whitepaper.md) for the technical long-form, [`tokenomics.md`](tokenomics.md) for the KRN token design, and [`use-cases.md`](use-cases.md) for the detailed application targets.*
