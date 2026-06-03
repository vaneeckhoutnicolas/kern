# Use cases

Kern's design — predictable finality, formal invariants, on-chain evolution — points to a specific class of applications. This document describes the five use cases the protocol is most directly designed for.

## 1. Regulated DeFi

**The problem.** Decentralized finance protocols have demonstrated that on-chain markets can clear without intermediaries, but the dominant Solidity stack makes it hard to *prove* properties that regulators, auditors, and large counterparties need: that the protocol is solvent, that liabilities never exceed assets, that user-deposited funds are always withdrawable subject to the documented mechanics. Hard forks to fix discovered bugs further complicate the institutional case.

**How Kern helps.** Skald's invariant system turns these properties into protocol-enforced constraints, not after-the-fact audits. A lending market can declare `invariant solvent { total_assets >= total_liabilities }`; the runtime rejects any transaction that would violate it. Combined with Kern's on-chain amendment path, the protocol can be upgraded to fix bugs without forking user funds onto a new chain.

**Concrete shape.**
- Tokenized money markets with formally declared collateralization invariants.
- Automated market makers with provable bounds on slippage and IL exposure.
- Yield strategies whose published risk profile is mechanically enforced.

## 2. Government and public-sector registries

**The problem.** Land titles, civil registers, professional licenses, public procurement records, asset declarations — these are domains where auditability, longevity, and credible governance matter far more than transaction throughput. They are also domains where a Layer 1 that requires hard forks for every parameter change is a poor institutional fit.

**How Kern helps.** Predictable finality (no probabilistic reorganizations to explain to a notary), on-chain governance (parameter changes follow a documented procedure with a clear audit trail), and formally verifiable contracts (registry semantics declared as invariants, not buried in implementation code) all map cleanly onto public-sector requirements.

**Concrete shape.**
- A national land-title registry where transfer rules and dispute resolution are encoded in Skald and amended through the protocol's own governance path.
- An e-procurement system where eligibility, bidding, and award rules are invariants of the contract, with public verifiability of every step.
- A professional-licensing registry where licensure issuance and revocation events are signed by recognized authorities and provably ordered.

## 3. Sovereign stablecoins and CBDC pilots

**The problem.** Central bank digital currencies and sovereign-backed stablecoins need finality (a CBDC payment cannot be probabilistically reversed an hour later), formal verification (the issuance logic should be auditable), and a clear governance model (monetary parameters change rarely but visibly).

**How Kern helps.** ~2-second deterministic finality is well within what payment networks expect. Skald's invariant system lets monetary-policy logic — issuance caps, redemption mechanics, holding limits — be expressed as enforced constraints. On-chain governance gives the issuing authority an explicit, auditable channel for parameter updates.

**Concrete shape.**
- A retail CBDC contract with holding-cap invariants per address.
- A wholesale stablecoin where redemption rights are guaranteed by an invariant tying the on-chain supply to a reserve attestation.
- A multi-issuer payment-rail where each issuer's logic is a separate contract but all share a settlement layer governed by the same on-chain process.

## 4. Cross-chain settlement

**The problem.** Most economic activity in crypto today runs on the EVM, but the EVM is not optimized as a settlement layer — its finality is probabilistic, its governance off-chain, its bytecode hard to formally verify. Settlement layers should be different from execution layers.

**How Kern helps.** Optimistic Smart Rollups (shipped; see [rollups.md](rollups.md) and [evm-fraud-proofs.md](evm-fraud-proofs.md)) let EVM applications run on a Kern-anchored rollup, with state commitments posted to Kern. The result: developers keep Hardhat, Foundry, MetaMask, and their existing toolchain; users keep their Ethereum-style wallets; but the *settlement* — the layer that says "this state is canonical, here is the final account of who owes what to whom" — has Kern's properties.

**Concrete shape.**
- An EVM rollup hosting existing DeFi protocols, with Kern as the settlement and bridge layer for cross-rollup transfers.
- Multi-chain asset bridges where the locked-side commitment is a Skald contract whose invariants enforce the bridge's accounting.
- High-value institutional settlements that prefer Kern's deterministic finality to L1 Ethereum's probabilistic finality.

## 5. Verifiable AI inference markets

**The problem.** As AI inference becomes a commodity service, buyers want assurances about *what* they bought: which model version produced the output, which inputs were used, whether the result was returned within the agreed latency budget. Off-chain attestations work, but a settlement layer where the assurance is itself enforceable is stronger.

**How Kern helps.** A Skald contract can encode the terms of an inference contract — input hash, model commitment, expected output schema, latency window — and invariants can enforce that payment is released only when an attestation matching those terms is posted. The result is a marketplace where assurances are part of the protocol, not part of a side agreement.

**Concrete shape.**
- A pay-per-inference marketplace where each call's parameters and attestation are recorded on-chain and payment is gated on attestation validity.
- A model-provenance registry where weights are committed by hash and inference results carry a verifiable pointer to the committed model.
- Cooperative inference markets where multiple providers submit attestations and consensus across them is enforced by the contract.

---

## What Kern is *not* for

To make the targeting concrete, the inverse is worth stating. Kern is not designed for:

- **Mass-market consumer NFTs and gaming** — these benefit from cheap, high-throughput execution that an L1 cannot economically deliver. They belong on a rollup.
- **Fully anonymous payments** — ZK-claims (shipped; see [zk_claims.py](../kern/zk_claims.py)) enable privacy-preserving *attestations*, but Kern is not a shielded-value chain; confidential transfers remain out of scope.
- **Maximally permissive smart-contract experimentation** — Skald's deliberate restrictions (no recursion — now enforced statically by the type checker — no dynamic dispatch, and primitive types only at present) are a feature when verifiability matters, but a friction when rapid prototyping does.

These are not failings of Kern; they are choices. The chain is designed to be excellent at a narrow set of things rather than mediocre at all of them.
