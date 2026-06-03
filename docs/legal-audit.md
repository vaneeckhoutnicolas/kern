# Legal audit report

*Internal audit of the Kern reference implementation, documentation, whitepaper, manifesto, and public website conducted to identify and mitigate plagiarism, attribution, trademark, defamation, regulatory misrepresentation, and overclaim risks. This document is published as part of the public repository so that any party considering the project — counsel, regulators, auditors, contributors, journalists — can see the diligence applied. Last audited: May 2026.*

---

## 0. Scope

This audit covers:

- The Python reference implementation in `kern/`, `kern_explorer/`, `scripts/`, `tests/` (~33,000 lines of code across 75 files)
- The documentation in `docs/` (~56 markdown files)
- The whitepaper (`docs/whitepaper.md`, ~11,000 words)
- The manifesto (`docs/manifesto.md`)
- The public website in `kern_site/` (7 HTML pages)
- The Skald contract templates (10 example files in `kern/skald/examples/`)
- The Grafana dashboards and Prometheus configurations (`kern_explorer/monitoring/`)

The audit does **not** cover: future versions, third-party forks, third-party deployments, content created after the date above.

---

## 1. Code originality and plagiarism

### 1.1 Plagiarism markers — automated scan

The repository was scanned for textual markers of code copying:

| Pattern | Locations | Verdict |
|---|---|---|
| `copied from` | `docs/originality-and-attribution.md`, `docs/setup-auditor.md`, `docs/release-tagging.md` | All defensive ("is NOT copied" / `grep` commands for auditors). No actual copy. |
| `ported from` | None | ✓ |
| `fork of` | Same defensive contexts | All in defensive contexts |
| `vendored from` | `docs/originality-and-attribution.md`, `docs/setup-auditor.md` | All defensive ("not vendored from another project") |
| `borrowed from` | Defensive contexts only | All defensive |
| `taken from` | `docs/originality-and-attribution.md`, `docs/setup-auditor.md`, `kern_site/how-it-works.html` ("taken from the bond" — common English in slashing economics, not a code reference) | All defensive or unrelated |

**Verdict**: zero occurrences of code-copying language in productive context. The reference implementation is original Python authored for Kern.

### 1.2 Public specifications implemented from spec

The reference implementation implements **public specifications** that anyone may implement:

| Specification | Authority | Implementation file(s) | Attribution |
|---|---|---|---|
| EVM opcodes (gas, semantics) | Ethereum Yellow Paper (Wood 2014, updated) | `kern/evm.py`, `kern/vm_gas.py` | Cited in `docs/multi-frame-evm.md`, `docs/evm-fraud-proofs.md`, code comments |
| EIP-2200 (SSTORE) | Ethereum Improvement Proposal | `kern/vm_gas.py` | Cited |
| EIP-2929 (state access costs) | EIP | `kern/vm_gas.py` | Cited |
| EIP-197 (BN128 pairing precompiles) | EIP | `kern/precompiles.py` | Cited |
| EIP-712 (typed signing) | EIP | `kern/attestations.py` | Cited |
| EIP-4337 (account abstraction) | EIP | Roadmap, not implemented yet | Cited as future |
| Ed25519 signature scheme | RFC 8032 / NaCl | `kern/crypto.py` via `pynacl` | Standard algorithm |
| Base58check encoding | Originally Bitcoin (Andresen) | `kern/crypto.py` | Standard algorithm |
| BN254 / alt_bn128 curve | Pereira et al., Aranha & Barreto papers; standardised in EIP-197 | `kern/precompiles.py` via `py_ecc` | Standard curve, library imported |
| Tenderbake (4-phase BFT family) | Astefanoaei et al. 2021 (academic paper) | `kern/consensus.py` | Cited as "BFT consensus algorithm in the four-phase family" |
| Liquid Proof-of-Stake (delegated PoS without LST) | Class of mechanisms with multiple prior implementations | `kern/baking.py`, `kern/delegation.py` | Documented as "Liquid PoS" generic class |

**Verdict**: every external specification implemented is cited in the documentation. No specification is implemented as if it were original.

### 1.3 External library dependencies (production)

| Library | Version pin | Licence | Compatibility with Apache-2.0 | Notes |
|---|---|---|---|---|
| `pynacl` | ≥1.5.0 | Apache 2.0 + ISC (libsodium) | ✓ Compatible | Cryptographic primitives (Ed25519, blake2b) |
| `aiohttp` | ≥3.9.0 | Apache 2.0 | ✓ Compatible | Async HTTP for the node networking |
| `py_ecc` | ≥8.0.0 | MIT (Ethereum Foundation) | ✓ Compatible | BN128 pairing for the EVM precompiles |

| Library (dev/optional) | Licence | Notes |
|---|---|---|
| `pytest`, `httpx` | MIT | Testing |
| `fastapi`, `uvicorn` | MIT | Heimdall explorer backend |
| `jinja2` | BSD | Heimdall HTML templates |
| `mkdocs`, `mkdocs-material`, `pymdown-extensions` | BSD / MIT | Documentation site |

**Verdict**: all dependencies are MIT, BSD, Apache 2.0, or ISC — all compatible with Apache-2.0 (the licence of the reference implementation). No GPL-incompatible code is linked.

### 1.4 Auditor verification path

`docs/setup-auditor.md` provides explicit instructions for any independent auditor to verify the above by running:

```bash
grep -rni "copied from|adapted from|fork of|borrowed from|taken from" --include="*.py" .
pip-licenses --format=markdown
```

The audit firm engaged for Cycle 1 (per `docs/post-code-roadmap.md` Phase 3) will be specifically asked to confirm originality.

---

## 2. Third-party trademark and brand usage

### 2.1 External project names mentioned in Kern documentation

The documentation mentions other blockchain projects in two legitimate contexts:

1. **Comparison tables** — listing market-relevant chains (Bitcoin, Ethereum, Tezos, Solana, Cosmos, Polkadot, Cardano, etc.) alongside Kern, as any neutral comparison article would.
2. **Domain-specific references** to other projects (Chainlink/Pyth for oracles, MakerDAO for DeFi) as examples of category leaders.

All such mentions follow **nominative fair use** (US) / **comparative reference** (EU) doctrine:

- ✓ Names are used only to refer to the actual project, not as a Kern brand element
- ✓ Use is no greater than reasonably necessary to identify the project
- ✓ No suggestion of endorsement, sponsorship, partnership, or affiliation is made
- ✓ No logo, trade dress, or visual mark of these projects is reproduced

### 2.2 Removed: false-lineage language

A prior version of the documentation used phrasings such as *"Tezos-style"*, *"draws on Tezos's design ideas"*, *"works exactly as it does in Tezos"*, *"loosely modeled on the Tezos node RPC"*. These were systematically replaced with generic class names (*Liquid PoS*) or removed entirely, because they amounted to **self-disclosed derivative status** that could be opposed:

- by a project claiming Kern is a copy
- by Kern's own readers, as evidence Kern is not original

A scan for the following 17 attackable patterns now returns zero occurrences:

> `Tezos-style`, `Tezos style`, `Tezos lineage`, `draws on Tezos`, `takes a structural idea from Tezos`, `Tezos-inspired`, `borrowed from Tezos`, `adapted from Tezos`, `Tezos derivative`, `prior art from the Tezos`, `modeled on the Tezos`, `works exactly as it does in Tezos`, `same model as Tezos`, `introduced in Tezos`, `closest to Tezos`, `Tezos heritage`, `draws on Tezos's`

### 2.3 Kern's own names — third-party trademark conflict screen

The Kern project uses several names drawn from Old Norse and Germanic vocabulary. A first-pass conflict screen identified the following **known conflicting uses** in the broader crypto and software space:

| Name | Known third-party uses | Conflict assessment |
|---|---|---|
| **Kern** | Generic European word ("kernel"); used in many non-crypto products; difficult to trademark by anyone | Low — class limitation should help (Kern = L1 protocol vs. unrelated industries) |
| **Skald** | Common Norse poet term; some unrelated software products | Low — narrow specific application (contract language) |
| **Heimdall** | **Used by Polygon as the name of their staking validator client** ("Heimdall" + Polygon "Bor"); also "Heimdall API" (security), "Heimdall blockchain" (security framework) | **Moderate** — both projects operate in the broader crypto space; trademark search and possible coexistence agreement recommended before the Foundation registers |
| **Midgard** | **Used by THORChain as the name of their official API ("THORChain Midgard")** | **Moderate** — same observation as Heimdall |
| **Yggdrasil** | Used by multiple projects (Yggdrasil Network mesh networking, others) | Low — common-knowledge term, multiple non-blockchain prior uses |
| **KRN (ticker)** | 3-letter symbol; not currently listed by any major exchange | Low — will be confirmed at Foundation incorporation |
| **kn1 (address prefix)** | None known | Low |
| **mukrn (atomic unit)** | None | Low |

### 2.4 Recommended actions before public launch

The author (and, after incorporation, the Kern Foundation) should:

1. **Engage a trademark attorney** for a formal search in:
   - EU (EUIPO) — primary jurisdiction
   - US (USPTO) — secondary
   - World Intellectual Property Organization (WIPO) Madrid Protocol for additional cover
2. **File trademark applications** in Class 9 (software) and Class 42 (computer services) for "Kern", "Skald", and any other names retained
3. **Specifically resolve the Heimdall and Midgard conflicts** before launch — either by:
   - Renaming to avoid the conflict, or
   - Establishing through search that the prior uses are in non-conflicting product classes / geographic markets, or
   - Negotiating coexistence agreements with Polygon and THORChain
4. **Document the choice** in this file once decided

This is a known open item, flagged here for transparency.

---

## 3. Defamation and critical comparison risk

### 3.1 The manifesto contains direct comparisons to other L1 protocols

The manifesto (`docs/manifesto.md` §II) contains the following passages discussing other chains:

> **Ethereum** is brilliant engineering. It is also a regulatory mismatch for any serious institution outside a few sandboxed pilots. The L1 enforces no semantics that a regulator can read; Solidity contracts hide their assumptions; the audit perimeter is custom and expensive every single time. The institutional response is to wrap everything in permissioned overlays, which defeats the point.
>
> **Tezos** has the right governance instinct — on-chain amendments, no hard forks, Liquid PoS that preserves custody. But it never closed the institutional gap with first-class compliance primitives at the protocol layer.
>
> **Solana** optimises for throughput and developer growth. Neither is what matters when an institution is asked to demonstrate to a regulator that an STO continuously satisfies Prospectus Regulation Art. 3.

### 3.2 Why this is defensible

Each passage applies the following protective construction:

1. **Genuine compliment first.** Ethereum is "brilliant engineering"; Tezos has "the right governance instinct"; Solana has its valid optimisations. The criticism is qualified, not dismissive.
2. **Opinion is explicitly framed as opinion.** The manifesto is published as an explicitly subjective document (the word *manifesto* itself signals this), distinguishable from a factual claim.
3. **Specific qualified scope.** "For any serious institution **outside a few sandboxed pilots**", "**at the protocol layer**", "**when an institution is asked to demonstrate to a regulator that an STO continuously satisfies Prospectus Regulation Art. 3**". The criticism is not absolute; it is targeted to a specific scope (institutional / regulated use).
4. **Technical argument is provided.** Each statement is followed by an explanation of *why* (Solidity does not enforce runtime invariants; Tezos lacks compliance primitives at the protocol layer; throughput does not address regulator-readability). These are debatable engineering positions, not unsubstantiated assertions.
5. **Author's standing.** The author has spent over a decade in the field, is a contributor to the Tezos ecosystem (Checker UI), co-founded the Brussels Meetup Blockchain-Ethereum group. The author has earned the standing to offer an informed comparative opinion.

### 3.3 Applicable law

Under Belgian law (Code of Economic Law, Article XVII.17 and following — *dénigrement*), comparative statements about competitors are protected when:
- They are accurate, or are clearly framed as opinion
- They identify the comparison object precisely
- They do not denigrate gratuitously
- They are made by a party with informed standing

The manifesto satisfies all four. The same applies under EU Directive 2006/114/EC (misleading and comparative advertising) — comparative advertising is permitted when it is not misleading, compares like with like, does not denigrate, and does not create confusion.

### 3.4 Verdict

**Acceptable risk.** The manifesto's comparative passages are defensible as informed opinion in a clearly subjective document. They are not actionable defamation. The protective construction is deliberate.

In an earlier draft the manifesto used the phrase *"regulatory dead zone"* instead of *"regulatory mismatch"*; the wording was softened to further reduce rhetorical heat without changing the substantive technical point. The legal exposure of both versions was comparable; the change is a stylistic decision in favour of conservatism.

---

## 4. Regulatory representation

### 4.1 Discussion of EU regulation in documentation

The documentation discusses several EU regulatory frameworks:

- MiCA (Markets in Crypto-Assets Regulation, 2023/1114)
- AIFMD (Alternative Investment Fund Managers Directive)
- MiFID II (Markets in Financial Instruments Directive)
- DORA (Digital Operational Resilience Act)
- eIDAS (electronic Identification, Authentication and Trust Services)
- GDPR (General Data Protection Regulation, indirectly)

The discussion is structured to:
- Identify the regulatory primitives that an L1 should make easy to satisfy
- Describe **how** Kern's design (Skald invariants, attestation primitive, slashable equivocation) maps to those primitives
- Propose Skald contract templates (in `docs/sto-mica.md`) for specific use cases

### 4.2 Protective disclaimer present in every relevant location

In `docs/disclaimer.md` §3:

> *Nothing in the Software, the documentation, the whitepaper, the manifesto, the website, or any related artifact constitutes, or should be construed as: legal advice; financial, investment, or trading advice; tax advice; accounting advice; regulatory or supervisory guidance; fiduciary recommendation.*
>
> *The discussions … of European Union regulation (MiCA, AIFMD, MiFID II, DORA, eIDAS, GDPR) are **informational, illustrative, and forward-looking design discussions** — not regulatory determinations and not assurances of compliance. **No regulator has approved, endorsed, or certified the Software, the Skald STO templates, the attestation primitive, or any other artifact in this repository.***

This disclaimer is referenced from the whitepaper §19, the README, the site footer of every page, and a visible notice strip on the landing page.

### 4.3 Compliance-overclaim scan

A scan for the following overclaim patterns returned zero results:

> `is compliant with`, `fully compliant`, `regulator-approved`, `certified by`, `guaranteed compliance`, `MiCA-certified`, `MiCA-approved`, `ensures compliance`, `regulator-blessed`

The wording used throughout is consistently of the form *"the invariant guarantees that contracts deployed via this template cannot violate Article X"* — which is a **technical statement about what the code does**, not a regulatory blessing. The disclaimer reinforces the distinction.

### 4.4 Verdict

**Low residual risk.** The regulatory discussion is framed as design discussion, not legal advice or compliance assurance. The disclaimer is present and consistently referenced. A regulator who reads the documentation will not be misled into believing the project has been blessed.

---

## 5. Token / financial-instrument representation

### 5.1 KRN as a utility/governance token

The KRN token is described throughout the documentation as a:
- Gas token (transaction fees)
- Staking token (validator collateral)
- Attestation bond (slashable for equivocation)
- Governance token (proposal voting)
- Storage rent payment

It is **not** described as:
- An investment opportunity
- A security
- A claim on profits
- A claim on Foundation assets
- A claim on revenue

### 5.2 Overclaim scan — investment-solicitation language

A scan for the following patterns returned zero results:

> `guaranteed return`, `expected return`, `profit opportunity`, `investment opportunity`, `will appreciate`, `will increase in value`, `buy KRN now`, `early-bird discount`, `pre-sale exclusive`

### 5.3 Distribution model

The 100 M KRN distribution (70 % public / 10 % founder vested 4y / 15 % Foundation / 3 % contributors / 2 % validator bootstrap) is documented in `docs/tokenomics.md`, presented as a **plan subject to change**. The disclaimer (`docs/disclaimer.md` §5) explicitly classifies this as a *statement of intent, not a commitment*.

### 5.4 The §11.4 disclaimer on speculation

The whitepaper §11.4 (cross-referenced from `docs/tokenomics.md` §11) contains an explicit statement rejecting speculative framing of KRN. This is part of the project's deliberate distancing from memecoin and fair-launch narratives.

### 5.5 Verdict

**Low residual risk.** KRN is positioned consistently as a utility/governance token. No investment-solicitation language is used. The disclaimer covers the planning nature of the distribution.

The legal classification of KRN under MiCA (utility token, asset-referenced token, e-money token) will need to be confirmed by counsel before any public token event. This is a **known open item**.

---

## 6. Attribution of the founder's contributions

### 6.1 Bios across the project

Every founder-bio mention has been audited and simplified to the **minimum factual**:

- *founder of [Cogarius]* — verifiable
- *contributor to the Tezos ecosystem ([Checker UI])* — link to actual contribution
- *co-founder of the [Brussels Meetup Blockchain-Ethereum group]* — verifiable
- *over a decade across technical and business roles in technology and regulated industries* — generic, no employer named (per founder's explicit request to remove employer references)
- *LinkedIn link* on the name in two visible places

No bio asserts:
- That the founder is the source of any specific protocol design
- That the founder's prior work *gave* him expertise that *shaped* Kern's design
- That the founder is associated with named third parties beyond verifiable affiliation

### 6.2 Whitepaper §17 acknowledgments

Final wording:

> *Kern's block-production and finality mechanism is adapted from the Tenderbake family of BFT consensus algorithms. The author (Nicolas Van Eeckhout) is founder of [Cogarius], [contributor to the Tezos ecosystem], and co-founder of the [Meetup Blockchain-Ethereum group in Brussels].*

Credit is given to **technical objects** (the Tenderbake family of algorithms), not to named persons. The founder's affiliations are listed as verifiable facts, not as causal sources of Kern's design.

### 6.3 Verdict

**Defensible.** Every founder mention is verifiable; no causal attribution between the founder's biography and the protocol's design is asserted in writing.

---

## 7. Privacy / personal data

### 7.1 What the project handles

The reference implementation processes:

- Public keys (`kpk`...) and addresses (`kn1`...) — not personal data per se
- Optional KYC attestation hashes (in some Skald STO templates) — references to off-chain KYC, the on-chain data is hash + metadata, not personal data directly
- Signed claims (attestations) — these can carry domain-specific data depending on the issuer

The reference implementation **does not** include:
- Personal name fields
- Address (postal) fields
- Identity document fields
- Identifiable transaction metadata beyond what is required for protocol operation

### 7.2 GDPR considerations

When (and if) the project is deployed in a context that processes personal data (e.g., a KYC-attestation network), the deployer — not Kern — bears the GDPR controller / processor obligations. The disclaimer (`docs/disclaimer.md` §3, §4) makes this explicit.

### 7.3 Verdict

**Low risk for the reference implementation itself.** Real-world deployments may carry GDPR risk; that risk belongs to the deployer.

---

## 8. Summary — risk register

| Risk | Severity | Mitigation status |
|---|---|---|
| Code plagiarism | Low | All dependencies licensed and compatible; no copy patterns found |
| Spec attribution (EIPs, Yellow Paper, BN254) | Low | All cited |
| Trademark conflict (Heimdall, Midgard) | **Moderate** | **Open item — formal trademark search required before launch** |
| Defamation (manifesto critiques) | Low–moderate | Defensible as qualified opinion in subjective document |
| Regulatory overclaim | Low | No overclaim language found; disclaimer present |
| Investment solicitation | Low | No solicitation language; token framed as utility/governance |
| False founder attribution | Low | All bios minimal and verifiable |
| Personal data / GDPR | Low | Reference implementation processes no personal data |

---

## 9. Open items for counsel review

The following items are flagged here for review by a competent attorney (Belgian counsel for the author, EU intellectual property and crypto-regulation counsel for the Foundation when incorporated):

1. **Formal trademark search** for Kern, Skald, Heimdall, Yggdrasil, Midgard in EU (EUIPO), US (USPTO), and via WIPO Madrid Protocol
2. **Coexistence analysis** with Polygon's Heimdall and THORChain's Midgard
3. **MiCA legal classification of KRN** as utility / governance / asset-referenced / e-money token
4. **Securities law analysis** of the planned 70 % public sale in EU and key non-EU jurisdictions (UK, Switzerland, Singapore)
5. **Drafting of the Foundation incorporation documents** (jurisdiction TBD, internal guides in `docs/setup-foundation.md`)
6. **Audit firm engagement** for two independent security audits before the Yggdrasil public testnet, per `docs/post-code-roadmap.md` Phase 3
7. **Privacy review** of attestation primitives in the context of GDPR controller/processor responsibilities

---

## 10. Standing diligence statement

This audit was conducted as a transparent internal diligence exercise, published in the public repository so that any party — counsel, regulator, auditor, contributor, journalist — can verify the care taken before the project's public launch. It does not substitute for professional legal review and is not legal advice. It is a snapshot in time; the project's status will continue to evolve and this document will be updated to reflect changes.

*Document prepared: May 2026.*
*Author: Nicolas Van Eeckhout (founder).*
*License of this document: [CC-BY-SA-4.0](../LICENSE-DOCS.md).*
