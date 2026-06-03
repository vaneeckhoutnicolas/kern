# Disclaimer

*This document is a standing notice from the author of the Kern reference implementation. It is referenced from the README, the whitepaper, the site footer, and the setup guides. By using, deploying, contracting on, or otherwise interacting with the Kern reference implementation or its derived artifacts, you acknowledge that you have read and understood the terms below.*

---

## 1. No warranty

The Kern reference implementation, the Skald contract language, the Heimdall explorer, the documentation, the whitepaper, and all related artifacts published under the `vaneeckhoutnicolas/kern` repository (collectively, the **"Software"**) are provided **"AS IS," without warranty of any kind**, express or implied, including without limitation any warranty of merchantability, fitness for a particular purpose, non-infringement, accuracy, reliability, security, regulatory compliance, or absence of defects.

This restates the warranty disclaimer in section 7 (Disclaimer of Warranty) of the Apache License, Version 2.0, under which the reference implementation is published. It is restated here in plain language to ensure no user can claim not to have seen it.

## 2. No liability of the author

To the maximum extent permitted by applicable law, **Nicolas Van Eeckhout (the author, the founder) and any contributor to the Kern project shall not be held liable** for any direct, indirect, incidental, special, exemplary, consequential, or punitive damages — including but not limited to loss of profits, loss of revenue, loss of data, loss of goodwill, business interruption, regulatory penalties, fines from supervisory authorities, third-party claims, or any other commercial or financial damages — arising from or in connection with:

- the use, misuse, modification, or inability to use the Software;
- any deployment of the Software, in test or production environments, on public or private networks;
- any smart contract, financial instrument, security token offering (STO), oracle network, public-goods round, attestation registry, or other application built on or interacting with the Software;
- any decision taken on the basis of information in the documentation or the whitepaper;
- any reliance on the Software for regulatory, legal, accounting, fiduciary, or compliance purposes;
- any third-party fork, derivative, modification, port, or service that incorporates or extends the Software;
- any loss, theft, slashing, freezing, or destruction of value (KRN, mukrn, other tokens, fiat-pegged claims, attestations) on any network running the Software or its derivatives.

This limitation of liability applies regardless of the form of action — contract, tort (including negligence), strict liability, or otherwise — and applies even if the author has been advised of the possibility of such damages.

## 3. No professional advice

Nothing in the Software, the documentation, the whitepaper, the manifesto, the website, or any related artifact constitutes, or should be construed as:

- legal advice;
- financial, investment, or trading advice;
- tax advice;
- accounting advice;
- regulatory or supervisory guidance;
- fiduciary recommendation.

The discussions in `docs/sto-mica.md`, `docs/oracle-network.md`, `docs/public-goods-funding.md`, `docs/setup-foundation.md`, the [whitepaper](whitepaper.md), and elsewhere of European Union regulation (MiCA, AIFMD, MiFID II, DORA, eIDAS, GDPR) are **informational, illustrative, and forward-looking design discussions** — not regulatory determinations and not assurances of compliance. **No regulator has approved, endorsed, or certified the Software, the Skald STO templates, the attestation primitive, or any other artifact in this repository.** Any party intending to deploy the Software in a regulated context must engage their own licensed legal counsel, compliance officer, auditor, and competent national supervisory authority (FSMA, AMF, BaFin, CSSF, Finantsinspektsioon, etc.) before relying on any property described here.

## 4. No endorsement of deployments

The author is **not responsible for**, has **no operational control over**, and **does not endorse** any:

- third-party network running the Kern reference implementation or any fork thereof;
- third-party smart contract, application, or service deployed on any such network;
- third-party representation about the Software, its properties, its security, its compliance, its value, or its future;
- token sale, public offering, private placement, airdrop, listing, derivative, wrapped asset, or any other financial product purporting to be associated with the Kern protocol or its native token (KRN).

The Kern Foundation, when incorporated (per [setup-foundation.md](setup-foundation.md)), will be the only entity authorised to represent the Kern protocol institutionally. Until the Foundation is incorporated, the author makes no representations of any kind on behalf of any third party.

## 5. No financial promise

The KRN token, the mukrn unit, the planned token distribution (documented in [tokenomics.md](tokenomics.md)), and the planned roadmap toward the Midgard mainnet (documented in [roadmap.md](roadmap.md) and [post-code-roadmap.md](post-code-roadmap.md)) are **statements of intent**, not commitments. They are subject to change without notice based on:

- security audit findings;
- regulatory developments and dialogue with supervisory authorities;
- legal counsel guidance;
- technical feasibility;
- the author's continuing time, capacity, and judgement.

**No party should acquire, transact in, or take a financial position based on the expectation that any of the planned milestones will occur, on any specific timeline, at any specific price, or with any specific outcome.** See the [whitepaper §11.4](whitepaper.md#114-on-speculation-memecoins-and-fair-launch-mythology) and [tokenomics.md §11](tokenomics.md) for the project's explicit position on speculation.

## 6. No security guarantee

The reference implementation, while internally tested (692 tests passing as of this writing, including property-based fuzzing) and internally reviewed, **has not yet undergone an independent professional security audit**. Two independent audits are a gating item before the Yggdrasil public testnet, and the audit cycle is documented in [post-code-roadmap.md](post-code-roadmap.md) Phase 3 and [setup-auditor.md](setup-auditor.md). Until those audits are complete and their findings remediated, the reference implementation **must be treated as pre-audit software** unsuitable for production deployment with material value at stake.

Even after the planned audits, the Software is published under Apache-2.0's "as is" terms; no audit removes that. Bugs may exist; consensus may stall; contracts may fail; data may be lost. Run the Software at your own risk.

## 7. No agency or partnership

Use of the Software, contribution to the repository, deployment of a node, operation of an explorer instance, deployment of a Skald contract, or any other interaction with the Kern protocol does **not** create:

- an agency relationship;
- a partnership;
- a joint venture;
- a fiduciary duty;
- an employment relationship;
- any contractual relationship beyond the terms of the licence (Apache-2.0 for code, CC-BY-SA-4.0 for documentation and whitepaper);

between the user and the author, or between the user and any contributor, or between the user and the Kern Foundation (when incorporated).

## 8. Jurisdiction and governing terms

The licence terms (Apache-2.0 for code, CC-BY-SA-4.0 for documentation) govern any dispute relating to the Software. The author is based in Belgium. **Any non-licence dispute** relating to the Software, the protocol, or the author's statements will be subject to the jurisdiction of the courts competent over the author's place of residence at the time the dispute arises, except where mandatory consumer-protection or competition law of the user's home jurisdiction provides otherwise.

Belgian moral rights (Code of Economic Law, Article XI.165) protect the author's attribution and the integrity of the work; nothing in this disclaimer waives those rights.

## 9. Third-party trademarks and fair use

The Software, the documentation, the whitepaper, and the public website contain references to other blockchain projects (Bitcoin, Ethereum, Tezos, Solana, Cosmos, Polkadot, Cardano, Chainlink, Pyth, MakerDAO, THORChain, Polygon, and others). These names are the trademarks of their respective owners and are used in this project under the **nominative fair use** doctrine (US) and the **comparative reference** doctrine (EU) — that is, to identify those projects as the subjects of factual comparison or as named examples in a category. No endorsement, sponsorship, partnership, or affiliation with any of those projects is asserted, implied, or intended. No logo, trade dress, or visual mark of any third party is reproduced.

The names "Kern," "Skald," "Heimdall," "Yggdrasil," and "Midgard" are reserved as marks of authenticity by the Kern project. See [`docs/originality-and-attribution.md`](originality-and-attribution.md) for the project's position on naming and forks.

A standing legal audit covering plagiarism, attribution, trademark, defamation, regulatory representation, and overclaim risks is published at [`docs/legal-audit.md`](legal-audit.md).

---

## 10. Effect of this notice

This disclaimer is part of the Software's documentation. It is incorporated by reference into every page of the public website (`kern_site/`), into the README of the repository, into the whitepaper, into every setup guide, and (via SPDX-License-Identifier headers) into every source file. **By using, copying, modifying, distributing, deploying, or otherwise interacting with the Software, you accept this disclaimer.** If you do not accept it, do not use the Software.

This notice may be amended by the author or, after incorporation, by the Kern Foundation. The version in effect at the time of any given use is the version in the `main` branch of the repository.

---

*Last updated: May 2026. Original author: Nicolas Van Eeckhout (founder).*
*License of this notice: [CC-BY-SA-4.0](../LICENSE-DOCS.md).*
