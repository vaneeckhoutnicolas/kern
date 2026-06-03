# Manifesto

*A statement of conviction, written by Nicolas Van Eeckhout, founder.*
*Version 1, May 2026. License: CC-BY-SA-4.0.*

---

## I.

I am building Kern because I believe **the next decade of blockchain adoption will not be won by the protocol that maximises transactions per second**.

It will be won by the protocol that institutions can adopt without lying to their regulators, their auditors, or the people they are accountable to.

That requires a different kind of L1. One that treats EU regulation — MiCA, AIFMD, MiFID II, DORA — not as obstacles to be circumvented, but as specifications to be encoded.

That protocol does not yet exist. Kern is my attempt to build it.

---

## II. What the current Layer-1s get wrong

I have spent the last ten years close to this field.

Co-founder of the [Meetup Blockchain-Ethereum group in Brussels](https://www.meetup.com/meetup-blockchain-ethereum-bruxelles/). [Contributor to the Tezos ecosystem](https://github.com/tezos-checker/checker-ui). Founder of [Cogarius](https://www.cogarius.com). I have watched institutions try to adopt this technology, and I have watched almost all of them either give up or wrap it in so many compliance layers that the technology becomes invisible.

Here is what I have observed:

- **Ethereum** is brilliant engineering. It is also a regulatory mismatch for any serious institution outside a few sandboxed pilots. The L1 enforces no semantics that a regulator can read; Solidity contracts hide their assumptions; the audit perimeter is custom and expensive every single time. The institutional response is to wrap everything in permissioned overlays, which defeats the point.

- **Tezos** has the right governance instinct — on-chain amendments, no hard forks, Liquid PoS that preserves custody. But it never closed the institutional gap with first-class compliance primitives at the protocol layer.

- **Solana** optimises for throughput and developer growth. Neither is what matters when an institution is asked to demonstrate to a regulator that an STO continuously satisfies Prospectus Regulation Art. 3.

- **Cosmos / Polkadot / others** offer modularity — fine engineering for protocol designers, opaque for institutions.

The pattern: every existing L1 forces institutions to choose between *not adopting* the protocol or *adopting it badly* (with so many compliance wrappers that the protocol itself becomes a footnote).

I want a third option.

---

## III. The thesis

The third option is what I call **institutional legibility**.

It means: the rules that an institution must follow — whether regulatory, procedural, or evidentiary — are encoded as protocol-enforced invariants that regulators, auditors, and counterparties can read directly, without trusting any intermediary.

When an STO contract is deployed on Kern, the regulator does not need to wait for an annual audit report. They open the explorer. They read the invariants. They see the compliance state, live.

When an oracle posts a value on Kern, that posting carries a slashable bond. If the oracle equivocates, anyone can submit evidence and earn 10% of the slashed amount. The reliability of the data is not a vendor promise; it is a cryptoeconomic property.

When a public goods round runs on Kern, the matching formula is explicit on-chain — not a committee's discretion translated into an opaque grant decision.

Institutional legibility is the property that makes Kern usable where other L1s are not. Everything else — consensus, language, governance — supports this thesis.

---

## IV. Five commitments

I commit to the following, as the founder and as a signature on this manifesto :

**1. The protocol stays narrow.** The L1 does one thing well: provide deterministic finality, verifiable execution, and the smallest possible set of primitives that institutions need. Application complexity belongs in Skald contracts, in rollups, or off-chain. I will resist every pressure to bloat the base layer.

**2. The language is small.** Skald has runtime-enforced invariants, a static type system, and a deliberately limited surface. A small language is one that auditors and regulators can actually read. A large language is one where compliance becomes an act of faith.

**3. Governance is on-chain, not off-chain.** Decisions about Kern — including consensus parameters, gas costs, even Skald itself — go through on-chain governance with equivocation slashing. No hard forks. No founder veto. The protocol can outlive me.

**4. The reference implementation is open source.** Forever. Apache-2.0, no asterisks, no rug-pulls. The Foundation may build proprietary tools on top; the L1 itself is everyone's.

**5. I will not pretend.** Where Kern has limits, I will document them. Where the audit is not done, I will say so. Where the Foundation is forming, I will not write press releases about a Foundation that does not yet exist. The reference implementation is the spec; the documentation is honest; the roadmap acknowledges what is and is not in scope. There will be no marketing fluff.

---

## V. What I refuse

A manifesto is also a refusal. Here is what Kern will not become :

- **Kern is not a memecoin platform.** The 70/10/15/3/2 KRN distribution is designed for institutional bootstrap, not for speculation. There is no "fair launch" theatre. There is no aggressive marketing schedule.

- **Kern is not Ethereum with extra steps.** EVM compatibility exists through optimistic rollups, where it belongs. The L1 is its own design, in its own language, with its own values. Solidity has a home on Kern; it does not get to dictate Kern.

- **Kern is not a private chain wearing a public chain costume.** Validators are open. Governance is on-chain. The KRN allocation is documented. Foundation operations are auditable. If you want a permissioned chain, use Hyperledger.

- **Kern is not a "compliance product" sold to institutions.** It is an open protocol whose properties happen to be what institutions need. The distinction matters. The protocol is owned by no one. The Foundation is its steward, not its proprietor.

- **Kern is not in a hurry.** The roadmap to Midgard mainnet is 12-18 months. Two professional security audits, a public testnet (Yggdrasil), regulatory dialogue. I would rather launch one year late than launch with one vulnerability.

---

## VI. Why this is built from Europe

Kern is built from Brussels, for the European Union's regulatory map, and that is deliberate.

Europe has done the hard work that the rest of the world has not :

- MiCA (Markets in Crypto-Assets, 2024) is the world's most coherent crypto framework.
- AIFMD governs institutional fund structures with rigour the US has never approached.
- MiFID II and DORA structure how financial services and digital operations interact with technology.
- The eIDAS framework, e-Residency, and the European Digital Identity Wallet provide the identity infrastructure that on-chain attestations need.

These frameworks are an asset, not a liability. They constitute the **specification** for what an institutionally-usable blockchain must look like. The protocol that takes them seriously gets to be the default for the European institutional market.

The reference implementation, the Skald templates, and the explorer are all built with European institutional adoption as the primary use case.

This is not a bet against the rest of the world. It is a bet that the rest of the world will, eventually, build the equivalent frameworks — and that protocols designed for them will travel.

---

## VII. The personal note

I have a day job in technology. I have no foundation behind me, no token sale, no team, no mandate. By any reasonable measure, I am exactly the wrong person to ship a Layer-1.

What I have is not certainty — it is a long view from the side of the room. Over the years I have watched many institutional pilots fail, almost never for reasons that were really about the technology, and almost always because of the gap between what the technology offered and what a regulator or an auditor could actually verify. I don't claim to have the answer. I think I have come to understand the question, and I wanted to set it down properly at least once.

So I built Kern in evenings and weekends, slowly, with the discipline of someone who has shipped institutional software before. The reference implementation is real Python — tested, documented, originated under my own authorship. The whitepaper is the design document. This manifesto is the conviction.

I'll be honest about what this is, for me. It is, in part, a door closing — the blockchain chapter of my own work — and an attempt to close it on something finished rather than something left half-built. One last try at finding out whether I had something to give to this community, something larger than myself. I'm not asking anyone's permission, and I'm not claiming Kern is the answer. I'm offering it, in good faith, to the people still trying to build a chain that institutions can genuinely read and trust. If it helps even a few of them, the evenings were worth it; and if it doesn't, then at least it was built once, carefully, and left for whoever comes next.

And if you recognize yourself in any of this — whether you're one person building on evenings like me, or an organization that has watched its own pilots stall in that same gap between what the technology promised and what it could actually prove — then make yourself known. Reach out, build on it, challenge it, carry it further. You'll find me on [LinkedIn](https://www.linkedin.com/in/vaneeckhout/). Kern was never meant to stay one person's project; if it's going to live, it will be because others — individuals and organizations alike — choose to make it theirs too.

---

## VIII. An invitation

If this manifesto reads true to you, there are three things you can do.

**If you are an engineer** — read the [whitepaper](whitepaper.md), read the [reference implementation](https://github.com/vaneeckhoutnicolas/kern), open the [setup guides](setup-guides.md). Tell me what is wrong with the design. Critical feedback at this stage is more valuable than any other contribution.

**If you are an institution or organization** — a fund, an STO issuer, an oracle network operator, a foundation considering on-chain grant-making, a telco settling cross-border with EU peers, or any other organization that needs infrastructure it can actually account for — the Kern verticals exist for you. The Skald templates ship audited and ready. Reach out before you build a custom Solidity contract; reach out before you give up on this technology entirely.

**If you are a regulator, auditor, or compliance counsel** — the [STO compliance spec](sto-mica.md) and the [Heimdall explorer](setup-heimdall-operator.md) are written for you. Read them, push back where they oversimplify, tell me what they would need to be useful in your workflow.

Subscribe to the updates at [kern.protocol](https://kern.protocol). Watch the [GitHub repository](https://github.com/vaneeckhoutnicolas/kern). Join the conversation when it opens.

---

*— Nicolas Van Eeckhout*
*Founder, [Cogarius](https://www.cogarius.com) · [Tezos ecosystem contributor](https://github.com/tezos-checker/checker-ui) · Co-founder, [Brussels Meetup Blockchain-Ethereum](https://www.meetup.com/meetup-blockchain-ethereum-bruxelles/)*
*Brussels, May 2026*

---

*This manifesto is published under CC-BY-SA-4.0. You may share, adapt, and translate it provided you credit the author and preserve the licence.*
