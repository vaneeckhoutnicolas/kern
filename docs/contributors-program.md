# Contributors Program

This document describes how Kern compensates contributors — code, security, documentation, ecosystem — beyond the standard transaction fees paid by network use.

The big picture: there are **three distinct channels** that pay contributors, each appropriate for a different phase and a different kind of work.

| Channel | Source | Volume (Year 1) | Decision-maker | For what kind of work |
|---|---|---|---|---|
| **Genesis contributor pool** | Genesis 3% allocation (3M KRN) | Up to 3M KRN total | Foundation | Pre-mainnet contributions |
| **Foundation grants** | Foundation 15% pool (15M KRN) | ~1-2M KRN/year typical | Foundation board | Strategic / operational |
| **Treasury grants** | On-chain treasury (5% of block rewards) | Grows from 0 toward ~50K KRN/year | On-chain vote (50%+1) | Ecosystem / public goods |

There is also a future fourth channel — **Retroactive Public Goods Funding (RPGF)** — planned for Year 2 onward, drawing from the on-chain treasury via a quarterly vote with weighted ballots.

---

## 1. Genesis contributor pool (3M KRN)

The 3% genesis allocation reserved for early contributors is the single largest channel for contributor compensation in Year 1, because the on-chain treasury starts empty.

### Who qualifies as an early contributor

Anyone who, **before mainnet launch**, contributed work that materially advanced the project. Examples:

- Significant code contributions (features, infrastructure, tooling) to the reference implementation
- Substantive audit work (paid security audits are separately compensated through the Foundation; what this covers is volunteer security review beyond that)
- Documentation work (specification, whitepaper, formal models)
- Skald applications that bootstrap the ecosystem
- Validator software (alternative client implementations, in other languages)
- Wallets, explorers, and tooling that bridge users to the protocol (including extensions to **Heimdall** — Sessions 2-4 of the Heimdall delivery plan are open contribution areas; see [setup-heimdall-operator.md](setup-heimdall-operator.md))

### Allocation process

Allocations are decided by the **Foundation** in consultation with the founder and any other recognized contributors. The process:

1. **Contribution log**: a public on-chain registry (or, until that's built, a public GitHub doc) of recognized contributions and their attribution.
2. **Allocation proposals**: the Foundation publishes individual proposals: "X mukrn to address Y for contribution Z, vesting 3 years with 6-month cliff."
3. **Public comment period**: 14 days for community feedback on each proposal.
4. **Foundation signoff and execution**: the Foundation multisig releases the KRN from the contributor pool address to the recipient (cliff-and-vest enforced off-chain by holding the locked KRN in the Foundation multisig).

### Vesting

Each individual grant from the pool vests **linearly over 3 years with a 6-month cliff**. This is shorter than the founder's 4-year vest because individual contributions are typically more discrete in time (a feature shipped, an audit completed) than the founder's open-ended responsibility.

### What you don't get

- **Forward contracts.** You can't claim future contributions in advance. Allocations are retroactive — for work already delivered or in delivery.
- **Disproportionate weight.** No single contributor (other than the founder) should hold > 0.5% of supply from this pool. If your contribution merits more, it goes through Foundation grants or treasury grants instead.
- **Pseudonymous lump-sum.** Recipients need a verifiable identity (real or stable pseudonym with consistent track record). Anonymous large grants invite optics problems.

---

## 2. Foundation grants (15M KRN pool)

The 15% Foundation pool is meant primarily for **operational** spending: paying auditors, infrastructure providers, the legal entity itself, and any future core-team employees. But it can also disburse grants to contributors when the work is strategic enough to warrant Foundation-level prioritization.

### What Foundation grants typically pay for

- **Audits.** Trail of Bits, OtterSec, Hashlock, Runtime Verification — these firms cost $50-300K per engagement. The Foundation contracts and pays.
- **Core development hires.** If/when the Foundation hires a full-time developer, security engineer, or product lead.
- **Strategic partnerships.** L1 integrations (e.g., a wallet partnership), bridges to other chains, exchange listings.
- **Bug bounties.** Critical vulnerability rewards. Tier 1 (consensus-level) bounties can reach 5-10% of the total Foundation pool for severe findings.
- **Public-facing legal and compliance.** Trademarks, KYC/AML for any partners that require it.

### Process

The Foundation operates per its bylaws (set up as part of the v1.0-rc Foundation incorporation milestone). Standard practice:

- **Board approval** for expenditures > 100 000 KRN.
- **Multisig execution** (e.g., 3-of-5 multisig of Foundation board members).
- **Quarterly public reporting** of expenditures.
- **Annual external audit** of Foundation finances.

### Why this is separate from on-chain treasury

The on-chain treasury (next section) is voted by stake-holders. That's great for community-aligned decisions, but inappropriate for hiring decisions, audit contracts, or anything requiring legal accountability or confidentiality. The Foundation handles those — same model as Ethereum Foundation, Tezos Foundation, Cosmos Stiftung.

---

## 3. On-chain treasury grants

The on-chain treasury grows continuously from issuance: 5% of every block reward flows in, in mukrn. It funds **community-governed** projects that should be visible and accountable.

### Mechanics

The on-chain treasury is implemented as a Skald contract (see [`governance.md`](governance.md) §"Treasury cycle"). Proposals follow a 2-phase cycle:

1. **Submission** (14 days): anyone can submit a proposal; submitter posts a 10 KRN bond.
2. **Vote** (7 days): stake-weighted vote with 50% majority + 25% quorum.
3. **Execution**: on success, the treasury contract releases funds to the proposed recipients.

### What treasury grants typically pay for

- **Ecosystem projects**: developer tooling, libraries, indexers, alternative clients.
- **Education**: tutorials, video courses, translation of docs.
- **Conferences and events**: meetups, hackathons, sponsorship of relevant gatherings.
- **Open-source applications**: novel Skald applications that benefit the network.
- **Research**: ongoing research into protocol improvements (e.g., better consensus, better Skald features).

### Year 1 expectations

The treasury starts at 0 KRN at mainnet launch and grows from issuance. Rough math: with 100M total supply and ~3% annual issuance giving ~3M new KRN/year, of which 5% goes to treasury = 150 000 KRN/year of inflow. By year 1's end, the treasury has accumulated ~150K KRN — enough to fund 5-15 modest grants.

This is intentionally modest in Year 1. Larger ecosystem investments come from Foundation grants until the treasury matures.

---

## 4. Retroactive Public Goods Funding (RPGF) — planned for Year 2+

The Optimism collective pioneered **Retroactive Public Goods Funding**: every ~6 months, an enveloped batch of public-goods contributions is funded based on *impact already delivered*, not promises for future work. The selection is made by a panel of "badge-holders" with weighted votes.

RPGF is planned for Kern starting Year 2:

- **Enveloppe** : a fixed share of treasury reserves, suggested 25-50% per quarter
- **Badge-holders** : initially the Foundation board; expanded over time to include recognized ecosystem contributors
- **Voting** : quadratic-with-stake-weighted (the same mechanism already implemented in the treasury cycle)
- **Eligibility** : only retrospectively — projects shipped 6-24 months before the funding round
- **Public review** : selections published with rationale; appeals window of 14 days

Why Year 2 and not Year 1: RPGF needs (a) enough treasury to fund a meaningful round, and (b) a track record of shipped work to evaluate. Year 1 is too early for both.

When RPGF goes live, an existing Skald contract template will codify the rules. Until then, the treasury is the default mechanism for community-funded ecosystem work.

---

## 5. Transaction fees: the always-on baseline

In addition to all the above, every contributor who runs a validator earns transaction fees and block rewards proportional to their effective stake. This is the always-on baseline that doesn't require any program, application, or vote.

For a contributor who is *also* a validator (running infrastructure as part of their contribution), the math:

- Block reward earned by their validator ÷ 1000 (rough share assuming 1000 validators eventually)
- Commission from delegators (default 10% of delegator rewards)
- Transaction fees from included txs

For a small validator with ~1% of total stake, this works out to roughly 0.25-2.7% annual yield on their stake plus some delegator commission — modest, but it scales with network use and with their growing delegator base.

---

## 6. What incentives this structure creates

The deliberate design:

- **Pre-mainnet contributors are paid from genesis** (3% pool) — they bear the highest risk (no network exists yet), they get the most concentrated allocation.
- **Operational and strategic work is paid by Foundation** — accountable, multisig-controlled, off-chain, with legal continuity.
- **Ecosystem and public-goods work is paid by on-chain treasury** — community-governed, transparent, on-chain auditable.
- **Validators are paid by network use** — the more activity, the more they earn; aligns infrastructure quality with network success.

This is the same multi-channel structure most successful L1s have converged on. Kern's contribution is to wire it cleanly with on-chain primitives (the treasury cycle is a Skald contract, the slashing-for-equivocation is a transaction kind, the delegation is permissionless) rather than to reinvent the financial logic.

---

## Reference

- Genesis distribution: [`tokenomics.md`](tokenomics.md) §4
- Treasury cycle implementation: [`governance.md`](governance.md)
- Staking and delegation: [`staking.md`](staking.md)
- Code: [`kern/governance.py`](../kern/governance.py) (treasury state machine)
