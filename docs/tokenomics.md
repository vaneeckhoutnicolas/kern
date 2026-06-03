# KRN — Token Economy

This document specifies the KRN token: its role, supply curve, distribution, sinks, and the adaptive-issuance formula that governs ongoing emission.

---

## 1. Why a native token?

A blockchain only needs a native token if four conditions are met:

1. **There is a scarce resource that must be metered.** Block space and state storage are scarce. Without a fee market in a native unit, the chain has no defense against spam or state bloat.
2. **There is a security budget that must be funded.** Validators must be paid enough that attacking the chain is more expensive than securing it. That payment must be in something with a market value tied to the chain's success.
3. **There is a governance mechanism that needs weighted voting.** "One person, one vote" is fragile against Sybils on-chain. Stake-weighted voting requires a stake unit.
4. **There is a coordination problem only an aligned token solves.** Validators, delegators, application developers, and end-users have aligned incentives if they share exposure to the same asset.

Kern satisfies all four. KRN is therefore not a marketing token; it is a protocol primitive.

## 2. Roles of KRN

| Role               | Mechanism                                                                                  |
|--------------------|--------------------------------------------------------------------------------------------|
| Transaction fees   | Every operation pays a fee in mukrn (10⁻⁶ KRN) to the producing baker.                      |
| Staking collateral | Validators stake KRN to be eligible to bake. Delegators delegate KRN without transferring custody. |
| Governance weight  | On-chain votes are weighted by active stake (own + delegated).                             |
| Storage rent       | Originating a contract requires a KRN deposit proportional to declared storage size; growing storage consumes additional KRN. |
| Treasury funding   | A fraction of every block reward (5% default) flows into the on-chain treasury.            |
| Slashing penalty   | Double-baking and double-endorsing destroy a portion of the offender's stake.              |

## 3. Supply

### 3.1 Genesis supply

**100 000 000 KRN** (one hundred million) at genesis.

This is a deliberately bounded number — not 10B (which dilutes price perception) and not 10M (which forces fractional unit-of-account amounts). 100M gives meaningful unit values at every market cap and matches the order of magnitude of Ethereum's own genesis (72M), Avalanche (720M), and Cosmos Hub (236M).

One KRN is divisible into 1 000 000 mukrn (micro-KRN). The internal accounting unit is the mukrn, so balances are integers and there's no floating-point error in supply math.

### 3.2 Emission

Kern uses **adaptive issuance**. Block rewards adjust to the realized staking ratio, with the goal of maintaining ~50% of the total supply staked.

The annualized inflation rate `i` is a function of the staking ratio `r`:

```
i(r) = i_min + (i_max - i_min) * smoothstep(1 - r)
```

with:

- `i_min = 0.0025` (0.25% annualized, when staking ratio is at or above target)
- `i_max = 0.06`   (6% annualized, when staking ratio is near zero)
- `smoothstep(x) = x² * (3 - 2x)` smoothing function so the rate doesn't jump

The block reward at any given moment is the per-block share of that annualized issuance, divided proportionally among the validators who endorsed the block (weighted by stake).

This achieves three properties:

1. When staking participation is low, rewards rise, attracting more stake.
2. When participation is high, rewards fall, reducing dilution of non-stakers.
3. The system self-stabilizes near the 50% target without any manual parameter adjustment.

The parameters `i_min`, `i_max`, and the target ratio are themselves amendable through on-chain governance.

### 3.3 Long-run supply

Under the adaptive issuance regime, KRN supply grows asymptotically but at a decelerating rate. Modeling with a 50% staking ratio steady state and 5% slashing/burn pressure on annual issuance gives a steady-state ~1% net annual inflation in the first decade, falling toward ~0.5% by year 20. The supply is never algorithmically capped; emission is an explicit governance decision.

### 3.4 Supply sinks

Several mechanisms remove KRN from circulation:

- **Storage rent.** A fraction of rent (50% default) is burned rather than going to bakers, creating a direct supply-state-size coupling.
- **Slashing burns.** Half of every slashed deposit is burned; the other half is paid to the reporter.
- **Failed-operation fees.** Transactions that fail (e.g., invariant violations) still pay their declared fee, but in this case 100% of the fee is burned rather than going to the baker — this aligns baker incentives with successful applications.
- **Treasury vesting non-claims.** Treasury grants that are not claimed by their vesting deadline are burned.

Net inflation = gross emission − all sinks. The protocol's design intent is for net inflation to remain low and predictable.

## 4. Distribution at genesis

The genesis distribution follows the Ethereum 2014 template, adjusted for 2026 best practices (vesting on the founder pool was added — Ethereum's lack of it is widely considered with hindsight a structural mistake).

| Category                          | % of supply | Amount (KRN)    | Vesting / unlock                                                 |
|-----------------------------------|------------:|----------------:|------------------------------------------------------------------|
| **Public sale**                   |        70%  |    70 000 000   | Liquid at genesis                                                |
| **Founder (Nicolas Van Eeckhout)** |       10%  |    10 000 000   | 1-year cliff + 4-year linear vest                                |
| **Foundation**                    |        15%  |    15 000 000   | Held by Foundation legal entity; spent only via Foundation governance |
| **Early contributors pool**       |         3%  |     3 000 000   | 6-month cliff + 3-year linear vest, individual grants per recipient |
| **Validator bootstrap pool**      |         2%  |     2 000 000   | Released over 1 year to initial validators                       |

**Total: 100% = 100 000 000 KRN**

### 4.1 Why this distribution

- **Mirror of Ethereum 2014 ratios (70/10/10/+).** Ethereum's ICO put ~83% to public, ~10% to early contributors, ~10% to Foundation. The 2026 adjustment is to add explicit vesting on the founder pool (the modern norm) and to break out a dedicated contributors and validator-bootstrap pool, each at modest percentages.
- **Public majority (70%).** Genesis decentralization is what gives an L1 long-term legitimacy. Without a large liquid public allocation, the chain starts captured.
- **Founder allocation with vesting (10%).** This is the modern standard, and it serves a real purpose: aligning the founder's incentive with long-term protocol health rather than short-term exit liquidity. Without vesting, the founder allocation becomes a sword of Damocles over the price; with it, the founder must build value over 5 years to fully realize their stake.
- **Foundation (15%).** Holds working capital for audits, dev grants, marketing, partnerships, and operational continuity. Spent via Foundation governance (multisig + legal accountability), distinct from the on-chain treasury, which is funded ongoing from issuance.
- **Early contributors pool (3%).** A pool — not individual line items — managed by the Foundation and distributed to people who contributed code, audits, documentation, or other significant work before mainnet. Individual grants vest 3 years with a 6-month cliff. See [`contributors-program.md`](contributors-program.md).
- **Validator bootstrap (2%).** Without seeding initial validators, the chain has a chicken-and-egg problem. This pool funds the first 5-10 validators for one year of operation while staking economics mature.

### 4.2 What's deliberately not in the distribution

- **No team allocation beyond the founder line item.** If/when others join in a "core team" capacity, they are paid from the Foundation pool and the contributors pool, subject to standard vesting. This avoids the visual of insiders self-paying.
- **No "airdrop to existing chain X holders" hack.** Airdrops to existing communities buy short-term attention and create mercenary holders.
- **No marketing allocation as a separate line item.** Marketing is funded through normal Foundation operations and treasury grants.
- **No "advisor" line item.** Advisors are paid from the contributors pool with the same vesting as anyone else.

### 4.3 The on-chain treasury (separate from genesis Foundation)

In addition to the genesis distribution, an on-chain treasury accumulates KRN ongoing from a fraction of every block reward (default 5%). This treasury is fundamentally different from the Foundation pool:

| | Foundation pool (15%) | On-chain treasury |
|---|---|---|
| **Source** | Genesis allocation, one-time | Ongoing — 5% of every block reward |
| **Custody** | Legal entity multisig | Smart contract |
| **Spending** | Foundation governance + legal | On-chain treasury vote (50% majority, 14d propose + 7d vote) |
| **Purpose** | Strategic ops (audits, partnerships) | Ecosystem grants, public goods |
| **Genesis amount** | 15 000 000 KRN | 0 (grows from block 1 onward) |

The Foundation is for things that need legal/operational accountability (signing contracts with auditors, paying employees, building partnerships). The on-chain treasury is for things that should be community-governed (funding application developers, education, public goods).

## 5. Fee market

### 5.1 Fee structure

Every transaction declares:

- `fee` — total fee paid in mukrn (10⁻⁶ KRN).
- `gas_limit` — declared upper bound on gas units consumed.

The protocol charges the declared `fee` regardless of whether the operation succeeds. For successful operations, the fee goes to the baker who included the transaction. For failed operations (invariant violations, contract reverts), the fee is burned.

Suggested minimum fees (subject to governance) are:

| Operation       | Suggested minimum |
|-----------------|-------------------|
| Transfer        | 1 000 mukrn       |
| Origination     | 10 000 mukrn + storage rent |
| Call            | 5 000 mukrn + per-gas-unit |
| Per gas unit    | 0.1 mukrn         |

### 5.2 Storage rent

Originating a contract requires a deposit proportional to the contract's declared storage schema. The default is:

```
storage_rent = base_origination + sum over storage fields of:
    int      → 100 mukrn
    bool     → 50 mukrn
    address  → 200 mukrn
    string   → 10 mukrn * max_length
```

This deposit is held by the protocol for as long as the contract exists. Calling a function that grows the storage (e.g., adding a string longer than the previous value) requires additional rent. The deposit is partially refunded if a contract reduces its storage footprint (the "decompression" refund).

50% of paid rent goes to the baker who included the origination/call; 50% is burned. This burning is a key supply sink and ties the KRN supply to actual on-chain state usage.

## 6. Staking and delegation

Kern uses **Liquid Proof-of-Stake**, the Tezos design: balances stay liquid and in the holder's custody, but can be delegated to a validator who counts them toward their effective stake. This is the opposite of Ethereum's 32-ETH-locked model, and the opposite of pool-based LSTs (liquid staking derivatives like Lido's stETH) — there is no derivative token, no smart-contract counterparty risk, and no minimum deposit.

For a complete reference see [`staking.md`](staking.md). The summary:

### 6.1 Becoming a validator (baking)

Any account holding ≥ 10 000 KRN may register as a validator. Registration consists of:

1. Calling the protocol's `register_validator` operation with a stake amount.
2. Maintaining a node that participates in consensus rounds (proposal + endorsement).

A validator who voluntarily exits is subject to a 14-day unbonding period before staked funds become transferable again.

### 6.2 Delegation (Liquid PoS baking delegation)

Any account holding any KRN may delegate it to an active validator using the `DELEGATE_STAKE` transaction. The delegation has the following Liquid PoS properties:

- **Custody stays with the delegator.** No KRN is transferred, no LST token is minted. The delegator's balance remains spendable at any time.
- **No lockup.** Delegation can be changed (`DELEGATE_STAKE` to a different validator) or removed (`UNDELEGATE_STAKE`) at any time, no waiting period.
- **No minimum.** Even 1 mukrn can be delegated. This is the main user-experience difference vs Ethereum's 32-ETH minimum.
- **One validator at a time.** Each delegator picks one validator. To split, the delegator splits balances across multiple addresses.
- **Effective stake = own stake + sum of delegated balances.** The validator's chance of being elected to propose a block, and their share of rewards, depends on this effective stake.
- **Reward split.** Block rewards earned by a validator are split: a `commission` (default 10%) goes to the validator off the top; the remainder is distributed to the validator and delegators in proportion to their share of effective stake.
- **Slashing exposure.** If the validator is slashed for equivocation or double-baking, delegators are slashed proportionally to their delegated balance. This is "skin in the game" — picking a validator carelessly has real cost.

The commission rate is set per validator and visible on-chain. Delegators can shop for low-commission validators, but should weigh that against the validator's uptime and reputation.

### 6.3 Slashing

Three slashable offenses:

- **Double-baking** — producing two distinct blocks at the same level. Penalty: 30% of stake.
- **Double-endorsing** — signing two contradictory endorsement messages at the same level. Penalty: 30% of stake.
- **Governance equivocation** — voting differently on the same proposal in the same phase (introduced in v0.8). Penalty: 30% of stake; reportable via `SLASH_EQUIVOCATION` transaction by anyone with the evidence.

Of every slashed amount: a whistleblower reward (10%) is paid to the reporter, and the rest is burned (reduces total supply).

Delegators are slashed proportionally — see §6.2.

## 7. Governance and the treasury

### 7.1 Two governance tracks

**Protocol amendments** — changes to consensus rules, KVM, gas pricing, Skald itself. Cycle: Proposal (5 days) → Exploration vote (5 days) → Cooldown (5 days) → Adoption vote (5 days) → Activation (5 days). Total: 25 days. Requires supermajority (≥ 80% stake) at both votes.

**Treasury allocations** — disbursements from the on-chain treasury to ecosystem projects. Cycle: Proposal (open submission, 14 days) → Vote (7 days) → Execution. Voting uses quadratic-with-stake-weight (`weight = sqrt(stake)`) to dampen large-holder dominance while still requiring skin in the game.

### 7.2 Treasury funding

- **Genesis endowment:** 0 KRN. The on-chain treasury starts empty and accumulates from issuance. The genesis Foundation pool (15M KRN) is held by a separate legal entity for strategic operations — see §4.3.
- **Ongoing inflow:** 5% of every block reward (governance-amendable).
- **Slashed bonds:** Half of rejected governance-proposal bonds flow to the treasury (introduced in v0.6).
- **Burn of unclaimed grants:** any grant not claimed by its vesting deadline returns to circulation as a burn.

The treasury is a Skald contract. Its spending rules — caps, multi-sig, voting thresholds — are declared invariants. The treasury itself cannot violate the rules it was given at deployment, and changing those rules requires the protocol-amendment cycle, not the treasury-allocation cycle.

### 7.3 What treasury funds typically pay for

- **Core protocol development** — paid via grants to teams maintaining the reference implementation and future clients.
- **Ecosystem projects** — developer tooling, indexers, explorers, libraries.
- **Security work** — audits, bug bounties, formal verification efforts.
- **Public goods** — documentation, education, conferences, research.

## 8. Modeling the supply curve

A back-of-the-envelope simulation of the supply curve over 10 years, assuming:

- Genesis supply: 100M KRN
- Adaptive issuance, average realized staking ratio 45%
- ~3% gross annual inflation in steady state
- ~1% effective burn from storage rent + slashing + failed-tx fees
- Treasury reflow ≈ neutral (paid out as fast as it comes in)

Yields approximately:

| Year | Supply (M KRN) | Notes                                                |
|-----:|---------------:|------------------------------------------------------|
|   0  |      100.0     | Genesis                                              |
|   1  |      102.0     | +2% net                                              |
|   3  |      106.0     | Insider vests largely complete (founder, contribs)   |
|   5  |      109.0     | Pure adaptive issuance + sinks                       |
|  10  |      118.0     | ~1.8% net annualized                                 |

These numbers are illustrative. Real values depend on governance choices and on actual staking participation.

## 9. Anti-patterns to avoid

This token is designed to *not* fall into the failure modes of recent L1 launches:

- **No pre-launch "points" inflation.** No farming-of-future-tokens that distorts incentives before the network exists.
- **No mercenary VC rounds with 0-month cliffs.** Earliest investor unlock is at 6 months.
- **No "fair launch" mythology that masks insider concentration.** The distribution is published, line-itemed, and verifiable on-chain at genesis.
- **No discretionary mint authority.** Issuance is algorithmic; the only way to change it is the protocol amendment cycle.
- **No team multi-sig that controls the chain.** The chain is controlled by stake votes, not by a small group of signers.

## 10. Token utility — when does demand actually arise?

A token is only valuable if it is *needed* for activity on the chain. Kern's KRN is needed for:

1. **Every transaction** — fees in KRN.
2. **Every contract deployment and storage growth** — rent in KRN.
3. **Every validator operation** — stake in KRN.
4. **Every governance vote** — stake-weighted in KRN.
5. **Every settlement of a rollup batch** — settlement fees in KRN (when rollups go live).
6. **Every cross-rollup transfer** — bridge fees in KRN.

The more activity the chain hosts, the more KRN must circulate as a working medium. The more storage applications deploy, the more KRN is locked as rent. The more security the chain needs, the more KRN must be staked. The token's value is plumbed into every part of the protocol's operation, not bolted on.

## 11. On speculation, memecoins, and "fair launch" mythology

This section exists because every native-token L1 receives the same questions, repeatedly, from communities that have seen the playbook of the last cycle. We answer them once, here, in writing, so that the rationale is documented rather than re-argued.

### Why is KRN not marketed as a memecoin?

A memecoin is a token whose value derives primarily from cultural attention rather than from protocol utility. The "value flywheel" is: meme → attention → speculation → price → more attention. This works — temporarily — for tokens that have no other source of value. It does not work for a token whose value is supposed to come from being the gas, stake, and bond unit of a Layer-1 protocol used by regulated institutions.

The two markets are mutually exclusive. A compliance officer at an EU fund (AIFMD-regulated) will not sign a term sheet pointing at an STO deployed on a chain whose native token trends on speculation forums next to dog-themed coins. The first day a Kern STO is approved by a national regulator (FSMA, AMF, BaFin, Finantsinspektsioon, …) is the same day every memecoin association becomes a permanent liability for the protocol. We cannot serve both audiences. We pick institutions.

This is not a moral judgement on memecoins. They are a legitimate cultural product. They are simply incompatible with Kern's positioning, and a founder who tells you otherwise has not understood the institutional market.

If, post-mainnet, the community wants memecoin-style assets *on top of* Kern, they can deploy them as Skald contracts — first-class assets on the chain, distinct from the L1's native token. Ethereum has thousands of memecoin ERC-20s; nobody confuses any of them with ETH itself. The same pattern is encouraged on Kern.

### Why no aggressive "fair launch" or airdrop?

"Fair launch" in current crypto parlance usually means one of two things:

1. **Genuine fair launch** — no premine, no team allocation, no investor allocation. This works for a coin whose value is purely cultural (Bitcoin in 2009, with no foundation; Doge in 2013). It does not work for an L1 that needs continuous funding for audits, validator bootstrap, ecosystem grants, and a multi-year roadmap. Without a Foundation allocation, the project would either die from lack of operating capital or rely on undisclosed insider distributions — which is the opposite of fairness.

2. **"Fair launch" theatre** — token distributed via points-farming, retroactive airdrop to wallets that interacted with a testnet, or similar gameable mechanisms that *appear* democratic but in practice concentrate ownership in sophisticated Sybil farmers. This is the dominant pattern in 2022-2025 L1 launches, and it has not been good for the chains that adopted it.

Kern's published distribution (70% public sale / 10% founder vested / 15% Foundation / 3% contributors / 2% validator bootstrap) is transparently insider-conservative at 10% — most VC-backed L1s allocate 25-40% to insiders. The 70% public allocation is genuinely public, conducted via a regulated sale mechanism (see [setup-foundation.md](setup-foundation.md) Step 7).

There will be no retroactive airdrop. There will be no pre-mainnet "points". There will be no surprise insider unlocks. The distribution is the distribution.

### Why no aggressive marketing or growth campaigns?

A protocol designed for regulated institutions cannot also be running a memecoin-style growth campaign. The compliance officer, the auditor, the regulator, and the institutional fund manager all do background checks on the projects they engage with. If those checks turn up a marketing campaign that resembles a coordinated speculation push, the conversation ends.

The marketing strategy is, accordingly, restrained:

- A landing page (this site) with an email capture for genuine product updates
- A whitepaper, a manifesto, an open repository
- Direct outreach to institutional pilot candidates (fintechs, foundations considering on-chain grant-making, oracle network operators)
- Conference presence at venues where the audience is institutional (Sibos, EthCC's institutional tracks, regulator-organised workshops)
- *No* paid influencer campaigns
- *No* Discord-driven hype cycles
- *No* exchange listing rush

This is slower. It produces fewer headlines. It also produces the relationships that matter for an institutional L1.

### What about token price? Does the founder want KRN to appreciate?

Yes — but only as a side effect of the protocol succeeding.

The founder allocation (10M KRN) is vested over 4 years with a 1-year cliff. The founder cannot extract liquidity from the protocol in the short term, and the protocol's primary success metric is not the token price; it is the count of regulated STOs deployed, attestation registries operational, oracle networks live, and public goods funded.

If Kern delivers on its institutional thesis, KRN will accrue value organically through the demand drivers documented in §10 (fees, stake, bond, rent). If Kern does not deliver, the founder allocation will be worth zero, and the founder will have spent five years building it anyway because the project is the right project to build regardless of personal outcome.

If you are reading this section while evaluating Kern as a speculative position, the honest answer is: there are faster ways to make money in crypto, and Kern is not optimised for them. We are optimised for being indispensable in ten years, not in ten weeks.

### See also

- [`manifesto.md`](manifesto.md) — the founder's explicit refusal of memecoin positioning (§V)
- [`tokenomics.md`](tokenomics.md) §9 — anti-patterns to avoid in the distribution
- [`tokenomics.md`](tokenomics.md) §10 — where KRN's utility-driven demand actually comes from
- [`post-code-roadmap.md`](post-code-roadmap.md) Phase 5 — public sale design constraints

---

## Summary table

| Property               | Value                                    |
|------------------------|------------------------------------------|
| Token                  | KRN                                      |
| Smallest unit          | mukrn (10⁻⁶ KRN)                          |
| Genesis supply         | 100 000 000 KRN                          |
| Founder allocation     | 10% (vested 4 years, 1-year cliff)      |
| Foundation allocation  | 15%                                      |
| Public sale            | 70%                                      |
| Issuance               | Adaptive (0.25% – 6% annualized)         |
| Target staking ratio   | 50%                                      |
| Default validator commission | 10%                                |
| Treasury share         | 5% of block rewards                      |
| Slashing penalty       | 30% of validator stake                   |
| Whistleblower reward   | 10% of slashed amount                    |
| Minimum self-stake     | 10 000 KRN                                |
| Validator unbonding    | 14 days                                  |
| Protocol amendment cycle | 25 days                                |
| Treasury allocation cycle | ~21 days                              |
