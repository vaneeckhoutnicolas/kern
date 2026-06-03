# Setup Guide — Foundation Setup

**Audience**: Nicolas Van Eeckhout (founder), and the initial Foundation board members once recruited.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- Identity documents (passport, proof of address)
- Initial capital: 30 000 – 80 000 EUR for incorporation and first-year operating costs (varies by jurisdiction)
- Legal counsel familiar with non-profit / foundation law in the chosen jurisdiction
- Long-term commitment (5+ years) — the Foundation outlives any single product release

**What this guide covers**: Choose the right legal jurisdiction, incorporate the Foundation, set up multisig wallets for the 15M KRN Foundation pool and the on-chain genesis ceremony, establish bylaws and governance, run the genesis ceremony.

**Critical**: The Foundation is the gating item for almost every other milestone. Without it: no audits can be contracted, no bug bounties can be paid, no Foundation pool can be held, no public sale can be conducted, no mainnet genesis can be signed.

**Estimated time**: 4–6 months from decision to operational Foundation.

---

## Decision 1 — Choose the legal jurisdiction

Four serious candidates. Each has tradeoffs.

### Option A — Swiss Stiftung (Foundation)

**Examples**: Ethereum Foundation (Zug), Tezos Foundation (Zug), Cardano Foundation (Zug), Cosmos Foundation (Zug, then dissolved).

| Aspect | Detail |
|---|---|
| Cost to incorporate | 30 000 – 50 000 CHF |
| Annual operating cost (legal + audit + admin) | 80 000 – 200 000 CHF |
| Time to incorporate | 2 – 4 months |
| Tax treatment | Tax-exempt if recognized as public benefit; otherwise 8.5% federal + cantonal |
| Brand value | Highest in crypto — "Zug Stiftung" is the gold standard |
| Geographic restriction on the founder | None — Nicolas can be Belgian and Foundation can be Swiss |
| Board requirement | Min 1 Swiss-resident board member |
| Reporting | Annual audited financials to the supervisory authority |

**Verdict**: Most credible globally, expensive, slow. Worth it if Kern aims to be a major L1.

### Option B — Estonian Foundation (Sihtasutus)

**Examples**: Used by several EU tech and blockchain initiatives leveraging Estonia's e-Residency programme. The Estonian Sihtasutus is the foundation-type non-profit under Estonian law (Sihtasutuste seadus), recognized across the EU as a non-profit legal person.

| Aspect | Detail |
|---|---|
| Cost to incorporate | 2 500 – 8 000 EUR (lower than Belgian/Swiss because of e-Residency tooling) |
| Annual operating cost | 10 000 – 40 000 EUR |
| Time to incorporate | 2 – 6 weeks (faster with e-Residency already issued) |
| Tax treatment | Generally tax-exempt for non-profit activities; corporate income tax 0% on retained profits, 22% on distributions only |
| Brand value | Strong in tech/blockchain — Estonia is the established crypto-friendly EU jurisdiction (MiCA-aligned, recognised regulator) |
| Geographic alignment with Nicolas | Operable remotely from Brussels via e-Residency; no need for physical relocation |
| Board requirement | Min 3 board members; no nationality requirement |
| Reporting | Annual report to the Estonian Business Register (Äriregister) |

**Verdict**: Strong fit for a tech-native, EU-wide L1 protocol. Estonia's e-Residency and digital-first administration make this the lowest-friction path for an EU-rooted founder operating internationally; the cost structure leaves more budget for audits and engineering. Recognised across the EU under the freedom-of-establishment principle.

### Option B-bis — Belgian AISBL (alternative)

**Examples**: Linux Foundation Europe, OpenSSL Foundation (in process).

| Aspect | Detail |
|---|---|
| Cost to incorporate | 5 000 – 15 000 EUR |
| Annual operating cost | 20 000 – 80 000 EUR |
| Time to incorporate | 1 – 3 months |
| Tax treatment | Generally tax-exempt for non-profit activities; 25% on commercial activities |
| Brand value | Moderate — well-known in EU, less so in US/Asia |
| Geographic alignment with Nicolas | Native — Nicolas can be founder + board member directly |
| Board requirement | Min 3 board members; nationalities of at least 2 EU countries |
| Reporting | Annual report to Service Public Fédéral Justice |

**Verdict**: Pragmatic alternative if proximity to FSMA (Belgium's regulator) or to Brussels-based EU institutions becomes a strategic factor. Higher annual cost than the Estonian path; comparable legal standing under EU law.

### Option C — Luxembourg Fondation

**Examples**: Some EU-focused crypto projects.

| Aspect | Detail |
|---|---|
| Cost to incorporate | 10 000 – 25 000 EUR |
| Annual operating cost | 40 000 – 100 000 EUR |
| Time to incorporate | 2 – 4 months |
| Tax treatment | Generally tax-exempt; minimum endowment ~50 000 EUR |
| Brand value | Moderate-high in EU financial circles |
| Geographic restriction on the founder | None |
| Board requirement | Min 3 board members |
| Reporting | Annual report to the Ministry of Justice |

**Verdict**: Middle ground between Belgian and Swiss. Strong financial/legal infrastructure.

### Option D — Wyoming DAO LLC (US)

**Examples**: Some newer DeFi protocols.

| Aspect | Detail |
|---|---|
| Cost to incorporate | 100 – 500 USD |
| Annual operating cost | 5 000 – 20 000 USD |
| Time to incorporate | 1 – 2 weeks |
| Tax treatment | Pass-through; LLC pays no entity tax |
| Brand value | Mixed — innovative, but US regulatory risk |
| Geographic alignment | None — Nicolas is Belgian, so this adds complexity |
| Board requirement | One "registered agent" in Wyoming; flexible governance |
| Reporting | Light |

**Verdict**: Cheap and fast but exposes the founder and the project to US securities and tax regulation. Not recommended for an EU-based founder building a protocol whose primary market is European institutional adoption.

### Recommendation

**Primary recommendation: Estonian Foundation (Sihtasutus).**

Reasoning:
- Nicolas, although based in Brussels, can operate the Foundation remotely via Estonia's e-Residency programme — no physical relocation required
- Estonia has the most established crypto-friendly legal framework in the EU, with regulator (Finantsinspektsioon) precedent on MiCA implementation and a well-tested foundation form (Sihtasutus)
- ~3x lower annual cost than Swiss or Belgian alternatives, leaving more of the early budget for security audits and engineering
- EU regulatory clarity (MiCA) applies the same to an Estonian, Belgian, or Swiss entity — the choice is operational, not regulatory
- Belgian moral rights (Article XI.165) continue to protect Nicolas's authorship regardless of where the Foundation is incorporated — see [originality-and-attribution.md](originality-and-attribution.md) §4
- Can be upgraded to a Swiss Stiftung later if the project's scale justifies the cost (Foundation transfers assets)

**Alternative recommendation: Belgian AISBL** — if proximity to FSMA (Belgium's regulator) or to Brussels-based EU institutions becomes a strategic factor (e.g., if Kern STO templates are first approved by FSMA, having the Foundation in the same jurisdiction may streamline dialogue).

**Alternative recommendation: Swiss Stiftung** — if Nicolas plans to raise significant private capital (5M+ EUR) and the additional cost is justified by the brand premium.

---

## Decision 2 — Confirm the choice

Before proceeding to Step 1, confirm:

- [ ] Jurisdiction: Estonian Foundation / Sihtasutus (or alternative — note your choice)
- [ ] Initial capital available: at least 50 000 EUR (covers incorporation + 6 months operating)
- [ ] Three board members identified (you + 2 others; Estonia has no nationality requirement for board members)
- [ ] e-Residency obtained or in progress (https://www.e-resident.gov.ee/) — required for remote operation by a non-Estonian resident
- [ ] Legal counsel engaged (Estonia: e.g., COBALT, Sorainen, Triniti, or smaller boutique with blockchain/foundation experience)
- [ ] Auditor engaged (Estonia: a member of the Estonian Auditors Association)

If any box is unchecked, address it before incorporation begins.

---

## Step 1 — Incorporate the Foundation (Estonian Sihtasutus path)

Working with your engaged legal counsel, and with e-Residency obtained:

1. **Draft the foundation deed (asutamisotsus) and statutes (põhikiri)** in Estonian (legal default), with English translation. Include:
   - Name: "Kern Foundation" / "Kerni Sihtasutus" (Estonian-language official name)
   - Purpose: "the development, promotion, and stewardship of the Kern blockchain protocol and Skald smart contract language; the funding of audits, ecosystem development, and public goods aligned with the Kern protocol's mission"
   - Domicile (registered office in Estonia — typically the e-Residency service provider's address initially)
   - Founders: Nicolas Van Eeckhout + initial board members
   - Initial capital: minimum 0 EUR by Estonian law (no minimum endowment required for a Sihtasutus; in practice, allocate a working capital of at least 10 000 EUR)
   - Governance: composition of the board (juhatus) + optional supervisory council (nõukogu), quorum, voting rules
   - Beneficiaries: explicitly the Kern protocol and its community (a Sihtasutus must be created in the interest of a defined purpose, not for the benefit of specific persons)
   - Dissolution clause: residual assets transfer to a similar non-profit (Estonian law requirement)

2. **Notarize the foundation deed** via an Estonian notary, either in person or via e-Notary (digital signature with e-Residency card). Cost: ~500 – 1 500 EUR.

3. **Register with the Estonian Business Register (Äriregister)** through the e-Business Register portal. Once registered, the Foundation receives an Estonian registry code (e.g., 90123456). Registration is usually completed within 1 – 5 business days.

4. **Open a bank account** in the Foundation's name. Estonian banks accepting foundation accounts: LHV Pank (most crypto-experienced), SEB, Swedbank. Non-Estonian alternatives accepting e-Residency entities: Wise Business, Revolut Business (operational), Bilderlings, Bank of Georgia (BoG). Crypto-friendly Swiss-style banks: SEBA, Sygnum (Switzerland) — can hold EUR but specialise in crypto.

**Verification**:

```
☐ Sihtasutus registered with Estonian Business Register (registry code obtained)
☐ Bank account active
☐ Initial board meeting minutes documented
☐ Foundation deed digitally notarised and stored
```

---

## Step 2 — Establish the bylaws (Foundation governance)

The statutes are the legal skeleton. The **bylaws** (or "internal rules of procedure" / *règlement d'ordre intérieur*) are the operational detail.

Draft and approve at the first board meeting:

### Board composition

- **Chair**: Nicolas Van Eeckhout (founder)
- **Treasurer**: A board member with finance/accounting background
- **Secretary**: A board member responsible for records and minutes
- **Other directors**: At least one technical director, one community/ecosystem director

Recommended: 5 board members total, with terms of 3 years, renewable. Conflict-of-interest disclosure required before each vote.

### Decision thresholds

| Decision | Threshold |
|---|---|
| Annual budget approval | Simple majority |
| Expenditure > 50 000 EUR | 2/3 majority |
| Expenditure > 250 000 EUR | Unanimous board approval |
| Bylaws amendment | 2/3 majority |
| Statutes amendment | Notarized + Moniteur publication |
| Foundation pool spend | Multisig (Step 4) AND board approval per above thresholds |
| Foundation dissolution | Unanimous + per statutes |

### Operational policies

- **Quarterly financial reports** published to the community (anonymized as needed)
- **Annual audited financials** by external auditor
- **Conflict-of-interest register** maintained
- **Public minutes** of board meetings (sensitive items redacted)
- **Whistleblower policy** for reporting irregularities

### Founder's rights (non-transferable)

Document explicitly that:

- Nicolas retains the right to be named as **founder of the Kern protocol** in all Foundation communications
- This right is **inalienable** and survives any subsequent role change, including Nicolas leaving the Foundation board
- This is consistent with Belgian moral rights law and applies regardless of the Apache-2.0 license terms

---

## Step 3 — Set up the founder allocation multisig

The 10M KRN founder pool (10% of genesis) needs to be held in a multisig that vests according to the schedule (1-year cliff + 4-year linear).

**Recommended structure**: 2-of-3 multisig with:
1. Nicolas's primary key (held by Nicolas)
2. Nicolas's backup key (held by Nicolas in a separate secure location, e.g., hardware wallet in safe deposit box)
3. Foundation treasurer's key (for emergency recovery if Nicolas is incapacitated)

**Why 2-of-3, not 1-of-1**: prevents catastrophic loss if Nicolas's primary key is compromised or lost. Why not 3-of-3: any single failure paralyzes vesting unlocks.

**Setup steps**:

1. Generate three keypairs:

```bash
mkdir -p ~/.kern/founder-multisig
chmod 700 ~/.kern/founder-multisig

for n in 1 2 3; do
    python /path/to/kern/scripts/generate_keys.py \
        --out ~/.kern/founder-multisig/sig$n.json
    chmod 600 ~/.kern/founder-multisig/sig$n.json
done

# Inspect
for n in 1 2 3; do
    echo "=== sig$n.json ==="
    jq '{address: .address, public_key: .public_key}' ~/.kern/founder-multisig/sig$n.json
done
```

2. Secure each key:
   - sig1.json (Nicolas primary): hardware wallet (e.g., Ledger Nano X), seed phrase written on metal plate in home safe
   - sig2.json (Nicolas backup): hardware wallet stored at a bank safe deposit box, different city if possible
   - sig3.json (Foundation treasurer): hardware wallet held by the treasurer at the Foundation premises

3. Originate the multisig Skald contract on Kern. The reference template will be provided in `kern/skald/examples/multisig.skald` for the genesis ceremony (TODO in v1.x). For v1.0-rc, the multisig is enforced off-chain by the Foundation custody policy (the 10M KRN is held at an address derived from sig1, with sig2 and sig3 capable of recovery via Foundation governance).

4. Test the multisig with a small amount (100 mukrn) BEFORE depositing the real 10M KRN. Confirm 2-of-3 signatures correctly authorize a transfer.

---

## Step 4 — Set up the Foundation pool multisig

The 15M KRN Foundation pool needs a more conservative multisig — this is operating capital for audits, partnerships, grants, hires.

**Recommended structure**: 3-of-5 multisig with:
1. Nicolas (founder)
2. Foundation Chair (may be Nicolas, may rotate)
3. Treasurer
4. Independent board member 1
5. Independent board member 2

**Why 3-of-5**: balances security (no single party can drain) with operational agility (don't need everyone for routine spends).

**Spending limits** (enforced by board policy, not the multisig itself):

| Spend size | Process |
|---|---|
| < 10 000 KRN (~$1k at $0.1/KRN) | Treasurer alone, post-hoc reported to board |
| 10 000 – 100 000 KRN | 2 board signers + chair approval |
| 100 000 – 1 000 000 KRN | 3 board signers + full board approval at meeting |
| > 1 000 000 KRN | Unanimous board + 30-day notice to community |

Setup is mechanically the same as Step 3 — generate 5 keypairs, secure each, originate the multisig contract.

---

## Step 5 — Set up the contributors pool multisig

The 3M KRN early contributors pool needs to release individual grants over time (per [contributors-program.md](contributors-program.md) §1).

**Recommended structure**: same 3-of-5 as the Foundation pool, since the same board approves grants.

**Process per grant**:

1. A board member or Nicolas proposes: "X mukrn to address Y for contribution Z, vesting 3 years with 6-month cliff"
2. Public comment period: 14 days (post in community channels, e.g., forum)
3. Board vote (at next meeting): 3/5 in favor
4. Multisig releases the KRN to the recipient (cliff-and-vest enforced off-chain by holding back the locked portion)

---

## Step 6 — Set up the validator bootstrap pool multisig

The 2M KRN validator bootstrap pool releases over 1 year to seed initial validators (per [tokenomics.md](tokenomics.md) §4).

**Structure**: 2-of-3 (Nicolas + 2 Foundation board members). Lighter than Foundation pool because the policy is mechanical (release X amount per month per onboarded validator).

---

## Step 7 — Plan the public sale (70M KRN)

This is the largest single decision and warrants extensive Foundation deliberation. Options:

### Option A — Time-bounded ICO (Ethereum 2014 style)

- 30-day fundraising window
- Fixed exchange rate (e.g., 1 KRN = 0.001 ETH)
- All-or-nothing minimum target
- Tokens distributed at genesis

**Pros**: simple, transparent. **Cons**: regulatory scrutiny in some jurisdictions; difficult to gauge "fair" rate upfront.

### Option B — Dutch auction

- Auction starts at high price, descends until all 70M sold
- Final price = clearing price (uniform for all buyers)
- 7-14 day window

**Pros**: price discovery; no insiders get better deal. **Cons**: complex; first 2 days have low engagement, last 2 days have stampedes.

### Option C — Liquidity Bootstrapping Pool (LBP)

- Use Balancer (or equivalent) on an existing chain (Ethereum) with Kern denominated by a wrapped token
- Price starts high, weight rebalances over time
- 3-day window typical

**Pros**: market-driven, smooth price discovery. **Cons**: requires another chain's infrastructure; high gas costs for buyers.

### Option D — Staged release

- 30M KRN at genesis at fixed price
- 20M KRN released at month 3 at clearing-price auction
- 20M KRN released at month 6 at floor price (community vote)

**Pros**: smoother price curve, more chances for retail; aligns with project milestones. **Cons**: extends fundraising window; risk of market fatigue.

### Recommendation

**Pre-mainnet recommendation: Option D (staged release)** — gives the Foundation operational runway across 6 months without dumping 70M KRN at once, and allows price to adjust to delivered milestones.

If Foundation needs all capital up-front for audit/development: Option A (simple ICO) at a moderately conservative price.

**Regulatory review required**: Engage securities counsel in EU (MiCA), Switzerland (FINMA), and US (SEC posture) before finalizing. The Foundation must NOT offer the public sale to US persons without specific exemption analysis.

---

## Step 8 — Plan the genesis ceremony

The genesis ceremony is the formal event where:
1. All five pool addresses are confirmed and final
2. The canonical `genesis.json` is generated using `scripts/build_v1_genesis.py`
3. The file is signed by multiple Foundation parties for attestation
4. The signed file is published to multiple persistent locations (IPFS, GitHub release, Foundation website, archived in Foundation records)
5. Mainnet validators bootstrap from this file

### Pre-ceremony preparation

```bash
# Generate the final pool addresses using the deterministic seeds
# from the build script, OR use the real Foundation multisig addresses.
# For production, REPLACE the placeholder seeds in scripts/build_v1_genesis.py
# with the actual multisig contract addresses generated in Steps 3-6.

cd /path/to/kern
python scripts/build_v1_genesis.py \
    --out /tmp/genesis_candidate.json \
    --vesting-out /tmp/vesting_candidate.json

# Review the output carefully:
jq '.balances' /tmp/genesis_candidate.json
jq '.validators' /tmp/genesis_candidate.json
jq '.pool_addresses' /tmp/genesis_candidate.json
```

Confirm with the entire Foundation board that:
- Total supply: 100 000 000 KRN ✓
- Pool addresses match the actual multisig addresses controlled by the Foundation ✓
- Bootstrap baker address has 1M KRN of stake ✓
- Vesting schedules in the side document are accurate ✓

### Day-of ceremony

1. **All board members convene** (in person or via secure video conference)
2. **Run `build_v1_genesis.py` live** with the final pool addresses
3. **Compute SHA-256 of the resulting genesis.json**: `sha256sum genesis.json`
4. **Each board member signs the hash** with their personal GPG key
5. **Sign the file itself with the Foundation's GPG key**: `gpg --detach-sign --armor genesis.json`
6. **Pin to IPFS**: `ipfs add genesis.json` → record the CID
7. **Publish**:
   - Tagged GitHub release at `github.com/vaneeckhoutnicolas/kern/releases/tag/midgard-genesis`
   - Foundation website (with SHA-256 + IPFS CID + Foundation signature)
   - Internet Archive (`archive.org`) snapshot for permanence
   - Notarized printout in Foundation records

### Post-ceremony

8. **Wait 7 days** before launching mainnet — community verification window
9. **Validators bootstrap from the published genesis.json** at the agreed launch time
10. **Foundation announces mainnet live** at the first block produced

The first block produced from the agreed genesis IS the start of Midgard.

---

## Step 9 — Ongoing operations

| Activity | Cadence |
|---|---|
| Board meeting | Monthly (minimum) |
| Quarterly financial report | Quarterly, published |
| Annual audited financials | Annually, by external auditor |
| Treasury proposal review (on-chain) | Continuous; Foundation may co-sponsor proposals |
| Grant proposal review (Foundation pool) | Monthly or as-needed |
| Public communications (Twitter, blog, conferences) | Continuous |
| Annual general meeting | Annually, open to community |

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| Notary appointment delayed | Estonian notary processes are fast (digital signatures via e-Residency), but Belgian/Swiss notaries are slower in summer | If using Estonian path, schedule notary appointment via e-Notary system; if using alternative path, schedule outside July-August |
| Bank refuses to open Foundation account | Crypto-related entity | Use a crypto-friendly bank: SEBA, Sygnum, or specialized providers; otherwise an EU neobank (Bunq, Wise Business) until a primary bank accepts |
| Initial capital depleted before mainnet | Underestimated audit costs ($150-300k for cycle 1) | Bridge with founder capital or a small private round; budget more conservatively |
| US person tries to participate in public sale | Geographic restrictions | Implement KYC + IP geofencing on the sale platform; document |
| Conflict-of-interest concerns about Nicolas being founder + board chair | Governance optics | Document a recusal policy: Nicolas recuses on any decision that directly benefits him or his vesting |

---

## Critical reminders

1. **Don't sign genesis until you're sure.** The genesis.json is the immutable starting state; mistakes are not fixable without a hard fork.
2. **Don't deposit 10M KRN into a multisig you haven't tested.** Always test with 100 mukrn first.
3. **Don't store all signing keys in the same physical location.** Geographic dispersion is the only protection against fire/theft/seizure.
4. **Don't underestimate the calendar time.** Foundation setup → audit cycle 1 → audit findings remediation → audit cycle 2 → genesis ceremony is realistically 9-15 months even with focus.
5. **Document everything.** Belgian moral rights law protects you, but only if you can prove the authorship and the timeline. Sign your commits, archive your decisions, retain meeting minutes.

---

## Next steps

After Foundation is operational:

1. **Engage audit firms** — see [setup-auditor.md](setup-auditor.md)
2. **Onboard initial validators** — coordinate via [setup-validator.md](setup-validator.md)
3. **Run Yggdrasil public testnet** — feedback cycle before mainnet. The Foundation should operate at least one official Heimdall instance per network (devnet, Yggdrasil, Midgard); see [setup-heimdall-operator.md](setup-heimdall-operator.md).
4. **Plan public sale and genesis ceremony** — Steps 7-8 above

The Foundation is the institutional embodiment of Kern. Treat it as the long-term home of the protocol.
