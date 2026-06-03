# Setup Guide — External Security Auditor

**Audience**: External security audit firms (e.g., Trail of Bits, OtterSec, Hashlock, Runtime Verification, ChainSecurity) engaged to audit Kern.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- Engagement letter signed between the Kern Foundation and the audit firm
- Auditor has access to a development environment matching Step 1 below
- Auditor has read the public protocol specifications

**What this guide covers**: Set up a clean reference environment, run the test suite to confirm baseline, locate the audit scope, surface known issues and previous audit findings, follow the disclosure protocol.

**Estimated time**: 4-8 weeks for an initial audit; 1-2 weeks for re-audit of fixes.

**Compensation**: per engagement letter with Kern Foundation. Typical range for an L1 audit: 100 000 – 300 000 USD per cycle.

---

## Step 1 — Set up a clean audit environment

Use a fresh Linux VM or container — never an environment shared with other clients.

```bash
# Ubuntu 22.04 baseline
sudo apt update && sudo apt install -y python3.11 python3.11-venv git \
    build-essential libsodium-dev curl jq

# Clone the audit target at a specific tag
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern
git checkout v1.0.0rc1   # or the tag specified in the engagement letter
git log -1 --pretty=fuller   # record the commit hash; include in your report

# Isolate environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

**Verification**:

```bash
pytest tests/ -v
# Expected: 368 passed, 2 skipped — record exact counts in your audit notes
# Record the test run time and resource usage too

python -c "import kern; print(kern.__file__)"
```

---

## Step 2 — Confirm code originality (audit deliverable)

Run the four originality checks (per [originality-and-attribution.md](originality-and-attribution.md) §1):

```bash
# Check 1: no external code disclaimers
grep -rni "copied from\|adapted from\|fork of\|borrowed from\|taken from" \
    --include="*.py" . | grep -v ".pytest_cache" | wc -l
# Expected: 0

# Check 2: only Kern copyright headers
grep -rn "Copyright (c)\|Copyright (C)" --include="*.py" . | \
    grep -v "Nicolas Van Eeckhout" | wc -l
# Expected: 0

# Check 3: SPDX header coverage
echo "Files lacking SPDX header:"
for f in $(find . -name "*.py" -not -path "*/__pycache__/*" \
            -not -path "*/keys/*" -not -path "./.venv/*"); do
    if ! grep -q "SPDX-License-Identifier: Apache-2.0" "$f"; then
        echo "  MISSING: $f"
    fi
done
# Expected: no MISSING lines

# Check 4: founder attribution coverage
grep -L "Nicolas Van Eeckhout" $(find . -name "*.py" \
    -not -path "*/__pycache__/*" -not -path "*/keys/*" -not -path "./.venv/*") | \
    head
# Expected: no output
```

**Audit deliverable**: include a "Code Originality Attestation" section in your audit report with these results. The Foundation requires this attestation for the public record. Confirm explicitly:

- [ ] The codebase is original Python (not vendored from any other blockchain project)
- [ ] SPDX-License-Identifier: Apache-2.0 is present on all 55+ Python files
- [ ] Copyright attribution to Nicolas Van Eeckhout is preserved
- [ ] The single external library dependency (`py_ecc`) is used via Python imports, not vendored

---

## Step 3 — Locate the audit scope

The audit covers the following modules at v1.0-rc:

### In scope — high priority

| Module | Purpose | Why high priority |
|---|---|---|
| `kern/crypto.py` | Ed25519, blake2b, base58check | Any bug here is catastrophic |
| `kern/chain.py` | State machine, apply_block, slashing, delegation | The heart of the protocol |
| `kern/transaction.py` | Tx format, signature scheme, all OpKind builders | Wire-format security |
| `kern/block.py` | Block header, txs root, signature aggregation | Consensus correctness |
| `kern/bft.py` | Multi-validator BFT (propose/preendorse/endorse) | Safety + liveness |
| `kern/consensus.py` | Proposer selection, slot lottery | Sybil resistance |
| `kern/governance.py` | Two-track governance, voting, equivocation slashing | Protocol evolution security |
| `kern/issuance.py` | Adaptive issuance, reward distribution, commission split | Economic security |
| `kern/evm/` | EVM rollup execution, gas pricing, BN254 precompile | Rollup correctness |
| `kern/skald/` | Skald interpreter and type checker | Contract execution correctness |
| `kern/trie.py` | Merkle trie, inclusion proofs | Light-client integrity |
| `kern/rollup.py` | Rollup state machine, fraud-proof bisection | Rollup security |
| `kern/forced_inclusion.py` | Censorship-resistance mailbox | UX-safety mechanism |

### In scope — medium priority

| Module | Purpose |
|---|---|
| `kern/network.py` | P2P gossip layer |
| `kern/storage.py` | Persistence layer |
| `kern/rpc.py` | RPC endpoint surface |
| `kern/node.py` | Process lifecycle |
| `scripts/build_v1_genesis.py` | Genesis state construction |
| `genesis.json` and `genesis_vesting.json` | Initial distribution correctness |

### In scope — supporting

| Module | Purpose |
|---|---|
| `kern/observability.py` | Logs and metrics |
| `kern/fuzzing.py` | Property-based fuzz harness (verify it's exercising the right invariants) |
| `tests/` | Test suite coverage and correctness |
| `docs/` | Specification fidelity to code |

### Out of scope

| Item | Why |
|---|---|
| Third-party libraries (`py_ecc`, `pynacl`, `aiohttp`) | Separately audited by their maintainers |
| Operating system, Python interpreter | Not part of Kern |
| Future v1.x roadmap items | Audited at their respective release tags |
| Networks and operational items | Audited in operational reviews, separately |

---

## Step 4 — Review known issues and prior findings

If this is a re-audit (audit cycle 2), the Foundation provides:

- Full audit cycle 1 report
- Code diff between audit cycle 1 commit and current
- Foundation responses to each cycle 1 finding (fixed / accepted risk / deferred)

If this is audit cycle 1, the Foundation provides:

- This guide
- The [API stability spec](api-stability.md) — what's frozen and must not change
- Internal known issues (none formally tracked at v1.0-rc; verbal disclosure during kickoff)
- Property-based fuzzing logs from `kern.fuzzing` showing edge cases already explored

---

## Step 5 — Set up your audit workflow

Recommended structure of your audit notes:

```
audit-kern-v10rc/
├── kickoff/
│   ├── engagement-letter.pdf
│   ├── scope-confirmation.md
│   └── baseline-test-run.log
├── code-review/
│   ├── consensus.md            # findings on consensus.py
│   ├── chain.md                # findings on chain.py
│   ├── governance.md           # findings on governance.py
│   ├── ... (one per module) ...
│   └── cross-module.md
├── findings/
│   ├── critical/               # one .md file per critical finding
│   ├── high/
│   ├── medium/
│   ├── low/
│   └── informational/
├── verification/
│   ├── reproducer-scripts/     # PoC scripts demonstrating each finding
│   └── regression-tests/       # New tests to prevent re-introduction
└── final-report/
    ├── executive-summary.md
    ├── methodology.md
    ├── findings.md             # consolidated
    ├── attestation.md          # originality + scope attestation
    └── recommendations.md
```

---

## Step 6 — Specific audit checks the Foundation expects

The following are explicit must-cover items. Do not omit any:

### Cryptographic primitives

- [ ] Ed25519 signature verification correctly rejects malformed signatures (R, S out of range; identity element; etc.)
- [ ] blake2b-256 domain separation is correctly applied across all hash contexts (tx, block, state, trie, addr)
- [ ] base58check encoding correctly handles edge cases (leading zeros, invalid characters, mismatched checksum)
- [ ] No timing-side-channel observable on signature operations (constant-time properties of pynacl)

### Transaction signing and replay

- [ ] Signed payload computation is canonical — same transaction always produces same bytes
- [ ] Nonce strictly monotonic per sender; replays rejected
- [ ] Fee accounting correctly handles edge cases (fee > balance, fee = 0)
- [ ] Gas limit and fee are independent (insufficient gas does NOT excuse fee payment)

### Consensus safety

- [ ] No two distinct blocks can be committed at the same level under any sequence of valid messages
- [ ] Fork choice is deterministic given the same input set
- [ ] Equivocation detection covers double-baking, double-endorsing, and governance double-voting
- [ ] BFT messages with invalid signatures are correctly rejected

### Slashing

- [ ] SLASH_EQUIVOCATION transaction can only be submitted with valid on-chain evidence
- [ ] Double-slashing the same offense is prevented (consumption flag works)
- [ ] Whistleblower reward arithmetic doesn't overflow or produce negative values
- [ ] Proportional delegator slashing correctly bounded by delegator balance
- [ ] Validator unbonding period correctly enforced

### Delegation

- [ ] DELEGATE_STAKE rejects unknown validators and self-delegation
- [ ] effective_stake correctly sums own + delegated balances at reward time
- [ ] split_validator_reward produces no negative shares, sums to original reward (modulo rounding to validator)
- [ ] Switching delegation correctly transitions to new validator (no double-counting)
- [ ] Commission rate update doesn't apply retroactively

### Governance

- [ ] Proposal phase transitions are timing-correct
- [ ] Quorum and supermajority thresholds are integer-arithmetic-correct (no off-by-one)
- [ ] Treasury bond settlement correctly applies success/rejection rules
- [ ] Quadratic voting computation is overflow-safe for large stakes
- [ ] Activated protocol amendments produce correct state changes

### EVM and rollups

- [ ] Gas accounting matches Yellow Paper for every supported opcode
- [ ] SSTORE EIP-2200 three-case pricing is correct
- [ ] Memory expansion cost calculation matches the spec
- [ ] BN254 pairing precompile produces correct results for empty input, identity case, and random valid inputs
- [ ] Fraud-proof bisection correctly converges in O(log n) steps
- [ ] Forced-inclusion mailbox deadlines correctly enforced

### Skald and contracts

- [ ] Type checker rejects all invalid programs in the test suite
- [ ] Invariant violations correctly revert the transaction atomically (no state changes persist)
- [ ] Storage rent correctly metered for contract origination and growth
- [ ] No way to escape declared bounds via integer overflow

### Genesis

- [ ] genesis.json totals to exactly 100 000 000 KRN (mukrn accounting)
- [ ] All five pool addresses are distinct
- [ ] Vesting schedules in genesis_vesting.json align with tokenomics.md §4
- [ ] State-root function defaults to "trie" for v1.0-rc

### Originality

- [ ] All 55 Python source files have proper SPDX-License-Identifier
- [ ] All 55 Python source files carry founder attribution to Nicolas Van Eeckhout
- [ ] No vendored external code present
- [ ] All design-influence citations (Tezos, Ethereum, EIPs) are properly noted as references, not represented as Kern's own innovation

---

## Step 7 — Reporting findings

Use the standard severity classification:

| Severity | Definition |
|---|---|
| **Critical** | Allows theft, loss, or destruction of user funds; chain split; consensus halt |
| **High** | Allows DoS; allows bypass of access control without fund loss; severe degradation |
| **Medium** | Allows confusion or unexpected behavior; would require remediation but not exploitable in current state |
| **Low** | Code quality, hardening, defense-in-depth opportunities |
| **Informational** | Style, documentation, optimization suggestions |

For each finding, your report should include:

1. **Title** (e.g., "Reentrancy in Treasury Distribution")
2. **Severity** (Critical/High/Medium/Low/Informational)
3. **Location** (file:line)
4. **Description** of the issue
5. **Impact** assessment (who is harmed, how, under what conditions)
6. **Proof of concept** (concrete reproducer)
7. **Recommended fix** (specific code change)
8. **Status** (will be filled by Foundation: Acknowledged / Fixed / Won't Fix / Accepted Risk)

---

## Step 8 — Coordinated disclosure

If you find a **Critical** or **High** severity issue:

1. **Do not disclose publicly.** Email the Foundation immediately at the security address provided in the engagement letter.
2. **Encrypt the disclosure** with the Foundation's GPG key.
3. **The Foundation has 90 days** to remediate (consistent with industry standard).
4. **After remediation** (or 90 days, whichever is sooner), the finding may be disclosed publicly.

For **Medium / Low / Informational** findings:

1. Include them in the audit report as normal.
2. Coordinated disclosure not required, but the Foundation prefers a 30-day grace period between report delivery and public release.

---

## Step 9 — Final report delivery

Deliver to the Foundation:

1. **Full audit report** (PDF, signed with audit firm's PGP key)
2. **Public summary** (markdown, suitable for blog/website publication)
3. **Originality attestation** (per Step 2, included in the full report)
4. **Reproducer code** for every finding (in a separate zip archive)
5. **Regression tests** the Foundation can incorporate into the test suite

The Foundation publishes:

- The full report on `docs.kern.protocol/audits/v1.0-cycle-1-trail-of-bits.pdf` (or equivalent)
- The public summary on the Foundation blog
- A response document addressing each finding

Your name and firm name are credited in [AUTHORS](../AUTHORS) and in the public audit record.

---

## Step 10 — Re-audit (cycle 2)

After Foundation applies fixes:

1. **Diff review** of the changes between cycle 1 commit and current
2. **Verify fixes** for every cycle 1 finding (use your original reproducers)
3. **Spot-check** for regressions in adjacent code
4. **Confirm no new findings** introduced by the remediation

Cycle 2 is typically scoped at 25-40% of cycle 1 effort.

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| Tests fail on fresh clone | Wrong tag checked out | `git checkout v1.0.0rc1` exactly |
| py_ecc tests fail | Dep not installed | `pip install -e ".[dev]"` |
| Cannot find a specific module | Codebase grew since last audit | Use `find . -name "*.py" -path "*kern*"` to locate |
| Foundation unresponsive during audit | Vacation, holidays, illness | Engagement letter should specify escalation contacts |
| Critical finding discovered | Coordinated disclosure protocol | Stop public communication, email Foundation immediately |

---

## Compensation and payment

Per the engagement letter. Standard structure:

- 25% on engagement start
- 50% on draft report delivery
- 25% on final report delivery + Foundation acceptance

Payment may be in EUR, USD, or KRN (post-mainnet) at the Foundation's option per engagement letter.

---

## Next steps after engagement

- Your firm joins the public record of Kern auditors at [AUTHORS](../AUTHORS) and on the docs site
- You may be invited to future audit cycles for v1.x releases
- You may participate in the Kern bug bounty program at higher-than-standard tier for previously-unfound issues
