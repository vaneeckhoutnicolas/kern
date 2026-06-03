# Internal Security Review — v1.1-rc

This document is the report of the **internal security review** of Kern v1.1-rc, conducted by the founder ahead of submitting the codebase to professional audit (cycle 1). It documents:

- The scope reviewed
- The methodology applied
- All findings discovered, with severity classifications
- The fixes applied
- The regression tests added
- **Limitations of this review and why a professional audit is still mandatory**

---

## CRITICAL DISCLAIMER

**This review is NOT a substitute for professional security audit by a specialized firm.**

A self-conducted internal review can catch obvious bugs and antipatterns, but cannot replace:

- The 6-12 weeks of focused work by a team of 3-5 specialists
- The proprietary tooling (advanced fuzzers, formal verification frameworks, custom static analyzers)
- The institutional experience of having seen hundreds of similar codebases and the attack vectors that emerged on each
- The independence of an outside party with no investment in the outcome

This review IS:

- A pass to catch the most obvious bugs before they consume expensive audit time
- Documentation of the security posture as of v1.1-rc
- A baseline for the audit firm to start from

**Kern v1.1-rc MUST undergo audit cycle 1 by a recognized firm (Trail of Bits, OtterSec, Hashlock, Runtime Verification, ChainSec, or equivalent) before any Midgard mainnet launch.** This requirement is in [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) §D and is non-negotiable.

---

## 1. Scope

The review covered all crypto-critical modules:

| Module | Lines | Reviewed |
|---|---:|---|
| `kern/attestation.py` (v1.1-rc, new) | ~270 | ✅ |
| `kern/chain.py` (handlers, esp. v1.1-rc additions) | ~1115 | ✅ |
| `kern/transaction.py` (Transaction model + builders) | ~510 | ✅ |
| `kern/crypto.py` (Ed25519 signing/verification) | ~180 | ✅ |
| `kern/zk_claims.py` (v1.1-rc, new) | ~230 | ✅ |
| `kern/governance.py` (proposal lifecycle, slashing) | ~860 | ✅ partial |
| `kern/rpc.py` (input parsing surface) | ~250 | ✅ |
| `kern/bft.py` (consensus) | ~620 | ⚠️ skimmed |
| `kern/evm/*` (rollup VM + BN254) | ~1700 | ⚠️ skimmed |
| `kern/skald/*` (typechecker + interpreter) | ~700 | ⚠️ skimmed |

The deeper review on BFT, EVM and Skald is deferred to the professional audit — these are large surfaces and an external auditor's review of them is more valuable than this author's.

---

## 2. Methodology

This review followed the standard threat-modeling approach:

1. **Identify trust boundaries**: where untrusted input crosses into trusted code paths (RPC, mempool, transaction parsing, contract calls)
2. **Identify assets**: KRN balance, total supply, validator set, governance state, attestation bonds, signed payload integrity
3. **For each handler in `apply_transaction`**, trace untrusted-input → state-mutation paths and check for:
   - Negative-value injection (fee, amount, gas_limit, nonce)
   - Integer overflow (Python ints are arbitrary precision, but DOS via huge values still possible)
   - Replay attacks (cross-network, cross-account, within-account)
   - Double-spend / double-slash
   - Access-control bypass
   - State-rollback inconsistency on partial failure
   - Signature malleability
4. **For cryptographic constructions**, check standard pitfalls:
   - Ed25519 (PyNaCl) — by construction not malleable, no low-s concern
   - Hash function pre-image / collision resistance — blake2b with domain separators
   - Replay across networks — chain_id binding
5. **For state consistency**, check the invariant: `total_supply == sum_of_all_balances + sum_of_locked_funds`

---

## 3. Findings

The review surfaced **7 findings** of varying severity. All have been fixed in the code shipped alongside this document, and each fix has a regression test in `tests/test_security_v11rc.py`.

### S-CRIT-1 — Negative fee enables baker theft (CRITICAL)

**Description**: The `Transaction` model accepted any integer for `fee`. The `_debit_fee` handler in `chain.py` checked `if bal < tx.fee`, then debited the sender with `bal - tx.fee` and credited the baker with `+tx.fee`. With a negative `fee`:

- `bal < -1000` is `False` (assuming `bal >= 0`), so the fee-debit check passed
- Sender's balance became `bal - (-1000) = bal + 1000` (credit, not debit)
- Baker's balance was credited with `-1000` (i.e., debited)

**Impact**: An attacker could drain the baker's balance with a single transaction. A coordinated attack of many transactions would drain every baker in turn, halting the chain.

**Proof of concept (in original code)**:
```
Before: attacker=1000, baker=1000000
Tx: fee=-500000 (signed by attacker)
After:  attacker=501000, baker=500000     ← 500k STOLEN
```

**Fix**: Added `Transaction.__post_init__` that raises `ValueError` if `fee < 0`. This is enforced at construction time, including via `from_dict` (the RPC parsing path), so a negative-fee transaction never reaches the mempool.

**Regression test**: `test_s_crit_1_negative_fee_rejected_at_construction`, `test_s_crit_1_negative_fee_rejected_via_from_dict`

### S-CRIT-2 — Negative amount in TRANSFER enables theft from "recipient" (CRITICAL)

**Description**: The `Transaction.amount` field accepted any integer. The TRANSFER handler in `apply_transaction` called `_debit(sender, amount)` and `_credit(recipient, amount)`. With a negative `amount`:

- `_debit(sender, -500k)`: checks `bal < -500k`, which is False, then does `bal - (-500k) = bal + 500k` (sender gains)
- `_credit(recipient, -500k)`: does `bal + (-500k) = bal - 500k` (named "recipient" loses)

**Impact**: Even worse than S-CRIT-1: an attacker could drain ANY ADDRESS (not just the baker) by naming it as recipient. No relationship with the victim is required.

**Proof of concept (in original code)**:
```
Before: attacker=10000, victim=1000000
Tx: amount=-500000, recipient=victim
After:  attacker=509000, victim=500000    ← 500k STOLEN
```

**Fix**: Same as S-CRIT-1 — `__post_init__` rejects `amount < 0`.

**Regression test**: `test_s_crit_2_negative_amount_rejected_at_construction`, `test_s_crit_2_negative_amount_rejected_via_from_dict`

### S-MAJ-1 — No cross-network replay protection (MAJOR)

**Description**: The `_signed_payload` method did not include any chain identifier. A transaction signed for devnet (e.g., `sender=A, nonce=0, recipient=B, amount=1000`) would have the same signed payload — and therefore the same valid signature — on testnet and on mainnet.

**Impact**: If a user signed a transaction for devnet and the corresponding nonce was unused on mainnet, an attacker could replay the same transaction on mainnet, draining the user's mainnet funds. The risk is particularly acute for users who reuse wallets across networks (common in development).

**Fix**:

1. Added `chain_id: Optional[str]` field to `Transaction`
2. Included it in `_signed_payload`, so the signature binds to the network
3. Updated `from_dict` to round-trip `chain_id`
4. Networks ship with their canonical chain_ids in genesis:
   - Devnet: `kern-devnet`
   - Previewnet: `kern-previewnet`
   - Yggdrasil: `kern-yggdrasil`
   - Midgard: `kern-midgard`

Transactions with `chain_id=None` (legacy) still work — they verify if the node operator hasn't enforced chain_id. Production nodes will enforce a chain_id check in mempool admission.

**Regression test**: `test_s_maj_1_chain_id_changes_signature`, `test_s_maj_1_chain_id_signature_does_not_verify_cross_network`, `test_s_maj_1_chain_id_none_is_self_consistent`

### S-MAJ-2 — Slash handler permanently locked unslashed portion of bond (MAJOR)

**Description**: In `_apply_slash_attestation_equivocation`, after a 30% slash, the remaining 70% of the bond stayed in the `attestation.bond` field forever:

- Could not be reclaimed via revoke (the `consumed_for_slashing` flag blocks it)
- Was not credited to any account
- Counted in `total_supply` (because we only subtracted the burned 27%)

**Impact**: Two separate problems:

1. **Accounting invariant violation**: `total_supply != sum_of_balances + sum_of_locked_bonds`, because the unreachable portion was counted in supply but in no account. This breaks the conservation invariant that every L1 needs.
2. **Misleading economic semantics**: the documented "30% slash" was effectively "100% loss" because the issuer could not retrieve the remaining 70%. The whitepaper and `attestations.md` claim 30%; the code did 100%.

**Fix**: After slashing the 30%, refund the remaining 70% to the issuer. Now:

- Slash: 30% (split 10% whistleblower / 20.7% burn / kept as `slash * 90/100` ratio inside the slash function)
- Refund: 70% returned to the issuer
- Bond field zeroed out (fully resolved)
- `total_supply` exactly tracks `sum_of_balances + sum_of_locked_bonds`

**Regression test**: `test_s_maj_2_slash_refunds_unslashed_portion_to_issuer`, `test_s_maj_2_supply_consistency_after_slash`

### S-MED-1 — `_index_key` collision via separator in inputs (MEDIUM)

**Description**: The attestation reverse-index key was built as `f"{issuer}|{schema_id}|{subject}"`. If `schema_id` or `subject` contained `|`, two distinct logical tuples mapped to the same key:

```
(A, "foo",     "bar|baz") → "A|foo|bar|baz"
(A, "foo|bar", "baz")     → "A|foo|bar|baz"   ← COLLISION
```

**Impact**: An attestation under a crafted `(schema, subject)` could end up at the same index entry as a legitimate one, causing `attestations_for(...)` to return both, potentially:

- Confusing consumers reading `latest_attestation`
- Creating a confusing equivocation-detection result
- Not exploitable for direct theft, but breaks the indexing invariant

**Fix**: Length-prefixed encoding: `f"{len(issuer)}:{issuer}|{len(schema_id)}:{schema_id}|{len(subject)}:{subject}"`. The length prefix unambiguously delimits each field even if the field contains `|`.

**Regression test**: `test_s_med_1_index_key_no_collision_with_separator_in_subject`, etc.

### S-MED-2 — `verify_zk_claim` accepted non-int proof points (MEDIUM)

**Description**: The structural validation in `verify_zk_claim` checked list lengths but not element types. A malicious payload like `proof_a = ["string", "garbage"]` passed the structural validation and (in the v1.1-rc stub) returned `True`.

**Impact**: For v1.1-rc this is a stub, so the impact is limited to giving false confidence in the demonstrator. But if any consumer code reads ZK-claim fields without further validation (e.g., a downstream Skald contract that branches on `claim.proof.a[0]`), it might misbehave.

**Fix**: Added explicit `isinstance(x, int)` checks on all proof point elements and public inputs.

**Regression test**: `test_s_med_2_verify_rejects_non_int_proof_a`, `_b`, `_c`, `_public_inputs`, plus `test_s_med_2_verify_accepts_well_formed`.

### S-MIN-1 — No range check on `gas_limit` and `nonce` (MINOR)

**Description**: The `Transaction` model accepted negative `gas_limit` or `nonce`. These are not directly exploitable for theft (the nonce check catches mismatched nonces; gas accounting doesn't underflow), but they violate the type-correctness contract.

**Impact**: Defense-in-depth. Not directly exploitable.

**Fix**: Same `__post_init__` rejects negative `gas_limit` and `nonce`.

---

## 4. Areas NOT exhaustively reviewed (deferred to professional audit)

The professional audit must cover these surfaces, which received only a skim in this internal review:

### 4.1 BFT consensus (`kern/bft.py`)

Subjects to verify:
- Double-signing detection completeness
- Long-range attack resistance
- Equivocation slashing at consensus level (separate from v1.1 attestation slashing)
- Validator set updates and the activation level for new validators
- View change protocol completeness and liveness

### 4.2 Rollup framework (`kern/rollup.py`, `kern/evm/*`)

Subjects to verify:
- Bisection-based fraud proof completeness
- Forced inclusion mechanism (`kern/forced_inclusion.py`) for censorship resistance
- EVM dynamic gas accounting at every opcode
- BN254 precompile boundary cases (point-at-infinity, non-curve points, twist attacks)
- State channel and frame management

### 4.3 Skald language (`kern/skald/*`)

Subjects to verify:
- Typechecker soundness (no false-positives where unsafe code typechecks)
- Interpreter consistency with typechecker (no runtime behavior the typechecker doesn't model)
- Storage layout and serialization roundtrips
- Invariant enforcement on every state-mutating entry point
- Gas accounting for every Skald operation

### 4.4 Governance (`kern/governance.py`)

Subjects to verify:
- Phase transitions and timing
- Bond settlement on each terminal phase
- Vote-equivocation slashing
- Treasury proposal execution atomicity
- Protocol amendment activation (function swaps, parameter changes)

### 4.5 Network and persistence (`kern/network.py`, `kern/storage.py`, `kern/trie.py`)

Subjects to verify:
- Storage trie merklization correctness
- Network message authentication
- DoS resistance (rate limiting, message size limits)
- Peer discovery and gossip soundness

### 4.6 RPC (`kern/rpc.py`)

Subjects to verify:
- Input validation on all endpoints
- Authentication where needed (currently no auth — open RPC)
- Pagination soundness
- Denial-of-service via crafted queries

---

## 5. Summary table

| Finding | Severity | Status | Regression test |
|---|---|---|---|
| S-CRIT-1: Negative fee enables baker theft | CRITICAL | ✅ Fixed | ✅ |
| S-CRIT-2: Negative amount enables recipient theft | CRITICAL | ✅ Fixed | ✅ |
| S-MAJ-1: No cross-network replay protection | MAJOR | ✅ Fixed | ✅ |
| S-MAJ-2: Slash handler locks unslashed bond | MAJOR | ✅ Fixed | ✅ |
| S-MED-1: `_index_key` collision with separator | MEDIUM | ✅ Fixed | ✅ |
| S-MED-2: `verify_zk_claim` lax type checks | MEDIUM | ✅ Fixed | ✅ |
| S-MIN-1: No range checks on gas_limit/nonce | MINOR | ✅ Fixed | (covered by S-CRIT tests) |

All findings closed. **Audit cycle 1 is still required before mainnet.**

---

## 6. Test count after security fixes

| Phase | Count |
|---|---:|
| v1.0-rc baseline | 378 |
| v1.1-rc additions (5.1-5.4) | +88 |
| **Security regression suite** (S-CRIT-1, S-CRIT-2, S-MAJ-1, S-MAJ-2, S-MED-1, S-MED-2) | **+17** |
| Updated v1.1-rc tests reflecting the new behavior | (modifications, no count change) |
| **Total passing tests** | **483** |
| Chaos tests skipped (intentional) | 2 |

---

## 7. Next steps

1. ✅ This security review documented and fixes applied
2. 🟡 Founder commits and pushes the fixes
3. 🔵 Engage professional audit firm (target: Trail of Bits, OtterSec, Hashlock, RV, ChainSec)
4. 🔵 Provide this document to the audit firm as input
5. 🔵 Audit cycle 1 — 6-12 weeks
6. 🔵 Apply audit findings, re-test, audit cycle 2
7. 🔵 Public release of audit reports

See [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md) §D for the full audit workflow.

---

## 8. Acknowledgments

This review was conducted by Nicolas Van Eeckhout (founder of Kern) over a focused session. The methodology drew on:

- "Smart Contract Security Verification Standard" (SCSVS), OWASP
- "Decentralized Application Security Verification Standard" (DASP)
- Trail of Bits' "Building Secure Smart Contracts" (Solidity-focused but principles transfer)
- Lessons from past audits of Tezos (CertiK, Inria), Ethereum (Trail of Bits, ConsenSys Diligence), and Cosmos (Informal Systems)

The fact that an internal review surfaced two CRITICAL vulnerabilities reinforces, rather than diminishes, the need for the professional audit. **Hidden bugs are still there. We just don't know them yet.**

---

## 9. Reference

- Fix commits: see git history for files `kern/transaction.py`, `kern/chain.py`, `kern/attestation.py`, `kern/zk_claims.py`
- Regression tests: [`tests/test_security_v11rc.py`](../tests/test_security_v11rc.py)
- Audit checklist: [`pre-mainnet-checklist.md`](pre-mainnet-checklist.md)
- Audit setup guide: [`setup-auditor.md`](setup-auditor.md)
