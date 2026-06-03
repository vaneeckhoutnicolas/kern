# Originality and Attribution

This document is the technical companion to [AUTHORS](../AUTHORS). It addresses two related questions:

1. **Is the Kern reference implementation original code?** (Answer: yes.)
2. **How is the founder's authorship preserved despite the Apache-2.0 license that permits derivatives?**

---

## 1. The originality claim

The Kern reference implementation at v1.0-rc is **original Python source code** authored under the direction and design specification of **Nicolas Van Eeckhout** — founder of [Cogarius](https://www.cogarius.com), [contributor to the Tezos ecosystem](https://github.com/tezos-checker/checker-ui), and co-founder of the [Brussels Meetup Blockchain-Ethereum group](https://www.meetup.com/meetup-blockchain-ethereum-bruxelles/). It is not a fork, port, or copy of any other blockchain codebase.

### What "original" means here

Specifically:

- **No source code is copied from any external project.** Every line of Python in `kern/` was written for Kern.
- **External public specifications are implemented from spec.** The EVM opcode semantics follow the Ethereum Yellow Paper (a public specification); the BN254 curve uses the public BN128 parameters; gas costs follow public EIP standards (EIP-2200, EIP-197). Implementing a public specification is not copying — it is what every implementor does.
- **Design influences are noted in code where relevant.** Where Kern's design implements a pattern that is already part of the public state-of-the-art in blockchain design (e.g., delegated Liquid Proof-of-Stake, dual-track on-chain governance), the relevant code includes a brief comment noting the pattern (e.g., `# Liquid PoS baking delegation`), but the implementation itself is fresh Python.
- **One external library dependency is used:** `py_ecc` (Ethereum Foundation's reference Python BN128 library). This is imported via Python's standard import mechanism. The dependency is declared in `requirements.txt` and `pyproject.toml`. The library's source code is not vendored into this repo.

### Audit trail

If you want to verify this independently:

```bash
# 1. Search for any disclaimer-style references to external code:
grep -rni "copied from\|adapted from\|fork of\|borrowed from\|taken from" \
    --include="*.py" .
# Expected: zero matches.

# 2. Search for copyright headers other than Kern:
grep -rn "Copyright (c)\|Copyright (C)" --include="*.py" . | \
    grep -v "Nicolas Van Eeckhout"
# Expected: zero matches.

# 3. Check the SPDX header coverage:
for f in $(find . -name "*.py" -not -path "*/__pycache__/*" -not -path "*/keys/*"); do
    if ! grep -q "SPDX-License-Identifier: Apache-2.0" "$f"; then
        echo "MISSING HEADER: $f"
    fi
done
# Expected: zero "MISSING HEADER" lines.

# 4. Check the founder attribution coverage:
grep -L "Nicolas Van Eeckhout" $(find . -name "*.py" -not -path "*/__pycache__/*" -not -path "*/keys/*")
# Expected: only files without ANY copyright header (none, currently).
```

These four checks are run as part of every audit cycle.

---

## 2. The naming and conceptual originality

Beyond the source code itself, the **identity** of Kern is original to Nicolas Van Eeckhout:

| Element | Origin |
|---|---|
| The name **Kern** (Old Norse: kernel/core) | Original — chosen by Nicolas to express the protocol's role as the "grain of state that endures" |
| The name **Skald** (Old Norse: court poet) for the contract language | Original — chosen to evoke a language that "tells the truth" via declared invariants |
| The Norse cosmology naming for networks (**Yggdrasil** testnet, **Midgard** mainnet) | Original conception |
| The Kern address format (`kn1...` base58check prefix) | Original encoding choice |
| The dual-track governance with proposal bonds + delegated voting + quadratic treasury + equivocation slashing | Original synthesis — no other protocol has all four together |
| The split between Foundation pool (15M, off-chain) and on-chain treasury (grows from issuance) | Original design choice |
| The 100M genesis with 70/10/15/3/2 split | Original parameterization (modeled on Ethereum 2014 template but Nicolas's specific numbers) |
| The integration of multi-frame EVM with native Skald and BFT consensus | Original system design |

---

## 3. How Apache-2.0 preserves the founder's recognition

Apache-2.0 is a permissive license that allows others to use, modify, and even create derivatives of Kern — including in proprietary, closed-source products. This is intentional — Kern's adoption depends on it being usable by application developers and institutions without legal friction.

But Apache-2.0 **does not** allow someone to:

- **Misrepresent authorship** of the original work
- **Strip copyright, license, or attribution notices** from source files (Apache-2.0 §4(c) requires retaining all copyright, patent, trademark, and attribution notices in any derivative)
- **Falsely claim** they wrote the original

### Concretely

If someone forks Kern:

1. They **must keep** the `SPDX-License-Identifier: Apache-2.0` header on every file they distribute.
2. They **must keep** the `Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors` line. They can *add* their own copyright on top (e.g., `Copyright (C) 2027 Jane Doe`), but they cannot remove Nicolas's.
3. They **must include** a copy of the LICENSE file (Apache-2.0) and the readable NOTICE file with any redistribution (Apache-2.0 §4(a) and §4(d)).
4. They **must declare** their modifications as separate from the upstream original.

Violating any of these voids their license to redistribute, and constitutes copyright infringement.

### What happens if attribution is stripped

Stripping the SPDX header, the NOTICE attribution, or the founder's copyright line is a **violation of Apache-2.0 §4** that gives Nicolas (and Kern contributors) standing to:

- File a DMCA notice to GitHub or wherever the offending fork is hosted.
- Send a cease-and-desist letter through Foundation counsel.
- Pursue civil remedies under copyright law in the jurisdiction of the infringement.

The Foundation (once incorporated — see [`setup-foundation.md`](setup-foundation.md)) will hold the moral rights and the legal authority to enforce attribution on behalf of all contributors, with Nicolas retaining individual standing as original author.

### What's allowed without attribution conflict

These uses do *not* require any change to Kern itself, so attribution is preserved transitively:

- **Running a Kern node** — no modification to Kern source code; no attribution issue.
- **Writing Skald contracts** that run on Kern — your contracts are your own work; Kern remains attributed.
- **Building a wallet or block explorer for Kern** — your wallet is your work, Kern source remains attributed in the Kern repository.
- **Building applications on a Kern rollup** — your application is your work.
- **Using Kern from proprietary code** — fully permitted by Apache-2.0 (it is permissive: there is no copyleft and no linking restriction), provided the notices and NOTICE file are retained.

---

## 4. The "moral rights" question

In some jurisdictions (notably France, Germany, Belgium) "moral rights" (*droit moral*) attach to authorship independent of copyright transfer. These typically include:

- **Right of paternity**: the right to be named as the author
- **Right of integrity**: the right to object to modifications that prejudice honor or reputation

Belgian copyright law (Article XI.165 of the Code of Economic Law) recognizes these rights and treats them as inalienable and perpetual.

As Nicolas Van Eeckhout is a Belgian author of the original work, his moral rights to be named as author of the Kern protocol are protected under Belgian law, independent of the Apache-2.0 license terms or any future transfer of economic rights to the Foundation.

This means: even if Nicolas were to transfer all economic rights in Kern to a foundation in the future, his right to be named as the original author **cannot** be transferred away, waived in the Apache-2.0 framework, or extinguished by forks.

---

## 5. Public claim of authorship

This repository, the v1.0-rc tagged release, and every git commit in the history through v1.0-rc are the canonical public record of Nicolas Van Eeckhout's authorship of Kern.

To establish the public claim further:

- The whitepaper ([docs/whitepaper.md](whitepaper.md)) is published in this repository with Nicolas's attribution.
- The executive summary ([docs/executive-summary.md](executive-summary.md)) is published with Nicolas's attribution.
- The AUTHORS file at the repository root is the canonical authorship record.
- The git tag `v1.0.0rc1` is signed (recommended: `git tag -s`) by Nicolas's GPG key, creating a cryptographic attestation of authorship at a specific date.

When the repository is published to GitHub at `github.com/vaneeckhoutnicolas/kern`, the GitHub commit history provides a third-party timestamp service for every commit, further establishing the authorship timeline.

### Recommended public attribution practices

For the author going forward:

1. **Sign every release tag** with `git tag -s vX.Y.Z` (requires GPG key configured).
2. **Use a stable identity** in git commits: `git config user.name "Nicolas Van Eeckhout"` and `user.email` pointing to a long-term professional email.
3. **Mention authorship in talks and publications** — Kern conferences, papers, presentations.
4. **Reserve the brand** — register trademark for "Kern" in the relevant jurisdictions when Foundation is set up. Trademark protects the *name* even after the source code is widely forked.
5. **Pre-publish** key design decisions (whitepaper, tokenomics, roadmap) on platforms that timestamp: arXiv, IPFS with named pins, or formal Foundation announcements.

---

## 6. Originality verification by independent auditors

When audit cycle 1 begins (see [setup-auditor.md](setup-auditor.md)), the engaged audit firm will be specifically asked to confirm:

1. The codebase is original Python (not vendored from another project).
2. The SPDX headers are consistent and present on all files.
3. The copyright attribution to Nicolas Van Eeckhout is preserved.
4. The external dependencies (just `py_ecc`, `pynacl`, `aiohttp`) are used as standard imports, not as vendored copies.
5. The design influences cited in comments and documentation are credited but not represented as Kern's own innovation.

The audit report will include a formal attestation of originality, which becomes part of the public Foundation record.

---

## 7. If you suspect attribution violation

If you find a fork, derivative work, or third-party product that:

- Strips the Apache-2.0 SPDX header, the NOTICE attribution, or Nicolas's copyright line
- Claims original authorship of Kern's design or code
- Uses the "Kern" trademark without authorization (after trademark registration)
- Misrepresents the protocol's history

Please report it to:

1. **Foundation legal** (once set up) — contact details in the Foundation governance document
2. **Nicolas directly** — for early-stage matters before Foundation incorporation
3. **GitHub DMCA** — for code-hosting violations
4. **Local copyright authority** — in the jurisdiction of the infringement

Including in your report:

- URL or identifier of the offending work
- Specific elements that constitute the violation
- Screenshots or copies preserved as evidence
- Your contact information so we can follow up

---

## Summary

The Kern reference implementation at v1.0-rc is:

- ✅ **Original** Python source written for Kern
- ✅ **Properly attributed** to Nicolas Van Eeckhout in every file's SPDX header
- ✅ **Apache-2.0 licensed** with attribution-preservation requirements
- ✅ **Protected by Belgian moral rights law** (paternity, integrity)
- ✅ **Publicly establishable** via git history, signed tags, and Foundation records
- ✅ **Designed to be forkable** for adoption while requiring attribution

This is the canonical attribution stance for the project.
