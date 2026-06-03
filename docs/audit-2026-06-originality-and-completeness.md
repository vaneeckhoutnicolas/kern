# Audit — Originality & Completeness (2026-06)

**Release:** `v1.1.0-rc2`
**Scope:** (1) independent originality / plagiarism review of the reference
implementation, and (2) a repository completeness pass. This document is the
companion record to [`originality-and-attribution.md`](originality-and-attribution.md)
and follows on from [`review-2026-05.md`](review-2026-05.md).

This is an engineering audit record, not legal advice. The securities-regime
statements below carry the same caveat as [`disclaimer.md`](disclaimer.md):
engage licensed counsel before any template is used for a real raise.

---

## Part A — Originality / plagiarism

**Verdict: no copied code found.** The reference implementation is original
Python. The four audit-trail checks in `originality-and-attribution.md` all pass
(no "copied from / adapted from / fork of" disclaimers; no non-Kern copyright
headers; `SPDX-License-Identifier: Apache-2.0` on every `.py` file; founder
attribution intact). Beyond those checks, the code was reviewed directly on the
components most prone to copying:

| Component | Finding |
|---|---|
| Cryptography (`crypto.py`) | Ed25519 (PyNaCl), blake2b-256, base58check with a **blake2b** checksum. This is *not* Ethereum's stack (secp256k1 / keccak256 / hex addresses) and *not* Bitcoin/Tezos base58check (double-SHA256 checksum). Copied code would carry the source project's primitives; it does not. |
| State trie (`trie.py`) | A binary radix trie with domain-separated blake2b hashing (`kern.trie.leaf` / `kern.trie.branch`), explicitly **not** Ethereum's hex-Patricia + RLP trie. Original design. |
| EVM (`evm/vm.py`, `evm/opcodes.py`) | A hand-written step executor built around per-instruction state commitments for the bisection fraud-proof protocol — a different architecture from py-evm's `Computation`/`Opcode` objects. Opcode **values** and gas **costs** match the Yellow Paper, which is a public specification: matching it is required for bytecode compatibility and is not copying. |
| BN254 (`evm/bn254.py`) | `py_ecc` is **imported** (with a graceful fallback), not vendored — exactly as declared. Curve arithmetic is written from the public BN128 parameters. |
| Consensus (`bft.py`) | A clean-room Python implementation of the **published** Tenderbake algorithm. Tezos is written in OCaml, so code copying is not even possible; implementing a published algorithm from its specification is standard practice. |

**One honest nuance — "original code" ≠ "original design."** The *code* is the
project's own, but several core *design patterns* are adopted from published
prior art (Tenderbake consensus, Ed25519 + base58check addressing, liquid-PoS
delegation, and Tezos-flavoured vocabulary such as `level` / `endorse`). This is
legal, conventional, and already documented in
`originality-and-attribution.md`. The accurate framing for an external auditor
is: *original implementation of publicly-specified algorithms, with influences
credited.* No action required.

---

## Part B — Completeness corrections applied in this release

### B1 — MiCA → securities-regime correction **completed** in code and assets · **[FIXED]**

[`review-2026-05.md`](review-2026-05.md) described the securities-vs-MiCA scope
correction as applied "throughout the repository." In fact only the **identifier
renames** had landed (`is_mica_compliant` → `is_compliant`,
`kern_sto_contracts_mica_compliant` → `kern_sto_contracts_compliant`, JSON field
`mica_compliant` → `compliant`). The human-facing **citations, labels, comments,
error strings, and prose** still framed the three STO templates as MiCA
instruments — the exact error MiCA Art. 2(4) excludes (tokenized equity, fund
units, and real-estate fund interests are financial instruments under MiFID II).

This release completes the correction, using the regime mapping already endorsed
in the `sto-mica.md` correction box and `v11rc-changes.md`:

| Was (MiCA) | Now (securities regime) |
|---|---|
| MiCA Art. 14 (whitepaper) | **Prospectus Regulation** Art. 3 (prospectus) |
| MiCA Art. 50 (custody) | **MiFID II** Art. 16(9) / **AIFMD** Art. 21 |
| MiCA Art. 88 (market abuse) | **MAR** Art. 14 |
| MiCA Art. 13 (qualified investor) | **Prospectus Regulation** Art. 2(e) |
| "MiCA compliance" (of an STO) | "securities compliance" |

Surfaces corrected:

- **Skald contracts** — `sto-startup-equity.skald`, `sto-real-estate.skald`,
  `sto-institutional-fund.skald`: header blocks, inline article citations, and
  the `require ... with "..."` error strings. (State-variable names such as
  `whitepaper_registered` / `prospectus_registered` were left unchanged to avoid
  altering the contract interface.)
- **Explorer** — `kern_explorer/metrics.py` (metric help text),
  `kern_explorer/indexer.py` (comment), `kern_explorer/templates/base.html`
  (nav title).
- **Monitoring** — `kern_explorer/monitoring/alerts/kern-alerts.yml`
  (alert summary/annotation text).
- **Website** — `kern_site/glossary.html`, `kern_site/use-cases.html`
  (the animated invariant cards), `kern_site/manifesto.html`. `whitepaper.html`
  was **regenerated** from the corrected `docs/whitepaper.md` via
  `build_whitepaper.py` (it is a generated artifact).
- **Docs** — `whitepaper.md`, `manifesto.md`, `legal-audit.md` (the manifesto
  blockquote and the matching analysis sentence), `naming-and-symbolism.md`,
  `skald-language.md`, `heimdall-ops-runbook.md`, `heimdall-rfp-next-gen.md`,
  `post-code-roadmap.md`; the `mkdocs.yml` nav label "STO MiCA compliance" →
  "STO securities compliance".
- **Tests** — `tests/test_heimdall_session2.py`: two mis-framed comments and one
  stale UI assertion (`"MiCA OK"` → `"Compliant"`, matching the actual badge).

**Legitimate MiCA references were deliberately retained**, namely: regulatory
landscape lists ("MiCA, AIFMD, MiFID II, DORA…"); the Art. 2(4) **exclusion**
statement itself; the discussion of **KRN-the-utility-token** classification
under MiCA (a genuinely in-scope question); the forbidden-marketing-phrase list
in `legal-audit.md` ("MiCA-certified", "MiCA-approved"); and the
characterization of MiCA as a coherent crypto-asset framework in the manifesto.
The filename `sto-mica.md` was kept (per the maintainer decision in
`review-2026-05.md`) to preserve inbound links; its content opens with the
correction box, and its §2 article-by-article prose remains explicitly
illustrative pending counsel review.

### B2 — Stale `LICENSE.GPL` removed · **[FIXED]**

`review-2026-05.md` recorded the removal of `LICENSE.GPL` as part of the
LGPL-3.0 → Apache-2.0 migration, but the 35 KB GPLv3 file was still present in
the tree — exactly the kind of stray file a licence scanner flags in a
permissively-licensed repo. It has now been deleted. `LICENSE` (Apache-2.0),
`NOTICE`, and `LICENSE-DOCS.md` (CC-BY-SA-4.0 for docs) remain; 0 SPDX headers
reference GPL/LGPL.

### B3 — `pyyaml` (and explorer deps) added to the `dev` extra · **[FIXED]**

Three Heimdall test modules import `yaml`, `httpx`, and `fastapi`/`jinja2`. Of
these, `pyyaml` was declared **nowhere**, so a clean `pip install -e .[dev]`
silently dropped ~150 tests from collection. The `dev` extra is now
self-sufficient for the full suite: it pulls in `pytest`, `httpx`, **`pyyaml`**,
`fastapi`, `uvicorn[standard]`, and `jinja2`.

### B4 — mkdocs nav & a broken link · **[FIXED]**

- `docs/fee-floor.md` (a substantive feature doc) and `docs/building-the-site.md`
  were on disk but absent from the mkdocs nav; both are now surfaced
  (Protocol and Build & run respectively).
- `docs/review-2026-05.md` linked `LICENSE-DOCS.md` as if it lived under `docs/`;
  the link now points to `../LICENSE-DOCS.md` (repo root).

---

## Verification

All checks were run after the corrections:

- **Tests:** `692 passed, 2 skipped` (full suite, with the now-self-sufficient
  `dev` extra). The edited Skald contracts still typecheck.
- **Code-wide MiCA audit:** the only remaining whole-word `MiCA` in
  `kern/`, `kern_explorer/`, and `tests/` is the **correct** exclusion
  statement in `tests/test_sto_templates.py`. No STO is described as a MiCA
  instrument anywhere in code, contracts, metrics, alerts, or templates.
- **Licence:** 0 GPL/LGPL SPDX headers; `LICENSE.GPL` gone; pyproject classifier
  is `Apache Software License`.
- **Docs site:** every `mkdocs.yml` nav target resolves; no broken in-docs
  `.md` links remain.
- **pyproject:** parses; `version = "1.1.0rc2"`.

---

## Release metadata

- **Package version:** `1.1.0rc2` (PEP 440), in `pyproject.toml`.
- **Git tag:** `v1.1.0-rc2` (annotated). Per
  [`release-tagging.md`](release-tagging.md), sign with `git tag -s` once a GPG
  key is configured; the tag in this bundle is annotated but unsigned because no
  signing key is available in the build environment.
- **Nature:** a correctness / hygiene release candidate over `v1.1.0-rc1`; no
  protocol or API behaviour changes (string, label, dependency, and packaging
  changes only).
