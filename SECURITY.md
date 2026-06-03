# Security Policy

Kern is pre-audit software under active development. We take the security of the
protocol, the Skald contract language, and the reference implementation seriously,
and we appreciate responsible disclosure.

## Supported versions

| Version    | Status                    | Security updates |
| ---------- | ------------------------- | ---------------- |
| v1.1-rc    | Current release candidate | Best-effort      |
| < v1.1-rc  | Superseded                | No               |

Kern has **not yet undergone an independent security audit** — a professional audit
is a gating item before the Yggdrasil testnet (see the roadmap). The software is
provided "as is", without warranty. Do not deploy it with real value.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.** A public report
of an exploitable flaw — especially in consensus, the EVM execution layer, the Skald
type checker, or the cryptographic primitives — can put any deployment at risk before
a fix is available.

Instead, report it privately through **GitHub Private Vulnerability Reporting**:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected component, and — ideally — a reproduction or
   proof of concept.

This opens a private advisory visible only to the maintainers.

### Consensus and cryptographic issues — coordinated disclosure

Bugs affecting **consensus safety or liveness, fund security, Skald invariant
enforcement, or the cryptographic layer** are treated as critical. For these, please:

- report privately (never publicly), and
- allow a reasonable window for a fix — and, where relevant, a coordinated release —
  before any public disclosure.

## What to expect

This is a small, independently maintained project. We aim to:

- acknowledge a valid report within a few business days,
- keep you informed as we investigate and remediate, and
- credit you in the advisory / release notes once a fix ships, if you wish.

## Scope

**In scope:** the protocol design, the Python reference implementation (`kern/`), the
Skald compiler and type checker, the Heimdall explorer (`kern_explorer/`), and the
deployment tooling (`docker/`, `scripts/`).

**Out of scope:** marketing-site content (`kern_site/`), third-party dependencies
(report those upstream — we track them via Dependabot), and theoretical issues without
practical impact on a node or a contract.

## Bug bounty

There is **no paid bug bounty yet**. A bounty program is planned around the testnet
and audit phases. Until then, disclosures are handled on a goodwill basis.
