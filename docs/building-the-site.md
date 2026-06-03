# Building and Publishing the Documentation Site

This document describes how to build the Kern documentation site (`docs.kern.protocol` or wherever it's hosted) from this repository.

The intent: the markdown source in `docs/` is the canonical content. **mkdocs-material** adds rendering, navigation, search, and dark mode. The `mkdocs.yml` config at the repo root drives the build.

---

## Local preview

```bash
# Install the docs dependencies
pip install -e ".[docs]"
# or: pip install mkdocs mkdocs-material pymdown-extensions

# Live-reload preview at http://127.0.0.1:8000
mkdocs serve

# One-shot build to ./site/
mkdocs build
```

The `mkdocs serve` command watches `docs/` and `mkdocs.yml` for changes and reloads in the browser.

---

## Publishing to GitHub Pages

Once the repo is hosted at `github.com/vaneeckhoutnicolas/kern`:

```bash
# This builds and pushes to the gh-pages branch.
mkdocs gh-deploy --force
```

GitHub Pages will then serve the site at:
- `https://kern-protocol.github.io/kern/` (default)
- `https://docs.kern.protocol/` (with custom CNAME)

For a custom domain, add a `CNAME` file in `docs/` containing the domain (e.g., `docs.kern.protocol`) — mkdocs will copy it to the gh-pages branch on each deploy. DNS for the domain must point CNAME records to `<username>.github.io`.

---

## Continuous deployment (recommended)

A GitHub Actions workflow can build the site on every push to `main`:

```yaml
# .github/workflows/docs.yml
name: Deploy docs

on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # for git-revision dates
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e ".[docs]"
      - run: mkdocs gh-deploy --force
```

This keeps `docs.kern.protocol` in sync with `main` automatically. No manual deploys.

---

## What the site contains

The `nav:` section of `mkdocs.yml` defines the structure:

1. **Overview** — executive summary, whitepaper, use cases, roadmap, landing
2. **Token economy** — tokenomics, staking, contributors program, issuance
3. **Protocol** — architecture, consensus, BFT, governance, trie
4. **Smart contracts** — Skald language, type checker
5. **Rollups & EVM** — rollup framework, multi-frame EVM, fraud proofs, forced inclusion
6. **Build & run** — node ops, API reference, API stability spec
7. **Change history** — per-version change docs

The landing page (`docs/index.md`) is rendered at the site root.

---

## What's NOT in the site

The README at the repository root is **not** rendered by mkdocs — it's GitHub's homepage for the project and serves a different audience (developers cloning the repo). Some duplication is intentional: the README is the "code-first" entry point; the mkdocs site is the "protocol-first" entry point.

If you want the README in the site, add it to `nav:` and use `docs/README.md` (mkdocs cannot pull from the repo root by default — you'd symlink or copy at build time).

---

## Adding a new page

1. Create `docs/your-new-page.md`.
2. Add an entry to `nav:` in `mkdocs.yml` under the appropriate section.
3. `mkdocs serve` to preview, `mkdocs gh-deploy --force` to publish.

All cross-doc links use relative markdown links (e.g., `[tokenomics](tokenomics.md)`) — they work both in GitHub's rendering of the source and in the rendered site.
