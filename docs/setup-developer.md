# Setup Guide — Developer

**Audience**: Anyone cloning the Kern repository to contribute code, tests, documentation, or tooling.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- Python 3.11 or later (`python3 --version`)
- Git 2.30 or later (`git --version`)
- 4 GB RAM, 10 GB disk free
- Familiarity with Python, pytest, and basic git workflow

**What this guide covers**: Clone the repo, install dependencies, run the test suite, make a change, verify, submit a pull request.

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern
```

If you plan to contribute, fork first on GitHub then clone your fork:

```bash
git clone https://github.com/<your-username>/kern.git
cd kern
git remote add upstream https://github.com/vaneeckhoutnicolas/kern.git
git fetch upstream
```

**Verification**:
```bash
ls -la
# Expected: AUTHORS, LICENSE, README.md, pyproject.toml, kern/, docs/, tests/
```

---

## Step 2 — Set up the Python environment

Recommended: virtual environment to isolate dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate

# Upgrade pip first
pip install --upgrade pip

# Install Kern with all dev and doc extras
pip install -e ".[dev,docs]"
```

**Verification**:
```bash
python -c "import kern; print(kern.__file__)"
# Expected: path inside the cloned repo's kern/__init__.py

pip show kern | head -5
# Expected: Name: kern, Version: 1.0.0rc1
```

---

## Step 3 — Run the full test suite

```bash
pytest tests/ -v
```

**Verification**: You should see exactly:
```
======================= 368 passed, 2 skipped in ~10s ========================
```

If any test fails on a fresh clone, that's a bug. Open an issue immediately.

To run a single test file:
```bash
pytest tests/test_delegation.py -v
```

To run with coverage (optional, requires `pip install coverage`):
```bash
coverage run --source=kern -m pytest tests/
coverage report -m
```

---

## Step 4 — Set up your git identity (for proper attribution)

```bash
git config user.name "Your Name"
git config user.email "your-real-email@example.com"

# Strongly recommended: sign your commits with GPG
git config user.signingkey <your-gpg-key-id>
git config commit.gpgsign true
```

This is important: the contributors program ([contributors-program.md](contributors-program.md)) attributes pre-mainnet contributions for KRN grants from the 3M contributors pool. Stable git identity = clear attribution.

**Verification**:
```bash
git config --list | grep user
git config --list | grep commit.gpgsign
```

---

## Step 5 — Make a contribution

Create a feature branch:

```bash
git checkout -b feature/<short-description>
```

Make your changes. Then before committing:

```bash
# 1. Run the test suite
pytest tests/

# 2. Run the markdown link checker (catches doc breakage)
python3 -c "
import re
from pathlib import Path
link_re = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
broken = []
for md in sorted(Path('.').rglob('*.md')):
    if 'data' in md.parts or '.pytest' in md.parts: continue
    text = md.read_text()
    for m in link_re.finditer(text):
        target = m.group(2)
        if target.startswith(('http://', 'https://', 'mailto:', '#')): continue
        path = target.split('#')[0]
        if not path: continue
        if not (md.parent / path).resolve().exists():
            broken.append((str(md), target))
print(f'BROKEN: {len(broken)}' if broken else 'All markdown links resolve.')
for src, link in broken: print(f'  {src}: [{link}]')
"

# 3. Verify SPDX headers exist on any new .py file you added
grep -L "SPDX-License-Identifier: Apache-2.0" $(git diff --name-only --cached --diff-filter=A | grep '\.py$')
# Expected: no output (all new files have the header)
```

If any new Python files lack the header, add at top:
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
```

---

## Step 6 — Commit and push

```bash
git add <your-files>
git commit -m "Short summary line (50 chars max)

Longer description if needed. Wrap at 72 chars.

Refs #<issue-number> if applicable."
```

Push to your fork:
```bash
git push origin feature/<short-description>
```

Then open a pull request on GitHub against `kern-protocol/kern:main`.

---

## Step 7 — Pull request checklist

Before requesting review, confirm:

- [ ] All tests pass: `pytest tests/`
- [ ] Markdown links resolve (see Step 5 script)
- [ ] SPDX headers on new Python files
- [ ] No `print()` debugging left in production code
- [ ] New tests added for new functionality
- [ ] Documentation updated if behavior changed (in `docs/`)
- [ ] Commit messages are clear and self-contained
- [ ] No commits accidentally including `keys/`, `data/`, or `__pycache__/`

The `.gitignore` should prevent the last item, but verify:
```bash
git status
# Expected: no `keys/*`, `data/*`, `__pycache__/*` in staged or unstaged
```

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'kern'` | Not installed in editable mode | `pip install -e .` |
| `pytest` collects 0 tests | Running from wrong directory | `cd` to repo root |
| `py_ecc` import errors during BN254 tests | Missing dep | `pip install -e ".[dev]"` |
| Markdown link check fails on `../kern/X.py` | False positive — mkdocs links to source code | Expected; ignore source-file warnings outside `docs/` |
| Tests pass locally, fail on CI | Different Python version | Pin to 3.11 in pyproject.toml `requires-python` |
| Commit rejected: "missing signoff" | Project requires signed commits | `git commit -s` or configure GPG signing (Step 4) |

---

## What to work on

If you don't know what to contribute, the [roadmap](roadmap.md) lists open milestones. Specifically:

- **v1.0-rc → v1.0**: audit findings remediation, doc polish, edge-case test coverage
- **v1.x**: BN254 via blst FFI (10x speedup), more EVM opcodes, additional Skald examples
- **Heimdall** (the official explorer): Sessions 2-4 of the Heimdall delivery plan — per-vertical dashboards, Grafana stack, UI polish (see [setup-heimdall-operator.md](setup-heimdall-operator.md))
- **Tooling**: wallet integrations, IDE tools for Skald
- **Skald applications**: AMMs, lending, identity contracts demonstrating the invariants pattern

Contributions that qualify for KRN grants from the contributors pool are tracked per [contributors-program.md](contributors-program.md).

---

## Next steps

- Read [architecture.md](architecture.md) to understand the code layout.
- Read [api-stability.md](api-stability.md) to know which surfaces you can rely on or extend.
- Read [skald-language.md](skald-language.md) if you'll work on the contract language.
- Read [governance.md](governance.md) if you'll work on the on-chain governance.
- Once your devnet runs, point [Heimdall](setup-heimdall-operator.md) at it — you get a live block explorer and Prometheus metrics for the chain you're hacking on, which is the fastest way to verify your changes have the effect you expect.
- Subscribe to the project mailing list (TBD) for design discussions.
