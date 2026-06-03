# Publishing this repository to GitHub

The contents of this folder are ready to push to a fresh GitHub repository. The steps below assume you have `git` installed and a GitHub account.

## 1. Create an empty repository on GitHub

Go to https://github.com/new and create a new repository (e.g. `kern`). **Do not** initialize it with a README, .gitignore, or license — those already exist in this folder.

Note the URL it gives you, e.g. `https://github.com/vaneeckhoutnicolas/kern.git`.

## 2. Initialize git locally and push

From inside this folder:

```bash
git init
git add .
git commit -m "Initial commit — Kern reference implementation v0.1"
git branch -M main
git remote add origin https://github.com/vaneeckhoutnicolas/kern.git
git push -u origin main
```

That's it. The repository will appear on GitHub with the README rendered on the landing page.

## 3. (Recommended) Add a few repository touches

On the GitHub page for the repo:

- Set the description: *"Kern — a Layer-1 blockchain protocol. Reference implementation in Python."*
- Add topics: `blockchain`, `layer-1`, `bft-consensus`, `proof-of-stake`, `smart-contracts`, `tezos`, `ethereum`, `python`
- Enable Issues (Settings → General → Features).
- Enable Discussions if you want community Q&A.

## 4. (Optional) Add a CI workflow

A minimal GitHub Actions workflow that runs the test suite on every push lives well at `.github/workflows/test.yml`:

```yaml
name: tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt pytest
      - run: python -m pytest tests/ -v
```

Add it, commit, push, and CI will run on every change.

## What's deliberately excluded from the repo

The `.gitignore` excludes:

- `keys/` — the directory containing private signing seeds. **Never commit private keys.**
- `data/` — runtime node state. Each operator's node has its own.
- `__pycache__/`, `*.sqlite*` — generated artifacts.

If you want to commit the genesis file you used for testing (so others can replicate), it's already at `genesis.json` in the repo root and *is* tracked by default.
