# Release Tagging — v1.0.0rc1 and beyond

This document explains how to tag releases of Kern. It is the canonical reference for the release process.

**Owner**: Nicolas Van Eeckhout (founder), and any successor maintainer designated by the Foundation.

---

## Tagging conventions

Kern follows **semantic versioning** with these rules (per [api-stability.md](api-stability.md) §6):

| Tag form | Meaning | Example |
|---|---|---|
| `vX.Y.Z` | Stable release | `v1.0.0`, `v1.1.0`, `v1.0.1` |
| `vX.Y.Z-rcN` | Release candidate (pre-stable) | `v1.0.0-rc1`, `v1.0.0-rc2` |
| `vX.Y.Z-alphaN`, `vX.Y.Z-betaN` | Earlier pre-release | rare; use only if needed |

The Python package version in `pyproject.toml` uses PEP 440:

| pyproject.toml form | Git tag | Notes |
|---|---|---|
| `1.0.0rc1` | `v1.0.0-rc1` | Note the hyphen in the tag but not in pyproject |
| `1.0.0` | `v1.0.0` | Stable |
| `1.0.1` | `v1.0.1` | Patch |

Always confirm the version in `pyproject.toml` matches the intended tag before tagging.

---

## Preparation checklist (before tagging any release)

```bash
# 1. Confirm you're on the right branch
cd /path/to/kern
git checkout main
git status   # should be "nothing to commit, working tree clean"

# 2. Confirm pyproject.toml version matches intended tag
grep '^version' pyproject.toml
# Expected for v1.0.0rc1 release: version = "1.0.0rc1"

# 3. Run the full test suite
pytest tests/
# Expected: 378 passed, 2 skipped (10 wallet CLI + 368 base)

# 4. Run the originality audit
grep -rni "copied from\|adapted from\|fork of" --include="*.py" . | \
    grep -v ".pytest_cache" | grep -v ".venv" | wc -l
# Expected: 0

# 5. Check SPDX coverage on all Python files
for f in $(find . -name "*.py" -not -path "*/__pycache__/*" \
            -not -path "*/keys/*" -not -path "./.venv/*"); do
    if ! grep -q "SPDX-License-Identifier: Apache-2.0" "$f"; then
        echo "MISSING: $f"
    fi
done
# Expected: no output

# 6. Verify all markdown links
python3 -c "
import re
from pathlib import Path
link_re = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
broken = []
for md in sorted(Path('.').rglob('*.md')):
    if 'data' in md.parts or '.pytest' in md.parts or 'site' in md.parts: continue
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
# Expected: All markdown links resolve.

# 7. Verify mkdocs site builds
mkdocs build 2>&1 | tail -3
# Expected: "INFO - Documentation built in <N> seconds"

# 8. Verify the wallet CLI works
python scripts/kern_wallet.py --help | head
# Expected: usage banner with all subcommands
```

If any check fails, **do not tag**. Fix and re-verify.

---

## Step 1 — Sign the commit (recommended for founder)

The founder's release commits should be GPG-signed. This creates a cryptographic attestation of authorship that survives even if GitHub goes away.

```bash
# One-time setup of GPG signing
gpg --full-generate-key   # if you don't have a key already
gpg --list-secret-keys --keyid-format LONG   # find your key ID
git config user.signingkey <YOUR_KEY_ID>
git config commit.gpgsign true
git config tag.gpgsign true   # also sign tags
```

Verify:

```bash
git config --get user.signingkey
git config --get commit.gpgsign   # true
git config --get tag.gpgsign      # true
```

---

## Step 2 — Tag the release

For v1.0.0rc1:

```bash
git tag -a v1.0.0-rc1 -m "Kern v1.0.0rc1

First release candidate. Code-frozen for audit cycle 1.

Highlights:
- Liquid PoS baking delegation (DELEGATE_STAKE, UNDELEGATE_STAKE)
- Genesis 100M KRN with Ethereum 2014-style distribution
  (70% public / 10% founder / 15% Foundation / 3% contributors / 2% validators)
- EVM Yellow Paper compliance (dynamic gas in vm.py::step)
- Real BN254 pairing via py_ecc (Groth16 identity verified)
- Slashing transaction (SLASH_EQUIVOCATION) closing the equivocation loop
- API stability spec frozen for v1.0
- 9 setup guides published
- Originality audit passed; founder attribution verified across 55 files

This release is the input to audit cycle 1. After audit findings are
remediated, v1.0.0 (stable) will follow.

Founder: Nicolas Van Eeckhout
License: Apache-2.0
Test count: 378 passing, 2 chaos tests intentionally skipped"
```

If your GPG signing is configured (Step 1), the tag is automatically signed. To force signing on a single tag without global config:

```bash
git tag -s v1.0.0-rc1 -m "..."   # explicit -s for signed
```

---

## Step 3 — Verify the tag

```bash
git tag -v v1.0.0-rc1
# Expected: "Good signature from <Nicolas Van Eeckhout>"
# (Will say "no public key" if you haven't published your key yet —
# publish via gpg --keyserver hkps://keys.openpgp.org --send-keys <KEY_ID>)
```

Display the tag:

```bash
git show v1.0.0-rc1
```

---

## Step 4 — Push the tag

```bash
# Push the commit history first if needed
git push origin main

# Then push the tag itself
git push origin v1.0.0-rc1
```

GitHub will display the tag at `https://github.com/vaneeckhoutnicolas/kern/releases/tag/v1.0.0-rc1`.

---

## Step 5 — Create a GitHub release

On GitHub, navigate to:
`https://github.com/vaneeckhoutnicolas/kern/releases/new`

- **Tag**: `v1.0.0-rc1` (existing)
- **Title**: `Kern v1.0.0rc1 — First release candidate`
- **Description**: paste the tag message body
- **Pre-release checkbox**: ✓ checked (because this is `-rc`, not stable)
- **Assets**: optionally upload a `kern-1.0.0rc1.tar.gz` for users who don't use git

Click "Publish release".

---

## Step 6 — Update the documentation site

If `docs.kern.protocol` is set up:

```bash
# Builds the new site from the v1.0.0-rc1 docs/ directory
mkdocs gh-deploy --force --message "Deploy v1.0.0-rc1 documentation"
```

This pushes the built site to the `gh-pages` branch. GitHub Pages serves it within ~1 minute.

---

## Step 7 — Announce

Public announcement channels:

- **Twitter / X**: announce the release with link to GitHub release page
- **Foundation blog** (when live): write a release post
- **Mailing list** (when established): release notice
- **Community forum** (when established): pinned release thread

Keep announcements factual: what's in the release, where to find it, what's next.

---

## Subsequent releases

### Patch release (v1.0.0-rc2, v1.0.1, etc.)

When fixing bugs in an existing major.minor:

```bash
# Bump version
sed -i 's/^version = "1.0.0rc1"$/version = "1.0.0rc2"/' pyproject.toml
git add pyproject.toml
git commit -m "Bump version to 1.0.0rc2"

# Tag and push
git tag -a v1.0.0-rc2 -m "..."
git push origin main v1.0.0-rc2
```

### Stable release (v1.0.0)

After audit cycle 1 is complete and fixes are applied:

```bash
# Bump version
sed -i 's/^version = "1.0.0rc[0-9]*"$/version = "1.0.0"/' pyproject.toml
git add pyproject.toml
git commit -S -m "Release Kern v1.0.0"

# Tag (signed!) and push
git tag -s v1.0.0 -m "Kern v1.0.0 — First stable release

This is the first stable release of Kern. Audit cycle 1 complete.
All Critical and High findings remediated.

[Include audit report links here.]

Per the API stability spec, the surfaces declared 'Frozen' will not
change in v1.x without a protocol amendment. The 'Stable' surfaces
will only be extended additively.

Founder: Nicolas Van Eeckhout
License: Apache-2.0"

git push origin main v1.0.0
```

### Minor release (v1.1.0, v1.2.0, ...)

Additive new features (no breaking changes to Frozen surfaces):

```bash
sed -i 's/^version = "1.0.[0-9]*"$/version = "1.1.0"/' pyproject.toml
git commit -S -m "Release Kern v1.1.0"
git tag -s v1.1.0 -m "Kern v1.1.0 — <summary of new features>"
git push origin main v1.1.0
```

### Major release (v2.0.0)

Breaking changes via on-chain governance amendment. This is a coordinated event involving the validator network:

1. **Submit protocol amendment** via GOVERNANCE_PROPOSE specifying v2.0 activation
2. **Wait for 25-day governance cycle** to complete (Exploration → Cooldown → Adoption → Activated)
3. **Confirm 80% supermajority approval** and 25% quorum
4. **At the activation block**, the v2.0 code path activates
5. **Tag the release** AFTER the on-chain activation

Critically: v2.0 tagging happens AFTER governance activation, not before. The git tag is documentation of what's running; the on-chain state is the truth.

---

## Rolling back a release

If a release introduces a Critical bug discovered shortly after tagging:

1. **Do not delete the tag** — that breaks anyone who already fetched it
2. **Issue a hotfix release** with an incremented patch number (`v1.0.1`)
3. **Document the bug** in the new release's notes
4. **Communicate broadly** through all announcement channels

Tags are immutable from the user's perspective. The Git protocol allows deletion, but doing so retroactively creates confusion. Always go forward, never backward.

---

## Reference

- [api-stability.md](api-stability.md) — what's frozen vs extensible per version
- [v10rc-changes.md](v10rc-changes.md) — content of the v1.0-rc release
- [pre-mainnet-checklist.md](pre-mainnet-checklist.md) — completeness gating before v1.0
- [originality-and-attribution.md](originality-and-attribution.md) — why signed tags matter
