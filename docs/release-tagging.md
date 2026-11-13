# Release Tagging

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
# Expected: 1202 passed, none skipped (v1.1-rc)

# 3b. Recompute the reference vectors of the signature profile with the Go
#     standard library (Go 1.27 or later; the CI does it on every pull request)
(cd tests/vectors/kern && \
    go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json)
# Expected last line: same values as the Python reference

# 3c. Run the official vectors with the same program: RFC 10073, NIST and
#     Project Wycheproof, the files the Python tests run
(cd tests/vectors/kern && go run profile_check.go -official ..)
# Expected last line: same verdicts as the Python tests

# 3d. Compare the official vectors kept in tests/vectors with the head of their
#     repositories (it downloads them, and changes nothing)
python scripts/check_vectors_upstream.py
# Expected last line: The 7 official files are those at the head of their repositories.
# A file that differs is read before it is taken (tests/vectors/README.md, Updating):
# decide before tagging whether the release takes it.

# 3e. Read the errata of FIPS 204: the spreadsheet of potential updates listed
#     under "Documentation" on https://csrc.nist.gov/pubs/fips/204/final.
#     An erratum that touches key generation, verification or an encoding is
#     settled before tagging.

# 3f. Check the record of the frozen profile against the git history
python tests/test_vectors.py
# Expected: kern/freeze.json is what its three files give

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

## Step 1 — Signing (SSH)

Every commit and tag of the founder is signed with a dedicated SSH key (`id_ed25519_signing`); the `protect-main` ruleset requires signed commits. One-time setup:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

To verify signatures locally, git needs the list of allowed signers:

```bash
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519_signing.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

On GitHub, the same public key is registered as a **signing key** (Settings, SSH and GPG keys, New SSH key, type "Signing key"), so that signed commits and tags show as "Verified".

---

## Step 2 — Citation and archive (before the first tag of a version)

1. `CITATION.cff` carries the version being tagged (`version: "1.1.0-rc2"` for `v1.1.0-rc2`; `tests/test_citation.py` keeps it equal to `pyproject.toml`). Validate it: `pip install cffconvert && cffconvert --validate`.
2. **Enable the repository in Zenodo before publishing the release**: on zenodo.org, log in with GitHub, open the GitHub tab of your profile, and switch `vaneeckhoutnicolas/kern` on. Zenodo archives every GitHub release published after that switch, pre-releases included, each with a permanent DOI that cannot be withdrawn: tag only what you are ready to have cited.

---

## Step 3 — Tag the release

```bash
git switch main
git pull --ff-only
git status --short          # must print nothing
git tag -s v1.1.0-rc2 -m "Kern v1.1.0-rc2

Release candidate 2 of v1.1. Pre-audit.

- Phase E consensus: Tendermint lock and valid round, persistent signing
  journal, one signed proposal per round, proposal equivocation evidence
  (docs/consensus-locking.md, sections 9 and 10)
- Bonded Proof-of-Stake delegation with slashing
- One-command multi-node devnet in Docker with Heimdall, Prometheus and
  Grafana (docs/devnet.md)
- Listening addresses (--rpc-bind, --p2p-bind); consensus metrics

Validated on a network simulator, real node processes and a containerized
devnet; not yet on a network of independent operators; not audited.

Founder: Nicolas Van Eeckhout
License: Apache-2.0 (code), CC-BY-SA-4.0 (documentation)"
```

`-s` signs the tag with the SSH key of Step 1.

---

## Step 4 — Verify and push the tag

```bash
git tag -v v1.1.0-rc2       # expected: Good "git" signature for <your email>
git push origin v1.1.0-rc2
```

---

## Step 5 — Create the GitHub release (Zenodo archives it)

On `https://github.com/vaneeckhoutnicolas/kern/releases/new`:

- **Tag**: `v1.1.0-rc2` (existing)
- **Title**: `Kern v1.1.0-rc2`
- **Description**: the body of the tag message
- **Set as a pre-release**: checked for any `-rcN` tag

Publish. Within minutes Zenodo archives the source of the tag and assigns two DOIs: one for this version, and a concept DOI that always resolves to the latest version. Zenodo takes its metadata from `CITATION.cff`.

Then, in a follow-up commit (signed, through a pull request):

1. Add the version DOI and the concept DOI to `CITATION.cff` (`doi:` and `identifiers:`, as in quantum-cortex) and to the "How to cite" section of the README.
   Recorded so far: v1.1.0-rc2 (8 November 2026), version DOI `10.5281/zenodo.24046904`, concept DOI `10.5281/zenodo.24046903`. The README badge points to the concept DOI and never needs updating; Software Heritage: `swh:1:rel:5b23398b47c4585379011dc86a05635604c29df0` for the signed tag (`git rev-parse v1.1.0-rc2`) and `swh:1:dir:5e8448555a4e5e0cdfe9cfe5158a1d3d8b727ae7` for its tree (`git rev-parse v1.1.0-rc2^{tree}`). `tests/test_citation.py` keeps the identifiers consistent.
2. Ask Software Heritage to archive the repository (`https://archive.softwareheritage.org/save/`), then add the `swh:1:dir:` identifier of the tag's tree to `CITATION.cff`.

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
