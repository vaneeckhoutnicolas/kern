# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""CITATION.cff stays in step with the version being released.

Zenodo takes its metadata from CITATION.cff when it archives a GitHub
release, and the DOI it assigns is permanent: a citation file left at an
older version would be archived, and cited, as such. The version in
CITATION.cff is the tag form of the PEP 440 version in pyproject.toml
(1.1.0rc2 -> 1.1.0-rc2, docs/release-tagging.md)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ModuleNotFoundError:                              # Python 3.10
    import tomli as tomllib                              # type: ignore

import yaml


def _tag_form(pep440: str) -> str:
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", pep440)
    assert m, pep440
    base, kind, n = m.groups()
    return base if kind is None else f"{base}-{ {'a': 'alpha', 'b': 'beta', 'rc': 'rc'}[kind] }{n}"


def _cff():
    return yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))


def test_citation_version_is_the_pyproject_version():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    cff = _cff()
    assert cff["version"] == _tag_form(version)
    release_urls = [i["value"] for i in cff.get("identifiers", []) if i["type"] == "url"]
    assert f"https://github.com/vaneeckhoutnicolas/kern/releases/tag/v{cff['version']}" in release_urls


def test_citation_metadata_needed_by_zenodo():
    cff = _cff()
    assert cff["cff-version"] == "1.2.0"
    assert cff["type"] == "software"
    assert cff["license"] == "Apache-2.0"
    assert cff["repository-code"] == "https://github.com/vaneeckhoutnicolas/kern"
    author = cff["authors"][0]
    assert (author["family-names"], author["given-names"]) == ("Van Eeckhout", "Nicolas")
    assert author["orcid"].startswith("https://orcid.org/")
    assert cff["title"] and cff["abstract"] and cff["keywords"]
    # The README's BibTeX cites the same version.
    assert f"version = {{{cff['version']}}}" in (ROOT / "README.md").read_text(encoding="utf-8")
