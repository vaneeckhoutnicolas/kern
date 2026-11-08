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


# The v1.1.0-rc2 edition archived by Zenodo on 8 November 2026: the version
# DOI names this edition; the concept DOI resolves to the latest archived one.
VERSION_DOI = "10.5281/zenodo.24046904"
CONCEPT_DOI = "10.5281/zenodo.24046903"
# Software Heritage identifier of the tag's tree: by construction the git
# tree hash of v1.1.0-rc2 (`git rev-parse v1.1.0-rc2^{tree}`).
SWHID = "swh:1:dir:5e8448555a4e5e0cdfe9cfe5158a1d3d8b727ae7"
# ... and of the signed tag itself (`git rev-parse v1.1.0-rc2`).
SWHID_REL = "swh:1:rel:5b23398b47c4585379011dc86a05635604c29df0"


def test_citation_carries_the_zenodo_dois():
    cff = _cff()
    assert cff["doi"] == VERSION_DOI
    dois = {i["value"]: i["description"] for i in cff["identifiers"] if i["type"] == "doi"}
    assert set(dois) == {VERSION_DOI, CONCEPT_DOI}
    assert "v1.1.0-rc2" in dois[VERSION_DOI]
    assert "concept DOI" in dois[CONCEPT_DOI]
    assert str(cff["date-released"]) == "2026-11-08"
    swh = [i for i in cff["identifiers"] if i["type"] == "swh"]
    assert [i["value"] for i in swh] == [SWHID, SWHID_REL]
    assert all("v1.1.0-rc2" in i["description"] for i in swh)


def test_readme_badge_and_citation_use_the_dois():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # The badge, right under the title, points to the concept DOI: it never
    # needs updating when a new version is archived.
    head = readme.split("\n## ", 1)[0]
    assert (f"[![DOI](https://zenodo.org/badge/DOI/{CONCEPT_DOI}.svg)]"
            f"(https://doi.org/{CONCEPT_DOI})") in head
    assert readme.index(CONCEPT_DOI) < readme.index("Notice.")
    cite = readme.split("## How to cite", 1)[1].split("\n## ", 1)[0]
    assert f"doi     = {{{VERSION_DOI}}}" in cite
    assert f"https://doi.org/{VERSION_DOI}" in cite
    assert f"https://doi.org/{CONCEPT_DOI}" in cite
    assert SWHID in cite and SWHID_REL in cite
