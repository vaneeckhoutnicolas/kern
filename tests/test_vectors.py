# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Where the test vectors come from, and that they have not changed.

tests/vectors holds two kinds of files. The official ones (RFC 10073, NIST,
Project Wycheproof) are unchanged copies: tests/vectors/SOURCES.json gives
the repository, the commit, the size and the SHA-256 of each, and a file
that is not listed, or that differs by one byte, fails here. The others
are the reference vectors of the signature profile, built in this
repository. That profile was frozen on 12 November 2026
(docs/hybrid-signatures.md, section 18): vectors can be added, and no
value it had on that day may change. tests/vectors/kern/freeze.json holds a
digest of each of them.

    python tests/test_vectors.py

recomputes that file from the git history, at the commit of the freeze,
and says whether it is the same. It needs the whole history, which the
test suite does not.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"
OFFICIAL = ("rfc10073", "nist-acvp", "wycheproof")
FROZEN = ("profile.json", "ed25519_edge_cases.json", "composite_signatures.json")

sys.path.insert(0, str(ROOT / "scripts"))

import check_vectors_upstream as upstream  # noqa: E402

SOURCES = json.loads((VECTORS / "SOURCES.json").read_text(encoding="utf-8"))
FREEZE = json.loads((VECTORS / "kern" / "freeze.json").read_text(encoding="utf-8"))
ENTRIES = {entry["path"]: entry for entry in SOURCES["files"]}
COPIES = [entry for entry in SOURCES["files"] if "repository" in entry]


# ---------------------------------------------------------------------------
# Every file has a stated origin
# ---------------------------------------------------------------------------

def test_every_file_of_the_vectors_is_listed_with_its_origin():
    on_disk = {path.relative_to(VECTORS).as_posix() for path in VECTORS.rglob("*")
               if path.is_file() and "__pycache__" not in path.parts}
    assert on_disk - {"SOURCES.json"} == set(ENTRIES)
    assert len(ENTRIES) == len(SOURCES["files"])                    # no path listed twice
    for entry in SOURCES["files"]:
        origins = {"repository", "generator", "written_here"} & set(entry)
        assert len(origins) == 1 and entry["licence"], entry["path"]
    # The three directories of official files hold copies and their notices, nothing built here.
    for path, entry in ENTRIES.items():
        directory = path.split("/")[0]
        if directory in OFFICIAL:
            assert "repository" in entry or path.endswith("/NOTICE.md"), path
        else:
            assert "repository" not in entry, path
    assert {entry["path"].split("/")[0] for entry in COPIES} == set(OFFICIAL)


def test_the_official_files_are_unchanged_copies():
    assert len(COPIES) == 7
    for entry in COPIES:
        raw = (VECTORS / entry["path"]).read_bytes()
        assert len(raw) == entry["bytes"], entry["path"]
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        assert b"\r" not in raw, entry["path"]                     # as upstream: no line ending was converted
        assert re.fullmatch(r"[0-9a-f]{40}", entry["commit"]), entry["path"]
        assert re.fullmatch(r"20\d\d-\d\d-\d\d", entry["date"]), entry["path"]
        assert re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", entry["repository"]), entry["path"]
        assert entry["upstream_path"] and not entry["upstream_path"].startswith("/"), entry["path"]
    # One commit per repository: the files of a directory were taken together.
    commits = {(entry["repository"], entry["commit"]) for entry in COPIES}
    assert len(commits) == len({entry["repository"] for entry in COPIES}) == 3


def test_git_never_converts_the_line_endings_of_the_official_files():
    """A file checked out with other line endings would no longer have the
    recorded SHA-256. The three directories are marked `-text`, and they
    are the only ones: the vectors of kern/ stay text for git."""
    rules = [line.split() for line in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    assert sorted(rules) == sorted([f"tests/vectors/{directory}/**", "-text"] for directory in OFFICIAL)


def test_every_official_directory_comes_with_its_licence():
    readme = (VECTORS / "README.md").read_text(encoding="utf-8")
    for directory, notice in (("rfc10073", "NOTICE.md"), ("nist-acvp", "NOTICE.md"), ("wycheproof", "LICENSE")):
        assert (VECTORS / directory / notice).is_file()
        assert f"`{directory}/{notice}`" in readme
    assert "Apache License" in (VECTORS / "wycheproof" / "LICENSE").read_text(encoding="utf-8")
    nist = (VECTORS / "nist-acvp" / "NOTICE.md").read_text(encoding="utf-8")
    assert "provided that you keep intact this entire notice" in nist
    assert "National Institute of Standards and Technology" in nist
    assert "IETF Trust" in (VECTORS / "rfc10073" / "NOTICE.md").read_text(encoding="utf-8")
    # A licence stated in the list points at a file that is there.
    for entry in COPIES:
        for named in re.findall(r"\(([\w-]+/[\w.]+)\)", entry["licence"]):
            assert (VECTORS / named).is_file(), named


def test_the_vectors_built_here_name_the_program_that_builds_them():
    built = {path: entry["generator"] for path, entry in ENTRIES.items() if "generator" in entry}
    assert set(built) == {f"kern/{name}" for name in FROZEN} | {"kern/freeze.json", "kern/schemas.json"}
    for path, generator in built.items():
        for program in re.findall(r"tests/[\w/.]+\.(?:py|go)", generator):
            assert (ROOT / program).is_file(), program
        assert "bytes" not in ENTRIES[path] and "sha256" not in ENTRIES[path]      # held by their content
    assert built["kern/profile.json"] == "tests/profile_reference.py"
    assert built["kern/ed25519_edge_cases.json"] == "tests/ed25519_reference.py"
    assert built["kern/schemas.json"] == "tests/schema_vectors.py, with tests/schema_reference.py"


# ---------------------------------------------------------------------------
# The values frozen with the profile
# ---------------------------------------------------------------------------

def digest(value: object) -> str:
    """SHA-256 of a value written as JSON with sorted keys and no white
    space, in UTF-8: the same whatever the layout and the line endings of
    the file it was read from."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def manifest_of(document: dict) -> dict:
    """What freeze.json records of one file: a digest per member, or a
    digest per item when the member is a list."""
    return {name: [digest(item) for item in value] if isinstance(value, list) else digest(value)
            for name, value in document.items()}


def changed_since_the_freeze(frozen: dict, document: dict) -> list[str]:
    """The values a file had at the freeze and no longer has. A member that
    existed keeps its value; a list keeps its items, in their order, and
    may only grow at its end. New members are additions."""
    found = []
    for name, expected in frozen.items():
        if name not in document:
            found.append(f"{name}: gone")
        elif not isinstance(expected, list):
            if isinstance(document[name], list) or digest(document[name]) != expected:
                found.append(f"{name}: changed")
        elif not isinstance(document[name], list) or len(document[name]) < len(expected):
            found.append(f"{name}: items gone")
        else:
            found += [f"{name}[{i}]: changed" for i, item in enumerate(expected) if digest(document[name][i]) != item]
    return found


def _vectors(name: str) -> dict:
    return json.loads((VECTORS / "kern" / name).read_text(encoding="utf-8"))


def test_no_value_frozen_with_the_profile_has_changed():
    assert tuple(FREEZE["files"]) == FROZEN
    for name in FROZEN:
        assert changed_since_the_freeze(FREEZE["files"][name], _vectors(name)) == [], name
    # What was added since, for rules that exist: text forms, and public keys under rule 2 alone.
    added = {name: sorted(set(_vectors(name)) - set(FREEZE["files"][name])) for name in FROZEN}
    assert added == {"profile.json": ["text_forms"],
                     "ed25519_edge_cases.json": ["public_keys", "public_keys_rule"],
                     "composite_signatures.json": []}
    # No list has grown: every addition so far is a new member.
    for name in FROZEN:
        document = _vectors(name)
        for member, expected in FREEZE["files"][name].items():
            if isinstance(expected, list):
                assert len(document[member]) == len(expected), (name, member)


def test_the_record_of_the_freeze_is_itself_held():
    """freeze.json could be edited along with a vector. Its own digest is
    written here, with what it covers: changing a frozen value takes
    changing this test, in plain sight."""
    assert FREEZE["commit"] == "9190880e55b1e4e2162be019498cff3d521d13c7"
    assert FREEZE["frozen_on"] == "2026-11-12"
    assert digest(FREEZE["files"]) == "3e356c189f321fd933784bdc9bb3e73fd974b4f3f62f7cbd8f33b564a16033d2"
    counted = {name: (len(members), sum(len(m) if isinstance(m, list) else 1 for m in members.values()))
               for name, members in FREEZE["files"].items()}
    assert counted == {"profile.json": (17, 91), "ed25519_edge_cases.json": (3, 33),
                       "composite_signatures.json": (8, 36)}
    assert len(FREEZE["files"]["ed25519_edge_cases.json"]["cases"]) == 31
    signatures = FREEZE["files"]["composite_signatures.json"]
    assert (len(signatures["python"]), len(signatures["go"]), len(signatures["invalid"])) == (7, 7, 17)
    note = (ROOT / "docs" / "hybrid-signatures.md").read_text(encoding="utf-8")
    assert "frozen in this sixth version, on 12 November 2026" in note
    assert "Vectors can be added for a rule that exists." in note


def test_the_guard_sees_a_change_and_lets_an_addition_pass():
    frozen = FREEZE["files"]["profile.json"]
    original = _vectors("profile.json")
    assert changed_since_the_freeze(frozen, original) == []

    def after(change) -> list[str]:
        document = copy.deepcopy(original)
        change(document)
        return changed_since_the_freeze(frozen, document)

    def one_hex_digit(document):                           # one character of one digest
        value = document["hash"][0]["digest"]
        document["hash"][0]["digest"] = ("1" if value[0] != "1" else "2") + value[1:]

    assert after(one_hex_digit) == ["hash[0]: changed"]
    assert after(lambda d: d["address"].__setitem__("address", "kn1")) == ["address: changed"]
    assert after(lambda d: d["derivation"][1].__setitem__("comment", "added")) == ["derivation[1]: changed"]
    assert after(lambda d: d.pop("contexts")) == ["contexts: gone"]
    assert after(lambda d: d["merkle"].pop()) == ["merkle: items gone"]
    assert after(lambda d: d.__setitem__("network_id", [d["network_id"]])) == ["network_id: changed"]
    assert after(lambda d: d.__setitem__("merkle", {"roots": d["merkle"]})) == ["merkle: items gone"]
    moved = after(lambda d: d["not_canonical"].insert(0, {"why": "a new case in front", "bytes": "00"}))
    assert moved == [f"not_canonical[{i}]: changed" for i in range(24)]
    swapped = after(lambda d: d["contexts"].reverse())
    assert swapped == [f"contexts[{i}]: changed" for i in (0, 1, 2, 4, 5, 6)]      # the middle one stays in place
    # Additions pass: a new member, a new case at the end of a list.
    assert after(lambda d: d.__setitem__("a_new_rule_covered", [1, 2, 3])) == []
    assert after(lambda d: d["not_canonical"].append({"why": "one more refusal", "bytes": "00"})) == []
    assert after(lambda d: d["text_forms"]["accepted"].pop()) == []                # added after the freeze


# ---------------------------------------------------------------------------
# The comparison with upstream (scripts/check_vectors_upstream.py), without the network
# ---------------------------------------------------------------------------

def _heads() -> dict[str, bytes]:
    """What the head of each repository answers when nothing has moved."""
    return {upstream.head_url(entry): (VECTORS / entry["path"]).read_bytes() for entry in COPIES}


def test_the_comparison_asks_for_each_official_file_at_the_head_of_its_repository():
    assert upstream.upstream_files(SOURCES) == COPIES
    assert upstream.head_url(ENTRIES["rfc10073/testvectors.json"]) == (
        "https://raw.githubusercontent.com/lamps-wg/draft-composite-sigs/HEAD/src/testvectors.json")
    assert upstream.head_url(ENTRIES["nist-acvp/ML-DSA-sigVer-FIPS204.json"]) == (
        "https://raw.githubusercontent.com/usnistgov/ACVP-Server/HEAD/"
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json")
    assert upstream.head_url(ENTRIES["wycheproof/LICENSE"]) == (
        "https://raw.githubusercontent.com/C2SP/wycheproof/HEAD/LICENSE")
    assert len(_heads()) == 7
    # The list is a file of the repository: it cannot send the program elsewhere.
    good = ENTRIES["wycheproof/LICENSE"]
    for field, value in (("repository", "https://example.org/C2SP/wycheproof"),
                         ("repository", "https://github.com/C2SP/wycheproof/../../other"),
                         ("repository", "https://github.com/C2SP"),
                         ("repository", "http://github.com/C2SP/wycheproof"),
                         ("repository", "https://github.com/C2SP/wycheproof?x=1"),
                         ("upstream_path", "../LICENSE"), ("upstream_path", "/etc/passwd"),
                         ("upstream_path", "a//b"), ("upstream_path", "a/./b"), ("upstream_path", ""),
                         ("upstream_path", "LICENSE?ref=x"), ("upstream_path", "a b")):
        try:
            upstream.head_url({**good, field: value})
        except ValueError:
            continue
        raise AssertionError(f"accepted: {field} = {value!r}")
    for address in ("http://raw.githubusercontent.com/C2SP/wycheproof/HEAD/LICENSE",
                    "https://example.org/LICENSE", "file:///etc/passwd"):
        try:
            upstream.fetch(address)                        # refused before any connection is made
        except ValueError:
            continue
        raise AssertionError(f"fetched: {address}")


def test_the_comparison_reports_a_file_that_moved_upstream_and_changes_nothing(monkeypatch, capsys):
    heads = _heads()
    before = {path: path.read_bytes() for path in VECTORS.rglob("*") if path.is_file()}
    assert [status for _, status, _ in upstream.compare(SOURCES, heads.__getitem__)] == ["same"] * 7
    monkeypatch.setattr(upstream, "fetch", heads.__getitem__)
    assert upstream.main([]) == 0
    assert "The 7 official files are those at the head of their repositories." in capsys.readouterr().out

    # One file has one more case upstream.
    moved = upstream.head_url(ENTRIES["wycheproof/ed25519_test.json"])
    monkeypatch.setattr(upstream, "fetch", lambda url: heads[url] + b"\n" if url == moved else heads[url])
    assert upstream.main([]) == 1
    printed = capsys.readouterr().out
    (line,) = [line for line in printed.splitlines() if line.startswith("DIFFERENT")]
    kept = ENTRIES["wycheproof/ed25519_test.json"]
    assert "wycheproof/ed25519_test.json" in line and kept["sha256"] in line and kept["commit"] in line
    assert hashlib.sha256(heads[moved] + b"\n").hexdigest() in line
    assert printed.count("same ") == 6 and "Nothing was changed." in printed

    # The same size and other bytes is a difference too.
    flipped = bytes([heads[moved][0] ^ 1]) + heads[moved][1:]
    statuses = upstream.compare(SOURCES, lambda url: flipped if url == moved else heads[url])
    assert [status for _, status, _ in statuses].count("DIFFERENT") == 1

    # A file that cannot be fetched is not a file that is the same.
    def unreachable(url: str) -> bytes:
        if url == moved:
            raise OSError("no route to host")
        return heads[url]

    monkeypatch.setattr(upstream, "fetch", unreachable)
    assert upstream.main([]) == 2
    assert "the comparison is not complete" in capsys.readouterr().out
    # A difference is reported even when another file cannot be fetched.
    other = upstream.head_url(ENTRIES["wycheproof/LICENSE"])
    monkeypatch.setattr(upstream, "fetch", lambda url: heads[url] + b"\n" if url == other else unreachable(url))
    assert upstream.main([]) == 1
    capsys.readouterr()
    assert upstream.main(["--help"]) == 2 and "changes nothing" in capsys.readouterr().out
    # Nothing was written: the program only reads.
    assert before == {path: path.read_bytes() for path in VECTORS.rglob("*") if path.is_file()}


def test_a_workflow_runs_the_comparison_every_month_and_can_write_nothing():
    workflow = (ROOT / ".github" / "workflows" / "vectors.yml").read_text(encoding="utf-8")
    assert re.search(r'^\s+- cron: "\d+ \d+ \d+ \* \*"', workflow, re.M)             # one day a month
    assert "workflow_dispatch:" in workflow
    assert re.search(r"^permissions:\n  contents: read\n", workflow, re.M) and "write" not in workflow
    assert "run: python scripts/check_vectors_upstream.py" in workflow
    assert "pip install" not in workflow                                           # the standard library alone
    # Actions are pinned to a commit, as in the other workflows.
    used = re.findall(r"uses: (\S+)", workflow)
    assert used and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action) for action in used)
    others = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    # The other use of the official files in the continuous integration: the Go program reads them.
    assert "run: go run profile_check.go -official .." in others
    assert "run: go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json" in others


if __name__ == "__main__":
    # The record of the freeze, recomputed from the files of that commit in the git history.
    def at_the_freeze(name: str) -> dict:
        shown = subprocess.run(["git", "show", f"{FREEZE['commit']}:tests/vectors/kern/{name}"],
                               cwd=ROOT, capture_output=True, check=True)
        return json.loads(shown.stdout.decode("utf-8"))

    recomputed = {name: manifest_of(at_the_freeze(name)) for name in FROZEN}
    same = recomputed == FREEZE["files"]
    print(f"commit {FREEZE['commit']}: kern/freeze.json is {'what' if same else 'NOT what'} its three files give")
    sys.exit(0 if same else 1)
