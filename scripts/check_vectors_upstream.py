#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Compare the official test vectors kept under tests/vectors with the head
of the repositories they come from.

    python scripts/check_vectors_upstream.py

The files of RFC 10073, NIST and Project Wycheproof are kept in this
repository as unchanged copies, each at a commit that
tests/vectors/SOURCES.json records. Upstream, cases are added and, rarely,
one is corrected. This program downloads each file from the head of the
default branch of its repository and compares its size and its SHA-256
with those recorded. It changes nothing, here or there: a file that
differs is to be read before it is taken, since these files fix the
verdicts of consensus code (tests/vectors/README.md).

What is downloaded is only measured and hashed, never parsed or run.

Exit code: 0 when every file is the one at the head; 1 when one differs;
2 when none differs and one could not be fetched. A scheduled workflow runs
this every month and fails on 1 and on 2.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "tests" / "vectors" / "SOURCES.json"

MAX_BYTES = 64 * 1024 * 1024            # the largest file kept today is under 5 megabytes
TIMEOUT_SECONDS = 60

_REPOSITORY = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)")
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")


def upstream_files(sources: dict) -> list[dict]:
    """The entries of SOURCES.json that are copies of a file of another
    repository."""
    return [entry for entry in sources["files"] if "repository" in entry]


def head_url(entry: dict) -> str:
    """Where the file of an entry is at the head of the default branch of
    its repository. Only a repository of github.com and a plain relative
    path give an address: the list is a file of this repository, and what
    it says must not send this program anywhere else."""
    match = _REPOSITORY.fullmatch(entry["repository"])
    segments = entry["upstream_path"].split("/")
    if match is None or not all(_SEGMENT.fullmatch(segment) for segment in segments):
        raise ValueError(f"not a file of a repository of github.com: {entry['repository']!r} {entry['upstream_path']!r}")
    owner, name = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{'/'.join(segments)}"


class _NoRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):      # type: ignore[no-untyped-def]
        return None                                    # a redirection is an error, not another address to follow


def fetch(url: str) -> bytes:
    """Download one file over HTTPS, without following a redirection and
    without reading more than MAX_BYTES."""
    if not url.startswith("https://raw.githubusercontent.com/"):
        raise ValueError(f"not an address this program downloads from: {url!r}")
    opener = urllib.request.build_opener(_NoRedirection)
    request = urllib.request.Request(url, headers={"User-Agent": "kern-check-vectors-upstream"})
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"more than {MAX_BYTES} bytes")
    return data


def compare(sources: dict, download: Callable[[str], bytes]) -> list[tuple[str, str, str]]:
    """One line per official file: its path, then `same`, `DIFFERENT` or
    `unreachable`, then what was found."""
    lines = []
    for entry in upstream_files(sources):
        try:
            data = download(head_url(entry))
        except (OSError, ValueError) as exc:           # urllib.error.URLError is an OSError
            lines.append((entry["path"], "unreachable", f"{type(exc).__name__}: {exc}"))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if (len(data), digest) == (entry["bytes"], entry["sha256"]):
            lines.append((entry["path"], "same", f"{len(data)} bytes"))
        else:
            lines.append((entry["path"], "DIFFERENT",
                          f"kept: {entry['bytes']} bytes, sha256 {entry['sha256']}, commit {entry['commit']}; "
                          f"at the head: {len(data)} bytes, sha256 {digest}"))
    return lines


def main(arguments: list[str] | None = None) -> int:
    if sys.argv[1:] if arguments is None else arguments:      # no option: there is one thing to do
        print(__doc__)
        return 2
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    lines = compare(sources, fetch)
    for path, status, detail in lines:
        print(f"{status:<11} {path}: {detail}")
    statuses = {status for _, status, _ in lines}
    if "DIFFERENT" in statuses:
        print("\nAt least one official file differs from the head of its repository. Nothing was changed.\n"
              "Read the difference upstream before taking the new file: tests/vectors/README.md, Updating.")
        return 1
    if "unreachable" in statuses:
        print("\nAt least one file could not be fetched: the comparison is not complete.")
        return 2
    print(f"\nThe {len(lines)} official files are those at the head of their repositories.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
