# Test vectors

Vectors that the cryptography of Kern must answer correctly, kept in the
repository so that the tests need no network and so that the Go client runs
the same files.

| Directory | What | From |
|---|---|---|
| `rfc10073/` | Composite ML-DSA, every combination of the standard; Kern uses `id-MLDSA65-Ed25519-SHA512` | IETF, LAMPS working group |
| `nist-acvp/` | ML-DSA key generation and signature verification (FIPS 204); Kern uses the ML-DSA-65 groups, and for verification the external, pure interface | NIST, ACVP Server |
| `wycheproof/` | ML-DSA-65 (verification, and signing from seeds) and Ed25519, with many malformed inputs | Project Wycheproof, C2SP |
| `kern/` | The reference vectors of the signature profile (`docs/hybrid-signatures.md`, section 17): its byte rules, the Ed25519 cases on which implementations disagree, composite signatures exchanged between two programs. The vectors of the schemas of structure version 1 (`docs/api-stability.md`, section 9). And the Go program that recomputes them | This repository |

`SOURCES.json` lists every file of this directory with its origin.

## Who runs them

- `tests/test_composite.py` and `tests/test_keys.py` run all of them
  against `kern.composite` and `kern.keys`, and `tests/test_profile_vectors.py`
  recomputes those of `kern/` with the Python references.
- `tests/test_schema_vectors.py` runs `kern/schemas.json` through
  `tests/schema_reference.py`, which is section 9 of `docs/api-stability.md`
  as executable text.
- `kern/profile_check.go` does the same with the Go standard library alone.
  The continuous integration runs it on every pull request, on the vectors
  of `kern/` and, with `-official`, on the official files.

## Unchanged copies

Every file that comes from elsewhere is the original, byte for byte: its
SHA-256 can be compared with the file at the commit named in
`SOURCES.json`. Nothing is extracted or reformatted. `.gitattributes`
keeps git from converting line endings in the three directories of
official files, and `tests/test_vectors.py` refuses a file of this
directory that `SOURCES.json` does not list, and an official file whose
size or SHA-256 differs.

The files of `kern/` are built in this repository by the programs
`SOURCES.json` names. They are text for git, which may convert their line
endings: what holds them is their content, recomputed by the tests.

## Frozen values

The signature profile was frozen on 12 November 2026
(`docs/hybrid-signatures.md`, section 18): the values of its vectors no
longer change. `kern/freeze.json` holds a digest of every value the three
vector files of `kern/` had on that day, and `tests/test_vectors.py`
fails when one of them changes or disappears. Vectors can be added for a
rule that exists: a new member in a file, or new cases at the end of a
list.

`kern/schemas.json` is not one of the three: the schemas it holds are a
draft under review, and the file is rebuilt with them.

## Licences

- `rfc10073/`: IETF Trust, see `rfc10073/NOTICE.md`.
- `nist-acvp/`: NIST, see `nist-acvp/NOTICE.md`.
- `wycheproof/`: Apache License 2.0, see `wycheproof/LICENSE`.
- `kern/`: Apache License 2.0, like the rest of this repository.

## Updating

A vector does not expire: it states what the standard says. Upstream files
change when cases are added, and rarely when one is corrected.

1. `python scripts/check_vectors_upstream.py` lists the official files that
   differ from the head of their repository. A scheduled workflow runs it
   every month and fails when one does; it changes nothing.
2. Read the difference. These files fix the verdicts of consensus code.
3. Replace the file with the new original, update its entry in
   `SOURCES.json` (commit, date, size, SHA-256), run the tests and the Go
   program, which assert the number of cases of each file.

The list of errata on the page of FIPS 204 is read at each release
(`docs/release-tagging.md`).
