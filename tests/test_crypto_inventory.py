# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The cryptographic inventory describes the code, not an intention.

docs/cryptographic-inventory.md lists every cryptographic primitive Kern
uses, what a quantum computer would do to each, and what the planned
hybrid signatures would cost. A list like that goes stale silently: one
more hash domain or one more library, and it is wrong. These tests read
the code through its syntax tree (imports and hash calls) and compare it
with the inventory and with the formats frozen in docs/api-stability.md.

They also keep the public texts honest: while every signature is plain
Ed25519, the inventory and the README must say that no part of Kern is
post-quantum, and any other line that mentions quantum computers has to
link to the inventory, where that status is stated.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

from kern.crypto import (
    PREFIX_ADDRESS,
    PREFIX_PUBKEY,
    PREFIX_SIGNATURE,
    KernKeypair,
    b58check_encode,
    verify,
)
from kern.transaction import make_transfer

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "cryptographic-inventory.md"
STABILITY = ROOT / "docs" / "api-stability.md"
README = ROOT / "README.md"

# The sentence the inventory and the README carry for as long as it is true.
STATUS = "No part of Kern is post-quantum today."


# ---------------------------------------------------------------------------
# Reading the code
# ---------------------------------------------------------------------------

def _sources(*packages: str) -> list[Path]:
    return [p for pkg in packages for p in sorted((ROOT / pkg).rglob("*.py"))]


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _enclosing_functions(tree: ast.AST) -> dict[ast.AST, str]:
    """Name of the innermost function around every node."""
    owner: dict[ast.AST, str] = {}

    def walk(node: ast.AST, current: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = node.name
        owner[node] = current
        for child in ast.iter_child_nodes(node):
            walk(child, current)

    walk(tree, "<module>")
    return owner


def _constant_keywords(call: ast.Call) -> dict[str, object]:
    return {k.arg: (k.value.value if isinstance(k.value, ast.Constant) else ...)
            for k in call.keywords if k.arg}


def _hash_calls() -> list[dict]:
    """Every hash computation in kern/: hashlib calls, and calls of the
    blake2b256 helper of kern.crypto. The helper's own body (a key passed
    through as a variable) is skipped: its callers are what matters."""
    found = []
    for path in _sources("kern"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            kw = _constant_keywords(node)
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id == "hashlib"):
                algo = func.attr
                if algo == "new":
                    assert node.args and isinstance(node.args[0], ast.Constant), _rel(path)
                    algo = str(node.args[0].value)
                size = kw.get("digest_size")
                key = kw.get("key")
            elif isinstance(func, ast.Name) and func.id == "blake2b256":
                algo, size, key = "blake2b", 32, kw.get("key")
            else:
                continue
            if key is ...:                       # kern.crypto.blake2b256 itself
                assert owner[node] == "blake2b256", (_rel(path), owner[node])
                continue
            found.append({
                "file": _rel(path), "function": owner[node], "algo": algo,
                "bytes": size, "key": key.decode() if isinstance(key, bytes) else None,
            })
    return found


def _keyed_domains() -> dict[str, int]:
    """BLAKE2b domain key -> output size in bits, as the code has them."""
    domains: dict[str, int] = {}
    for call in _hash_calls():
        if call["key"] is None:
            continue
        assert call["algo"] == "blake2b", call
        bits = call["bytes"] * 8
        assert domains.setdefault(call["key"], bits) == bits, call
    return domains


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def _section(text: str, heading: str) -> str:
    """The body of the markdown section whose heading starts with `heading`."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index("\n" + heading) + 1
    end = re.compile(r"^#{1,%d} " % level, re.M).search(text, start + len(heading))
    return text[start:end.start() if end else len(text)]


def _inventory() -> str:
    return INVENTORY.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Hash functions and their domains
# ---------------------------------------------------------------------------

DOMAIN_ROW = re.compile(r"^\| `(kern\.[a-z0-9_.]+)` \| (\d+) bits \|", re.M)


def test_inventory_lists_every_hash_domain_with_its_size():
    """Both ways: a domain added to the code must be added to the table,
    and a row that no longer matches any code must go."""
    documented = {key: int(bits) for key, bits in DOMAIN_ROW.findall(_inventory())}
    assert documented == _keyed_domains()


def test_api_stability_names_only_hash_domains_that_exist():
    """It used to list kern.tx.hash, kern.block.hash and kern.trie.node,
    which the code has never used: an alternative client built from that
    table would compute different hashes."""
    section = _section(STABILITY.read_text(encoding="utf-8"), "### 2.6 Hash function")
    documented = {key: int(bits) for key, bits in DOMAIN_ROW.findall(section)}
    code = _keyed_domains()
    assert documented, "the table of section 2.6 is gone"
    assert documented == {key: code.get(key) for key in documented}
    # The identities every client must reproduce are in the frozen table.
    assert {"kern.tx", "kern.block", "kern.merkle", "kern.state", "kern.addr"} <= set(documented)
    assert "cryptographic-inventory.md" in section


def test_hash_algorithms_and_unkeyed_uses_are_the_documented_ones():
    calls = _hash_calls()
    assert {c["algo"] for c in calls} == {"blake2b", "sha256", "sha3_256", "ripemd160"}
    unkeyed = {(c["file"], c["function"], c["bytes"])
               for c in calls if c["algo"] == "blake2b" and c["key"] is None}
    assert unkeyed == {
        ("kern/crypto.py", "b58check_encode", 32),       # checksum, first 4 bytes
        ("kern/crypto.py", "b58check_decode", 32),
        ("kern/consensus.py", "select_proposer", 8),     # public proposer draw
        ("kern/evm/frames.py", "_precompile_blake2f", 64),   # placeholder at 0x09
    }
    inventory = _inventory()
    for name in ("BLAKE2b", "SHA-256", "SHA3-256", "RIPEMD-160", "Keccak-256",
                 "`select_proposer`", "checksum", "0x09"):
        assert name in inventory, name


# ---------------------------------------------------------------------------
# Signatures, keys and libraries
# ---------------------------------------------------------------------------

def test_signatures_are_plain_ed25519_from_a_32_byte_seed():
    from nacl.signing import SigningKey

    seed = bytes(range(32))
    kp = KernKeypair.from_seed(seed)
    assert kp.public_key == bytes(SigningKey(seed).verify_key)     # RFC 8032 derivation
    signature = kp.sign(b"kern")
    assert (len(kp.public_key), len(signature)) == (32, 64)
    assert verify(kp.public_key, b"kern", signature)
    assert not verify(kp.public_key, b"kern", signature + b"\x00")
    assert STATUS in _inventory()
    assert STATUS in README.read_text(encoding="utf-8")


def test_only_the_listed_libraries_do_cryptography():
    watched = {"hashlib", "hmac", "secrets", "ssl", "random", "nacl", "py_ecc",
               "cryptography", "Crypto", "Cryptodome", "ecdsa", "coincurve", "blst",
               "oqs", "pqcrypto", "sha3", "blake3", "jwt", "passlib", "bcrypt"}
    users: dict[str, set[str]] = {}
    for path in _sources("kern", "kern_explorer"):
        for module in _imports(path) & watched:
            users.setdefault(module, set()).add(_rel(path))
    assert set(users) == {"hashlib", "nacl", "py_ecc", "random"}
    assert users["nacl"] == {"kern/crypto.py", "kern/evm/frames.py"}
    assert users["py_ecc"] == {"kern/evm/bn254.py", "kern/zk_claims.py"}
    assert users["random"] == {"kern/fuzzing.py"}                  # seeded test generators
    inventory = _inventory()
    for module in ("nacl", "py_ecc", "random"):
        for name in users[module]:
            assert f"`{name}`" in inventory, name

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = {re.split(r"[<>=!~\[ ]", d, maxsplit=1)[0].lower().replace("_", "-")
                for d in project["dependencies"]}
    known = {"pynacl", "py-ecc", "cryptography", "pycryptodome", "pycryptodomex", "ecdsa",
             "coincurve", "blspy", "liboqs-python", "pqcrypto", "pyopenssl", "blake3"}
    assert declared & known == {"pynacl", "py-ecc"}
    assert "PyNaCl" in inventory and "py_ecc" in inventory


def test_api_stability_gives_the_real_prefixes_and_lengths():
    """It gave 0x0142, 0x0d0f and 0x097f, and signatures of 100+ characters."""
    section = _section(STABILITY.read_text(encoding="utf-8"), "### 2.5 Address format")
    assert set(re.findall(r"0x[0-9a-f]+", section)) == {
        "0x" + PREFIX_ADDRESS.hex(), "0x" + PREFIX_PUBKEY.hex(), "0x" + PREFIX_SIGNATURE.hex()}
    assert 'digest_size=20, key="kern.addr"' in section
    for seed in (bytes(32), bytes(range(32)), b"\xff" * 32):
        kp = KernKeypair.from_seed(seed)
        signature = kp.sign_b58(b"kern")
        assert kp.address.startswith("kn1")
        assert kp.public_key_b58.startswith("9XY") and signature.startswith("9XZL")
        for value, what in ((kp.address, "Addresses"), (kp.public_key_b58, "Public keys"),
                            (signature, "Signatures")):
            assert re.search(rf"^{what} are [^.]*\b{len(value)} characters", section, re.M), what


# ---------------------------------------------------------------------------
# What hybrid signatures would cost
# ---------------------------------------------------------------------------

# FIPS 204, table 2: public key and signature sizes in bytes.
ML_DSA = {"ML-DSA-44": (1312, 2420), "ML-DSA-65": (1952, 3309)}
ED25519 = (32, 64)


def _encoded_length(prefix: bytes, payload_bytes: int) -> int:
    lengths = {len(b58check_encode(prefix, bytes([fill]) * payload_bytes)) for fill in (0, 0x5A, 0xFF)}
    assert len(lengths) == 1, lengths                     # does not depend on the content
    return lengths.pop()


def _reference_transfer():
    sender = KernKeypair.from_seed(bytes(range(32)))
    recipient = KernKeypair.from_seed(bytes(range(1, 33)))
    tx = make_transfer(sender, recipient.address, amount=1_000_000, nonce=1)
    tx.chain_id = "kern-devnet-placeholder"               # as the wallet does, then signs again
    tx.sign(sender)
    assert tx.verify_signature()
    return tx


def _measured_sizes() -> dict[str, list[int | None]]:
    """Rows of the cost table: today, hybrid with ML-DSA-44, hybrid with
    ML-DSA-65. A hybrid key or signature is the Ed25519 one followed by
    the ML-DSA one, encoded as today."""
    tx = _reference_transfer()
    full = len(json.dumps(tx.to_dict(), sort_keys=True, separators=(",", ":")).encode())
    key_now, sig_now = len(tx.sender_pubkey), len(tx.signature or "")
    rows: dict[str, list[int | None]] = {
        "Public key, bytes": [ED25519[0]],
        "Signature, bytes": [ED25519[1]],
        "Public key, encoded characters": [key_now],
        "Signature, encoded characters": [sig_now],
        "Transfer, signed payload": [tx.encoded_size()],
        "Transfer, complete": [full],
        "Transfer, complete, key kept in the account": [None],
        "Certificate of 4 signatures": [4 * sig_now],
        "Certificate of 30 signatures": [30 * sig_now],
        "Certificate of 100 signatures": [100 * sig_now],
    }
    for pk, sig in ML_DSA.values():
        key_chars = _encoded_length(PREFIX_PUBKEY, ED25519[0] + pk)
        sig_chars = _encoded_length(PREFIX_SIGNATURE, ED25519[1] + sig)
        rows["Public key, bytes"].append(ED25519[0] + pk)
        rows["Signature, bytes"].append(ED25519[1] + sig)
        rows["Public key, encoded characters"].append(key_chars)
        rows["Signature, encoded characters"].append(sig_chars)
        rows["Transfer, signed payload"].append(tx.encoded_size() - key_now + key_chars)
        rows["Transfer, complete"].append(full - key_now + key_chars - sig_now + sig_chars)
        rows["Transfer, complete, key kept in the account"].append(full - key_now - sig_now + sig_chars)
        for n in (4, 30, 100):
            rows[f"Certificate of {n} signatures"].append(n * sig_chars)
    return rows


def test_the_cost_table_is_recomputed_from_the_code():
    section = _section(_inventory(), "## 4. ")
    assert list(ML_DSA) == re.findall(r"ML-DSA-\d+", section.split("\n|---", 1)[0].rsplit("\n", 1)[-1])
    for label, expected in _measured_sizes().items():
        row = re.search(rf"^\| {re.escape(label)} \|(.*)\|$", section, re.M)
        assert row, f"no row {label!r} in the cost table"
        cells = [c.strip().replace(",", "") for c in row.group(1).split("|")]
        assert [int(c) if c.isdigit() else None for c in cells] == expected, label


def test_size_accounting_leaves_the_signature_out_as_the_inventory_says():
    """The fee floor and the block size cap use encoded_size(). The inventory
    lists this as a point to settle before signatures weigh kilobytes: when
    the accounting changes, this test and that paragraph change with it."""
    tx = _reference_transfer()
    assert tx.encoded_size() == len(tx._signed_payload())
    assert (tx.signature or "").encode() not in tx._signed_payload()
    assert "`encoded_size()`" in _section(_inventory(), "## 4. ")


# ---------------------------------------------------------------------------
# Public texts
# ---------------------------------------------------------------------------

def _public_texts() -> list[Path]:
    return ([README]
            + sorted((ROOT / "docs").rglob("*.md"))
            + sorted((ROOT / "kern_site").glob("*.html"))
            + sorted((ROOT / "scripts" / "brief").glob("*.html")))


def test_every_mention_of_quantum_computers_links_to_the_inventory():
    """A sentence about quantum resistance, anywhere in the public texts,
    must send the reader to the page that states the current status."""
    loose = []
    for path in _public_texts():
        if path == INVENTORY:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = line.lower().replace("quantum-cortex", "")      # the sibling repository
            if "quantum" in text and "cryptographic-inventory" not in text:
                loose.append(f"{_rel(path)}:{number}")
    assert not loose, loose


def test_the_inventory_can_be_found():
    assert "docs/cryptographic-inventory.md" in README.read_text(encoding="utf-8")
    nav = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert re.search(r"^\s+- [^:\n]+: cryptographic-inventory\.md$", nav, re.M)
    stability = STABILITY.read_text(encoding="utf-8")
    assert "cryptographic-inventory.md" in _section(stability, "### 2.7 Signature scheme")
    # The inventory names the test that checks it, and the claims it refuses.
    inventory = _inventory()
    assert "tests/test_crypto_inventory.py" in inventory
    assert "## 5. What Kern does not claim" in inventory
