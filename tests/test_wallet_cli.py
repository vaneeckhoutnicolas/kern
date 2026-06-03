# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Smoke tests for the kern_wallet CLI.

These tests exercise the CLI's argument parsing and the file-system-side
operations (keygen, inspect) without requiring a running RPC. The
network commands (transfer, delegate, etc.) are covered by integration
tests when an RPC is available; here we just verify the parser
accepts the right shapes."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WALLET_CLI = REPO_ROOT / "scripts" / "kern_wallet.py"


def run_cli(*args, expect_success=True):
    """Run the wallet CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, str(WALLET_CLI)] + list(args),
        capture_output=True, text=True, timeout=10,
    )
    if expect_success and result.returncode != 0:
        raise AssertionError(
            f"CLI failed: {' '.join(args)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.returncode, result.stdout, result.stderr


def test_help_works():
    """--help should list every subcommand."""
    rc, out, _ = run_cli("--help")
    assert rc == 0
    for cmd in ("keygen", "inspect", "balance", "head", "validators",
                "governance", "transfer", "delegate", "undelegate",
                "vote", "slash"):
        assert cmd in out


def test_keygen_creates_valid_keyfile():
    """keygen should produce a keyfile that inspect can read back."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        rc, out, _ = run_cli("keygen", "--out", keyfile)
        assert rc == 0
        assert "Generated new keypair" in out
        assert "kn1" in out

        # File should exist and have restrictive permissions
        assert Path(keyfile).exists()
        st = os.stat(keyfile)
        # Only owner-readable (POSIX systems)
        if sys.platform != "win32":
            mode = st.st_mode & 0o777
            assert mode == 0o600, f"keyfile permissions {oct(mode)} not 0600"

        # File should be valid JSON with expected fields
        with open(keyfile) as f:
            data = json.load(f)
        assert "address" in data
        assert data["address"].startswith("kn1")
        assert "public_key" in data
        assert data["public_key"].startswith("9X")
        assert "seed_hex" in data
        assert len(data["seed_hex"]) == 64   # 32 bytes hex-encoded

        # inspect should print the same address
        rc, out, _ = run_cli("inspect", keyfile)
        assert rc == 0
        assert data["address"] in out


def test_keygen_refuses_overwrite_without_force():
    """By default keygen refuses to overwrite an existing file."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        rc, _, _ = run_cli("keygen", "--out", keyfile)
        assert rc == 0

        # Second time without --force should fail
        rc, _, stderr = run_cli("keygen", "--out", keyfile, expect_success=False)
        assert rc != 0
        assert "Refusing to overwrite" in stderr


def test_keygen_force_overrides():
    """With --force, keygen overwrites existing file."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        run_cli("keygen", "--out", keyfile)
        with open(keyfile) as f:
            first = json.load(f)

        run_cli("keygen", "--out", keyfile, "--force")
        with open(keyfile) as f:
            second = json.load(f)

        # The two keys should be different
        assert first["address"] != second["address"]


def test_inspect_handles_missing_file():
    """inspect on a nonexistent file gives a clean error."""
    rc, _, stderr = run_cli("inspect", "/tmp/nonexistent-file-xyz",
                            expect_success=False)
    assert rc != 0
    assert "not found" in stderr.lower()


def test_inspect_handles_invalid_json():
    """inspect on a non-JSON file gives a clean error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not json at all")
        fname = f.name
    try:
        rc, _, stderr = run_cli("inspect", fname, expect_success=False)
        assert rc != 0
        assert "not valid json" in stderr.lower() or "expecting" in stderr.lower()
    finally:
        os.unlink(fname)


def test_subcommand_required():
    """Running without a subcommand should error."""
    rc, _, _ = run_cli(expect_success=False)
    assert rc != 0


def test_transfer_requires_target_and_amount():
    """transfer without --to or --amount should error from argparse."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        run_cli("keygen", "--out", keyfile)

        # Missing --to
        rc, _, _ = run_cli("transfer", keyfile, "--amount", "10",
                          expect_success=False)
        assert rc != 0

        # Missing --amount
        rc, _, _ = run_cli("transfer", keyfile, "--to", "kn1xxx",
                          expect_success=False)
        assert rc != 0


def test_delegate_requires_validator():
    """delegate without --validator should error from argparse."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        run_cli("keygen", "--out", keyfile)

        rc, _, _ = run_cli("delegate", keyfile, expect_success=False)
        assert rc != 0


def test_vote_validates_choices():
    """vote with invalid --vote or --track should error from argparse."""
    with tempfile.TemporaryDirectory() as td:
        keyfile = os.path.join(td, "test.json")
        run_cli("keygen", "--out", keyfile)

        # Invalid vote
        rc, _, _ = run_cli("vote", keyfile, "--proposal", "p1",
                          "--track", "protocol", "--vote", "maybe",
                          expect_success=False)
        assert rc != 0

        # Invalid track
        rc, _, _ = run_cli("vote", keyfile, "--proposal", "p1",
                          "--track", "lasagna", "--vote", "yes",
                          expect_success=False)
        assert rc != 0


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} wallet-CLI tests passed.")
