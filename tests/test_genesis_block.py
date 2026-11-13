# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The genesis block is built from the genesis file, and from nothing else.

Its timestamp is part of its header, hence of its hash. `build_genesis_block`
used to take the time of the machine when the file gave none: two operators
who initialised their nodes from one file, at two moments, started two
chains. A genesis without an integer `timestamp` is now refused.
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern import node
from kern.crypto import KernKeypair
from kern.node import build_genesis_block, cmd_init
from kern.storage import Storage

ROOT = Path(__file__).resolve().parent.parent
KEYS = [KernKeypair.from_seed(bytes([n]) * 32) for n in (1, 2, 3, 4)]


def a_genesis() -> dict:
    validators = [{"address": k.address, "pubkey": k.public_key_b58, "stake": 1_000_000} for k in KEYS]
    return {
        "chain_id": "kern-test",
        "timestamp": 1_794_000_000,
        "genesis_proposer": {"address": KEYS[0].address, "pubkey": KEYS[0].public_key_b58},
        "genesis_signature": "ksig" + "0" * 95,
        "validators": validators,
        "balances": {k.address: 2_000_000 for k in KEYS},
    }


def without_timestamp() -> dict:
    return {name: value for name, value in a_genesis().items() if name != "timestamp"}


def test_a_genesis_without_a_timestamp_is_refused():
    with pytest.raises(ValueError, match="timestamp"):
        build_genesis_block(without_timestamp())


@pytest.mark.parametrize("value", [None, "2027-Q3 (target)", "1794000000", 1794000000.0, 1.5, True, -1, [1794000000]])
def test_the_timestamp_is_an_integer_of_zero_or_more(value):
    with pytest.raises(ValueError, match="timestamp"):
        build_genesis_block({**a_genesis(), "timestamp": value})


@pytest.mark.parametrize("value", [0, 1, 1_794_000_000, 2**63 - 1])
def test_control_an_integer_timestamp_is_the_timestamp_of_the_block(value):
    assert build_genesis_block({**a_genesis(), "timestamp": value}).header.timestamp == value


def test_the_clock_of_the_machine_is_never_read(monkeypatch):
    def clock():
        raise AssertionError("the genesis block was built with the time of the machine")

    monkeypatch.setattr(node.time, "time", clock)
    build_genesis_block(a_genesis())
    with pytest.raises(ValueError, match="timestamp"):
        build_genesis_block(without_timestamp())


def test_two_builds_of_one_genesis_at_two_moments_give_one_block(monkeypatch):
    first = build_genesis_block(a_genesis())
    now = time.time()
    monkeypatch.setattr(node.time, "time", lambda: now + 3600)
    second = build_genesis_block(copy.deepcopy(a_genesis()))
    assert first.hash_hex() == second.hash_hex() and first.to_dict() == second.to_dict()
    assert build_genesis_block({**a_genesis(), "timestamp": 1_794_000_001}).hash_hex() != first.hash_hex()


def _init(tmp_path: Path, genesis: dict) -> tuple[int, Path]:
    path, data = tmp_path / "genesis.json", tmp_path / "data"
    path.write_text(json.dumps(genesis), encoding="utf-8")
    return cmd_init(argparse.Namespace(genesis=str(path), data_dir=str(data))), data


def test_init_refuses_a_genesis_without_a_timestamp_and_initialises_nothing(tmp_path, capsys):
    code, data = _init(tmp_path, without_timestamp())
    assert code == 1
    assert "timestamp" in capsys.readouterr().err
    assert not data.exists()         # nothing was written: the operator corrects the file and starts again


def test_control_init_with_a_timestamp(tmp_path, capsys):
    code, data = _init(tmp_path, a_genesis())
    assert code == 0
    printed = capsys.readouterr().out
    storage = Storage(str(data))
    try:
        block = storage.get_block_by_level(0)
        assert block is not None and block.header.timestamp == 1_794_000_000
        assert block.hash_hex() == build_genesis_block(a_genesis()).hash_hex() and block.hash_hex() in printed
    finally:
        storage.close()


def test_the_genesis_the_devnet_generator_writes_has_its_timestamp(tmp_path):
    """scripts/build_genesis.py writes the moment it runs, once, in the
    file every node of the devnet is initialised from."""
    keyfile = tmp_path / "baker.json"
    keyfile.write_text(json.dumps({"address": KEYS[0].address, "public_key": KEYS[0].public_key_b58}), encoding="utf-8")
    out = tmp_path / "genesis.json"
    before = int(time.time())
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_genesis.py"), "--validator", f"{keyfile}:1000000",
                    "--out", str(out)], check=True, capture_output=True, cwd=tmp_path)
    genesis = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(genesis["timestamp"], int) and before <= genesis["timestamp"] <= int(time.time())
    again = json.loads(out.read_text(encoding="utf-8"))
    assert build_genesis_block(genesis).hash_hex() == build_genesis_block(again).hash_hex()


def test_the_genesis_of_the_repository_is_not_one_a_node_starts_from():
    """genesis.json at the root is a placeholder for a network that does
    not exist: it names no proposer and no moment, and no node can be
    initialised from it as it stands."""
    genesis = json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))
    assert "timestamp" not in genesis and "genesis_proposer" not in genesis
    with pytest.raises((ValueError, KeyError)):
        build_genesis_block(genesis)
