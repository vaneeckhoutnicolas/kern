# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""scripts/devnet.py without Docker: ports read from the generated compose
file, and the `check` logic (every validator holds the same block at every
level) on fake nodes. The Docker path itself was run on a real devnet
(docs/devnet.md)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "networks"))
sys.path.insert(0, str(ROOT))

import pytest

import devnet  # noqa: E402
import devnet_bootstrap  # noqa: E402


def test_ports_come_from_the_generated_compose_file(tmp_path):
    out = tmp_path / "devnet"
    devnet_bootstrap.build(out, 11, 10**12, 10**12, 10**15)
    ports = devnet.node_ports(out)
    assert list(ports) == [f"baker{i}" for i in range(11)]       # numeric order
    assert ports["baker10"] == devnet_bootstrap.BASE_RPC_PORT + 10


def _fake(chains, down=()):
    """chains: node -> list of block hashes from level 0."""
    ports = {name: 20000 + i for i, name in enumerate(chains)}
    by_port = {p: n for n, p in ports.items()}

    def get(url):
        port = int(url.split(":")[2].split("/")[0])
        name = by_port[port]
        if name in down:
            raise OSError("connection refused")
        chain = chains[name]
        if url.endswith("/chain/head"):
            return {"level": len(chain) - 1, "hash": chain[-1]}
        level = int(url.rsplit("/", 1)[1])
        return {"hash": chain[level], "header": {"level": level}}
    return ports, get


def test_check_agrees_up_to_the_lowest_head():
    ports, get = _fake({"baker0": ["g", "a", "b", "c"], "baker1": ["g", "a", "b"],
                        "baker2": ["g", "a", "b", "c", "d"]})
    assert devnet.divergences(ports, get) == (2, [], [])


def test_check_reports_a_divergence():
    ports, get = _fake({"baker0": ["g", "a", "b"], "baker1": ["g", "a", "X"]})
    assert devnet.divergences(ports, get) == (2, [2], [])


def test_check_skips_a_node_that_does_not_answer():
    ports, get = _fake({"baker0": ["g", "a"], "baker1": ["g", "a"], "baker2": ["g"]},
                       down=("baker2",))
    assert devnet.divergences(ports, get) == (1, [], ["baker2"])


def test_commands_other_than_up_need_a_devnet(tmp_path):
    with pytest.raises(SystemExit):
        devnet.main(["--out", str(tmp_path / "none"), "status"])
    assert devnet.main(["--out", str(tmp_path / "none"), "down"]) == 0
