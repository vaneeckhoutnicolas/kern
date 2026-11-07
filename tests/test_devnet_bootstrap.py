# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""networks/devnet_bootstrap.py must produce a devnet that can start.

The generated docker-compose file could not start a single node: its
command repeated the image's entrypoint (`python -m kern.node`), passed
`--peers` (the node takes `--peer`, once per peer), gave the RPC and the
peer-to-peer layer the same port, and never initialized the data
directory. Docker is not available in the test environment, so each
service's command is checked against the node's own argument parser, and
the genesis is initialized with the node's own `init`."""

import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern import node as node_mod

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "networks"))

import devnet_bootstrap  # noqa: E402


def _generate(out, n=3):
    devnet_bootstrap.build(out, n, initial_stake=1_000_000_000_000,
                           initial_balance=10**12, faucet_balance=10**15)
    return json.loads((out / "docker-compose.yml").read_text())


def _node_commands(service):
    """The `python -m kern.node ...` invocations a service runs."""
    entry = service.get("entrypoint")
    cmd = service["command"]
    assert entry == ["sh", "-c"] and isinstance(cmd, str), "expected a shell command"
    out = []
    for part in cmd.split(";"):
        words = shlex.split(part)
        if words and words[0] == "exec":
            words = words[1:]
        assert words[:3] == ["python", "-m", "kern.node"], part
        out.append(words[3:])
    return out


def test_every_service_command_is_accepted_by_the_node(tmp_path):
    compose = _generate(tmp_path / "devnet")
    names = sorted(compose["services"])
    for name, svc in compose["services"].items():
        init, start = _node_commands(svc)
        a = node_mod.build_parser().parse_args(init)
        assert (a.cmd, a.data_dir, a.genesis) == ("init", "/data", "/genesis.json")
        s = node_mod.build_parser().parse_args(start)
        assert s.cmd == "start" and s.data_dir == "/data"
        assert s.rpc_port != s.p2p_port
        # Inside the container the RPC must listen beyond loopback for the
        # published port to work; the host publishes it on its loopback only.
        assert s.rpc_bind == "0.0.0.0"
        assert svc["ports"] == [f"127.0.0.1:{18732 + names.index(name)}:{s.rpc_port}"]
        assert sorted(p.split(":")[0] for p in s.peer) == sorted(set(names) - {name})
        assert all(p.endswith(f":{s.p2p_port}") for p in s.peer)
        assert s.baker_key == f"/keys/{name}.json"


def test_the_build_context_is_the_repository(tmp_path):
    for out in (tmp_path / "devnet", ROOT / "networks" / "devnet-test-tmp"):
        try:
            compose = _generate(out)
            for svc in compose["services"].values():
                ctx = (out / svc["build"]["context"]).resolve()
                assert ctx == ROOT
                assert (ctx / svc["build"]["dockerfile"]).is_file()
        finally:
            if out.parent == ROOT / "networks":
                import shutil
                shutil.rmtree(out, ignore_errors=True)


def test_the_generated_genesis_initializes_a_node(tmp_path):
    _generate(tmp_path / "devnet")
    data = tmp_path / "data"
    rc = node_mod.main(["init", "--genesis", str(tmp_path / "devnet" / "genesis.json"),
                        "--data-dir", str(data)])
    assert rc == 0
