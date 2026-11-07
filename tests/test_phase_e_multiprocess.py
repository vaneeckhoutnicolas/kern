# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, E1: multi-process integration test (consensus-locking.md 9.4).

tests/bft_sim.py drives real engines but models the node and the network.
This test runs four complete `python -m kern.node` processes, each with its
own data directory, validator key and signing journal, connected over the
real peer-to-peer layer on localhost. It checks that:

1. every node finalizes blocks and all agree on every block hash;
2. a node that starts from genesis with only the blocks (fetched over RPC)
   verifies the quorum of each one on its own and reaches the same state;
3. with one validator stopped, the three others (three quarters of the
   stake) keep finalizing;
4. the stopped validator restarts from its data directory and its signing
   journal, catches up, and nobody signs conflicting votes (no slashing
   transaction appears).

This is still one machine. It is not the multi-machine devnet with
independent operators, which remains to be run."""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kern.block import Block  # noqa: E402
from kern.chain import Chain, initial_state_from_genesis  # noqa: E402
from kern.crypto import KernKeypair  # noqa: E402
from kern.node import build_genesis_block  # noqa: E402
from kern.signing_journal import JOURNAL_FILE  # noqa: E402

N = 4
STAKE = 1_000_000_000_000
BLOCK_TIME = 0.5


def _free_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as r:
        return json.loads(r.read())


def _height(port):
    try:
        return _get(port, "/chain/head")["level"]
    except Exception:
        return -1


def _wait(pred, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture
def devnet(tmp_path):
    keys = [KernKeypair.from_seed(bytes([0xD0 + i]) * 32) for i in range(N)]
    genesis = {
        "chain_id": "kern-e1-integration",
        "timestamp": int(time.time()),
        "balances": {k.address: 2 * STAKE for k in keys},
        "validators": [{"address": k.address, "pubkey": k.public_key_b58, "stake": STAKE}
                       for k in keys],
        "genesis_proposer": {"address": keys[0].address, "pubkey": keys[0].public_key_b58},
    }
    gpath = tmp_path / "genesis.json"
    gpath.write_text(json.dumps(genesis))
    p2p = _free_ports(N)
    rpc = _free_ports(N)
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONUNBUFFERED="1")
    nodes = []
    for i, k in enumerate(keys):
        d = tmp_path / f"node{i}"
        keyfile = tmp_path / f"baker{i}.json"
        keyfile.write_text(json.dumps({"seed_hex": (bytes([0xD0 + i]) * 32).hex()}))
        subprocess.run([sys.executable, "-m", "kern.node", "init", "--genesis", str(gpath),
                        "--data-dir", str(d)], check=True, env=env, cwd=ROOT,
                       capture_output=True)
        nodes.append({"dir": d, "key": keyfile, "rpc": rpc[i], "p2p": p2p[i], "proc": None,
                      "log": open(tmp_path / f"node{i}.log", "w")})

    def start(i):
        n = nodes[i]
        peers = []
        for j in range(N):
            if j != i:
                peers += ["--peer", f"127.0.0.1:{nodes[j]['p2p']}"]
        n["proc"] = subprocess.Popen(
            [sys.executable, "-m", "kern.node", "start", "--data-dir", str(n["dir"]),
             "--rpc-port", str(n["rpc"]), "--p2p-port", str(n["p2p"]),
             "--baker-key", str(n["key"]), "--block-time", str(BLOCK_TIME), *peers],
            env=env, cwd=ROOT, stdout=n["log"], stderr=subprocess.STDOUT)

    def stop(i):
        p = nodes[i]["proc"]
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        nodes[i]["proc"] = None

    yield {"nodes": nodes, "start": start, "stop": stop, "genesis": genesis, "path": tmp_path}
    for i in range(N):
        stop(i)
        nodes[i]["log"].close()


def _logs(devnet):
    out = []
    for i, n in enumerate(devnet["nodes"]):
        n["log"].flush()
        text = (devnet["path"] / f"node{i}.log").read_text(errors="replace")
        out.append(f"--- node{i} ---\n" + "\n".join(text.splitlines()[-25:]))
    return "\n".join(out)


def _blocks(port, hi):
    return [_get(port, f"/chain/block/{lvl}") for lvl in range(1, hi + 1)]


def test_four_node_processes_agree_survive_a_stop_and_resync(devnet):
    nodes = devnet["nodes"]
    for i in range(N):
        devnet["start"](i)
    try:
        _wait(lambda: all(_height(n["rpc"]) >= 6 for n in nodes), 120, "6 blocks on every node")
    except AssertionError:
        raise AssertionError(_logs(devnet))

    # 1. Agreement on every block.
    common = min(_height(n["rpc"]) for n in nodes)
    chains = [[b["header"] for b in _blocks(n["rpc"], common)] for n in nodes]
    hashes = [[json.dumps(h, sort_keys=True) for h in c] for c in chains]
    assert all(h == hashes[0] for h in hashes), "nodes disagree on a finalized block"

    # 2. A fresh verifier checks every quorum from the blocks alone.
    genesis = devnet["genesis"]
    gblock = build_genesis_block(genesis)
    assert gblock.hash_hex() == Block.from_dict(_get(nodes[0]["rpc"], "/chain/block/0")).hash_hex()
    fresh = Chain(gblock, genesis["validators"], initial_state=initial_state_from_genesis(genesis))
    for d in _blocks(nodes[1]["rpc"], common):
        fresh.append(Block.from_dict(d), require_quorum=True)
    assert fresh.head.hash_hex() == Block.from_dict(_get(nodes[2]["rpc"], f"/chain/block/{common}")).hash_hex()

    # 3. One validator down: three quarters of the stake keep going.
    devnet["stop"](3)
    live = nodes[:3]
    target = max(_height(n["rpc"]) for n in live) + 4
    try:
        _wait(lambda: all(_height(n["rpc"]) >= target for n in live), 90,
              "progress with one validator stopped")
    except AssertionError:
        raise AssertionError(_logs(devnet))

    # 4. Restart from the same data directory and journal; it catches up.
    assert (nodes[3]["dir"] / JOURNAL_FILE).exists()
    devnet["start"](3)
    goal = max(_height(n["rpc"]) for n in live) + 2
    try:
        _wait(lambda: all(_height(n["rpc"]) >= goal for n in nodes), 90, "catch-up after restart")
    except AssertionError:
        raise AssertionError(_logs(devnet))
    common = min(_height(n["rpc"]) for n in nodes)
    heads = {json.dumps(_get(n["rpc"], f"/chain/block/{common}")["header"], sort_keys=True)
             for n in nodes}
    assert len(heads) == 1

    # Nobody equivocated: no slashing report was filed by any node, and
    # none was included in a block.
    for i in range(N):
        assert "submitted slashing evidence" not in (devnet["path"] / f"node{i}.log").read_text(
            errors="replace")
    for d in _blocks(nodes[0]["rpc"], common):
        assert not any(t.get("kind") == "slash_consensus_equivocation" for t in d["transactions"])
