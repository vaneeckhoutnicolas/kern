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


def _make_devnet(tmp_path, stakes):
    n_nodes = len(stakes)
    keys = [KernKeypair.from_seed(bytes([0xD0 + i]) * 32) for i in range(n_nodes)]
    genesis = {
        "chain_id": "kern-e1-integration",
        "timestamp": int(time.time()),
        "balances": {k.address: 2 * s for k, s in zip(keys, stakes)},
        "validators": [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                       for k, s in zip(keys, stakes)],
        "genesis_proposer": {"address": keys[0].address, "pubkey": keys[0].public_key_b58},
    }
    gpath = tmp_path / "genesis.json"
    gpath.write_text(json.dumps(genesis))
    p2p = _free_ports(n_nodes)
    rpc = _free_ports(n_nodes)
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

    def start(i, extra_env=None):
        n = nodes[i]
        peers = []
        for j in range(n_nodes):
            if j != i:
                peers += ["--peer", f"127.0.0.1:{nodes[j]['p2p']}"]
        n["proc"] = subprocess.Popen(
            [sys.executable, "-m", "kern.node", "start", "--data-dir", str(n["dir"]),
             "--rpc-port", str(n["rpc"]), "--p2p-port", str(n["p2p"]),
             "--baker-key", str(n["key"]), "--block-time", str(BLOCK_TIME), *peers],
            env=dict(env, **(extra_env or {})), cwd=ROOT, stdout=n["log"],
            stderr=subprocess.STDOUT)

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

    def crash(i):
        """Kill the process with no chance to clean up (SIGKILL on Linux,
        TerminateProcess on Windows): no final snapshot, nothing flushed
        that was not already synced."""
        p = nodes[i]["proc"]
        if p is not None and p.poll() is None:
            p.kill()
            p.wait()
        nodes[i]["proc"] = None

    def close():
        for i in range(n_nodes):
            stop(i)
            nodes[i]["log"].close()

    return {"nodes": nodes, "start": start, "stop": stop, "crash": crash, "close": close,
            "genesis": genesis, "path": tmp_path}


@pytest.fixture
def devnet(tmp_path):
    d = _make_devnet(tmp_path, [STAKE] * N)
    yield d
    d["close"]()


@pytest.fixture
def weighted_devnet(tmp_path):
    d = _make_devnet(tmp_path, [9 * STAKE, STAKE])            # 90 % / 10 %
    yield d
    d["close"]()


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


def test_weighted_90_10_survives_repeated_crashes_of_the_dominant_validator(weighted_devnet):
    """Review of f24564b, P1. Two validators, 90 % and 10 % of the stake.
    The 90 % validator is the proposer of almost every round and finalizes
    alone through its self-commit. It is killed outright several times, at
    different moments of block production, and restarted from the same data
    directory and signing journal. Expected: no stuck level, the same block
    at every level on both nodes, every block verified independently, and
    no conflicting signature."""
    d = weighted_devnet
    nodes = d["nodes"]
    big, small = nodes
    for i in range(2):
        d["start"](i)
    try:
        _wait(lambda: min(_height(n["rpc"]) for n in nodes) >= 3, 90, "first blocks")
        for k, pause in enumerate((0.13, 0.41, 0.77, 1.9)):
            time.sleep(pause)                                  # crash at varied points
            d["crash"](0)
            before = _height(small["rpc"])
            time.sleep(1.0)
            # The 10 % validator alone cannot finalize anything new: at most
            # the block its partner had already proposed with its self-commit.
            assert _height(small["rpc"]) <= before + 1
            d["start"](0)
            goal = max(_height(n["rpc"]) for n in nodes) + 3
            _wait(lambda: min(_height(n["rpc"]) for n in nodes) >= goal, 90,
                  f"progress after crash {k + 1}")
    except AssertionError:
        raise AssertionError(_logs(d))

    common = min(_height(n["rpc"]) for n in nodes)
    headers = [[json.dumps(b["header"], sort_keys=True) for b in _blocks(n["rpc"], common)]
               for n in nodes]
    assert headers[0] == headers[1], "the two nodes disagree on a finalized block"

    genesis = d["genesis"]
    fresh = Chain(build_genesis_block(genesis), genesis["validators"],
                  initial_state=initial_state_from_genesis(genesis))
    for blk in _blocks(small["rpc"], common):
        fresh.append(Block.from_dict(blk), require_quorum=True)

    log = (d["path"] / "node0.log").read_text(errors="replace")
    assert "submitted slashing evidence" not in log


@pytest.mark.parametrize("failpoint", ["after_self_commit", "after_proposal_signed",
                                       "after_proposal_broadcast"])
def test_weighted_90_10_crash_at_each_failpoint(weighted_devnet, failpoint):
    """Review of f24564b, P1, with the crash placed exactly: the 90 %
    validator dies at the named point of its third proposal (after the
    self-commit and lock are synced; after the PROPOSE is signed; after
    the proposal is broadcast, before the block is finalized). It restarts
    from the same data directory. Expected: the level it was working on is
    finalized with the same payload on both nodes, the chain moves on, and
    every block verifies independently."""
    from kern.failpoints import FAILPOINT_EXIT_CODE

    d = weighted_devnet
    nodes = d["nodes"]
    big, small = nodes
    d["start"](1)
    d["start"](0, {"KERN_FAILPOINT": failpoint, "KERN_FAILPOINT_SKIP": "2"})
    try:
        _wait(lambda: big["proc"].poll() is not None, 90, f"crash at {failpoint}")
        assert big["proc"].returncode == FAILPOINT_EXIT_CODE
        big["proc"] = None
        stuck_level = max(_height(small["rpc"]), 0) + 1
        journal = (big["dir"] / JOURNAL_FILE).read_text()
        locked = [json.loads(line) for line in journal.splitlines()
                  if json.loads(line)["level"] == stuck_level
                  and json.loads(line)["kind"] == "endorse"]
        d["start"](0)
        _wait(lambda: min(_height(n["rpc"]) for n in nodes) >= stuck_level + 3, 90,
              f"progress after restart from {failpoint}")
    except AssertionError:
        raise AssertionError(_logs(d))

    common = min(_height(n["rpc"]) for n in nodes)
    headers = [[json.dumps(b["header"], sort_keys=True) for b in _blocks(n["rpc"], common)]
               for n in nodes]
    assert headers[0] == headers[1]
    final = Block.from_dict(_get(small["rpc"], f"/chain/block/{stuck_level}"))
    # The block finalized at the crash level is the one the lock named.
    assert {r["block_hash"] for r in locked} <= {final.hash_hex()}

    genesis = d["genesis"]
    fresh = Chain(build_genesis_block(genesis), genesis["validators"],
                  initial_state=initial_state_from_genesis(genesis))
    for blk in _blocks(small["rpc"], common):
        fresh.append(Block.from_dict(blk), require_quorum=True)

