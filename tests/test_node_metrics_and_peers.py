# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Node metrics and peer connections, found with the Docker devnet
(scripts/devnet.py).

1. kern_peers_connected counted only outgoing connections that succeeded
   at start; nodes reached through incoming connections showed 0 peers.
2. A failed outgoing connection was never retried. Nodes started together
   (or restarted together, or split by a network cut) never connected to
   each other again.
3. kern_chain_height and kern_blocks_applied_total were updated inside
   apply_block, which also runs to validate every proposal: the height ran
   one level ahead and applied blocks were counted about twice.
4. kern_blocks_produced_total was never incremented.
5. Nothing showed the consensus itself: the round in progress, round
   timeouts, the round a block was finalized in, equivocation evidence.

Every test here fails on 7c437aa."""

import asyncio
import socket
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiohttp.test_utils import TestClient, TestServer

from kern.node import Node
from kern.observability import REGISTRY
from kern.rpc import build_app
from kern.storage import Storage

from test_phase_e_invalid_first_proposal import _chain, _envelope, _keys, _run, _setup


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _metric(text, name):
    for line in text.splitlines():
        if line.startswith(name + " "):
            return float(line.split()[1])
    raise AssertionError(f"{name} not in metrics")


def _scrape(node):
    async def go():
        client = TestClient(TestServer(build_app(node)))
        await client.start_server()
        try:
            return await (await client.get("/metrics")).text()
        finally:
            await client.close()
    return asyncio.run(go())


def _plain_node(tmp_path, name, peers=()):
    path = tmp_path / name
    path.mkdir()
    return Node(str(path), _chain(_keys()), Storage(str(path)), None,
                rpc_port=_free_port(), p2p_port=_free_port(), peers=list(peers),
                block_time=1.0, rpc_host="127.0.0.1", p2p_host="127.0.0.1")


async def _until(cond, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        await asyncio.sleep(0.05)
    return False


# ----------------------------------------------------------------- peers

def test_incoming_connections_count_as_peers(tmp_path, monkeypatch):
    monkeypatch.setattr("kern.node.PEER_RETRY_SECONDS", 0.2, raising=False)
    a = _plain_node(tmp_path, "a")
    b = _plain_node(tmp_path, "b", peers=[f"127.0.0.1:{a.p2p_port}"])

    async def go():
        ta = asyncio.create_task(a.start())
        await _until(lambda: a.network is not None and a.network._server is not None)
        tb = asyncio.create_task(b.start())
        ok = await _until(lambda: a.network.connection_count >= 1
                          and b.network.connection_count >= 1)
        await b.stop(); await a.stop()
        await tb; await ta
        return ok

    assert asyncio.run(go())


def test_a_peer_that_was_down_is_connected_when_it_comes_up(tmp_path, monkeypatch):
    """B is started first and A is not listening yet; once A is up, B
    connects to it. After A stops and comes back, B connects again."""
    monkeypatch.setattr("kern.node.PEER_RETRY_SECONDS", 0.2, raising=False)
    a_port = _free_port()
    a_dir = tmp_path / "a"
    a_dir.mkdir()

    def make_a():
        return Node(str(a_dir), _chain(_keys()), Storage(str(a_dir)), None,
                    rpc_port=_free_port(), p2p_port=a_port, peers=[], block_time=1.0,
                    rpc_host="127.0.0.1", p2p_host="127.0.0.1")

    b = _plain_node(tmp_path, "b", peers=[f"127.0.0.1:{a_port}"])

    async def go():
        tb = asyncio.create_task(b.start())
        await asyncio.sleep(0.5)                       # B's first attempt fails
        a = make_a()
        ta = asyncio.create_task(a.start())
        first = await _until(lambda: a.network is not None and a.network.connection_count >= 1)
        await a.stop(); await ta
        await _until(lambda: b.network.connection_count == 0)
        a2 = make_a()
        ta2 = asyncio.create_task(a2.start())
        again = await _until(lambda: a2.network is not None and a2.network.connection_count >= 1)
        await a2.stop(); await ta2
        await b.stop(); await tb
        return first, again

    assert asyncio.run(go()) == (True, True)


# ----------------------------------------------------------------- chain

def test_validating_a_proposal_does_not_move_the_chain_metrics(tmp_path, monkeypatch):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    applied = REGISTRY._metrics["kern_blocks_applied_total"].value()
    _run(node, good)                                   # validated, not finalized
    text = _scrape(node)
    assert node.chain.height == 0
    assert _metric(text, "kern_chain_height") == 0
    assert REGISTRY._metrics["kern_blocks_applied_total"].value() == applied
    storage.close()


def test_finalized_blocks_move_the_chain_metrics(tmp_path, monkeypatch):
    """A block this validator proposed and that is finalized counts as
    produced and applied, and sets the height and the finalization round."""
    from kern.consensus import propose_block, select_proposer
    import kern.consensus as consensus_mod
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    r = next(r for r in range(64) if select_proposer(
        chain.head.hash_hex(), chain.validators, r)["address"] == me.address)
    with monkeypatch.context() as mp:
        mp.setattr(consensus_mod.time, "time", lambda: 1_700_000_100)
        block = propose_block(parent=chain.head, mempool=[], proposer_keypair=me,
                              proposer_pubkey_b58=me.public_key_b58,
                              state_before=chain.state, round_=r)
    block.cert_round = r + 2                          # finalized two rounds later
    produced = REGISTRY._metrics["kern_blocks_produced_total"].value()
    applied = REGISTRY._metrics["kern_blocks_applied_total"].value()
    node.chain.append(block, require_quorum=False)
    node._after_block_applied(block, broadcast=False)
    text = _scrape(node)
    assert _metric(text, "kern_chain_height") == 1
    assert _metric(text, "kern_blocks_produced_total") == produced + 1
    assert _metric(text, "kern_blocks_applied_total") == applied + 1
    assert _metric(text, "kern_consensus_last_finalized_round") == r + 2
    storage.close()


# ----------------------------------------------------------------- consensus

def test_consensus_metrics(tmp_path, monkeypatch):
    keys, chain, proposer, me, node, storage = _setup(tmp_path)
    bad = _envelope(chain, proposer, monkeypatch, 1_700_000_100, invalid=True)
    good = _envelope(chain, proposer, monkeypatch, 1_700_000_101)
    _run(node, bad, good)                              # one proposal equivocation
    node._round = 3
    timeouts = REGISTRY._metrics["kern_consensus_round_timeouts_total"].value()
    text = _scrape(node)
    assert _metric(text, "kern_consensus_round") == 3
    assert _metric(text, "kern_consensus_level") == 1
    assert _metric(text, "kern_consensus_proposal_evidence") == 1
    assert _metric(text, "kern_consensus_round_timeouts_total") == timeouts
    storage.close()


# ----------------------------------------------------------------- histogram

def test_histogram_buckets_are_cumulative_once():
    """Prometheus buckets are cumulative counts that never exceed _count.
    `observe` already counts a value in every bucket that covers it, and
    `render` added them up again: on the devnet, 334 blocks showed 3000 in
    the 10 s bucket, and the dashboards read a p95 block apply time of
    7.7 s for a real mean of 0.2 ms."""
    from kern.observability import Histogram
    h = Histogram("t_seconds", buckets=(0.001, 0.01, 0.1))
    for v in (0.0005, 0.005, 0.05, 0.5):
        h.observe(v)
    lines = dict(line.rsplit(" ", 1) for line in h.render() if not line.startswith("#"))
    assert lines['t_seconds_bucket{le="0.001"}'] == "1"
    assert lines['t_seconds_bucket{le="0.01"}'] == "2"
    assert lines['t_seconds_bucket{le="0.1"}'] == "3"
    assert lines['t_seconds_bucket{le="+Inf"}'] == "4"
    assert lines["t_seconds_count"] == "4"
