# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.rpc
--------

JSON-over-HTTP RPC for the Kern node. Endpoints use a flat, predictable
`/chain/...` namespace so that wallets, explorers and tooling can target
them without ceremony.

The injection endpoint is write-facing and therefore guarded: a per-client
fixed-window rate limiter sheds abusive request volume, and mempool
admission is bounded per sender and globally (see
`docs/mempool-rpc-hardening.md`).

Endpoints:

    GET  /chain/head
    GET  /chain/block/{level}
    GET  /chain/block/by_hash/{hash}
    GET  /chain/balance/{address}
    GET  /chain/nonce/{address}
    GET  /chain/contract/{address}
    POST /chain/inject_transaction
    GET  /chain/mempool
    GET  /chain/validators
    GET  /chain/health
    GET  /chain/governance     (v0.6)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Deque, Dict

from aiohttp import web

from .transaction import Transaction

LOG = logging.getLogger("kern.rpc")

if TYPE_CHECKING:
    from .node import Node


# Default rate-limit budget for write-facing endpoints: at most
# RATE_LIMIT_MAX requests per client identity within a RATE_LIMIT_WINDOW_S
# sliding window. Reads are not limited.
RATE_LIMIT_MAX = 100
RATE_LIMIT_WINDOW_S = 10.0

# Read endpoints get their own, more generous budget: legitimate polling
# (block explorers, Prometheus scrapes) must not be throttled, but a GET
# flood — cheaper for an attacker than the write path — should still be shed.
READ_RATE_LIMIT_MAX = 600


class RateLimiter:
    """In-process sliding-window rate limiter keyed by client identity.

    Deliberately dependency-free and per-process: it is a first line of
    defence against trivial flooding of the injection endpoint, not a
    substitute for an edge proxy / WAF in production deployments.
    """

    def __init__(self, max_events: int = RATE_LIMIT_MAX,
                 window_s: float = RATE_LIMIT_WINDOW_S):
        self.max_events = max_events
        self.window_s = window_s
        self._hits: Dict[str, Deque[float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        dq = self._hits.setdefault(key, deque())
        cutoff = now - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.max_events:
            return False
        dq.append(now)
        return True


def make_read_throttle(read_limiter: "RateLimiter", window_s: float, exempt: set):
    """Build an aiohttp middleware that rate-limits GET requests per client.

    Non-GET requests pass through untouched (the write path does its own,
    stricter limiting inside ``inject_transaction``). Paths in ``exempt`` —
    typically the liveness endpoint — are never throttled, so a ``429`` can
    never be mistaken for an unhealthy node by a load balancer or monitor.
    """
    @web.middleware
    async def throttle_reads(request: web.Request, handler):
        if request.method == "GET" and request.path not in exempt:
            client = request.remote or "unknown"
            if not read_limiter.allow(client):
                return web.json_response(
                    {"error": "rate limit exceeded"},
                    status=429,
                    headers={"Retry-After": str(int(window_s))},
                )
        return await handler(request)

    return throttle_reads


def build_app(
    node: "Node",
    rate_limit_max: int = RATE_LIMIT_MAX,
    rate_limit_window_s: float = RATE_LIMIT_WINDOW_S,
    read_rate_limit_max: int = READ_RATE_LIMIT_MAX,
) -> web.Application:
    app = web.Application()
    # Write path (transaction injection): a strict budget — see inject_transaction.
    limiter = RateLimiter(rate_limit_max, rate_limit_window_s)
    app["rate_limiter"] = limiter
    # Read path (every GET endpoint): a separate, more generous budget applied
    # as a middleware, with the liveness endpoint exempt.
    read_limiter = RateLimiter(read_rate_limit_max, rate_limit_window_s)
    app["read_rate_limiter"] = read_limiter
    app.middlewares.append(
        make_read_throttle(read_limiter, rate_limit_window_s, {"/chain/health"})
    )

    async def head(_req: web.Request) -> web.Response:
        h = node.chain.head
        return web.json_response({
            "level": h.header.level,
            "hash": h.hash_hex(),
            "timestamp": h.header.timestamp,
            "proposer": h.header.proposer,
            "txs": len(h.transactions),
        })

    async def block_by_level(req: web.Request) -> web.Response:
        level = int(req.match_info["level"])
        if level < 0 or level > node.chain.height:
            return web.json_response({"error": "no such block"}, status=404)
        block = node.storage.get_block_by_level(level)
        if block is None:
            return web.json_response({"error": "no such block"}, status=404)
        return web.json_response(block.to_dict())

    async def block_by_hash(req: web.Request) -> web.Response:
        h = req.match_info["hash"]
        block = node.storage.get_block_by_hash(h)
        if block is None:
            return web.json_response({"error": "no such block"}, status=404)
        return web.json_response(block.to_dict())

    async def balance(req: web.Request) -> web.Response:
        addr = req.match_info["address"]
        bal = node.chain.state["balances"].get(addr, 0)
        return web.json_response({"address": addr, "balance": bal})

    async def nonce(req: web.Request) -> web.Response:
        addr = req.match_info["address"]
        n = node.chain.state["nonces"].get(addr, 0)
        return web.json_response({"address": addr, "nonce": n})

    async def contract(req: web.Request) -> web.Response:
        addr = req.match_info["address"]
        c = node.chain.state["contracts"].get(addr)
        if c is None:
            return web.json_response({"error": "no such contract"}, status=404)
        return web.json_response({"address": addr, **c})

    async def inject_transaction(req: web.Request) -> web.Response:
        client = req.remote or "unknown"
        if not limiter.allow(client):
            return web.json_response(
                {"error": "rate limit exceeded"},
                status=429,
                headers={"Retry-After": str(int(rate_limit_window_s))},
            )
        body = await req.json()
        try:
            tx = Transaction.from_dict(body)
        except Exception as e:
            return web.json_response({"error": f"malformed transaction: {e}"}, status=400)
        if not tx.verify_signature():
            return web.json_response({"error": "invalid signature"}, status=400)
        admitted = node.storage.add_to_mempool(tx)
        if not admitted:
            return web.json_response(
                {"error": "mempool full or per-sender limit reached"},
                status=429,
            )
        # Broadcast to peers only once the tx is accepted locally.
        if node.network is not None:
            asyncio.create_task(node.network.broadcast_tx(tx.to_dict()))
        return web.json_response({"hash": tx.hash_hex()})

    async def mempool(_req: web.Request) -> web.Response:
        # Bound per-request work: report the true mempool size, but serialise
        # only a capped slice of hashes so this read cannot be turned into an
        # amplification vector (previously it drained up to 10,000 rows/call).
        txs = node.storage.drain_mempool(max_n=1000)
        return web.json_response({
            "size": node.storage.mempool_size(),
            "returned": len(txs),
            "hashes": [tx.hash_hex() for tx in txs],
        })

    async def validators(_req: web.Request) -> web.Response:
        return web.json_response(node.chain.validators)

    async def health(_req: web.Request) -> web.Response:
        return web.json_response({
            "ok": True,
            "level": node.chain.height,
            "peers": len(node.network.peers) if node.network else 0,
            "mempool": node.storage.mempool_size(),
        })

    async def governance(_req: web.Request) -> web.Response:
        """Return the current governance state: active proposals, activated
        changes, treasury executions, and the current state_root function."""
        gov = node.chain.state.get("governance", {})
        return web.json_response({
            "state_root_function": node.chain.state.get("state_root_function", "json"),
            "issuance_params": node.chain.state.get("issuance_params"),
            "protocol": {
                "proposals": gov.get("protocol", {}).get("proposals", {}),
                "activated_changes": gov.get("protocol", {}).get("activated_changes", []),
                "bond_count": len(gov.get("protocol", {}).get("bonds", {})),
            },
            "treasury": {
                "proposals": gov.get("treasury", {}).get("proposals", {}),
                "executions": gov.get("treasury", {}).get("executions", []),
                "bond_count": len(gov.get("treasury", {}).get("bonds", {})),
            },
        })

    async def metrics(_req: web.Request) -> web.Response:
        """Prometheus scrape endpoint. v0.9."""
        from .observability import REGISTRY, render_metrics
        # Refresh dynamic gauges before rendering.
        g_mempool = REGISTRY._metrics.get("kern_mempool_size")
        if g_mempool is not None:
            g_mempool.set(node.storage.mempool_size())  # type: ignore
        g_peers = REGISTRY._metrics.get("kern_peers_connected")
        if g_peers is not None and node.network is not None:
            g_peers.set(len(node.network.peers))  # type: ignore
        return web.Response(text=render_metrics(),
                            content_type="text/plain; version=0.0.4")

    app.router.add_get("/chain/head", head)
    app.router.add_get("/chain/block/{level:\\d+}", block_by_level)
    app.router.add_get("/chain/block/by_hash/{hash}", block_by_hash)
    app.router.add_get("/chain/balance/{address}", balance)
    app.router.add_get("/chain/nonce/{address}", nonce)
    app.router.add_get("/chain/contract/{address}", contract)
    app.router.add_post("/chain/inject_transaction", inject_transaction)
    app.router.add_get("/chain/mempool", mempool)
    app.router.add_get("/chain/validators", validators)
    app.router.add_get("/chain/health", health)
    app.router.add_get("/chain/governance", governance)
    app.router.add_get("/metrics", metrics)
    return app
