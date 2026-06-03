# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.rpc
--------

JSON-over-HTTP RPC for the Kern node. Endpoints loosely follow the Tezos
RPC structure to keep the cognitive load low for anyone coming from
Tezos.

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
from typing import TYPE_CHECKING

from aiohttp import web

from .transaction import Transaction

LOG = logging.getLogger("kern.rpc")

if TYPE_CHECKING:
    from .node import Node


def build_app(node: "Node") -> web.Application:
    app = web.Application()

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
        body = await req.json()
        try:
            tx = Transaction.from_dict(body)
        except Exception as e:
            return web.json_response({"error": f"malformed transaction: {e}"}, status=400)
        if not tx.verify_signature():
            return web.json_response({"error": "invalid signature"}, status=400)
        node.storage.add_to_mempool(tx)
        # Broadcast to peers.
        if node.network is not None:
            asyncio.create_task(node.network.broadcast_tx(tx.to_dict()))
        return web.json_response({"hash": tx.hash_hex()})

    async def mempool(_req: web.Request) -> web.Response:
        txs = node.storage.drain_mempool(max_n=10_000)
        return web.json_response({
            "size": len(txs),
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
