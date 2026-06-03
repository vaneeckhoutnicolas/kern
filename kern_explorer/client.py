# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern_explorer.client
====================

Async HTTP client for the Kern node RPC.

The indexer uses this to tail the chain. The web app uses this for
live queries (e.g., mempool, latest validator set) that benefit from
freshness over staleness in the SQLite cache.

Design choices:
- httpx for async (mature, well-tested; aiohttp would also work but
  httpx has a nicer API for this size of client)
- All endpoints return parsed JSON dicts; on HTTP error, we raise
  KernRpcError with the status code and body — callers decide whether
  to retry, log, or surface
- Reasonable per-request timeout (10s) so a stuck node doesn't freeze
  the indexer; the indexer's loop has its own retry logic
"""

from __future__ import annotations

from typing import Any, Optional

import httpx


class KernRpcError(Exception):
    """Raised when the Kern RPC returns a non-success status or is unreachable."""

    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"RPC {status} from {url}: {body[:200]}")
        self.status = status
        self.body = body
        self.url = url


class KernRpcClient:
    """Async client wrapping the Kern node RPC.

    Use as an async context manager OR call .close() explicitly when done."""

    def __init__(self, base_url: str = "http://127.0.0.1:8732", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> "KernRpcClient":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # --- low-level ---------------------------------------------------------

    async def _get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        try:
            r = await self._client.get(url)
        except httpx.HTTPError as e:
            raise KernRpcError(0, str(e), url) from e
        if r.status_code >= 400:
            raise KernRpcError(r.status_code, r.text, url)
        return r.json()

    async def _post(self, path: str, payload: dict) -> Any:
        url = f"{self.base_url}{path}"
        try:
            r = await self._client.post(url, json=payload)
        except httpx.HTTPError as e:
            raise KernRpcError(0, str(e), url) from e
        if r.status_code >= 400:
            raise KernRpcError(r.status_code, r.text, url)
        return r.json()

    # --- chain ------------------------------------------------------------

    async def head(self) -> dict:
        """Return the current chain head: {level, hash, parent_hash, ...}."""
        return await self._get("/chain/head")

    async def block(self, level: int) -> dict:
        """Return the full block at a given level."""
        return await self._get(f"/chain/block/{level}")

    async def block_by_hash(self, block_hash: str) -> dict:
        return await self._get(f"/chain/block/by_hash/{block_hash}")

    async def balance(self, address: str) -> dict:
        """Return {balance: int} for an address (in mukrn)."""
        return await self._get(f"/chain/balance/{address}")

    async def nonce(self, address: str) -> dict:
        return await self._get(f"/chain/nonce/{address}")

    async def contract(self, address: str) -> Optional[dict]:
        """Return contract code + storage, or None if no contract at this address."""
        try:
            return await self._get(f"/chain/contract/{address}")
        except KernRpcError as e:
            if e.status == 404:
                return None
            raise

    async def mempool(self) -> list[dict]:
        """Return pending transactions in the mempool."""
        result = await self._get("/chain/mempool")
        # Older RPC returns a dict {"pending": [...]} ; newer returns a list directly
        if isinstance(result, dict):
            return result.get("pending", [])
        return result

    async def validators(self) -> list[dict]:
        return await self._get("/chain/validators")

    async def health(self) -> dict:
        return await self._get("/chain/health")

    async def governance(self) -> dict:
        return await self._get("/chain/governance")

    async def inject_transaction(self, tx: dict) -> dict:
        return await self._post("/chain/inject_transaction", tx)
