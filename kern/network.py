# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.network
------------

Minimal asyncio-based peer-to-peer network for the reference node.

Each peer connection is a length-prefixed JSON message stream. Three
message kinds are exchanged:

    {"kind": "hello",       "level": N, "peers": [...]}
    {"kind": "block",       "block": {...}}
    {"kind": "transaction", "tx": {...}}

This is intentionally simple. A production node would use a binary
framing protocol with versioning, peer scoring, and gossip mesh routing
(libp2p / gossipsub style).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable, List, Optional, Set, Tuple

LOG = logging.getLogger("kern.network")


async def _read_msg(reader: asyncio.StreamReader) -> Optional[dict]:
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    length = int.from_bytes(header, "big")
    if length <= 0 or length > 16 * 1024 * 1024:
        return None
    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(payload.decode("utf-8"))


async def _write_msg(writer: asyncio.StreamWriter, msg: dict) -> None:
    payload = json.dumps(msg).encode("utf-8")
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()


class Network:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        on_block: Callable[[dict], Awaitable[None]],
        on_tx: Callable[[dict], Awaitable[None]],
        get_head_level: Callable[[], int],
    ):
        self.host = host
        self.port = port
        self.on_block = on_block
        self.on_tx = on_tx
        self.get_head_level = get_head_level
        self.peers: Set[Tuple[str, int]] = set()
        self._writers: List[asyncio.StreamWriter] = []
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        LOG.info("P2P listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for w in self._writers:
            w.close()

    async def connect(self, peer_host: str, peer_port: int) -> None:
        try:
            reader, writer = await asyncio.open_connection(peer_host, peer_port)
        except OSError as e:
            LOG.warning("failed to connect to %s:%d: %s", peer_host, peer_port, e)
            return
        self.peers.add((peer_host, peer_port))
        self._writers.append(writer)
        await _write_msg(writer, {"kind": "hello", "level": self.get_head_level()})
        asyncio.create_task(self._reader_loop(reader, writer))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        await _write_msg(writer, {"kind": "hello", "level": self.get_head_level()})
        await self._reader_loop(reader, writer)

    async def _reader_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                msg = await _read_msg(reader)
                if msg is None:
                    break
                kind = msg.get("kind")
                if kind == "hello":
                    LOG.debug("hello from peer at level %d", msg.get("level", -1))
                elif kind == "block":
                    await self.on_block(msg["block"])
                elif kind == "transaction":
                    await self.on_tx(msg["tx"])
                else:
                    LOG.warning("unknown msg kind: %s", kind)
        finally:
            try:
                writer.close()
            except Exception:
                pass
            if writer in self._writers:
                self._writers.remove(writer)

    async def broadcast_block(self, block_dict: dict) -> None:
        await self._broadcast({"kind": "block", "block": block_dict})

    async def broadcast_tx(self, tx_dict: dict) -> None:
        await self._broadcast({"kind": "transaction", "tx": tx_dict})

    async def _broadcast(self, msg: dict) -> None:
        dead = []
        for w in self._writers:
            try:
                await _write_msg(w, msg)
            except Exception:
                dead.append(w)
        for w in dead:
            if w in self._writers:
                self._writers.remove(w)
