# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.network
------------

Asyncio peer-to-peer network for the reference node.

Each peer connection is a length-prefixed JSON message stream. Message
kinds on the wire (see docs/consensus-wire.md for the full protocol):

    {"kind": "hello",      "level": N}
    {"kind": "proposal",   "block": {...},          candidate block (pre-quorum),
                           "proposal": {...},       signed PROPOSE message and,
                           "proof": {...} | null}   for a re-proposal, its proof
    {"kind": "consensus",  "msg": {...}}            propose/preendorse/endorse
    {"kind": "block",      "block": {...}}          finalized block (with QC)
    {"kind": "transaction","tx": {...}}
    {"kind": "get_blocks", "from": A, "to": B}      catch-up sync request
    {"kind": "blocks",     "blocks": [{...}, ...]}  catch-up sync response

Hardening in this layer: a 16 MiB per-message cap, a connection cap, and
a per-response block cap on sync replies. Deduplication and re-gossip
policy live in the node (kern.node), which owns the seen-sets. A
production node would additionally use a binary framing protocol with
versioning, peer scoring, and gossip mesh routing (libp2p / gossipsub
style); this remains the documented production path.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable, List, Optional, Set, Tuple

LOG = logging.getLogger("kern.network")

MAX_MSG_BYTES = 16 * 1024 * 1024
MAX_CONNECTIONS = 128
MAX_BLOCKS_PER_SYNC_REPLY = 512


async def _read_msg(reader: asyncio.StreamReader) -> Optional[dict]:
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    length = int.from_bytes(header, "big")
    if length <= 0 or length > MAX_MSG_BYTES:
        return None
    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict):
        return None
    return msg


async def _write_msg(writer: asyncio.StreamWriter, msg: dict) -> None:
    payload = json.dumps(msg).encode("utf-8")
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()


class Network:
    """The node's P2P endpoint.

    All `on_*` callbacks are async and receive already-JSON-decoded dicts;
    strict schema validation (Transaction.from_dict etc.) happens in the
    node handlers, which are the ingress gates. Callbacks other than
    on_block/on_tx are optional so that older tooling constructing a
    minimal Network keeps working.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        on_block: Callable[[dict], Awaitable[None]],
        on_tx: Callable[[dict], Awaitable[None]],
        get_head_level: Callable[[], int],
        on_proposal: Optional[Callable[[dict], Awaitable[None]]] = None,
        on_consensus: Optional[Callable[[dict], Awaitable[None]]] = None,
        get_blocks_fn: Optional[Callable[[int, int], List[dict]]] = None,
        on_peer_level: Optional[Callable[[int], Optional[Tuple[int, int]]]] = None,
    ):
        self.host = host
        self.port = port
        self.on_block = on_block
        self.on_tx = on_tx
        self.get_head_level = get_head_level
        self.on_proposal = on_proposal
        self.on_consensus = on_consensus
        self.get_blocks_fn = get_blocks_fn
        self.on_peer_level = on_peer_level
        self.peers: Set[Tuple[str, int]] = set()
        self._writers: List[asyncio.StreamWriter] = []
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        LOG.info("P2P listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        # Close connections first: since Python 3.12, Server.wait_closed()
        # waits for every connection handler to return, and our reader
        # loops only return once their transport is closed.
        for w in list(self._writers):
            try:
                w.close()
            except Exception:
                pass
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2)
            except asyncio.TimeoutError:
                LOG.warning("server close timed out; continuing shutdown")

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
        if len(self._writers) >= MAX_CONNECTIONS:
            LOG.warning("connection cap reached (%d); refusing peer", MAX_CONNECTIONS)
            writer.close()
            return
        self._writers.append(writer)
        await _write_msg(writer, {"kind": "hello", "level": self.get_head_level()})
        await self._reader_loop(reader, writer)

    async def _reader_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                msg = await _read_msg(reader)
                if msg is None:
                    break
                try:
                    await self._dispatch(msg, writer)
                except Exception:
                    # A handler error on one message must not kill the
                    # connection: log and keep reading.
                    LOG.exception("error handling %r message", msg.get("kind"))
        finally:
            try:
                writer.close()
            except Exception:
                pass
            if writer in self._writers:
                self._writers.remove(writer)

    async def _dispatch(self, msg: dict, writer: asyncio.StreamWriter) -> None:
        kind = msg.get("kind")
        if kind == "hello":
            level = msg.get("level", -1)
            LOG.debug("hello from peer at level %s", level)
            if self.on_peer_level is not None and isinstance(level, int):
                rng = self.on_peer_level(level)
                if rng is not None:
                    await _write_msg(writer, {"kind": "get_blocks",
                                              "from": rng[0], "to": rng[1]})
        elif kind == "proposal":
            if self.on_proposal is not None:
                await self.on_proposal({k: v for k, v in msg.items() if k != "kind"})
        elif kind == "consensus":
            if self.on_consensus is not None:
                await self.on_consensus(msg.get("msg") or {})
        elif kind == "block":
            await self.on_block(msg.get("block") or {})
        elif kind == "transaction":
            await self.on_tx(msg.get("tx") or {})
        elif kind == "get_blocks":
            if self.get_blocks_fn is not None:
                lo, hi = msg.get("from"), msg.get("to")
                if isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi:
                    hi = min(hi, lo + MAX_BLOCKS_PER_SYNC_REPLY - 1)
                    blocks = self.get_blocks_fn(lo, hi)
                    await _write_msg(writer, {"kind": "blocks", "blocks": blocks})
        elif kind == "blocks":
            blist = msg.get("blocks")
            if isinstance(blist, list):
                for b in blist[:MAX_BLOCKS_PER_SYNC_REPLY]:
                    await self.on_block(b if isinstance(b, dict) else {})
        else:
            LOG.warning("unknown msg kind: %s", kind)

    # ------------------------------------------------------------ outbound

    async def broadcast_block(self, block_dict: dict) -> None:
        await self._broadcast({"kind": "block", "block": block_dict})

    async def broadcast_proposal(self, envelope: dict) -> None:
        """Phase E: `envelope` is {"block", "proposal", "proof"}."""
        await self._broadcast({"kind": "proposal", **envelope})

    async def broadcast_consensus(self, msg_dict: dict) -> None:
        await self._broadcast({"kind": "consensus", "msg": msg_dict})

    async def broadcast_tx(self, tx_dict: dict) -> None:
        await self._broadcast({"kind": "transaction", "tx": tx_dict})

    async def request_blocks(self, from_level: int, to_level: int) -> None:
        await self._broadcast({"kind": "get_blocks",
                               "from": from_level, "to": to_level})

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
