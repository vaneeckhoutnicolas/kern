# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A catch-up reply is bounded by its bytes, and a node that is behind
asks again until it has caught up.

A `blocks` reply used to be bounded by a number of blocks only, 512. A peer
drops a frame of more than 16 MiB and closes the connection, so a node
behind by 512 blocks that weigh more than that together received nothing,
at every attempt. The reply is now filled up to a budget in bytes, half a
frame, and the node that asked asks for what follows.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern import network as net


def a_block(level: int, weight: int) -> dict:
    """Something of the shape of a block, of about `weight` bytes as JSON."""
    return {"header": {"level": level}, "transactions": ["x" * max(0, weight - 60)]}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def nothing(_message: dict) -> None:
    return None


class Behind:
    """A node that is behind: it keeps the blocks it receives when each one
    follows its head, as a chain does."""

    def __init__(self) -> None:
        self.levels: list[int] = []
        self.network = net.Network("127.0.0.1", free_port(), on_block=self.on_block, on_tx=nothing,
                                   get_head_level=lambda: self.height, on_peer_level=self.on_peer_level)

    @property
    def height(self) -> int:
        return len(self.levels)

    async def on_block(self, block: dict) -> None:
        if block.get("header", {}).get("level") == self.height + 1:
            self.levels.append(block["header"]["level"])

    def on_peer_level(self, level: int):
        return (self.height + 1, level) if level > self.height else None


class Ahead:
    """A node that holds a chain and counts the requests it serves."""

    def __init__(self, blocks: list[dict]) -> None:
        self.blocks = {b["header"]["level"]: b for b in blocks}
        self.requests: list[tuple[int, int]] = []
        self.network = net.Network("127.0.0.1", free_port(), on_block=nothing, on_tx=nothing,
                                   get_head_level=lambda: len(self.blocks), get_blocks_fn=self.get_blocks)

    def get_blocks(self, lo: int, hi: int) -> list[dict]:
        self.requests.append((lo, hi))
        out = []
        for level in range(lo, hi + 1):
            if level not in self.blocks:
                break
            out.append(self.blocks[level])
        return out


async def catch_up(ahead: Ahead, behind: Behind, *, until: int, patience: float = 20.0) -> None:
    await ahead.network.start()
    await behind.network.start()
    try:
        assert await behind.network.connect("127.0.0.1", ahead.network.port)
        waited = 0.0
        while behind.height < until and behind.network.connection_count and waited < patience:
            await asyncio.sleep(0.02)
            waited += 0.02
        await asyncio.sleep(0.1)                      # anything still on its way arrives
        behind.open = behind.network.connection_count == 1     # type: ignore[attr-defined]
    finally:
        await behind.network.stop()
        await ahead.network.stop()


async def one_reply(ahead: Ahead, lo: int, hi: int) -> tuple[int, list[int]]:
    """The size of the frame a node answers to one request, and the levels in it."""
    await ahead.network.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", ahead.network.port)
        try:
            async def frame() -> tuple[int, dict]:
                length = int.from_bytes(await reader.readexactly(4), "big")
                return length, json.loads(await reader.readexactly(length))

            _, hello = await frame()
            assert hello["kind"] == "hello"
            payload = json.dumps({"kind": "get_blocks", "from": lo, "to": hi}).encode()
            writer.write(len(payload).to_bytes(4, "big") + payload)
            await writer.drain()
            length, reply = await asyncio.wait_for(frame(), timeout=20)
            assert reply["kind"] == "blocks"
            return length, [b["header"]["level"] for b in reply["blocks"]]
        finally:
            writer.close()
    finally:
        await ahead.network.stop()


def test_512_blocks_that_weigh_more_than_a_frame_are_all_received():
    """The case that was measured: 512 blocks of 41 kB, 20 MiB in all."""
    blocks = [a_block(level, 41_204) for level in range(1, 513)]
    assert sum(len(json.dumps(b)) for b in blocks) > net.MAX_MSG_BYTES
    ahead, behind = Ahead(blocks), Behind()
    asyncio.run(catch_up(ahead, behind, until=512))
    assert behind.levels == list(range(1, 513))
    assert behind.open                                # type: ignore[attr-defined]


def test_a_reply_stays_within_its_budget_and_gives_the_first_levels_asked_for():
    blocks = [a_block(level, 300_000 + 1_000 * (level % 7)) for level in range(1, 101)]
    length, levels = asyncio.run(one_reply(Ahead(blocks), 1, 100))
    assert length <= net.MAX_SYNC_REPLY_BYTES == net.MAX_MSG_BYTES // 2
    assert levels == list(range(1, len(levels) + 1)) and 20 <= len(levels) < 100
    # One block more would not have fitted.
    assert length + len(json.dumps(blocks[len(levels)])) > net.MAX_SYNC_REPLY_BYTES
    length, levels = asyncio.run(one_reply(Ahead(blocks), 40, 100))
    assert levels[0] == 40 and length <= net.MAX_SYNC_REPLY_BYTES


def test_a_reply_is_filled_to_the_byte(monkeypatch):
    """The size that is counted is the size of the frame: a reply that fits
    exactly is sent whole, and one byte less of room is one block less."""
    blocks = [a_block(level, 2_000) for level in range(1, 8)]
    three = len(net._encode({"kind": "blocks", "blocks": blocks[:3]}))
    for room, expected in ((three, 3), (three - 1, 2), (three + 1, 3)):
        monkeypatch.setattr(net, "MAX_SYNC_REPLY_BYTES", room)
        reply = net.sync_reply(Ahead(blocks).get_blocks, 1, 7)
        assert [b["header"]["level"] for b in reply] == list(range(1, expected + 1)), room
        assert len(net._encode({"kind": "blocks", "blocks": reply})) <= room
    # And the 512 blocks of the largest reply, when they are light, are counted one by one.
    monkeypatch.setattr(net, "MAX_SYNC_REPLY_BYTES", net.MAX_MSG_BYTES // 2)
    many = [a_block(level, 10) for level in range(1, 600)]
    assert len(net.sync_reply(Ahead(many).get_blocks, 1, 599)) == 512
    assert len(net.sync_reply(Ahead(many).get_blocks, 90, 599)) == 510


def test_a_block_alone_always_travels(monkeypatch):
    """A block heavier than the budget is sent alone: a reply that held no
    block would leave the node behind where it is, for ever."""
    monkeypatch.setattr(net, "MAX_SYNC_REPLY_BYTES", 10_000, raising=False)
    blocks = [a_block(1, 50_000), a_block(2, 50_000), a_block(3, 2_000), a_block(4, 2_000), a_block(5, 2_000)]
    length, levels = asyncio.run(one_reply(Ahead(blocks), 1, 5))
    assert levels == [1] and length > 10_000
    length, levels = asyncio.run(one_reply(Ahead(blocks), 3, 5))
    assert levels == [3, 4, 5] and length <= 10_000
    ahead, behind = Ahead(blocks), Behind()
    asyncio.run(catch_up(ahead, behind, until=5))
    assert behind.levels == [1, 2, 3, 4, 5]


def test_control_small_blocks_still_come_512_at_a_time():
    blocks = [a_block(level, 200) for level in range(1, 1201)]
    length, levels = asyncio.run(one_reply(Ahead(blocks), 1, 1200))
    assert levels == list(range(1, net.MAX_BLOCKS_PER_SYNC_REPLY + 1)) and length < net.MAX_SYNC_REPLY_BYTES
    ahead, behind = Ahead(blocks), Behind()
    asyncio.run(catch_up(ahead, behind, until=1200))
    assert behind.levels == list(range(1, 1201))      # three replies, without waiting for anything else


def test_a_node_asks_again_only_while_the_replies_bring_it_forward(monkeypatch):
    """A peer that answers with blocks the node cannot use is not asked
    again and again."""
    monkeypatch.setattr(net, "MAX_SYNC_REPLY_BYTES", 10_000, raising=False)
    blocks = [a_block(level, 4_000) for level in range(1, 21)]
    ahead, behind = Ahead(blocks), Behind()

    async def refuse(_block: dict) -> None:           # the node keeps nothing: every block is refused
        return None

    behind.network.on_block = refuse
    asyncio.run(catch_up(ahead, behind, until=20, patience=1.0))
    assert behind.height == 0
    # One request, served by reading and weighing three blocks, of which two fit; no second request.
    assert ahead.requests == [(1, 1), (2, 2), (3, 3)]


def test_a_reply_with_no_block_ends_the_exchange():
    ahead, behind = Ahead([]), Behind()
    ahead.network.get_head_level = lambda: 9           # it says it is at level 9 and holds nothing
    asyncio.run(catch_up(ahead, behind, until=9, patience=1.0))
    assert behind.height == 0 and behind.open         # type: ignore[attr-defined]
    assert ahead.requests == [(1, 1)]                  # asked once, and not again
    # The level a peer announced is forgotten with its connection.
    assert behind.network._peer_levels == {} and ahead.network._peer_levels == {}


@pytest.mark.parametrize("request_", [{"from": 0, "to": 3}, {"from": 5, "to": 2}, {"from": "1", "to": 3},
                                      {"from": 1}, {"from": -1, "to": 3}])
def test_control_a_request_that_makes_no_sense_gets_no_reply(request_):
    ahead = Ahead([a_block(level, 200) for level in range(0, 6)])

    async def ask() -> list[int] | None:
        await ahead.network.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", ahead.network.port)
            try:
                length = int.from_bytes(await reader.readexactly(4), "big")
                await reader.readexactly(length)
                payload = json.dumps({"kind": "get_blocks", **request_}).encode()
                writer.write(len(payload).to_bytes(4, "big") + payload)
                await writer.drain()
                try:
                    length = int.from_bytes(await asyncio.wait_for(reader.readexactly(4), timeout=0.3), "big")
                except asyncio.TimeoutError:
                    return None
                reply = json.loads(await reader.readexactly(length))
                return [b["header"]["level"] for b in reply["blocks"]]
            finally:
                writer.close()
        finally:
            await ahead.network.stop()

    answer = asyncio.run(ask())
    if request_ == {"from": 0, "to": 3}:
        assert answer == [0, 1, 2, 3]                  # the genesis can be asked for today
    else:
        assert answer is None


# ---------------------------------------------------------------------------
# The same with a real chain
# ---------------------------------------------------------------------------

CONTRACT = "contract Counter {\n storage { count: int, }\n entry increment() { count = count + 1; }\n}\n"


def a_real_chain(blocks: int, code_bytes: int):
    """A chain of one validator, valid under full validation, whose every
    block originates one contract padded with a comment."""
    from kern.block import Block, BlockHeader, txs_merkle_root_hex
    from kern.chain import Chain, state_root_hex
    from kern.consensus import propose_block
    from kern.crypto import KernKeypair
    from kern.transaction import make_origination

    validator = KernKeypair.from_seed(bytes([0xC0]) * 32)
    validators = [{"address": validator.address, "pubkey": validator.public_key_b58, "stake": 100}]
    state = {"balances": {validator.address: 10**12}, "nonces": {}, "contracts": {}, "validators": validators}
    header = BlockHeader(level=0, payload_round=0, timestamp=1_700_000_000, parent_hash="0" * 64,
                         state_root=state_root_hex(state), txs_root=txs_merkle_root_hex([]),
                         proposer=validator.address, proposer_pubkey=validator.public_key_b58)
    header.sign(validator)
    genesis = Block(header=header)
    chain = Chain(genesis, validators, initial_state=state)
    code = CONTRACT + "// " + "x" * (code_bytes - len(CONTRACT) - 4) + "\n"
    for nonce in range(blocks):
        tx = make_origination(validator, code, {"count": 0}, nonce=nonce)
        block = propose_block(parent=chain.head, mempool=[tx], proposer_keypair=validator,
                              proposer_pubkey_b58=validator.public_key_b58, state_before=chain.state, round_=0)
        assert len(block.transactions) == 1
        chain.append(block, require_quorum=True)
    return chain, Chain(genesis, validators, initial_state=state)


def test_a_real_chain_is_caught_up_over_several_replies(monkeypatch):
    from kern.block import Block

    full, late = a_real_chain(blocks=12, code_bytes=2_000)
    weights = [len(json.dumps(b.to_dict())) for b in full.blocks[1:]]
    monkeypatch.setattr(net, "MAX_MSG_BYTES", 16_000)
    monkeypatch.setattr(net, "MAX_SYNC_REPLY_BYTES", 8_000, raising=False)
    assert sum(weights) > net.MAX_MSG_BYTES > net.MAX_SYNC_REPLY_BYTES > 2 * max(weights)

    async def on_block(block: dict) -> None:
        late.append(Block.from_dict(block), require_quorum=True)      # full validation, as a node applies it

    async def run() -> int:
        ahead = net.Network("127.0.0.1", free_port(), on_block=nothing, on_tx=nothing,
                            get_head_level=lambda: full.height,
                            get_blocks_fn=lambda lo, hi: [b.to_dict() for b in full.blocks[lo:hi + 1]])
        behind = net.Network("127.0.0.1", free_port(), on_block=on_block, on_tx=nothing,
                             get_head_level=lambda: late.height,
                             on_peer_level=lambda level: (late.height + 1, level) if level > late.height else None)
        await ahead.start()
        await behind.start()
        try:
            assert await behind.connect("127.0.0.1", ahead.port)
            for _ in range(500):
                if late.height == full.height or not behind.connection_count:
                    break
                await asyncio.sleep(0.02)
            return behind.connection_count
        finally:
            await behind.stop()
            await ahead.stop()

    connections = asyncio.run(run())
    assert late.height == full.height == 12 and connections == 1
    assert late.head.hash_hex() == full.head.hash_hex()
