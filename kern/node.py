# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.node
---------

The Kern node binary. Combines storage, chain state, P2P network, RPC
server, and (optionally) baker logic into a running process.

CLI:

    python -m kern.node init  --genesis genesis.json --data-dir DIR
    python -m kern.node start --data-dir DIR --rpc-port 8732 --p2p-port 9732
                              [--baker-key keys/baker1.json]
                              [--peer host:port ...]
                              [--block-time 1.0]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import List, Optional

from aiohttp import web

from .block import Block, BlockHeader, txs_merkle_root_hex
from .chain import Chain, apply_block, state_root_hex
from .consensus import BakerConfig, propose_block, select_proposer, DEFAULT_BLOCK_TIME_S
from .crypto import KernKeypair
from .network import Network
from .rpc import build_app
from .storage import Storage
from .transaction import Transaction

LOG = logging.getLogger("kern.node")


# ---------------------------------------------------------------------------
# Genesis utilities
# ---------------------------------------------------------------------------

def load_genesis(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_genesis_block(genesis: dict) -> Block:
    """Build the genesis block (level 0). It has no transactions and a
    state_root computed from the pre-funded balances declared in the
    genesis dict."""
    state = {
        "balances": dict(genesis.get("balances", {})),
        "nonces": {},
        "contracts": {},
        "validators": list(genesis.get("validators", [])),
    }
    header = BlockHeader(
        level=0,
        round=0,
        timestamp=int(genesis.get("timestamp", time.time())),
        parent_hash="0" * 64,
        state_root=state_root_hex(state),
        txs_root=txs_merkle_root_hex([]),
        proposer=genesis["genesis_proposer"]["address"],
        proposer_pubkey=genesis["genesis_proposer"]["pubkey"],
        signature=genesis.get("genesis_signature", "ksig" + "0" * 95),
    )
    # The genesis block's "signature" is a magic placeholder — every node
    # accepts it because it matches what's declared in genesis.json.
    return Block(header=header, transactions=[], commits=[])


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class Node:
    def __init__(
        self,
        data_dir: str,
        chain: Chain,
        storage: Storage,
        baker: Optional[BakerConfig],
        rpc_port: int,
        p2p_port: int,
        peers: List[str],
        block_time: float,
    ):
        self.data_dir = data_dir
        self.chain = chain
        self.storage = storage
        self.baker = baker
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.bootstrap_peers = peers
        self.block_time = block_time
        self.network: Optional[Network] = None
        self._app_runner: Optional[web.AppRunner] = None
        self._tasks: List[asyncio.Task] = []
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        self.network = Network(
            host="0.0.0.0",
            port=self.p2p_port,
            on_block=self._on_block_msg,
            on_tx=self._on_tx_msg,
            get_head_level=lambda: self.chain.height,
        )
        await self.network.start()

        # Bootstrap peer connections.
        for spec in self.bootstrap_peers:
            host, port_s = spec.split(":")
            asyncio.create_task(self.network.connect(host, int(port_s)))

        # RPC.
        app = build_app(self)
        self._app_runner = web.AppRunner(app)
        await self._app_runner.setup()
        site = web.TCPSite(self._app_runner, "0.0.0.0", self.rpc_port)
        await site.start()
        LOG.info("RPC listening on 0.0.0.0:%d", self.rpc_port)

        # Baker loop.
        if self.baker is not None:
            self._tasks.append(asyncio.create_task(self._baker_loop()))

        LOG.info("Kern node started — head level %d", self.chain.height)
        await self._stop_event.wait()

    async def stop(self) -> None:
        LOG.info("Shutting down node...")
        self._stop_event.set()
        for t in self._tasks:
            t.cancel()
        if self.network:
            await self.network.stop()
        if self._app_runner:
            await self._app_runner.cleanup()
        self.storage.close()

    # --- Network handlers ----------------------------------------------------

    async def _on_block_msg(self, block_dict: dict) -> None:
        try:
            block = Block.from_dict(block_dict)
            if block.header.level <= self.chain.height:
                return
            if block.header.level != self.chain.height + 1:
                # Out-of-order: a real node would request missing blocks.
                LOG.warning("ignoring out-of-order block at level %d (head %d)",
                            block.header.level, self.chain.height)
                return
            self.chain.append(block)
            self.storage.save_block(block)
            self.storage.save_state(self.chain.state)
            # Drop included txs from the mempool.
            self.storage.remove_from_mempool([tx.hash_hex() for tx in block.transactions])
            LOG.info("applied gossiped block %d (hash %s, %d txs)",
                     block.header.level, block.hash_hex()[:12], len(block.transactions))
        except Exception as e:
            LOG.warning("rejected gossiped block: %s", e)

    async def _on_tx_msg(self, tx_dict: dict) -> None:
        try:
            tx = Transaction.from_dict(tx_dict)
            if not tx.verify_signature():
                return
            self.storage.add_to_mempool(tx)
        except Exception as e:
            LOG.warning("rejected gossiped tx: %s", e)

    # --- Baker loop ----------------------------------------------------------

    async def _baker_loop(self) -> None:
        assert self.baker is not None
        LOG.info("baker started for address %s", self.baker.keypair.address)
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.block_time)

                # Are we the proposer for the next round?
                parent = self.chain.head
                proposer = select_proposer(
                    parent_hash_hex=parent.hash_hex(),
                    validators=self.chain.validators,
                    round_=parent.header.round + 1,
                )
                if proposer["address"] != self.baker.keypair.address:
                    # Not our turn this round.
                    continue

                txs = self.storage.drain_mempool(max_n=self.baker.max_txs_per_block)
                block = propose_block(
                    parent=parent,
                    mempool=txs,
                    proposer_keypair=self.baker.keypair,
                    proposer_pubkey_b58=self.baker.pubkey_b58,
                    state_before=self.chain.state,
                    round_=parent.header.round + 1,
                )
                self.chain.append(block)
                self.storage.save_block(block)
                self.storage.save_state(self.chain.state)
                self.storage.remove_from_mempool([tx.hash_hex() for tx in block.transactions])

                LOG.info(
                    "baked block %d (hash %s, %d txs)",
                    block.header.level, block.hash_hex()[:12], len(block.transactions),
                )

                if self.network:
                    asyncio.create_task(self.network.broadcast_block(block.to_dict()))
            except asyncio.CancelledError:
                break
            except Exception:
                LOG.exception("baker loop error")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    genesis = load_genesis(args.genesis)
    os.makedirs(args.data_dir, exist_ok=True)
    storage = Storage(args.data_dir)

    if storage.head_level() >= 0:
        print(f"data-dir already initialized at level {storage.head_level()}", file=sys.stderr)
        return 1

    from .chain import initial_state_from_genesis

    genesis_block = build_genesis_block(genesis)
    initial_state = initial_state_from_genesis(genesis)
    # Reset nonces/contracts so they start clean (initial_state_from_genesis
    # only fills balances + validators).
    initial_state.setdefault("nonces", {})
    initial_state.setdefault("contracts", {})
    chain = Chain(
        genesis_block,
        genesis.get("validators", []),
        initial_state=initial_state,
    )
    storage.save_block(genesis_block)
    storage.save_state(chain.state)
    storage.close()
    print(f"Initialized node at {args.data_dir}")
    print(f"  Genesis hash: {genesis_block.hash_hex()}")
    print(f"  Validators: {len(chain.validators)}")
    print(f"  Pre-funded accounts: {len(initial_state['balances'])}")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    storage = Storage(args.data_dir)
    if storage.head_level() < 0:
        print("data-dir not initialized; run `init` first", file=sys.stderr)
        return 1

    # Load the genesis block and the persisted state snapshot.
    genesis = storage.get_block_by_level(0)
    assert genesis is not None
    persisted_state = storage.load_state() or {}
    validators = persisted_state.get("validators", [])

    # Rebuild the genesis-state-of-the-world (balances at level 0) so we can
    # replay subsequent blocks deterministically. Since the persisted state
    # reflects the *current* head, we don't reuse it directly — instead we
    # reconstruct the level-0 state from the storage-saved validator set
    # plus the balances that the genesis block committed to.
    # For simplicity (and because we only persist head-state, not historical
    # snapshots), we initialize Chain at level 0 with the persisted state if
    # head is 0, otherwise we trust the saved head-state and skip replay.
    if storage.head_level() == 0:
        chain = Chain(genesis, validators, initial_state=persisted_state)
    else:
        # Use persisted state directly; we've already validated all blocks
        # up to head as they were applied.
        chain = Chain(genesis, validators, initial_state=persisted_state)
        # Replay all blocks above genesis to populate chain.blocks list.
        for level in range(1, storage.head_level() + 1):
            b = storage.get_block_by_level(level)
            if b is not None:
                chain.blocks.append(b)
        # chain.state already reflects head; no replay of state needed.

    baker: Optional[BakerConfig] = None
    if args.baker_key:
        with open(args.baker_key, encoding="utf-8") as f:
            keyfile = json.load(f)
        seed = bytes.fromhex(keyfile["seed_hex"])
        kp = KernKeypair.from_seed(seed)
        baker = BakerConfig(
            keypair=kp,
            pubkey_b58=kp.public_key_b58,
            block_time=args.block_time,
        )
        LOG.info("baker key loaded: %s", kp.address)

    node = Node(
        data_dir=args.data_dir,
        chain=chain,
        storage=storage,
        baker=baker,
        rpc_port=args.rpc_port,
        p2p_port=args.p2p_port,
        peers=args.peer or [],
        block_time=args.block_time,
    )

    async def runner() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(node.stop()))
            except NotImplementedError:
                pass
        await node.start()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="kern.node")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--genesis", required=True)
    p_init.add_argument("--data-dir", required=True)
    p_init.set_defaults(func=cmd_init)

    p_start = sub.add_parser("start")
    p_start.add_argument("--data-dir", required=True)
    p_start.add_argument("--rpc-port", type=int, default=8732)
    p_start.add_argument("--p2p-port", type=int, default=9732)
    p_start.add_argument("--baker-key", default=None)
    p_start.add_argument("--peer", action="append", default=[])
    p_start.add_argument("--block-time", type=float, default=DEFAULT_BLOCK_TIME_S)
    p_start.set_defaults(func=cmd_start)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
