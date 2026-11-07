# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.node
---------

The Kern node binary. Combines storage, chain state, P2P network, RPC
server, and (optionally) baker logic into a running process.

The consensus driver in this module wires kern.bft (the three-phase
Tenderbake-style engine) to kern.network: proposals travel as full blocks
on the "proposal" channel, pre-endorsements and endorsements as signed
ConsensusMessages on the "consensus" channel, and a block is appended
with require_quorum=True only once its endorsement quorum certificate
has been gathered. See docs/consensus-wire.md for the protocol.

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
from typing import Dict, List, Optional, Set, Tuple

from aiohttp import web

from .bft import BftEngine, ConsensusMessage, MsgKind
from .block import Block, BlockHeader, txs_merkle_root_hex
from .chain import Chain, apply_block, state_root_hex, validate_and_apply
from .consensus import BakerConfig, propose_block, select_proposer, DEFAULT_BLOCK_TIME_S
from .crypto import KernKeypair
from .network import Network
from .rpc import build_app
from .storage import Storage
from .transaction import Transaction

LOG = logging.getLogger("kern.node")

# Dedup sets are advisory only (correctness never depends on them: stale
# blocks are rejected by level, duplicate txs by the mempool primary key,
# and repeated consensus messages are idempotent in the engine), so a
# blunt clear-on-overflow bound is sufficient.
MAX_SEEN_ENTRIES = 50_000


# ---------------------------------------------------------------------------
# Genesis utilities
# ---------------------------------------------------------------------------

def load_genesis(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        genesis = json.load(f)
    check_genesis_safety(genesis)
    return genesis


# Seed bytes used by scripts/build_v1_genesis.py for its placeholder pool
# and baker addresses (bytes([b]) * 32). Their keys are public.
_PLACEHOLDER_SEED_BYTES = (0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xB0)


def check_genesis_safety(genesis: dict) -> None:
    """Refuse a genesis that names a mainnet while holding funds or stake
    on addresses whose private keys are public (audit 2, point 5).

    Devnet and test genesis files may use public seeds on purpose; only a
    chain_id containing "mainnet" triggers the check. Raises ValueError."""
    chain_id = str(genesis.get("chain_id") or "")
    if "mainnet" not in chain_id.lower():
        return
    if genesis.get("placeholder_keys"):
        raise ValueError(f"genesis {chain_id!r} is marked placeholder_keys; refusing to run it as mainnet")
    public = {KernKeypair.from_seed(bytes([b]) * 32).address for b in _PLACEHOLDER_SEED_BYTES}
    used = set(genesis.get("balances", {})) | {v.get("address") for v in genesis.get("validators", [])}
    leaked = sorted(used & public)
    if leaked:
        raise ValueError(
            f"genesis {chain_id!r} funds addresses derived from public placeholder seeds: {leaked}"
        )


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


def load_chain(storage: Storage) -> Chain:
    """Load the chain from storage: latest state snapshot, then
    deterministic replay of the stored blocks above the snapshot level.

    Snapshots are periodic (Storage.maybe_save_state), so after a crash
    at most `snapshot_interval` blocks are replayed through apply_block —
    the same pure function that produced the state in the first place.
    Legacy databases (snapshot level -1, written by pre-snapshot nodes at
    head) are loaded as-is with no replay."""
    genesis = storage.get_block_by_level(0)
    if genesis is None:
        raise RuntimeError("storage has no genesis block; run `init` first")
    state = storage.load_state() or {}
    snap_level = storage.load_state_level()
    head = storage.head_level()
    if snap_level < 0:
        snap_level = head
    for level in range(snap_level + 1, head + 1):
        b = storage.get_block_by_level(level)
        if b is None:
            raise RuntimeError(f"missing block at level {level} during replay")
        state, _ = apply_block(state, b)
    chain = Chain(genesis, state.get("validators", []), initial_state=state)
    for level in range(1, head + 1):
        b = storage.get_block_by_level(level)
        if b is not None:
            chain.blocks.append(b)
    return chain


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

        # Consensus engine — present iff this node holds a validator key.
        self.bft: Optional[BftEngine] = None
        if baker is not None:
            self.bft = BftEngine(
                own_keypair=baker.keypair,
                own_pubkey_b58=baker.pubkey_b58,
                validator_set=list(chain.validators),
            )

        # Pending (pre-quorum) proposals, keyed by (level, block_hash).
        self._pending: Dict[Tuple[int, str], Block] = {}
        # Advisory dedup sets (see MAX_SEEN_ENTRIES note above).
        self._seen_blocks: Set[str] = set()
        self._seen_txs: Set[str] = set()
        self._seen_cons: Set[Tuple[str, int, int, str, str]] = set()
        # Next nonce for this validator's own slashing reports (Phase D).
        self._next_report_nonce: int = 0
        # Round management for the level currently being decided.
        self._round: int = chain.head.header.round + 1
        self._round_deadline: float = 0.0
        self._proposed_this_round: bool = False
        self._last_block_at: float = time.monotonic()
        self._last_sync_request: float = 0.0

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self.network = Network(
            host="0.0.0.0",
            port=self.p2p_port,
            on_block=self._on_block_msg,
            on_tx=self._on_tx_msg,
            get_head_level=lambda: self.chain.height,
            on_proposal=self._on_proposal_msg,
            on_consensus=self._on_consensus_msg,
            get_blocks_fn=self._get_blocks,
            on_peer_level=self._on_peer_level,
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

        # Consensus driver (proposer + endorser duties).
        if self.baker is not None:
            self._tasks.append(asyncio.create_task(self._consensus_loop()))

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
        # Final exact snapshot so restart never has to replay.
        self.storage.save_state(self.chain.state, self.chain.height)
        self.storage.close()

    # ------------------------------------------------------------ helpers

    def _round_timeout(self) -> float:
        return max(2.0, self.block_time * 4)

    def _refresh_engine(self) -> None:
        if self.bft is not None:
            self.bft.validator_set = self.chain.validators
            self.bft.current_round = self._round
            self.bft.min_level = max(self.bft.min_level, self.chain.height + 1)

    @staticmethod
    def _trim(seen: set) -> None:
        if len(seen) > MAX_SEEN_ENTRIES:
            seen.clear()

    def _after_block_applied(self, block: Block, *, broadcast: bool) -> None:
        """Common bookkeeping once a block has been appended to the chain
        (self-finalized, gossiped, or synced)."""
        level = block.header.level
        self.storage.save_block(block)
        self.storage.maybe_save_state(self.chain.state, level)
        self.storage.remove_from_mempool([tx.hash_hex() for tx in block.transactions])
        self._seen_blocks.add(block.hash_hex())
        self._trim(self._seen_blocks)
        # Reset consensus context for the next level.
        self._pending = {k: v for k, v in self._pending.items() if k[0] > level}
        if self.bft is not None:
            self.bft.prune_below(level + 1)
        self._round = block.header.round + 1
        self._proposed_this_round = False
        self._round_deadline = time.monotonic() + self._round_timeout()
        self._last_block_at = time.monotonic()
        LOG.info("finalized block %d (hash %s, %d txs, %d quorum entries)",
                 level, block.hash_hex()[:12], len(block.transactions),
                 len(block.commits) + len(block.endorsements))
        if broadcast and self.network:
            asyncio.create_task(self.network.broadcast_block(block.to_dict()))

    # ------------------------------------------------------------ consensus

    async def _consensus_loop(self) -> None:
        assert self.baker is not None and self.bft is not None
        LOG.info("consensus driver started for %s", self.baker.keypair.address)
        tick = min(0.2, self.block_time / 5) if self.block_time > 0 else 0.2
        self._round_deadline = time.monotonic() + self._round_timeout()
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(tick)
                now = time.monotonic()
                self._refresh_engine()

                if now > self._round_deadline:
                    self._round += 1
                    self._proposed_this_round = False
                    self._round_deadline = now + self._round_timeout()
                    LOG.info("round timeout at level %d — advancing to round %d",
                             self.chain.height + 1, self._round)

                parent = self.chain.head
                proposer = select_proposer(
                    parent_hash_hex=parent.hash_hex(),
                    validators=self.chain.validators,
                    round_=self._round,
                )
                if (proposer["address"] == self.baker.keypair.address
                        and not self._proposed_this_round
                        and now - self._last_block_at >= self.block_time):
                    await self._propose(parent)

                await self._try_finalize()
            except asyncio.CancelledError:
                break
            except Exception:
                LOG.exception("consensus loop error")

    async def _propose(self, parent: Block) -> None:
        assert self.baker is not None and self.bft is not None
        txs = self.storage.drain_mempool(max_n=self.baker.max_txs_per_block)
        evicted: list = []
        block = propose_block(
            parent=parent,
            mempool=txs,
            proposer_keypair=self.baker.keypair,
            proposer_pubkey_b58=self.baker.pubkey_b58,
            state_before=self.chain.state,
            round_=self._round,
            evict_out=evicted,
        )
        if evicted:
            # Transactions that can never become valid (bad signature,
            # consumed nonce) are dropped so they are not re-tried forever.
            self.storage.remove_from_mempool(evicted)
        h = block.hash_hex()
        self._pending[(block.header.level, h)] = block
        self._proposed_this_round = True
        LOG.info("proposed block %d round %d (hash %s, %d txs)",
                 block.header.level, block.header.round, h[:12],
                 len(block.transactions))
        if self.network:
            await self.network.broadcast_proposal(block.to_dict())
        # Self-deliver the proposal to our own engine: emits our
        # pre-endorsement, which loops back through _ingest_consensus and,
        # in single-validator operation, drives the full pre-endorse →
        # endorse → quorum-certificate sequence within this tick.
        out = self.bft.on_proposal(block.header.level, block.header.round, h)
        await self._emit_consensus(out)

    async def _emit_consensus(self, msgs: List[ConsensusMessage]) -> None:
        for m in msgs:
            if self.network:
                await self.network.broadcast_consensus(m.to_dict())
            await self._ingest_consensus(m, from_wire=False)

    async def _ingest_consensus(self, msg: ConsensusMessage, *, from_wire: bool) -> None:
        if self.bft is None:
            return
        # PROPOSE never rides the consensus channel in this protocol:
        # proposals travel as full blocks so that a validator only ever
        # pre-endorses a hash whose block it has fully validated. Drop
        # bare PROPOSE messages from the wire.
        if from_wire and msg.kind == MsgKind.PROPOSE:
            return
        # Phase C (external review, point C): the dedup key includes the
        # block hash. It used to be (kind, level, round, validator), so a
        # second, CONFLICTING vote from the same validator was dropped here
        # and the equivocation never reached the engine or the network.
        key = (msg.kind.value, msg.level, msg.round, msg.validator, msg.block_hash)
        if key in self._seen_cons:
            return
        self._seen_cons.add(key)
        self._trim(self._seen_cons)
        out = self.bft.on_message(msg)
        if from_wire and self.network:
            # Re-gossip newly seen consensus messages for mesh propagation
            # (conflicting votes included, so every node sees the evidence).
            asyncio.create_task(self.network.broadcast_consensus(msg.to_dict()))
        self._submit_evidence()
        await self._emit_consensus(out)
        await self._try_finalize()

    def _submit_evidence(self) -> None:
        """Turn equivocation evidence gathered by the engine into a signed
        SLASH_CONSENSUS_EQUIVOCATION transaction from this validator, added
        to the local mempool and gossiped. The chain re-verifies the
        evidence and slashes each offence once, so duplicate reports from
        several validators are harmless (they fail and pay their fee)."""
        if self.bft is None or self.baker is None:
            return
        from .transaction import make_slash_consensus_equivocation
        for ev in self.bft.take_evidence():
            try:
                kp = self.baker.keypair
                # Phase D: several reports can be filed before any of them
                # is included; each needs its own nonce. Take the higher of
                # the chain's nonce and the next one this node handed out.
                nonce = max(self.chain.state.get("nonces", {}).get(kp.address, 0),
                            self._next_report_nonce)
                self._next_report_nonce = nonce + 1
                tx = make_slash_consensus_equivocation(
                    kp, ev.msg_a.to_dict(), ev.msg_b.to_dict(), nonce=nonce,
                    chain_id=self.chain.state.get("chain_id"),
                )
                if self.storage.add_to_mempool(tx):
                    LOG.warning("submitted slashing evidence against %s (tx %s)",
                                ev.offender, tx.hash_hex()[:12])
                    if self.network:
                        asyncio.create_task(self.network.broadcast_tx(tx.to_dict()))
            except Exception:
                LOG.exception("could not submit slashing evidence against %s", ev.offender)

    async def _try_finalize(self) -> None:
        """Append any pending proposal whose endorsement quorum certificate
        has been reached. commits stay exactly as proposed (they feed the
        state_root); the wire QC goes into block.endorsements, sorted for
        a deterministic encoding."""
        if self.bft is None:
            return
        level = self.chain.height + 1
        for (lvl, h), block in list(self._pending.items()):
            if lvl != level:
                continue
            qc = self.bft.get_endorse_qc(lvl, block.header.round)
            if qc is None or qc.block_hash != h:
                continue
            block.endorsements = sorted(
                f"{addr}:{sig}" for addr, sig in qc.signatures.items()
            )
            try:
                self.chain.append(block, require_quorum=True)
            except ValueError as e:
                LOG.error("finalization failed at level %d: %s", lvl, e)
                continue
            self._after_block_applied(block, broadcast=True)
            break

    # ------------------------------------------------------------ network in

    async def _on_proposal_msg(self, block_dict: dict) -> None:
        try:
            block = Block.from_dict(block_dict)
        except (ValueError, KeyError) as e:
            LOG.warning("rejected proposal: %s", e)
            return
        h = block.hash_hex()
        level = self.chain.height + 1
        if block.header.level != level or (level, h) in self._pending:
            return
        if h in self._seen_blocks:
            return
        parent = self.chain.head
        # The proposal must come from the legitimate proposer of the round
        # it claims, and rounds only move forward.
        if block.header.round < parent.header.round + 1:
            return
        expected = select_proposer(
            parent_hash_hex=parent.hash_hex(),
            validators=self.chain.validators,
            round_=block.header.round,
        )
        if expected["address"] != block.header.proposer:
            LOG.warning("proposal at level %d round %d from illegitimate "
                        "proposer %s", level, block.header.round,
                        block.header.proposer)
            return
        # Full validation BEFORE pre-endorsing (quorum not required on a
        # proposal — the quorum is what we are about to help build).
        err, _ = validate_and_apply(
            block, parent.header, self.chain.state, self.chain.validators,
            require_quorum=False,
        )
        if err is not None:
            LOG.warning("invalid proposal at level %d: %s", level, err)
            return
        self._pending[(level, h)] = block
        if block.header.round > self._round:
            self._round = block.header.round
            self._proposed_this_round = False
        self._round_deadline = time.monotonic() + self._round_timeout()
        if self.network:
            asyncio.create_task(self.network.broadcast_proposal(block.to_dict()))
        if self.bft is not None:
            out = self.bft.on_proposal(block.header.level, block.header.round, h)
            await self._emit_consensus(out)
        await self._try_finalize()

    async def _on_consensus_msg(self, msg_dict: dict) -> None:
        try:
            msg = ConsensusMessage.from_dict(msg_dict)
        except (ValueError, KeyError) as e:
            LOG.warning("rejected consensus message: %s", e)
            return
        if not msg.verify_signature():
            return
        await self._ingest_consensus(msg, from_wire=True)

    async def _on_block_msg(self, block_dict: dict) -> None:
        try:
            block = Block.from_dict(block_dict)
        except (ValueError, KeyError) as e:
            LOG.warning("rejected gossiped block: %s", e)
            return
        h = block.hash_hex()
        if h in self._seen_blocks:
            return
        level = block.header.level
        if level <= self.chain.height:
            return
        if level == self.chain.height + 1:
            try:
                # Every networked block must carry a verified > 2/3 quorum.
                self.chain.append(block, require_quorum=True)
            except ValueError as e:
                LOG.warning("rejected gossiped block at level %d: %s", level, e)
                return
            self._after_block_applied(block, broadcast=False)
            if self.network:
                asyncio.create_task(self.network.broadcast_block(block.to_dict()))
            await self._try_finalize()
        else:
            # Peer is ahead of us: catch-up sync (rate-limited).
            now = time.monotonic()
            if self.network and now - self._last_sync_request > 2.0:
                self._last_sync_request = now
                LOG.info("behind peer (head %d < %d) — requesting blocks",
                         self.chain.height, level)
                await self.network.request_blocks(self.chain.height + 1, level)

    async def _on_tx_msg(self, tx_dict: dict) -> None:
        try:
            tx = Transaction.from_dict(tx_dict)
        except (ValueError, KeyError) as e:
            LOG.warning("rejected gossiped tx: %s", e)
            return
        h = tx.hash_hex()
        if h in self._seen_txs:
            return
        self._seen_txs.add(h)
        self._trim(self._seen_txs)
        if not tx.verify_signature():
            return
        if self.storage.add_to_mempool(tx) and self.network:
            asyncio.create_task(self.network.broadcast_tx(tx.to_dict()))

    # ------------------------------------------------------------ sync out

    def _get_blocks(self, lo: int, hi: int) -> List[dict]:
        out: List[dict] = []
        for level in range(lo, hi + 1):
            b = self.storage.get_block_by_level(level)
            if b is None:
                break
            out.append(b.to_dict())
        return out

    def _on_peer_level(self, level: int) -> Optional[Tuple[int, int]]:
        if level > self.chain.height:
            return (self.chain.height + 1, level)
        return None


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
    storage.save_state(chain.state, 0)
    storage.close()
    print(f"Initialized node at {args.data_dir}")
    print(f"  Genesis hash: {genesis_block.hash_hex()}")
    print(f"  Validators: {len(chain.validators)}")
    print(f"  Pre-funded accounts: {len(initial_state['balances'])}")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    from .evm.bn254 import PY_ECC_AVAILABLE
    if not PY_ECC_AVAILABLE:
        # A node without the BN254 backend cannot evaluate pairings and
        # would diverge from its peers on any block that needs one.
        print("error: py_ecc is required (pip install -r requirements.txt)", file=sys.stderr)
        return 1
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    storage = Storage(args.data_dir)
    if storage.head_level() < 0:
        print("data-dir not initialized; run `init` first", file=sys.stderr)
        return 1

    # Latest snapshot + deterministic replay of the blocks above it.
    chain = load_chain(storage)

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
