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
import ipaddress
import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

from aiohttp import web

from .bft import (BftEngine, ConsensusMessage, MAX_ROUND_DISTANCE, MsgKind,
                  QuorumCertificate)
from .block import Block, BlockHeader, txs_merkle_root_hex
from .chain import Chain, apply_block, state_root_hex, validate_and_apply
from . import failpoints
from .consensus import (BakerConfig, propose_block, round_timeout, select_proposer,
                        DEFAULT_BLOCK_TIME_S)
from .crypto import KernKeypair
from .network import Network
from .rpc import build_app
from .signing_journal import JOURNAL_FILE, JournalError, SigningJournal
from .storage import Storage
from .transaction import Transaction

LOG = logging.getLogger("kern.node")

# Dedup sets are advisory only (correctness never depends on them: stale
# blocks are rejected by level, duplicate txs by the mempool primary key,
# and repeated consensus messages are idempotent in the engine), so a
# blunt clear-on-overflow bound is sufficient.
MAX_SEEN_ENTRIES = 50_000

# The signing journal is compacted every this many finalized levels.
JOURNAL_COMPACT_EVERY = 64


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
        payload_round=0,
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

# Listening addresses. The RPC answers anyone who reaches it (including the
# transaction submission endpoint), so it stays on this machine unless the
# operator opens it; peers must reach the peer-to-peer layer.
DEFAULT_RPC_BIND = "127.0.0.1"
DEFAULT_P2P_BIND = "0.0.0.0"


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
        rpc_host: str = DEFAULT_RPC_BIND,
        p2p_host: str = DEFAULT_P2P_BIND,
    ):
        self.data_dir = data_dir
        self.chain = chain
        self.storage = storage
        self.baker = baker
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.rpc_host = rpc_host
        self.p2p_host = p2p_host
        self.bootstrap_peers = peers
        self.block_time = block_time
        self.network: Optional[Network] = None
        self._app_runner: Optional[web.AppRunner] = None
        self._tasks: List[asyncio.Task] = []
        self._stop_event = asyncio.Event()

        # Consensus engine — present iff this node holds a validator key.
        self.bft: Optional[BftEngine] = None
        self.journal: Optional[SigningJournal] = None
        # Round management for the level currently being decided. Phase E:
        # every level starts at round 0 (consensus-locking.md 9.1).
        self._round: int = 0
        if baker is not None:
            self.bft = BftEngine(
                own_keypair=baker.keypair,
                own_pubkey_b58=baker.pubkey_b58,
                validator_set=list(chain.validators),
            )

        # Validated (pre-quorum) proposals, keyed by (level, block_hash).
        # Phase E: a payload keeps its hash across rounds, so one entry
        # serves every round in which it is proposed.
        self._pending: Dict[Tuple[int, str], Block] = {}
        self._seen_proposals: Set[Tuple[int, int, str, str, int]] = set()
        # Review of 84cbbcc: the first proposal seen for each (level, round),
        # as (block hash, signed PROPOSE, envelope). Only that block is
        # validated and kept; another one for the same (level, round) is
        # equivocation evidence, never validated or stored. Review of
        # e67ed17: the entry is kept even when that first block turns out
        # to be invalid, so a later block of the round is never voted on
        # unvalidated and the two signed messages stay available as evidence.
        # Review of 7e005a6: only that signed message can go further; any
        # other one for the round, even for the same block, is evidence.
        self._round_proposal: Dict[Tuple[int, int], Tuple[str, ConsensusMessage, dict]] = {}
        # (level, hash) of proposed blocks that failed validation: checked once.
        self._invalid_proposals: Set[Tuple[int, str]] = set()
        self._relayed_conflicts: Set[Tuple[int, int]] = set()
        # (level, round) the engine was last told about.
        self._engine_pos: Tuple[int, int] = (-1, -1)
        # Advisory dedup sets (see MAX_SEEN_ENTRIES note above).
        self._seen_blocks: Set[str] = set()
        self._seen_txs: Set[str] = set()
        self._seen_cons: Set[Tuple[str, int, int, str, str]] = set()
        # Next nonce for this validator's own slashing reports (Phase D).
        self._next_report_nonce: int = 0
        self._round_deadline: float = 0.0
        self._proposed_this_round: bool = False
        self._last_block_at: float = time.monotonic()
        self._last_sync_request: float = 0.0
        # Phase E: the signing journal is opened last, once every structure
        # it restores into (the pending blocks) exists.
        if self.bft is not None:
            self._open_signing_journal()

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self.network = Network(
            host=self.p2p_host,
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
        site = web.TCPSite(self._app_runner, self.rpc_host, self.rpc_port)
        await site.start()
        LOG.info("RPC listening on %s:%d", self.rpc_host, self.rpc_port)
        if not ipaddress.ip_address(self.rpc_host).is_loopback:
            LOG.warning("RPC reachable beyond this machine (%s): put a reverse proxy "
                        "and a firewall in front of it (docs/setup-validator.md)",
                        self.rpc_host)

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

    def _open_signing_journal(self) -> None:
        """Phase E (consensus-locking.md 9.2): open the signing journal and
        restore the lock, valid round and round of the level in progress.

        A journal that cannot be read is moved aside and a new one is
        started, and so is a missing journal on a chain already past
        genesis: in both cases this validator does not sign at the level in
        progress, and resumes once that level has been finalized by others.
        """
        assert self.bft is not None
        level = self.chain.height + 1
        chain_id = self.chain.state.get("chain_id")
        path = os.path.join(self.data_dir, JOURNAL_FILE)
        suspend = False
        try:
            journal = SigningJournal(path, chain_id)
            if not journal.existed and self.chain.height > 0:
                LOG.warning("no signing journal in %s at height %d: not signing until "
                            "level %d is finalized by others", self.data_dir,
                            self.chain.height, level)
                suspend = True
        except JournalError as e:
            aside = f"{path}.unreadable-{int(time.time())}"
            LOG.error("signing journal unreadable (%s); moved to %s. Not signing until "
                      "level %d is finalized by others", e, aside, level)
            os.replace(path, aside)
            journal = SigningJournal(path, chain_id)
            suspend = True
        if suspend:
            self.bft.no_signing_through_level = level
        rec = journal.restore(level)
        if self.bft.restore_lock(level, rec.locked_round, rec.locked_hash,
                                 rec.valid_round, rec.valid_hash, rec.valid_qc):
            LOG.info("restored the pre-endorsement certificate of round %d at level %d "
                     "from the signing journal", rec.valid_round, level)
        self._round = max(0, rec.max_round)
        self.bft.journal = journal
        self.journal = journal
        self._restore_kept_blocks(level, rec.locked_hash)

    def _restore_kept_blocks(self, level: int, locked_hash: Optional[str]) -> None:
        """Review of f24564b, P1: bring back the blocks this validator kept
        on disk before signing for them. A kept block is validated again
        before use. If this validator holds the quorum alone and is locked
        on one of its own blocks, its self-commit is counted again: that
        block is final, and the node finalizes it instead of staying locked
        on a hash it could no longer propose."""
        assert self.bft is not None and self.journal is not None
        parent = self.chain.head
        for d in self.journal.blocks(level):
            try:
                block = Block.from_dict(d)
            except (ValueError, KeyError, TypeError):
                continue
            err, _ = validate_and_apply(block, parent.header, self.chain.state,
                                        self.chain.validators, require_quorum=False)
            if err is not None:
                LOG.warning("kept block at level %d no longer valid: %s", level, err)
                continue
            h = block.hash_hex()
            block.endorsements, block.cert_round = [], None
            self._pending[(level, h)] = block
            LOG.info("restored kept block %d (hash %s) from the signing journal", level, h[:12])
            if block.commits and h == locked_hash:
                self._refresh_engine()
                if self._adopt_self_commit(block):
                    LOG.info("own self-commit for block %d counted again after restart", level)

    def _keep_block(self, block: Block) -> bool:
        """Write a block body to the signing journal's block file (synced)
        before anything is signed over it. False if it cannot be written:
        the caller then signs nothing."""
        if self.journal is None:
            return True
        d = block.to_dict()
        d["endorsements"] = []
        d.pop("cert_round", None)
        try:
            self.journal.record_block(block.header.level, block.hash_hex(), d)
        except OSError:
            LOG.exception("could not keep block %d on disk; not signing for it",
                          block.header.level)
            return False
        return True

    def _own_address(self) -> Optional[str]:
        return self.baker.keypair.address if self.baker is not None else None

    def _base_timeout(self) -> float:
        return max(2.0, self.block_time * 4)

    def _round_timeout(self) -> float:
        return round_timeout(self._base_timeout(), self._round)

    def _refresh_engine(self) -> None:
        if self.bft is not None:
            self.bft.validator_set = self.chain.validators
            self.bft.current_round = self._round
            self.bft.min_level = max(self.bft.min_level, self.chain.height + 1)

    async def _set_round(self, round_: int) -> None:
        """Move to `round_` at the level in progress and let the engine vote
        in it if its proposal and votes are already there."""
        self._round = round_
        self._proposed_this_round = False
        self._round_deadline = time.monotonic() + self._round_timeout()
        await self._sync_engine_round()

    async def _sync_engine_round(self) -> None:
        if self.bft is None:
            return
        pos = (self.chain.height + 1, self._round)
        if pos == self._engine_pos:
            return
        self._engine_pos = pos
        self._refresh_engine()
        await self._emit_consensus(self.bft.enter_round(*pos))
        self._prune_round_data()

    def _prune_round_data(self) -> None:
        """Review of 0695a80, P2: what the node keeps per round of the level
        in progress follows the engine's round window. Proposals of rounds
        that left the window are dropped, except those of the lock and the
        valid round, and so are the blocks that no kept proposal, lock or
        valid round refers to. A level that does not finalize for many
        rounds no longer accumulates one block per round in memory."""
        if self.bft is None:
            return
        level, cur = self.chain.height + 1, self._round
        kept = self.bft.kept_rounds(level)

        def in_reach(r: int) -> bool:
            return abs(r - cur) <= MAX_ROUND_DISTANCE or r in kept

        self._round_proposal = {k: v for k, v in self._round_proposal.items()
                                if k[0] != level or in_reach(k[1])}
        self._relayed_conflicts = {k for k in self._relayed_conflicts
                                   if k[0] != level or in_reach(k[1])}
        live = {v[0] for k, v in self._round_proposal.items() if k[0] == level}
        lv = self.bft.levels.get(level)
        if lv is not None:
            live |= {h for h in (lv.locked_hash, lv.valid_hash) if h is not None}
        self._pending = {k: v for k, v in self._pending.items()
                         if k[0] != level or k[1] in live}
        self._invalid_proposals = {k for k in self._invalid_proposals
                                   if k[0] != level or k[1] in live}

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
        if self.journal is not None and level % JOURNAL_COMPACT_EVERY == 0:
            self.journal.compact(level + 1)
        self._seen_proposals = {k for k in self._seen_proposals if k[0] > level}
        self._round_proposal = {k: v for k, v in self._round_proposal.items() if k[0] > level}
        self._invalid_proposals = {k for k in self._invalid_proposals if k[0] > level}
        self._relayed_conflicts = {k for k in self._relayed_conflicts if k[0] > level}
        self._round = 0
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
        await self._recover()
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(tick)
                now = time.monotonic()
                self._refresh_engine()

                if now > self._round_deadline:
                    LOG.info("round timeout at level %d — advancing to round %d",
                             self.chain.height + 1, self._round + 1)
                    await self._set_round(self._round + 1)
                else:
                    skip = self.bft.round_to_skip_to(self.chain.height + 1)
                    if skip is not None:
                        LOG.info("more than a third of the stake is at round %d — "
                                 "moving there", skip)
                        await self._set_round(skip)
                await self._sync_engine_round()

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

    async def _recover(self) -> None:
        """First step after start: let the engine act on the round restored
        from the journal, and finalize a block whose certificate is already
        complete (a restored self-commit of a validator holding the quorum
        alone)."""
        await self._sync_engine_round()
        await self._try_finalize()

    async def _propose(self, parent: Block) -> None:
        """Propose at the current round (consensus-locking.md, rule 5): the
        block of the engine's valid round when there is one, with its
        pre-endorsement certificate as proof; otherwise a new payload."""
        assert self.baker is not None and self.bft is not None
        level, r = parent.header.level + 1, self._round
        self._proposed_this_round = True
        lv = self.bft.level_state(level)
        block: Optional[Block] = None
        valid_round, proof = -1, None
        if lv.valid_round >= 0 and lv.valid_hash is not None:
            cand = self._pending.get((level, lv.valid_hash))
            qc = self.bft.find_preendorse_qc(level, lv.valid_round, lv.valid_hash)
            if cand is not None and qc is not None:
                block, valid_round, proof = cand, lv.valid_round, qc
        if block is None:
            txs = self.storage.drain_mempool(max_n=self.baker.max_txs_per_block)
            evicted: list = []
            block = propose_block(
                parent=parent,
                mempool=txs,
                proposer_keypair=self.baker.keypair,
                proposer_pubkey_b58=self.baker.pubkey_b58,
                state_before=self.chain.state,
                round_=r,
                evict_out=evicted,
            )
            if evicted:
                # Transactions that can never become valid (bad signature,
                # consumed nonce) are dropped so they are not re-tried forever.
                self.storage.remove_from_mempool(evicted)
            if not self._keep_block(block):
                return
            if block.commits:
                if not self._adopt_self_commit(block):
                    LOG.warning("not proposing at level %d round %d: own endorsement "
                                "refused by the lock or the signing journal", level, r)
                    return
                failpoints.hit("after_self_commit")
        h = block.hash_hex()
        proposal = self.bft.make_proposal(level, r, h, valid_round)
        if proposal is None:
            LOG.warning("not proposing at level %d round %d: refused by the signing "
                        "journal", level, r)
            return
        failpoints.hit("after_proposal_signed")
        self._pending[(level, h)] = block
        envelope = self._envelope(block, proposal, proof)
        self._round_proposal.setdefault((level, r), (h, proposal, envelope))
        self._seen_proposals.add((level, r, h, proposal.validator, valid_round))
        LOG.info("proposed block %d round %d (payload round %d, valid round %d, "
                 "hash %s, %d txs)", level, r, block.header.payload_round,
                 valid_round, h[:12], len(block.transactions))
        if self.network:
            await self.network.broadcast_proposal(envelope)
            failpoints.hit("after_proposal_broadcast")
        # Self-deliver the proposal to our own engine: emits our
        # pre-endorsement, which loops back through _ingest_consensus and,
        # in single-validator operation, drives the full pre-endorse →
        # endorse → quorum-certificate sequence within this tick.
        out = self.bft.on_proposal(level, r, h, valid_round=valid_round, proof=proof,
                                   proposal_msg=proposal)
        await self._emit_consensus(out)

    def _adopt_self_commit(self, block: Block) -> bool:
        """The self-commit of a proposer holding the quorum alone goes
        through the engine (journal and lock) before the block is shown."""
        assert self.bft is not None and self.baker is not None
        addr, _, sig = block.commits[0].partition(":")
        msg = ConsensusMessage(kind=MsgKind.ENDORSE, level=block.header.level,
                               round=block.header.payload_round,
                               block_hash=block.hash_hex(), validator=addr,
                               validator_pubkey=self.baker.pubkey_b58, signature=sig)
        return self.bft.adopt_self_commit(msg)

    @staticmethod
    def _envelope(block: Block, proposal: ConsensusMessage,
                  proof: Optional[QuorumCertificate]) -> dict:
        b = block.to_dict()
        # A proposal carries no quorum yet: the endorsements of the round
        # that finalizes it are added by each node.
        b["endorsements"] = []
        b.pop("cert_round", None)
        return {"block": b, "proposal": proposal.to_dict(),
                "proof": proof.to_dict() if proof is not None else None}

    async def _emit_consensus(self, msgs: List[ConsensusMessage]) -> None:
        for m in msgs:
            if m.kind == MsgKind.ENDORSE and m.validator == self._own_address():
                failpoints.hit("before_endorse_broadcast", m.level)
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
            # Phase E: an endorsement certificate at ANY round finalizes
            # the payload; its round is stored as cert_round.
            qc = self.bft.find_endorse_qc(lvl, h)
            if qc is None:
                continue
            block.cert_round = qc.round
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

    async def _on_proposal_msg(self, envelope: dict) -> None:
        """A proposal: {"block", "proposal" (signed PROPOSE), "proof"}.

        Checks, in order (docs/consensus-wire.md): decoding; level; the
        PROPOSE signature and its signer being the proposer selected for
        the proposal round; the first signed proposal of the round is then
        recorded (a different later one is only evidence); the valid round (-1 for a new payload, whose
        payload round is then the proposal round; otherwise a verified
        pre-endorsement certificate for the block at valid_round, with
        payload_round <= valid_round < round); full validation of the block,
        including the header proposer of the payload round. Only then the
        engine sees it."""
        try:
            if not isinstance(envelope, dict):
                raise ValueError("proposal: expected an object")
            block = Block.from_dict(envelope.get("block"))  # type: ignore[arg-type]
            pmsg = ConsensusMessage.from_dict(envelope.get("proposal"))  # type: ignore[arg-type]
            raw_proof = envelope.get("proof")
            proof = QuorumCertificate.from_dict(raw_proof) if raw_proof is not None else None
        except (ValueError, KeyError, TypeError) as e:
            LOG.warning("rejected proposal: %s", e)
            return
        h = block.hash_hex()
        level = self.chain.height + 1
        r, vr = pmsg.round, pmsg.valid_round
        if (block.header.level != level or pmsg.kind != MsgKind.PROPOSE
                or pmsg.level != level or pmsg.block_hash != h):
            return
        key = (level, r, h, pmsg.validator, vr)
        if key in self._seen_proposals or h in self._seen_blocks:
            return
        if self.bft is not None and not self.bft.in_window(level, r):
            return
        if not pmsg.verify_signature():
            return
        parent = self.chain.head
        validators = self.chain.validators
        expected = select_proposer(parent_hash_hex=parent.hash_hex(),
                                   validators=validators, round_=r)
        if expected["address"] != pmsg.validator:
            LOG.warning("proposal at level %d round %d from illegitimate "
                        "proposer %s", level, r, pmsg.validator)
            return
        # Review of 0695a80, P2: the first signed PROPOSE of the selected
        # proposer occupies its (level, round) before the valid round is
        # checked, so that a later, different proposal is kept as evidence
        # even when the first one fails those checks (as section 10.8 does
        # for a block that fails validation).
        first = self._round_proposal.setdefault((level, r), (h, pmsg, envelope))
        if first[1] is not pmsg and first[1].to_dict() != pmsg.to_dict():
            # Review of 7e005a6: another signed PROPOSE for this (level,
            # round), whether for another block or for the same block with
            # another valid round. Only the message that occupies the round
            # can go further (it may come back with a valid proof, which the
            # proposer does not sign); this one is evidence, relayed once
            # with the first so that other nodes keep it too, and never
            # validated, stored, kept or voted on (reviews of e67ed17 and
            # 7e005a6).
            if self.bft is not None:
                self.bft.record_proposal_equivocation(first[1], pmsg)
            if self.network and (level, r) not in self._relayed_conflicts:
                self._relayed_conflicts.add((level, r))
                for env in (first[2], envelope):
                    asyncio.create_task(self.network.broadcast_proposal(env))
            LOG.warning("conflicting proposal at level %d round %d from %s: kept as evidence, "
                        "not validated", level, r, pmsg.validator)
            return
        # The valid round and the payload round are signed by the proposer
        # (the block hash binds the header): a wrong one is the proposer's
        # fault, and the round stays occupied by that proposal. The proof is
        # not signed by the proposer and a relay may have damaged it, so a
        # bad proof is only refused here: the same signed proposal arriving
        # later with a valid proof is accepted (it is not marked as seen).
        if vr < 0:
            if block.header.payload_round != r:
                LOG.warning("new proposal at level %d round %d with payload round %d",
                            level, r, block.header.payload_round)
                return
        else:
            if not block.header.payload_round <= vr < r:
                LOG.warning("re-proposal at level %d round %d: payload round %d, "
                            "valid round %d", level, r, block.header.payload_round, vr)
                return
            if (proof is None or proof.kind != MsgKind.PREENDORSE or proof.level != level
                    or proof.round != vr or proof.block_hash != h
                    or not proof.verify(validators)[0]):
                LOG.warning("re-proposal at level %d round %d without a valid proof "
                            "for valid round %d", level, r, vr)
                return
        self._seen_proposals.add(key)
        self._trim(self._seen_proposals)
        if (level, h) in self._invalid_proposals:
            return
        if (level, h) not in self._pending:
            # Full validation BEFORE pre-endorsing (quorum not required on a
            # proposal — the quorum is what we are about to help build).
            err, _ = validate_and_apply(block, parent.header, self.chain.state,
                                        validators, require_quorum=False)
            if err is not None:
                self._invalid_proposals.add((level, h))
                LOG.warning("invalid proposal at level %d: %s", level, err)
                return
            block.endorsements = []
            block.cert_round = None
            self._pending[(level, h)] = block
        if self.network:
            asyncio.create_task(self.network.broadcast_proposal(envelope))
        if r > self._round and r <= self._round + MAX_ROUND_DISTANCE:
            await self._set_round(r)
        if self.bft is not None:
            if not self._keep_block(self._pending[(level, h)]):
                return
            self._refresh_engine()
            out = self.bft.on_proposal(level, r, h, valid_round=vr, proof=proof,
                                       proposal_msg=pmsg)
            await self._emit_consensus(out)
            await self._ingest_commits(self._pending[(level, h)])
        await self._try_finalize()

    async def _ingest_commits(self, block: Block) -> None:
        """Review of f24564b, P1: the endorsements a proposal carries in
        `commits` (the self-commit of a proposer holding the quorum alone)
        are ENDORSE votes for the payload round like any other. Counting
        them lets the other validators finalize the block even if its
        proposer dies before gossiping the finalized block. Each entry is
        checked by the engine (signature, validator, window)."""
        if self.bft is None:
            return
        keys = {v["address"]: v["pubkey"] for v in self.chain.validators}
        for entry in block.commits:
            addr, sep, sig = entry.partition(":")
            if not sep or addr not in keys:
                continue
            msg = ConsensusMessage(kind=MsgKind.ENDORSE, level=block.header.level,
                                   round=block.header.payload_round,
                                   block_hash=block.hash_hex(), validator=addr,
                                   validator_pubkey=keys[addr], signature=sig)
            await self._ingest_consensus(msg, from_wire=False)

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
        rpc_host=args.rpc_bind,
        p2p_host=args.p2p_bind,
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


def _bind_address(value: str) -> str:
    """An IPv4 or IPv6 address to listen on (not a host name, no port)."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IP address: {value!r}") from None


def build_parser() -> argparse.ArgumentParser:
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
    p_start.add_argument("--rpc-bind", type=_bind_address, default=DEFAULT_RPC_BIND,
                         help="address the RPC listens on (default %(default)s, this "
                              "machine only; 0.0.0.0 for every interface)")
    p_start.add_argument("--p2p-bind", type=_bind_address, default=DEFAULT_P2P_BIND,
                         help="address the peer-to-peer layer listens on (default "
                              "%(default)s, every interface)")
    p_start.add_argument("--baker-key", default=None)
    p_start.add_argument("--peer", action="append", default=[])
    p_start.add_argument("--block-time", type=float, default=DEFAULT_BLOCK_TIME_S)
    p_start.set_defaults(func=cmd_start)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
