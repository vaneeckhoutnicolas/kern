# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Deterministic network simulator for the BFT engine (Phase E, E1 step 1).

Several real `kern.bft.BftEngine` instances exchange messages through a
simulated network that can delay, drop and reorder every message. Each
simulated node follows the rules of `kern.node.Node` for one level:

- a round timer; on timeout the node moves to the next round;
- the proposer of a round is `kern.consensus.select_proposer`;
- a proposal is accepted if it comes from the legitimate proposer of its
  round and that round is at least 0 (the parent is genesis at round 0,
  so the node's rule `round >= parent.round + 1` is not modelled here:
  the simulated parent has no round);
- a node finalizes the block of a round as soon as its engine holds an
  endorsement quorum certificate for that block, then broadcasts the
  finalized block; a node that has not finalized yet adopts a finalized
  block it receives (the node's block-gossip path, which checks the
  quorum: here every broadcast decision carries a real certificate);
- after finalizing, a node takes no further part in that level (the node
  prunes the level from its engine), but re-announces its finalized block
  once per round interval, which models the node's catch-up sync (a node
  behind a peer requests the missing blocks).

The block hash is derived from (level, round, proposer), as in Kern, where
the header contains the round and the proposer: a block re-proposed in a
later round is a different block.

Nothing here is used by the node; it exists to judge consensus changes.
"""

from __future__ import annotations

import hashlib
import heapq
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from kern.bft import BftEngine, ConsensusMessage, MsgKind, QuorumCertificate
from kern.consensus import select_proposer
from kern.crypto import KernKeypair

PARENT_HASH = "00" * 32


def block_hash(level: int, round_: int, proposer: str) -> str:
    return hashlib.blake2b(f"{level}|{round_}|{proposer}".encode(), digest_size=32).hexdigest()


@dataclass(frozen=True)
class Proposal:
    level: int
    round: int
    proposer: str
    block_hash: str


@dataclass(frozen=True)
class Decided:
    level: int
    round: int
    block_hash: str
    qc: QuorumCertificate


Payload = object  # ConsensusMessage | Proposal | Decided

# A delivery policy returns the delay of one message, or None to drop it.
# Arguments: (src index, dst index, send time, payload).
Policy = Callable[[int, int, float, Payload], Optional[float]]


def fixed_delay(d: float = 0.01) -> Policy:
    return lambda src, dst, t, p: d


@dataclass(order=True)
class _Envelope:
    deliver_at: float
    seq: int
    src: int = field(compare=False)
    dst: int = field(compare=False)
    payload: Payload = field(compare=False)


class SimNode:
    def __init__(self, sim: "Simulation", idx: int, kp: KernKeypair, validators: List[dict]):
        self.sim = sim
        self.idx = idx
        self.kp = kp
        self.validators = validators
        self.engine = BftEngine(own_keypair=kp, own_pubkey_b58=kp.public_key_b58,
                                validator_set=[dict(v) for v in validators])
        self.level = sim.level
        self.round = 0
        self.engine.current_round = 0
        self.engine.min_level = self.level
        self.deadline = sim.timeout
        self.proposed_rounds: set = set()
        self.pending: Dict[str, Proposal] = {}
        self.decision: Optional[Decided] = None
        self.next_announce = 0.0

    # ------------------------------------------------------------- outbound
    def _emit(self, msgs: List[ConsensusMessage]) -> None:
        for m in msgs:
            self.sim.broadcast(self.idx, m)
            self._ingest(m)

    def _ingest(self, msg: ConsensusMessage) -> None:
        if self.decision is not None:
            return
        self._emit(self.engine.on_message(msg))
        self._try_finalize()

    # --------------------------------------------------------------- events
    def tick(self, now: float) -> None:
        if self.decision is not None:
            if now >= self.next_announce:
                self.next_announce = now + self.sim.timeout
                self.sim.broadcast(self.idx, self.decision)
            return
        if now >= self.deadline:
            self.round += 1
            self.engine.current_round = self.round
            self.deadline = now + self.sim.timeout
        proposer = select_proposer(PARENT_HASH, self.validators, self.round)
        if proposer["address"] == self.kp.address and self.round not in self.proposed_rounds:
            self.proposed_rounds.add(self.round)
            p = Proposal(self.level, self.round, self.kp.address,
                         block_hash(self.level, self.round, self.kp.address))
            self.sim.broadcast(self.idx, p)
            self._accept_proposal(p, now)

    def deliver(self, payload: Payload, now: float) -> None:
        if self.decision is not None:
            return
        if isinstance(payload, Proposal):
            self._on_proposal(payload, now)
        elif isinstance(payload, Decided):
            ok, _ = payload.qc.verify(self.validators)
            if ok and payload.qc.block_hash == payload.block_hash:
                self._decide(payload, rebroadcast=False)
        elif isinstance(payload, ConsensusMessage):
            self._ingest(payload)

    def _on_proposal(self, p: Proposal, now: float) -> None:
        if p.level != self.level or p.block_hash in self.pending:
            return
        expected = select_proposer(PARENT_HASH, self.validators, p.round)
        if expected["address"] != p.proposer or p.block_hash != block_hash(p.level, p.round, p.proposer):
            return
        self._accept_proposal(p, now)

    def _accept_proposal(self, p: Proposal, now: float) -> None:
        self.pending[p.block_hash] = p
        if p.round > self.round:
            self.round = p.round
            self.engine.current_round = p.round
        self.deadline = now + self.sim.timeout
        self._emit(self.engine.on_proposal(p.level, p.round, p.block_hash))
        self._try_finalize()

    def _try_finalize(self) -> None:
        if self.decision is not None:
            return
        for h, p in list(self.pending.items()):
            qc = self.engine.get_endorse_qc(p.level, p.round)
            if qc is not None and qc.block_hash == h:
                self._decide(Decided(p.level, p.round, h, qc), rebroadcast=True)
                return

    def _decide(self, d: Decided, *, rebroadcast: bool) -> None:
        self.decision = d
        self.sim.decisions.append((self.sim.now, self.idx, d.round, d.block_hash))
        self.engine.prune_below(self.level + 1)
        self.next_announce = self.sim.now + self.sim.timeout
        if rebroadcast:
            self.sim.broadcast(self.idx, d)


class Simulation:
    """Run n validators of equal stake (or `stakes`) at one level."""

    def __init__(self, n: int = 4, policy: Optional[Policy] = None, *,
                 stakes: Optional[List[int]] = None, timeout: float = 1.0,
                 tick: float = 0.05, level: int = 1, seed_base: int = 0x70):
        self.level = level
        self.timeout = timeout
        self.tick_every = tick
        self.policy = policy or fixed_delay()
        self.now = 0.0
        self._seq = 0
        self._queue: List[_Envelope] = []
        self.decisions: List[Tuple[float, int, int, str]] = []
        self.messages_sent = 0
        keys = [KernKeypair.from_seed(bytes([seed_base + i]) * 32) for i in range(n)]
        stakes = stakes or [1] * n
        self.validators = [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                           for k, s in zip(keys, stakes)]
        self.nodes = [SimNode(self, i, k, self.validators) for i, k in enumerate(keys)]

    def index_of(self, address: str) -> int:
        return next(i for i, v in enumerate(self.validators) if v["address"] == address)

    def proposer_of(self, round_: int) -> int:
        return self.index_of(select_proposer(PARENT_HASH, self.validators, round_)["address"])

    def broadcast(self, src: int, payload: Payload) -> None:
        for dst in range(len(self.nodes)):
            if dst == src:
                continue
            delay = self.policy(src, dst, self.now, payload)
            self.messages_sent += 1
            if delay is None:
                continue
            self._seq += 1
            heapq.heappush(self._queue, _Envelope(self.now + max(0.0, delay), self._seq,
                                                  src, dst, payload))

    def run(self, until: float = 30.0) -> "Simulation":
        next_tick = 0.0
        while self.now <= until:
            if all(n.decision is not None for n in self.nodes):
                break
            if self._queue and self._queue[0].deliver_at <= next_tick:
                env = heapq.heappop(self._queue)
                self.now = env.deliver_at
                self.nodes[env.dst].deliver(env.payload, self.now)
            else:
                self.now = next_tick
                for node in self.nodes:
                    node.tick(self.now)
                next_tick += self.tick_every
        return self

    # ---------------------------------------------------------- properties
    def decided_hashes(self) -> Dict[int, str]:
        return {n.idx: n.decision.block_hash for n in self.nodes if n.decision is not None}

    def forked(self) -> bool:
        return len(set(self.decided_hashes().values())) > 1

    def all_decided(self) -> bool:
        return all(n.decision is not None for n in self.nodes)


def random_policy(seed: int, *, drop: float = 0.1, max_delay: float = 2.0,
                  gst: float = 15.0, post_gst_delay: float = 0.05) -> Policy:
    """Asynchronous until `gst` (random delays up to `max_delay`, random
    drops), then synchronous (every message delivered within
    `post_gst_delay`). A message sent before GST is delivered no later than
    GST plus the post-GST delay, as in the partial synchrony model."""
    rng = random.Random(seed)

    def policy(src: int, dst: int, t: float, payload: Payload) -> Optional[float]:
        if t >= gst:
            return rng.uniform(0.0, post_gst_delay)
        if rng.random() < drop:
            return None
        return min(rng.uniform(0.0, max_delay), gst + post_gst_delay - t)

    return policy
