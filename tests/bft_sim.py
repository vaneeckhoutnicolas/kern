# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Deterministic network simulator for the BFT engine (Phase E, E1).

Several real `kern.bft.BftEngine` instances exchange messages through a
simulated network that can delay, drop and reorder every message. Each
honest simulated node follows the rules of `kern.node.Node` (Phase E):

- every level starts at round 0; a round timer of `timeout(r) = base +
  r * base / 2` moves the node to the next round; the node also moves to
  a later round when validators holding more than a third of the stake
  already vote there, or when it accepts a valid proposal for it;
- the proposer of a round is `kern.consensus.select_proposer(parent hash,
  validators, round)`; it proposes the engine's valid block again (with
  its valid round and the pre-endorsement certificate as proof) when
  there is one, otherwise a new payload;
- a proposal is accepted when the signed PROPOSE message comes from the
  proposer of its round, the payload was produced by the proposer of its
  payload round, and a re-proposal carries a verified certificate for
  `payload_round <= valid_round < round`;
- a node finalizes a payload as soon as its engine holds an endorsement
  certificate for it at any round, broadcasts the decision, and moves to
  the next level. A node adopts a decision it receives for its level
  after checking the certificate (the node's block-gossip path), and
  re-announces its decisions once per base timeout (the node's
  catch-up sync).

The block hash is derived from (level, parent, payload round, producer):
a payload keeps its hash when it is proposed again in a later round.

Adversaries: a byzantine node can be "silent" (sends nothing) or
"equivocate": as proposer it sends two different payloads to the two
halves of the network, and it pre-endorses and endorses every block it
hears of, in every round, ignoring all lock rules.

A node can crash and restart: while it is down it receives nothing; on
restart its engine is rebuilt from scratch and restored from its signing
journal, as `kern.node.Node.__init__` does.

Nothing here is used by the node; it exists to judge consensus changes.
"""

from __future__ import annotations

import hashlib
import heapq
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from kern.bft import (BftEngine, ConsensusMessage, MAX_ROUND_DISTANCE, MsgKind,
                      QuorumCertificate)
from kern.consensus import round_timeout, select_proposer
from kern.crypto import KernKeypair
from kern.signing_journal import SigningJournal

GENESIS_HASH = "00" * 32
PARENT_HASH = GENESIS_HASH          # parent of level 1 (kept for older tests)


def block_hash(level: int, parent: str, payload_round: int, producer: str, salt: str = "") -> str:
    return hashlib.blake2b(f"{level}|{parent}|{payload_round}|{producer}|{salt}".encode(),
                           digest_size=32).hexdigest()


@dataclass(frozen=True)
class Proposal:
    level: int
    round: int
    block_hash: str
    payload_round: int
    producer: str
    parent: str
    valid_round: int
    proof: Optional[QuorumCertificate]
    msg: ConsensusMessage
    salt: str = ""


@dataclass(frozen=True)
class Decided:
    level: int
    round: int                       # cert_round
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
    def __init__(self, sim: "Simulation", idx: int, kp: KernKeypair, validators: List[dict],
                 *, journal_path: Optional[str] = None):
        self.sim = sim
        self.idx = idx
        self.kp = kp
        self.validators = validators
        self.journal_path = journal_path
        self.down = False
        self.level = sim.first_level
        self.parent = GENESIS_HASH
        self.decisions: Dict[int, Decided] = {}
        self.future: Dict[int, Decided] = {}
        self.next_announce = 0.0
        self._boot(now=0.0)

    # ------------------------------------------------------------ lifecycle
    def _boot(self, now: float) -> None:
        self.engine = BftEngine(own_keypair=self.kp, own_pubkey_b58=self.kp.public_key_b58,
                                validator_set=[dict(v) for v in self.validators])
        self.engine.min_level = self.level
        self.round = 0
        if self.journal_path is not None:
            j = SigningJournal(self.journal_path, "sim")
            rec = j.restore(self.level)
            self.engine.restore_lock(self.level, rec.locked_round, rec.locked_hash,
                                     rec.valid_round, rec.valid_hash)
            self.round = max(0, rec.max_round)
            self.engine.journal = j
        self.engine.current_round = self.round
        self.deadline = now + self.timeout()
        self.proposed: Set[Tuple[int, int]] = set()
        self.seen: Set[Tuple[int, int, str, str, int]] = set()
        self.pending: Dict[str, Proposal] = {}

    def crash(self) -> None:
        self.down = True

    def restart(self, now: float) -> None:
        self.down = False
        self._boot(now)

    @property
    def done(self) -> bool:
        return self.level > self.sim.last_level

    def timeout(self) -> float:
        return round_timeout(self.sim.timeout, self.round)

    # ------------------------------------------------------------- outbound
    def _emit(self, msgs: List[ConsensusMessage]) -> None:
        for m in msgs:
            self.sim.broadcast(self.idx, m)
            self._ingest(m)

    def _ingest(self, msg: ConsensusMessage) -> None:
        if self.done:
            return
        self._emit(self.engine.on_message(msg))
        self._try_finalize()

    def _set_round(self, r: int, now: float) -> None:
        self.round = r
        self.deadline = now + self.timeout()
        self._emit(self.engine.enter_round(self.level, r))
        self._try_finalize()

    # --------------------------------------------------------------- events
    def tick(self, now: float) -> None:
        if self.down:
            return
        if now >= self.next_announce and self.decisions:
            self.next_announce = now + self.sim.timeout
            for d in self.decisions.values():
                self.sim.broadcast(self.idx, d)
        if self.done:
            return
        if now >= self.deadline:
            self._set_round(self.round + 1, now)
        else:
            skip = self.engine.round_to_skip_to(self.level)
            if skip is not None:
                self._set_round(skip, now)
        if self.done:
            return
        proposer = select_proposer(self.parent, self.validators, self.round)
        if proposer["address"] == self.kp.address and (self.level, self.round) not in self.proposed:
            self.proposed.add((self.level, self.round))
            self._propose(now)

    def _propose(self, now: float) -> None:
        lv = self.engine.level_state(self.level)
        p_round, producer, salt = self.round, self.kp.address, ""
        valid_round, proof, h = -1, None, None
        if lv.valid_round >= 0 and lv.valid_hash in self.pending:
            qc = self.engine.find_preendorse_qc(self.level, lv.valid_round, lv.valid_hash)
            if qc is not None:
                old = self.pending[lv.valid_hash]
                h, p_round, producer, salt = old.block_hash, old.payload_round, old.producer, old.salt
                valid_round, proof = lv.valid_round, qc
        if h is None:
            h = block_hash(self.level, self.parent, self.round, self.kp.address)
        msg = self.engine.make_proposal(self.level, self.round, h, valid_round)
        if msg is None:
            return
        p = Proposal(self.level, self.round, h, p_round, producer, self.parent,
                     valid_round, proof, msg, salt)
        self.sim.proposals_sent.append((self.idx, self.level, self.round, valid_round))
        self.sim.broadcast(self.idx, p)
        self._on_proposal(p, now)

    def deliver(self, payload: Payload, now: float) -> None:
        if self.down:
            return
        if isinstance(payload, Proposal):
            self._on_proposal(payload, now)
        elif isinstance(payload, Decided):
            self._on_decided(payload)
        elif isinstance(payload, ConsensusMessage):
            self._ingest(payload)

    def _valid_proposal(self, p: Proposal) -> bool:
        if p.level != self.level or p.parent != self.parent or p.msg.block_hash != p.block_hash:
            return False
        if p.msg.round != p.round or p.msg.valid_round != p.valid_round or not p.msg.verify_signature():
            return False
        if select_proposer(self.parent, self.validators, p.round)["address"] != p.msg.validator:
            return False
        if select_proposer(self.parent, self.validators, p.payload_round)["address"] != p.producer:
            return False
        if p.block_hash != block_hash(p.level, p.parent, p.payload_round, p.producer, p.salt):
            return False
        if p.valid_round < 0:
            return p.payload_round == p.round
        q = p.proof
        return (p.payload_round <= p.valid_round < p.round and q is not None
                and q.kind == MsgKind.PREENDORSE and q.level == p.level
                and q.round == p.valid_round and q.block_hash == p.block_hash
                and q.verify(self.validators)[0])

    def _on_proposal(self, p: Proposal, now: float) -> None:
        if self.done:
            return
        key = (p.level, p.round, p.block_hash, p.msg.validator, p.valid_round)
        if key in self.seen or not self.engine.in_window(p.level, p.round):
            return
        if not self._valid_proposal(p):
            return
        self.seen.add(key)
        self.pending.setdefault(p.block_hash, p)
        if p.msg.validator != self.kp.address:
            self.sim.broadcast(self.idx, p)       # the node re-gossips proposals
        if self.round < p.round <= self.round + MAX_ROUND_DISTANCE:
            self._set_round(p.round, now)
        self._emit(self.engine.on_proposal(p.level, p.round, p.block_hash,
                                           valid_round=p.valid_round, proof=p.proof,
                                           proposal_msg=p.msg))
        self._try_finalize()

    def _try_finalize(self) -> None:
        if self.done:
            return
        for h in list(self.pending):
            qc = self.engine.find_endorse_qc(self.level, h)
            if qc is not None:
                self._decide(Decided(self.level, qc.round, h, qc), rebroadcast=True)
                return

    def _on_decided(self, d: Decided) -> None:
        if self.done or d.level < self.level:
            return
        if d.level > self.level:
            self.future[d.level] = d
            return
        q = d.qc
        if (q.kind == MsgKind.ENDORSE and q.level == d.level and q.block_hash == d.block_hash
                and q.round == d.round and q.verify(self.validators)[0]):
            self._decide(d, rebroadcast=False)

    def _decide(self, d: Decided, *, rebroadcast: bool) -> None:
        self.decisions[d.level] = d
        self.sim.decisions.append((self.sim.now, self.idx, d.level, d.round, d.block_hash))
        if rebroadcast:
            self.sim.broadcast(self.idx, d)
        self.level += 1
        self.parent = d.block_hash
        self.pending = {}
        self.engine.prune_below(self.level)
        self.round = 0
        self.engine.current_round = 0
        self.deadline = self.sim.now + self.timeout()
        if self.journal_path is not None and self.engine.journal is not None:
            self.engine.journal.compact(self.level)  # type: ignore[attr-defined]
        if self.done:
            return
        self._emit(self.engine.enter_round(self.level, 0))
        nxt = self.future.pop(self.level, None)
        if nxt is not None:
            self._on_decided(nxt)


class ByzantineNode(SimNode):
    """A validator that breaks every rule it can without forging signatures."""

    def __init__(self, *args, mode: str = "equivocate", **kwargs):
        self.mode = mode
        super().__init__(*args, **kwargs)
        self.voted: Set[Tuple[str, int, int, str]] = set()
        self.heard: Dict[Tuple[int, int], Set[str]] = {}

    def _sign_vote(self, kind: MsgKind, level: int, round_: int, h: str) -> None:
        key = (kind.value, level, round_, h)
        if key in self.voted:
            return
        self.voted.add(key)
        m = ConsensusMessage(kind=kind, level=level, round=round_, block_hash=h,
                             validator=self.kp.address, validator_pubkey=self.kp.public_key_b58)
        m.sign(self.kp)
        self.sim.broadcast(self.idx, m)

    def _vote_for_everything(self, level: int, round_: int, h: str) -> None:
        self.heard.setdefault((level, round_), set()).add(h)
        self._sign_vote(MsgKind.PREENDORSE, level, round_, h)
        self._sign_vote(MsgKind.ENDORSE, level, round_, h)

    def tick(self, now: float) -> None:
        if self.mode == "silent" or self.down:
            return
        # Follow the honest nodes' level through their decisions.
        if now >= self.deadline:
            self.round += 1
            self.deadline = now + self.timeout()
        proposer = select_proposer(self.parent, self.validators, self.round)
        if proposer["address"] == self.kp.address and (self.level, self.round) not in self.proposed:
            self.proposed.add((self.level, self.round))
            n = len(self.sim.nodes)
            for salt, targets in (("a", range(0, n, 2)), ("b", range(1, n, 2))):
                h = block_hash(self.level, self.parent, self.round, self.kp.address, salt)
                msg = ConsensusMessage(kind=MsgKind.PROPOSE, level=self.level, round=self.round,
                                       block_hash=h, validator=self.kp.address,
                                       validator_pubkey=self.kp.public_key_b58, valid_round=-1)
                msg.sign(self.kp)
                p = Proposal(self.level, self.round, h, self.round, self.kp.address,
                             self.parent, -1, None, msg, salt)
                for dst in targets:
                    if dst != self.idx:
                        self.sim.send(self.idx, dst, p)
                self._vote_for_everything(self.level, self.round, h)

    def deliver(self, payload: Payload, now: float) -> None:
        if self.mode == "silent" or self.down:
            return
        if isinstance(payload, Proposal) and payload.level == self.level:
            self._vote_for_everything(payload.level, payload.round, payload.block_hash)
        elif isinstance(payload, ConsensusMessage) and payload.level == self.level:
            self._vote_for_everything(payload.level, payload.round, payload.block_hash)
        elif isinstance(payload, Decided) and payload.level == self.level:
            self.decisions[payload.level] = payload
            self.level += 1
            self.parent = payload.block_hash
            self.round = 0
            self.deadline = now + self.timeout()


class Simulation:
    """Run n validators of equal stake (or `stakes`) for one or more levels."""

    def __init__(self, n: int = 4, policy: Optional[Policy] = None, *,
                 stakes: Optional[List[int]] = None, timeout: float = 1.0,
                 tick: float = 0.05, level: int = 1, levels: int = 1, seed_base: int = 0x70,
                 byzantine: Optional[Dict[int, str]] = None,
                 journal_dir: Optional[str] = None):
        self.first_level = level
        self.last_level = level + levels - 1
        self.level = level
        self.timeout = timeout
        self.tick_every = tick
        self.policy = policy or fixed_delay()
        self.now = 0.0
        self._seq = 0
        self._queue: List[_Envelope] = []
        self.decisions: List[Tuple[float, int, int, int, str]] = []
        self.proposals_sent: List[Tuple[int, int, int, int]] = []
        self.messages_sent = 0
        self.events: List[Tuple[float, Callable[[], None]]] = []
        keys = [KernKeypair.from_seed(bytes([seed_base + i]) * 32) for i in range(n)]
        stakes = stakes or [1] * n
        self.validators = [{"address": k.address, "pubkey": k.public_key_b58, "stake": s}
                           for k, s in zip(keys, stakes)]
        self.byzantine = dict(byzantine or {})
        self.nodes: List[SimNode] = []
        for i, k in enumerate(keys):
            jp = f"{journal_dir}/node{i}.jsonl" if journal_dir else None
            if i in self.byzantine:
                self.nodes.append(ByzantineNode(self, i, k, self.validators,
                                                mode=self.byzantine[i]))
            else:
                self.nodes.append(SimNode(self, i, k, self.validators, journal_path=jp))

    @property
    def honest(self) -> List[SimNode]:
        return [n for n in self.nodes if n.idx not in self.byzantine]

    def index_of(self, address: str) -> int:
        return next(i for i, v in enumerate(self.validators) if v["address"] == address)

    def proposer_of(self, round_: int, parent: str = GENESIS_HASH) -> int:
        return self.index_of(select_proposer(parent, self.validators, round_)["address"])

    def at(self, t: float, action: Callable[[], None]) -> "Simulation":
        """Schedule an action (for instance a crash or a restart) at time t."""
        self.events.append((t, action))
        self.events.sort(key=lambda e: e[0])
        return self

    def send(self, src: int, dst: int, payload: Payload) -> None:
        delay = self.policy(src, dst, self.now, payload)
        self.messages_sent += 1
        if delay is None:
            return
        self._seq += 1
        heapq.heappush(self._queue, _Envelope(self.now + max(0.0, delay), self._seq,
                                              src, dst, payload))

    def broadcast(self, src: int, payload: Payload) -> None:
        for dst in range(len(self.nodes)):
            if dst != src:
                self.send(src, dst, payload)

    def run(self, until: float = 30.0) -> "Simulation":
        next_tick = 0.0
        while self.now <= until:
            if all(n.done for n in self.honest):
                break
            if self.events and self.events[0][0] <= min(
                    next_tick, self._queue[0].deliver_at if self._queue else next_tick):
                t, action = self.events.pop(0)
                self.now = max(self.now, t)
                action()
            elif self._queue and self._queue[0].deliver_at <= next_tick:
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
    def decided_hashes(self, level: Optional[int] = None) -> Dict[int, str]:
        lvl = self.first_level if level is None else level
        return {n.idx: n.decisions[lvl].block_hash for n in self.honest if lvl in n.decisions}

    def forked(self) -> bool:
        return any(len(set(self.decided_hashes(lvl).values())) > 1
                   for lvl in range(self.first_level, self.last_level + 1))

    def all_decided(self) -> bool:
        return all(n.done for n in self.honest)

    def evidence_against(self, idx: int) -> list:
        addr = self.validators[idx]["address"]
        out = []
        for n in self.nodes:
            if n.idx in self.byzantine:
                continue
            out += [e for e in n.engine.pending_evidence if e.offender == addr]
        return out


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
