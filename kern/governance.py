# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.governance
===============

On-chain governance for Kern. Two parallel tracks:

1. **Protocol amendments** — changes to consensus rules, KVM, gas pricing,
   issuance parameters, Skald itself. Uses a five-phase cycle (Proposal,
   Exploration vote, Cooldown, Adoption vote, Activation). Requires
   supermajority (≥ 80%) at both votes.

2. **Treasury allocations** — disbursements from the on-chain treasury
   contract to ecosystem projects. Uses a two-phase cycle (Proposal,
   Vote). Requires simple majority weighted by stake.

The protocol-amendment track is intentionally slow and high-bar. Treasury
allocations move faster because they don't change the protocol — they
just move money.

Design
------

A Proposal is a typed object with a unique id, a sender, a payload
describing the change/spend, and the cycle phase it currently sits in.
Time is measured in "L1 cycles" — windows of N blocks. The reference
implementation uses small windows (10–30 blocks) for fast testing; the
production protocol uses days-long windows per `tokenomics.md`.

Vote weight is by active validator stake. A "yes" vote signs over
(proposal_id, voter_address, cycle_index). Equivocation (yes+no from
the same voter on the same proposal) is detectable from the on-chain
record and slashable under the same rules as BFT equivocation.

State machine
-------------

Protocol amendment cycle:

    SUBMITTED ──proposal_window_end──► EXPLORATION
        │                                  │
        │                                  ├─yes ≥ 80%──► COOLDOWN ──cooldown_end──► ADOPTION
        │                                  │                                            │
        │                                  └─yes < 80%──► REJECTED                      ├─yes ≥ 80%──► ACTIVATED
        │                                                                                │
        └──submitter_withdraws──► WITHDRAWN                                              └─yes < 80%──► REJECTED

Treasury cycle:

    SUBMITTED ──proposal_window_end──► VOTING
        │                                 │
        │                                 ├─yes > 50%──► EXECUTED
        │                                 │
        └──submitter_withdraws──► WITHDRAWN
                                          └─yes ≤ 50%──► REJECTED

The Python state machine here is the spec; on-chain it is realized as
two Skald contracts (`ProtocolGovernance` and `Treasury`) whose state
is the proposal list + tallies.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default cycle windows in BLOCKS. Production values would be much larger
# (e.g., 5 days × 86_400 s/day × 1 block/s = 432_000 blocks per phase).
# Defaults here are tuned for testability.
DEFAULT_PROPOSAL_BLOCKS = 100         # ~5 days at 1s; here ~100s for tests
DEFAULT_EXPLORATION_BLOCKS = 100
DEFAULT_COOLDOWN_BLOCKS = 100
DEFAULT_ADOPTION_BLOCKS = 100
DEFAULT_ACTIVATION_BLOCKS = 100

DEFAULT_TREASURY_PROPOSAL_BLOCKS = 200
DEFAULT_TREASURY_VOTE_BLOCKS = 100

# Supermajority threshold (numerator/denominator) for protocol amendments.
PROTOCOL_SUPERMAJORITY_NUM = 4
PROTOCOL_SUPERMAJORITY_DEN = 5   # 80%

# Simple majority for treasury.
TREASURY_MAJORITY_NUM = 1
TREASURY_MAJORITY_DEN = 2   # 50%

# Minimum quorum: at least this fraction of stake must vote (yes+no, abstain
# doesn't count) for the result to be valid.
MIN_QUORUM_NUM = 1
MIN_QUORUM_DEN = 4   # 25%


# ---------------------------------------------------------------------------
# Vote-weight schemes (v0.8)
# ---------------------------------------------------------------------------

class WeightScheme(str, Enum):
    """How a voter's stake translates into voting weight.

    LINEAR: weight = stake. Used historically and for protocol amendments
    (where stake-aligned decision-making is appropriate).

    QUADRATIC: weight = isqrt(stake). Dampens the influence of large
    holders. Used by default for treasury votes — these are spending
    decisions where broader participation is more important than
    stake-weighted finality.
    """
    LINEAR = "linear"
    QUADRATIC = "quadratic"


def _isqrt(n: int) -> int:
    """Integer square root. Used for quadratic weighting on integer stakes."""
    if n < 0:
        return 0
    if n < 2:
        return n
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def vote_weight(stake: int, scheme: WeightScheme) -> int:
    """Translate a stake amount into a vote weight per the given scheme."""
    if scheme == WeightScheme.QUADRATIC:
        return _isqrt(stake)
    return stake


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

class ProtocolPhase(str, Enum):
    SUBMITTED = "submitted"
    EXPLORATION = "exploration"
    COOLDOWN = "cooldown"
    ADOPTION = "adoption"
    ACTIVATED = "activated"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class TreasuryPhase(str, Enum):
    SUBMITTED = "submitted"
    VOTING = "voting"
    EXECUTED = "executed"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class Vote(str, Enum):
    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"


# ---------------------------------------------------------------------------
# Payload schemas
# ---------------------------------------------------------------------------

# A protocol-amendment payload changes one or more named protocol parameters.
# The valid keys are governed at the protocol level; unknown keys are rejected.
#
#   {"params": {"i_max": 0.05, "block_time_seconds": 1.5}}
#
# Special payload: state-root-function swap (the v0.5 demo case).
#   {"swap": "state_root_function", "to": "trie"}
#
# Future versions will accept new payload kinds (e.g., Skald patch payloads).

KNOWN_PROTOCOL_PAYLOAD_KEYS = {"params", "swap", "to"}

# Allowed parameter names for the "params" payload.
ALLOWED_PARAMS = {
    "i_min", "i_max", "target_staking_ratio", "target_block_time_seconds",
    "treasury_share", "proposer_bonus",
    "block_time_seconds",
    # Optional L1 fee floor + block size cap (see kern.chain). Off unless
    # `fee_floor_enabled` is set. Changing these is a consensus rule change,
    # which is exactly why they live behind the governance whitelist.
    "fee_floor_enabled", "fee_floor_base", "fee_floor_per_byte", "max_block_bytes",
}

# Allowed swap targets.
ALLOWED_SWAPS = {"state_root_function": {"json", "trie"}}


def validate_protocol_payload(payload: dict) -> Optional[str]:
    """Return None if payload is well-formed, else an error string."""
    if not isinstance(payload, dict):
        return "payload must be a dict"
    keys = set(payload.keys())
    extra = keys - KNOWN_PROTOCOL_PAYLOAD_KEYS
    if extra:
        return f"unknown payload keys: {sorted(extra)}"
    if "params" in payload:
        params = payload["params"]
        if not isinstance(params, dict):
            return "'params' must be a dict"
        for k in params:
            if k not in ALLOWED_PARAMS:
                return f"unknown param: {k}"
    if "swap" in payload:
        target = payload["swap"]
        to = payload.get("to")
        if target not in ALLOWED_SWAPS:
            return f"unknown swap target: {target}"
        if to not in ALLOWED_SWAPS[target]:
            return f"unknown swap value '{to}' for {target}"
    return None


def validate_treasury_payload(payload: dict) -> Optional[str]:
    """A treasury payload says who receives how much KRN, with an optional
    memo. Multi-recipient batches are allowed."""
    if not isinstance(payload, dict):
        return "payload must be a dict"
    if "recipients" not in payload:
        return "missing 'recipients'"
    recipients = payload["recipients"]
    if not isinstance(recipients, list) or not recipients:
        return "'recipients' must be a non-empty list"
    for r in recipients:
        if not isinstance(r, dict):
            return "each recipient must be a dict"
        if "address" not in r or "amount" not in r:
            return "each recipient needs address+amount"
        if not isinstance(r["amount"], int) or r["amount"] <= 0:
            return "amount must be a positive int (mukrn)"
    return None


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------

@dataclass
class ProtocolProposal:
    """A protocol amendment proposal walking through the 5-phase cycle."""

    proposal_id: str               # hex
    submitter: str                 # kn1...
    payload: dict
    submitted_at_level: int
    phase: ProtocolPhase = ProtocolPhase.SUBMITTED
    # Voting tallies — keyed by phase ("exploration", "adoption").
    votes: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Phase transition history.
    phase_transitions: List[Tuple[str, int]] = field(default_factory=list)
    # v0.8: equivocations recorded for slashing. List of dicts:
    #   {"voter": addr, "phase": str, "first_vote": str, "second_vote": str,
    #    "first_level": int, "second_level": int}
    equivocations: List[dict] = field(default_factory=list)
    # Window parameters at submission time (locked in for this proposal).
    proposal_blocks: int = DEFAULT_PROPOSAL_BLOCKS
    exploration_blocks: int = DEFAULT_EXPLORATION_BLOCKS
    cooldown_blocks: int = DEFAULT_COOLDOWN_BLOCKS
    adoption_blocks: int = DEFAULT_ADOPTION_BLOCKS
    activation_blocks: int = DEFAULT_ACTIVATION_BLOCKS

    def __post_init__(self):
        if not self.phase_transitions:
            self.phase_transitions.append((self.phase.value, self.submitted_at_level))
        self.votes.setdefault("exploration", {})
        self.votes.setdefault("adoption", {})

    def to_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "submitter": self.submitter,
            "payload": self.payload,
            "submitted_at_level": self.submitted_at_level,
            "phase": self.phase.value,
            "votes": {k: dict(v) for k, v in self.votes.items()},
            "phase_transitions": list(self.phase_transitions),
            "equivocations": list(self.equivocations),
            "proposal_blocks": self.proposal_blocks,
            "exploration_blocks": self.exploration_blocks,
            "cooldown_blocks": self.cooldown_blocks,
            "adoption_blocks": self.adoption_blocks,
            "activation_blocks": self.activation_blocks,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolProposal":
        prop = cls(
            proposal_id=d["proposal_id"],
            submitter=d["submitter"],
            payload=d["payload"],
            submitted_at_level=d["submitted_at_level"],
            phase=ProtocolPhase(d["phase"]),
            proposal_blocks=d.get("proposal_blocks", DEFAULT_PROPOSAL_BLOCKS),
            exploration_blocks=d.get("exploration_blocks", DEFAULT_EXPLORATION_BLOCKS),
            cooldown_blocks=d.get("cooldown_blocks", DEFAULT_COOLDOWN_BLOCKS),
            adoption_blocks=d.get("adoption_blocks", DEFAULT_ADOPTION_BLOCKS),
            activation_blocks=d.get("activation_blocks", DEFAULT_ACTIVATION_BLOCKS),
        )
        # Restore mutable fields after __post_init__ defaults are set.
        prop.votes = {k: dict(v) for k, v in d.get("votes", {}).items()}
        prop.votes.setdefault("exploration", {})
        prop.votes.setdefault("adoption", {})
        prop.equivocations = list(d.get("equivocations", []))
        # phase_transitions is replaced rather than appended-to.
        if "phase_transitions" in d:
            prop.phase_transitions = list(d["phase_transitions"])
        return prop


@dataclass
class TreasuryProposal:
    """A treasury allocation proposal."""

    proposal_id: str
    submitter: str
    payload: dict
    submitted_at_level: int
    phase: TreasuryPhase = TreasuryPhase.SUBMITTED
    votes: Dict[str, str] = field(default_factory=dict)  # voter -> "yes"/"no"
    phase_transitions: List[Tuple[str, int]] = field(default_factory=list)
    proposal_blocks: int = DEFAULT_TREASURY_PROPOSAL_BLOCKS
    vote_blocks: int = DEFAULT_TREASURY_VOTE_BLOCKS

    def __post_init__(self):
        if not self.phase_transitions:
            self.phase_transitions.append((self.phase.value, self.submitted_at_level))

    def total_amount(self) -> int:
        return sum(r["amount"] for r in self.payload.get("recipients", []))

    def to_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "submitter": self.submitter,
            "payload": self.payload,
            "submitted_at_level": self.submitted_at_level,
            "phase": self.phase.value,
            "votes": dict(self.votes),
            "phase_transitions": list(self.phase_transitions),
            "proposal_blocks": self.proposal_blocks,
            "vote_blocks": self.vote_blocks,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TreasuryProposal":
        prop = cls(
            proposal_id=d["proposal_id"],
            submitter=d["submitter"],
            payload=d["payload"],
            submitted_at_level=d["submitted_at_level"],
            phase=TreasuryPhase(d["phase"]),
            proposal_blocks=d.get("proposal_blocks", DEFAULT_TREASURY_PROPOSAL_BLOCKS),
            vote_blocks=d.get("vote_blocks", DEFAULT_TREASURY_VOTE_BLOCKS),
        )
        prop.votes = dict(d.get("votes", {}))
        if "phase_transitions" in d:
            prop.phase_transitions = list(d["phase_transitions"])
        return prop


def proposal_id(submitter: str, payload: dict, salt: int = 0) -> str:
    """Deterministic proposal id: hash of submitter + canonical payload + salt."""
    d = {"submitter": submitter, "payload": payload, "salt": salt}
    blob = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.blake2b(blob, digest_size=16, key=b"kern.gov.id").hexdigest()


# ---------------------------------------------------------------------------
# Tally logic
# ---------------------------------------------------------------------------

def _tally(
    votes: Dict[str, str],
    validator_set: List[dict],
    *,
    scheme: WeightScheme = WeightScheme.LINEAR,
    delegations: Optional[Dict[str, str]] = None,
) -> Tuple[int, int, int, int]:
    """Return (yes_weight, no_weight, abstain_weight, total_weight).

    `scheme` controls how stake → weight (linear or quadratic).

    `delegations` maps {delegator_address: validator_address}. Delegated
    stake follows the validator's vote unless the delegator has cast their
    own (override). For v0.8 we model delegations as additive: a
    validator's effective stake = their own stake + their delegators'
    stake (minus any delegator that voted independently)."""
    delegations = delegations or {}

    # 1. Resolve effective stake per validator. Start with each validator's
    # raw stake, then add delegated stake.
    effective: Dict[str, int] = {v["address"]: v.get("stake", 0) for v in validator_set}
    delegated_by_validator: Dict[str, List[str]] = {}
    for delegator, val_addr in delegations.items():
        # Find the delegator's stake (treat unregistered as 0).
        d_stake = next((v.get("stake", 0) for v in validator_set
                        if v["address"] == delegator), 0)
        if val_addr in effective:
            effective[val_addr] += d_stake
            delegated_by_validator.setdefault(val_addr, []).append(delegator)

    # 2. Subtract delegators whose own vote overrides their delegation.
    for delegator, val_addr in delegations.items():
        if delegator in votes:  # delegator cast independent vote → opt out
            d_stake = next((v.get("stake", 0) for v in validator_set
                            if v["address"] == delegator), 0)
            if val_addr in effective:
                effective[val_addr] -= d_stake

    # 3. Tally votes, converting effective stake to weight via scheme.
    yes_w = no_w = abs_w = 0
    total_w = sum(vote_weight(s, scheme) for s in effective.values())

    for voter, vote in votes.items():
        # Look up effective stake (may be a validator or an independent delegator).
        if voter in effective:
            stake = effective[voter]
        else:
            # Independent voter (delegator who overrode): just use their own stake.
            stake = next((v.get("stake", 0) for v in validator_set
                          if v["address"] == voter), 0)
        w = vote_weight(stake, scheme)
        if vote == Vote.YES.value:
            yes_w += w
        elif vote == Vote.NO.value:
            no_w += w
        elif vote == Vote.ABSTAIN.value:
            abs_w += w

    return yes_w, no_w, abs_w, total_w


def _passes_supermajority(yes: int, no: int, total: int) -> bool:
    """Yes must be ≥ 80% of decisive votes (yes+no), AND quorum must be met."""
    decisive = yes + no
    # Quorum: at least 25% of total stake voted decisively.
    if decisive * MIN_QUORUM_DEN < total * MIN_QUORUM_NUM:
        return False
    return yes * PROTOCOL_SUPERMAJORITY_DEN >= decisive * PROTOCOL_SUPERMAJORITY_NUM


def _passes_majority(yes: int, no: int, total: int) -> bool:
    decisive = yes + no
    if decisive * MIN_QUORUM_DEN < total * MIN_QUORUM_NUM:
        return False
    # Strict majority: yes > 50% of decisive
    return yes * TREASURY_MAJORITY_DEN > decisive * TREASURY_MAJORITY_NUM


# ---------------------------------------------------------------------------
# ProtocolGovernance — the state machine wrapper
# ---------------------------------------------------------------------------

class ProtocolGovernance:
    """Manages active proposals for the protocol-amendment track."""

    def __init__(self, validator_set: List[dict]):
        self.validator_set = validator_set
        self.proposals: Dict[str, ProtocolProposal] = {}
        # Activated parameter changes accumulate here; the protocol can
        # call `effective_params(current_params)` to merge them in.
        self.activated_changes: List[dict] = []

    # ----- submission ------------------------------------------------------

    def submit(self, submitter: str, payload: dict, current_level: int,
               salt: int = 0) -> Tuple[bool, str, Optional[str]]:
        """Submit a new proposal. Returns (ok, reason, proposal_id)."""
        err = validate_protocol_payload(payload)
        if err:
            return False, f"invalid payload: {err}", None
        if not any(v["address"] == submitter for v in self.validator_set):
            return False, "submitter must be a registered validator", None
        pid = proposal_id(submitter, payload, salt)
        if pid in self.proposals:
            return False, "duplicate proposal", None
        prop = ProtocolProposal(
            proposal_id=pid, submitter=submitter, payload=payload,
            submitted_at_level=current_level,
        )
        self.proposals[pid] = prop
        return True, "ok", pid

    def withdraw(self, proposal_id: str, sender: str) -> Tuple[bool, str]:
        prop = self.proposals.get(proposal_id)
        if prop is None:
            return False, "no such proposal"
        if prop.submitter != sender:
            return False, "only submitter can withdraw"
        if prop.phase not in (ProtocolPhase.SUBMITTED,):
            return False, f"cannot withdraw in phase {prop.phase.value}"
        prop.phase = ProtocolPhase.WITHDRAWN
        prop.phase_transitions.append((prop.phase.value, prop.submitted_at_level))
        return True, "ok"

    # ----- voting ---------------------------------------------------------

    def vote(self, proposal_id: str, voter: str, vote: Vote,
             current_level: int) -> Tuple[bool, str]:
        prop = self.proposals.get(proposal_id)
        if prop is None:
            return False, "no such proposal"
        if prop.phase not in (ProtocolPhase.EXPLORATION, ProtocolPhase.ADOPTION):
            return False, f"voting not open in phase {prop.phase.value}"
        if not any(v["address"] == voter for v in self.validator_set):
            return False, "voter not in validator set"
        phase_key = prop.phase.value

        # v0.8: equivocation detection. If the voter has already cast a
        # vote in this phase, and the new vote differs, record it as
        # equivocation. The new vote is rejected (the original stands).
        # In a real BFT network the equivocation is detected from the
        # signed message history (two signed votes with different content
        # for the same proposal+phase) and used as slashing evidence.
        existing = prop.votes[phase_key].get(voter)
        if existing is not None and existing != vote.value:
            prop.equivocations.append({
                "voter": voter,
                "phase": phase_key,
                "first_vote": existing,
                "second_vote": vote.value,
                "second_at_level": current_level,
            })
            return False, "equivocation detected; original vote stands"

        prop.votes[phase_key][voter] = vote.value
        return True, "ok"

    # ----- cycle advancement ---------------------------------------------

    def advance_phases(self, current_level: int) -> List[Tuple[str, str]]:
        """Walk all proposals and advance them to the next phase if the
        current phase window has elapsed. Returns a list of
        (proposal_id, new_phase) transitions that just happened.

        Called by the chain at every block."""
        transitions: List[Tuple[str, str]] = []
        for prop in self.proposals.values():
            new_phase = self._next_phase(prop, current_level)
            if new_phase is not None and new_phase != prop.phase:
                prop.phase = new_phase
                prop.phase_transitions.append((new_phase.value, current_level))
                if new_phase == ProtocolPhase.ACTIVATED:
                    self.activated_changes.append(dict(prop.payload))
                transitions.append((prop.proposal_id, new_phase.value))
        return transitions

    def _next_phase(self, prop: ProtocolProposal,
                    current_level: int) -> Optional[ProtocolPhase]:
        """Compute the next phase for a proposal given the current level."""
        if prop.phase in (ProtocolPhase.ACTIVATED, ProtocolPhase.REJECTED,
                          ProtocolPhase.WITHDRAWN):
            return None  # terminal

        base = prop.submitted_at_level
        end_submitted = base + prop.proposal_blocks
        end_exploration = end_submitted + prop.exploration_blocks
        end_cooldown = end_exploration + prop.cooldown_blocks
        end_adoption = end_cooldown + prop.adoption_blocks
        end_activation = end_adoption + prop.activation_blocks

        if prop.phase == ProtocolPhase.SUBMITTED:
            if current_level >= end_submitted:
                return ProtocolPhase.EXPLORATION
        elif prop.phase == ProtocolPhase.EXPLORATION:
            if current_level >= end_exploration:
                yes, no, _abs, tot = _tally(prop.votes["exploration"], self.validator_set)
                if _passes_supermajority(yes, no, tot):
                    return ProtocolPhase.COOLDOWN
                return ProtocolPhase.REJECTED
        elif prop.phase == ProtocolPhase.COOLDOWN:
            if current_level >= end_cooldown:
                return ProtocolPhase.ADOPTION
        elif prop.phase == ProtocolPhase.ADOPTION:
            if current_level >= end_adoption:
                yes, no, _abs, tot = _tally(prop.votes["adoption"], self.validator_set)
                if _passes_supermajority(yes, no, tot):
                    return ProtocolPhase.ACTIVATED
                return ProtocolPhase.REJECTED
        # ACTIVATED is terminal; no further transitions needed.
        return None

    # ----- effective parameters ------------------------------------------

    def effective_params(self, current: dict) -> dict:
        """Apply all activated param changes to `current`. Later changes
        override earlier ones (last-write-wins)."""
        merged = dict(current)
        for change in self.activated_changes:
            if "params" in change:
                merged.update(change["params"])
        return merged

    def active_swap(self, target: str) -> Optional[str]:
        """Return the most recent activated value for `target` (e.g.,
        'state_root_function'), or None if no swap has activated."""
        result: Optional[str] = None
        for change in self.activated_changes:
            if change.get("swap") == target:
                result = change.get("to")
        return result


# ---------------------------------------------------------------------------
# TreasuryGovernance — the state machine for treasury allocations
# ---------------------------------------------------------------------------

class TreasuryGovernance:
    """Manages treasury-allocation proposals. Independent of protocol
    amendments — different cycle, different threshold, different effect.

    v0.8: defaults to QUADRATIC weight scheme for vote tallying, to
    reduce large-holder dominance on spending decisions. Supports
    delegations: a non-validator can delegate their stake to a validator
    via `set_delegation`; their stake then follows the validator's vote
    unless they cast their own."""

    def __init__(
        self,
        validator_set: List[dict],
        treasury_balance: int = 0,
        *,
        scheme: WeightScheme = WeightScheme.QUADRATIC,
        delegations: Optional[Dict[str, str]] = None,
    ):
        self.validator_set = validator_set
        self.treasury_balance = treasury_balance
        self.scheme = scheme
        self.delegations: Dict[str, str] = dict(delegations or {})
        self.proposals: Dict[str, TreasuryProposal] = {}
        # Executed payouts: each entry is {"recipients": [...], "block": N}
        self.executions: List[dict] = []

    def set_delegation(self, delegator: str, validator: str) -> Tuple[bool, str]:
        """Delegate a non-validator's stake to a validator. v0.8."""
        if not any(v["address"] == validator for v in self.validator_set):
            return False, "delegate target is not a validator"
        self.delegations[delegator] = validator
        return True, "ok"

    def clear_delegation(self, delegator: str) -> Tuple[bool, str]:
        if delegator in self.delegations:
            del self.delegations[delegator]
            return True, "ok"
        return False, "no delegation to clear"

    def set_validators(self, validators: List[dict]) -> None:
        """Validators may change between cycles; update the set."""
        self.validator_set = validators

    def set_balance(self, balance: int) -> None:
        self.treasury_balance = balance

    def submit(self, submitter: str, payload: dict, current_level: int,
               salt: int = 0) -> Tuple[bool, str, Optional[str]]:
        err = validate_treasury_payload(payload)
        if err:
            return False, f"invalid payload: {err}", None
        # Treasury proposals are open to anyone (not just validators) —
        # voting is still restricted to validators.
        pid = proposal_id(submitter, payload, salt)
        if pid in self.proposals:
            return False, "duplicate proposal", None
        # Sanity: the requested total must not exceed the current treasury
        # balance at submission time (it might exceed by execution time if
        # other proposals have spent in the meantime — caught at execute).
        total = sum(r["amount"] for r in payload["recipients"])
        if total > self.treasury_balance:
            return False, f"requested {total} > treasury balance {self.treasury_balance}", None
        prop = TreasuryProposal(
            proposal_id=pid, submitter=submitter, payload=payload,
            submitted_at_level=current_level,
        )
        self.proposals[pid] = prop
        return True, "ok", pid

    def withdraw(self, proposal_id: str, sender: str) -> Tuple[bool, str]:
        prop = self.proposals.get(proposal_id)
        if prop is None:
            return False, "no such proposal"
        if prop.submitter != sender:
            return False, "only submitter can withdraw"
        if prop.phase != TreasuryPhase.SUBMITTED:
            return False, f"cannot withdraw in phase {prop.phase.value}"
        prop.phase = TreasuryPhase.WITHDRAWN
        prop.phase_transitions.append((prop.phase.value, prop.submitted_at_level))
        return True, "ok"

    def vote(self, proposal_id: str, voter: str, vote: Vote,
             current_level: int) -> Tuple[bool, str]:
        prop = self.proposals.get(proposal_id)
        if prop is None:
            return False, "no such proposal"
        if prop.phase != TreasuryPhase.VOTING:
            return False, f"voting not open in phase {prop.phase.value}"
        if not any(v["address"] == voter for v in self.validator_set):
            return False, "voter not in validator set"
        prop.votes[voter] = vote.value
        return True, "ok"

    def advance_phases(self, current_level: int) -> List[Tuple[str, str]]:
        """Advance proposals. May trigger payouts (in EXECUTED transitions),
        which deduct from `self.treasury_balance`."""
        transitions: List[Tuple[str, str]] = []
        for prop in self.proposals.values():
            new_phase = self._next_phase(prop, current_level)
            if new_phase is None or new_phase == prop.phase:
                continue
            # If transitioning to EXECUTED, ensure treasury still has funds.
            if new_phase == TreasuryPhase.EXECUTED:
                total = prop.total_amount()
                if self.treasury_balance < total:
                    new_phase = TreasuryPhase.REJECTED
                else:
                    self.treasury_balance -= total
                    self.executions.append({
                        "proposal_id": prop.proposal_id,
                        "recipients": list(prop.payload["recipients"]),
                        "block": current_level,
                    })
            prop.phase = new_phase
            prop.phase_transitions.append((new_phase.value, current_level))
            transitions.append((prop.proposal_id, new_phase.value))
        return transitions

    def _next_phase(self, prop: TreasuryProposal,
                    current_level: int) -> Optional[TreasuryPhase]:
        if prop.phase in (TreasuryPhase.EXECUTED, TreasuryPhase.REJECTED,
                          TreasuryPhase.WITHDRAWN):
            return None
        base = prop.submitted_at_level
        end_submitted = base + prop.proposal_blocks
        end_voting = end_submitted + prop.vote_blocks

        if prop.phase == TreasuryPhase.SUBMITTED:
            if current_level >= end_submitted:
                return TreasuryPhase.VOTING
        elif prop.phase == TreasuryPhase.VOTING:
            if current_level >= end_voting:
                yes, no, _abs, tot = _tally(
                    prop.votes, self.validator_set,
                    scheme=self.scheme, delegations=self.delegations,
                )
                if _passes_majority(yes, no, tot):
                    return TreasuryPhase.EXECUTED
                return TreasuryPhase.REJECTED
        return None


# ---------------------------------------------------------------------------
# Skald contract templates
# ---------------------------------------------------------------------------

PROTOCOL_GOVERNANCE_SKALD = """
// protocol_governance.skald — on-chain protocol amendment registry.
//
// The full state machine lives in kern.governance (the L1 runtime).
// This contract is the canonical anchor for tallies and activated
// changes; on-chain explorers and clients read from it.

contract ProtocolGovernance {
    storage {
        cycle_length_blocks: int,
        supermajority_num: int,
        supermajority_den: int,
        quorum_num: int,
        quorum_den: int,
        activated_count: int,
    }

    invariant valid_threshold {
        supermajority_num <= supermajority_den
    }

    invariant valid_quorum {
        quorum_num <= quorum_den
    }

    invariant nonneg_count {
        activated_count >= 0
    }

    entry record_activation() {
        activated_count = activated_count + 1;
    }

    view total_activations() -> int {
        activated_count
    }
}
"""


TREASURY_GOVERNANCE_SKALD = """
// treasury.skald — on-chain treasury contract.
//
// Holds the protocol treasury balance; releases funds only via the
// governance state machine (which calls `release` after a proposal
// reaches EXECUTED).

contract Treasury {
    storage {
        governance: address,
        balance: int,
        total_released: int,
        execution_count: int,
    }

    invariant solvent {
        balance >= 0
    }

    invariant nonneg_release {
        total_released >= 0
    }

    entry deposit() {
        require amount > 0 with "must attach amount";
        balance = balance + amount;
    }

    entry release(n: int) {
        require sender == governance with "only governance";
        require n > 0 with "amount must be positive";
        require balance >= n with "insufficient treasury balance";
        balance = balance - n;
        total_released = total_released + n;
        execution_count = execution_count + 1;
    }

    view available() -> int {
        balance
    }
}
"""


def get_protocol_governance_skald() -> str:
    return PROTOCOL_GOVERNANCE_SKALD


def get_treasury_skald() -> str:
    return TREASURY_GOVERNANCE_SKALD


# ---------------------------------------------------------------------------
# Proposal bonds — anti-spam economics
# ---------------------------------------------------------------------------

# Submitting a proposal requires posting a bond. The bond is:
# - refunded if the proposal reaches ACTIVATED (protocol) or EXECUTED (treasury)
# - refunded if the proposal is WITHDRAWN before voting starts
# - burned (50%) and paid to treasury (50%) if the proposal is REJECTED
#
# Bonds are amounts in mukrn. Defaults are tuned for v0.6 testability.

DEFAULT_PROTOCOL_BOND = 100_000_000        # 100 KRN
DEFAULT_TREASURY_BOND = 10_000_000         # 10 KRN

BOND_BURN_PCT = 50
BOND_TREASURY_PCT = 50  # remainder of the lost bond goes to treasury


@dataclass
class BondOutcome:
    """The fate of a proposal bond when its proposal terminates."""

    refund_to_submitter: int = 0
    burn: int = 0
    to_treasury: int = 0

    @property
    def total(self) -> int:
        return self.refund_to_submitter + self.burn + self.to_treasury


def resolve_bond(bond: int, terminal_phase: str, was_decided_by_vote: bool) -> BondOutcome:
    """Compute how the bond should be split based on the proposal's
    terminal phase.

    - ACTIVATED / EXECUTED → full refund
    - WITHDRAWN → full refund (only allowed before voting starts)
    - REJECTED by a vote → burn 50%, to treasury 50%
    - REJECTED without a vote (e.g., quorum failure on a one-sided vote) →
      treat as a vote-decided rejection: same as above. The bond is still
      lost. This prevents griefing via low-stakes spam.
    """
    if terminal_phase in ("activated", "executed", "withdrawn"):
        return BondOutcome(refund_to_submitter=bond)
    # REJECTED
    burn = bond * BOND_BURN_PCT // 100
    to_treasury = bond - burn
    return BondOutcome(burn=burn, to_treasury=to_treasury)


# ---------------------------------------------------------------------------
# State-dict round-tripping
# ---------------------------------------------------------------------------

def empty_governance_state() -> dict:
    """The initial governance state to embed in a chain state dict."""
    return {
        "protocol": {
            "proposals": {},          # proposal_id -> serialized ProtocolProposal
            "activated_changes": [],  # list of dicts
            "bonds": {},              # proposal_id -> {"submitter": addr, "amount": int}
        },
        "treasury": {
            "proposals": {},
            "executions": [],
            "bonds": {},
        },
    }


def load_protocol_governance(gov_state: dict, validator_set: list) -> ProtocolGovernance:
    """Rebuild a ProtocolGovernance from its serialized state."""
    gov = ProtocolGovernance(validator_set)
    proto = gov_state.get("protocol", {})
    gov.activated_changes = list(proto.get("activated_changes", []))
    for pid, d in proto.get("proposals", {}).items():
        gov.proposals[pid] = ProtocolProposal.from_dict(d)
    return gov


def save_protocol_governance(gov_state: dict, gov: ProtocolGovernance) -> None:
    """Write a ProtocolGovernance back into the state dict."""
    proto = gov_state.setdefault("protocol", {})
    proto["proposals"] = {pid: p.to_dict() for pid, p in gov.proposals.items()}
    proto["activated_changes"] = list(gov.activated_changes)


def load_treasury_governance(gov_state: dict, validator_set: list,
                              balance: int) -> TreasuryGovernance:
    treas = gov_state.get("treasury", {})
    # Read scheme + delegations from state dict, default to quadratic.
    scheme_str = treas.get("scheme", WeightScheme.QUADRATIC.value)
    scheme = WeightScheme(scheme_str)
    delegations = dict(treas.get("delegations", {}))
    gov = TreasuryGovernance(
        validator_set, treasury_balance=balance,
        scheme=scheme, delegations=delegations,
    )
    gov.executions = list(treas.get("executions", []))
    for pid, d in treas.get("proposals", {}).items():
        gov.proposals[pid] = TreasuryProposal.from_dict(d)
    return gov


def save_treasury_governance(gov_state: dict, gov: TreasuryGovernance) -> None:
    treas = gov_state.setdefault("treasury", {})
    treas["proposals"] = {pid: p.to_dict() for pid, p in gov.proposals.items()}
    treas["executions"] = list(gov.executions)
    treas["scheme"] = gov.scheme.value
    treas["delegations"] = dict(gov.delegations)
