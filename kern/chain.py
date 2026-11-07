# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.chain
----------

The chain state machine: balances, nonces, originated contracts, and the
rules for applying a block to advance the ledger.

State layout
============

state = {
    "balances":   { kn1...: int },          # in mukrn
    "nonces":     { kn1...: int },          # last applied nonce
    "contracts":  { kn1...: {               # originated contracts
                       "code": str,
                       "storage": Any,
                   } },
    "validators": [ {                       # active validator set
                       "address": str,
                       "pubkey": str,
                       "stake": int,
                   } ],
}

State root commitment
=====================

The state root is the blake2b-256 hash of the canonical JSON serialization
of the state dict. This is not a Merkle-Patricia trie (a planned upgrade),
but it commits to the same set of state slots and lets headers be verified
against the produced state.
"""

from __future__ import annotations

import hashlib
import json
import copy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .block import Block, BlockHeader, txs_merkle_root_hex
from .crypto import blake2b256
from .transaction import OpKind, Transaction
from .skald import interpret_origination, interpret_call, SkaldError


MUKRN_PER_KRN = 1_000_000


@dataclass
class ApplyResult:
    """Outcome of applying a single transaction."""
    ok: bool
    gas_used: int = 0
    error: Optional[str] = None
    new_contract: Optional[str] = None
    # v1.0-rc: free-form extras (e.g., slashing breakdown)
    extra: Optional[dict] = None


def state_root_hex(state: dict) -> str:
    """Commit to the entire state with a single hash.

    The function used is governance-controlled. By default ('json' mode),
    we hash the canonical JSON of the state. After a successful
    `swap state_root_function → trie` governance amendment, the state
    encodes `state_root_function: "trie"` and we dispatch to the binary
    Merkle trie implementation in `kern.trie`, which produces a different
    commitment scheme that also supports light-client proofs.

    The active mode is read from `state["state_root_function"]` (a key
    that the governance activation sets). Absent → JSON for backward
    compatibility with v0.1-v0.4 genesis files.
    """
    mode = state.get("state_root_function", "json")
    if mode == "trie":
        from .trie import state_root_trie_hex
        return state_root_trie_hex(state)
    # Default: JSON hash. We exclude the mode key from the hashed payload
    # so that the absence/presence of the key doesn't itself change the
    # root in a confusing way; the mode is implicit in the function used.
    payload = {k: v for k, v in state.items() if k != "state_root_function"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return blake2b256(canonical, key=b"kern.state").hex()


def empty_state() -> dict:
    return {
        "balances": {},
        "nonces": {},
        "contracts": {},
        "validators": [],
        # v0.4 additions: total supply tracking and treasury account.
        "total_supply": 0,
        "treasury_address": None,
        # Optional issuance parameters; absent means "use defaults".
        "issuance_params": None,
        # v0.5: which state-root function is active. "json" by default;
        # governance can swap to "trie" via a protocol amendment.
        "state_root_function": "json",
        # v0.6: on-chain governance state. Two parallel tracks (protocol
        # amendments + treasury allocations). See kern/governance.py.
        "governance": {
            "protocol": {"proposals": {}, "activated_changes": [], "bonds": {}},
            "treasury": {"proposals": {}, "executions": [], "bonds": {}},
        },
        # v1.0-rc: Liquid PoS baking delegation. Maps delegator address
        # to validator address. Delegators retain custody of their KRN;
        # the delegation just lets the validator count the balance toward
        # their effective stake at reward time. See kern.issuance.
        "delegations": {},
        # Per-validator commission rate (percent). Defaults to
        # DEFAULT_COMMISSION_PCT if not set. Validators can update via
        # the SET_COMMISSION transaction (future). Maps address -> int %.
        "commission_rates": {},
        # v1.1-rc: slashable attestation registry. See kern.attestation.
        # attestations: attestation_id -> attestation record (dict)
        # attestations_by_subject: (issuer|schema|subject) -> [ids]
        "attestations": {},
        "attestations_by_subject": {},
    }


def initial_state_from_genesis(genesis: dict) -> dict:
    """Build the genesis state from a genesis.json dict."""
    state = empty_state()
    for addr, balance in genesis.get("balances", {}).items():
        state["balances"][addr] = int(balance)
    state["validators"] = [dict(v) for v in genesis.get("validators", [])]
    # Total supply at genesis = sum of all pre-funded balances.
    state["total_supply"] = sum(state["balances"].values())
    # Phase D: a validator's own stake is BONDED out of its balance. It
    # used to be a number declared next to an equal, fully spendable
    # balance, i.e. consensus weight with no collateral behind it.
    # total_supply is unchanged: the stake is still part of the supply.
    for v in state["validators"]:
        stake = int(v.get("stake", 0))
        bal = state["balances"].get(v["address"], 0)
        if bal < stake:
            raise ValueError(
                f"genesis validator {v['address']} declares stake {stake} "
                f"but only has a balance of {bal} to bond it from"
            )
        state["balances"][v["address"]] = bal - stake
    # Phase B (audit 1, finding 8): a declared total_supply must match the
    # balances it claims to sum. A genesis file whose two numbers disagree
    # is refused instead of being silently corrected.
    declared = genesis.get("total_supply")
    if declared is not None and int(declared) != state["total_supply"]:
        raise ValueError(
            f"genesis total_supply {declared} does not equal the sum of "
            f"genesis balances {state['total_supply']}"
        )
    # Phase B (audit 1, finding 9): the network identifier becomes part of
    # consensus state, and every transaction must be signed for it.
    chain_id = genesis.get("chain_id")
    if chain_id is not None and not isinstance(chain_id, str):
        raise ValueError("genesis chain_id must be a string")
    state["chain_id"] = chain_id
    # Phase C: optional epoch length, then the first consensus snapshot.
    for key in ("epoch_blocks", "delegation_unbonding_blocks", "attestation_unbonding_blocks"):
        if genesis.get(key) is not None:
            state[key] = int(genesis[key])
    # Phase D: bonded funds must stay slashable for at least as long as
    # they can weigh in a consensus snapshot (one epoch), and slashing
    # evidence is accepted for the unbonding period.
    if delegation_unbonding_blocks(state) < epoch_blocks(state):
        raise ValueError("delegation_unbonding_blocks must be >= epoch_blocks")
    state["consensus_set"] = compute_consensus_set(state)
    state["treasury_address"] = genesis.get("treasury_address")
    state["issuance_params"] = genesis.get("issuance_params")
    return state


# --- Address derivation for originated contracts --------------------------

def derive_contract_address(origination_tx_hash: bytes) -> str:
    """Originated contract address: blake2b-160 of the origination tx hash,
    base58check encoded with the 'kn1' prefix. Same address space as user
    accounts — Kern has no EOA/contract distinction at the protocol layer
    (account abstraction is native)."""
    from .crypto import b58check_encode, PREFIX_ADDRESS
    h = hashlib.blake2b(origination_tx_hash, digest_size=20, key=b"kern.addr").digest()
    return b58check_encode(PREFIX_ADDRESS, h)


# --- Transaction application ----------------------------------------------

def _check_signature_and_nonce(tx: Transaction, state: dict) -> Optional[str]:
    if not tx.verify_signature():
        return "invalid signature"
    # Phase B (audit 1, finding 9): cross-network replay protection. The
    # signature already covers chain_id; the state machine now enforces
    # it. A chain whose state carries a chain_id accepts only transactions
    # signed for exactly that chain_id (a null chain_id is refused). Test
    # chains built without a chain_id keep accepting null.
    expected_chain = state.get("chain_id")
    if expected_chain is not None and tx.chain_id != expected_chain:
        return f"wrong chain_id: expected {expected_chain!r}, got {tx.chain_id!r}"
    expected_nonce = state["nonces"].get(tx.sender, 0)
    if tx.nonce != expected_nonce:
        return f"bad nonce: expected {expected_nonce}, got {tx.nonce}"
    return None


def _debit_fee(tx: Transaction, state: dict) -> Optional[str]:
    bal = state["balances"].get(tx.sender, 0)
    if bal < tx.fee:
        return f"insufficient balance for fee: have {bal}, need {tx.fee}"
    state["balances"][tx.sender] = bal - tx.fee
    return None


def _credit(state: dict, addr: str, amount: int) -> None:
    state["balances"][addr] = state["balances"].get(addr, 0) + amount


def _debit(state: dict, addr: str, amount: int) -> Optional[str]:
    bal = state["balances"].get(addr, 0)
    if bal < amount:
        return f"insufficient balance: have {bal}, need {amount}"
    state["balances"][addr] = bal - amount
    return None


def apply_transaction(state: dict, tx: Transaction, baker: str) -> ApplyResult:
    """Apply a single transaction to `state` (mutates in place).

    Fees flow to the baker. Any operation that can mutate state and *then*
    fail is wrapped in a snapshot/rollback so partial application cannot
    corrupt the ledger.

    Snapshot strategy (performance + correctness):
    - Signature, nonce, and fee checks happen *before* any mutation, so they
      need no snapshot. A spam transaction with a bad signature or nonce
      therefore costs no deep copy at all.
    - `TRANSFER` debits the sender via `_debit`, which checks the balance
      *before* mutating; it cannot leave partial state, so the hot path takes
      no snapshot either. (Fee is still retained on a failed transfer, by
      design, to deter spam — matching the previous behaviour.)
    - Every remaining op (`ORIGINATE`, `CALL`, governance, slashing,
      delegation, attestation) may mutate and then raise — notably `CALL`,
      which moves value to the callee before running contract logic that can
      revert. Those take a deep-copy snapshot, taken *after* the fee debit and
      nonce bump so that a rollback naturally retains the fee and nonce without
      having to re-apply them.

    `gas_used` values are unchanged from prior releases and do not affect the
    state root (there is no receipts trie); only `state` is consensus-relevant.
    """
    # --- Pre-mutation validation: nothing has changed yet, no snapshot needed.
    err = _check_signature_and_nonce(tx, state)
    if err:
        return ApplyResult(ok=False, error=err)

    err = _debit_fee(tx, state)  # mutates only on success
    if err:
        return ApplyResult(ok=False, error=err)

    # Fee goes to baker; bump nonce now that the fee is paid.
    _credit(state, baker, tx.fee)
    state["nonces"][tx.sender] = tx.nonce + 1

    # --- Structural checks per kind. These run AFTER the fee debit and nonce
    # bump on purpose: a malformed operation that was correctly signed pays
    # its fee like any other failed operation, so it cannot be replayed
    # for free (Phase B, audit 1 finding 7). They replace the former
    # `assert` statements, which crashed block production instead of
    # rejecting the transaction.
    malformed = _malformed_reason(tx)
    if malformed is not None:
        return ApplyResult(ok=False, error=f"malformed transaction: {malformed}",
                           gas_used=tx.gas_limit)

    # --- Hot path: TRANSFER cannot leave partial state -> no snapshot.
    if tx.kind == OpKind.TRANSFER:
        assert tx.recipient is not None  # guaranteed by _malformed_reason
        err = _debit(state, tx.sender, tx.amount)
        if err:
            # Fee retained, nonce bumped (anti-spam); no partial state to undo.
            return ApplyResult(ok=False, error=err, gas_used=tx.gas_limit)
        _credit(state, tx.recipient, tx.amount)
        return ApplyResult(ok=True, gas_used=1000)

    # --- All other ops may mutate then fail -> snapshot for atomic rollback.
    snapshot = copy.deepcopy(state)
    try:
        if tx.kind == OpKind.ORIGINATE:
            assert tx.code is not None  # guaranteed by _malformed_reason
            contract_addr = derive_contract_address(tx.hash())
            # Validate and "compile" the Skald source.
            storage = interpret_origination(tx.code, tx.initial_storage)
            state["contracts"][contract_addr] = {
                "code": tx.code,
                "storage": storage,
            }
            return ApplyResult(ok=True, gas_used=10_000, new_contract=contract_addr)

        if tx.kind == OpKind.CALL:
            assert tx.recipient is not None and tx.entry is not None  # see _malformed_reason
            contract = state["contracts"].get(tx.recipient)
            if contract is None:
                raise RuntimeError(f"contract {tx.recipient} not found")

            # Attach any value sent with the call.
            if tx.amount > 0:
                err = _debit(state, tx.sender, tx.amount)
                if err:
                    raise RuntimeError(err)
                _credit(state, tx.recipient, tx.amount)

            new_storage = interpret_call(
                contract["code"],
                contract["storage"],
                tx.entry,
                tx.params,
                sender=tx.sender,
                amount=tx.amount,
                self_addr=tx.recipient,
            )
            contract["storage"] = new_storage
            return ApplyResult(ok=True, gas_used=20_000)

        if tx.kind == OpKind.GOVERNANCE_PROPOSE:
            return _apply_governance_propose(state, tx)

        if tx.kind == OpKind.GOVERNANCE_VOTE:
            return _apply_governance_vote(state, tx)

        if tx.kind == OpKind.SLASH_EQUIVOCATION:
            return _apply_slash_equivocation(state, tx)

        if tx.kind == OpKind.DELEGATE_STAKE:
            return _apply_delegate_stake(state, tx)

        if tx.kind == OpKind.UNDELEGATE_STAKE:
            return _apply_undelegate_stake(state, tx)

        if tx.kind == OpKind.ATTEST:
            return _apply_attest(state, tx)

        if tx.kind == OpKind.REVOKE_ATTESTATION:
            return _apply_revoke_attestation(state, tx)

        if tx.kind == OpKind.SLASH_ATTESTATION_EQUIVOCATION:
            return _apply_slash_attestation_equivocation(state, tx)

        if tx.kind == OpKind.SLASH_CONSENSUS_EQUIVOCATION:
            return _apply_slash_consensus_equivocation(state, tx)

    except Exception as e:
        # Roll back to the post-fee/post-nonce snapshot: the operation is
        # undone but the fee stays debited and the nonce stays bumped.
        #
        # Phase B (audit 1, finding 7): this used to catch only RuntimeError
        # and SkaldError. Any other exception raised by a handler (TypeError,
        # AttributeError, KeyError, ValueError, ...) escaped into
        # propose_block / apply_block and halted block production on every
        # baker that saw the transaction. Every exception is now a
        # deterministic rejection. The error string records the exception
        # class, not only its message, so receipts stay informative.
        state.clear()
        state.update(snapshot)
        if isinstance(e, (RuntimeError, SkaldError)):
            msg = str(e)
        else:
            msg = f"{type(e).__name__}: {e}"
        return ApplyResult(ok=False, error=msg, gas_used=tx.gas_limit)

    return ApplyResult(ok=False, error="unknown op kind")


# Operation kinds whose `params` must be a JSON object (or absent). CALL is
# excluded: its params are an arbitrary Skald value passed to the entry point.
_DICT_PARAM_KINDS = frozenset({
    OpKind.GOVERNANCE_PROPOSE, OpKind.GOVERNANCE_VOTE, OpKind.SLASH_EQUIVOCATION,
    OpKind.DELEGATE_STAKE, OpKind.UNDELEGATE_STAKE, OpKind.ATTEST,
    OpKind.REVOKE_ATTESTATION, OpKind.SLASH_ATTESTATION_EQUIVOCATION,
    OpKind.SLASH_CONSENSUS_EQUIVOCATION,
})


def _malformed_reason(tx: Transaction) -> Optional[str]:
    """Return why `tx` is structurally unusable for its kind, or None.

    Pure and deterministic. Field TYPES are already enforced by
    Transaction.__post_init__; this checks the kind-specific presence rules
    that the handlers rely on."""
    if tx.kind in (OpKind.TRANSFER, OpKind.CALL) and not tx.recipient:
        return f"{tx.kind.value} requires a recipient"
    if tx.kind == OpKind.CALL and not tx.entry:
        return "call requires an entry point"
    if tx.kind == OpKind.ORIGINATE and not tx.code:
        return "originate requires code"
    if tx.kind in _DICT_PARAM_KINDS and tx.params is not None and not isinstance(tx.params, dict):
        return f"{tx.kind.value} params must be a JSON object"
    return None


# --- Block application ----------------------------------------------------

def _compute_staked(state: dict) -> int:
    """Total effective stake, the basis for the staking ratio.

    Phase B (audit 1, finding 4): this used to sum validator self-stake
    only, while rewards and slashing already counted delegated liquid
    balances (effective_stake). The emission curve therefore saw a lower
    staking ratio than the one actually at work and over-issued. It now
    uses the same effective stake as rewards and governance."""
    return sum(effective_stake(state, v["address"]) for v in state.get("validators", []))


def _governance_validator_set(state: dict) -> List[dict]:
    """The validator set as governance must weigh it: same addresses and
    order as state["validators"], with `stake` replaced by the effective
    stake (own stake plus bonded delegations, Phase D).

    Phase B (audit 1, findings 5 and 6): there used to be three views of
    delegation (state["delegations"] for rewards, a separate copy inside
    the treasury governance state, and none at all on the protocol track),
    and a delegator outside the validator set weighed zero. The canonical
    record is now state["delegations"], applied identically to both
    governance tracks through this function. Returns copies; the state's
    own validator records are never mutated."""
    out = []
    for v in state.get("validators", []):
        w = dict(v)
        w["stake"] = effective_stake(state, v["address"])
        out.append(w)
    return out


def _apply_block_rewards(state: dict, block: Block) -> None:
    """Credit per-block issuance rewards: treasury share + per-validator
    distribution. Updates total_supply. Mutates state in place.

    Skipped at level 0 (genesis); only validators present at the time of
    the block are eligible (which matches reality — you can't be rewarded
    for a block before you joined the validator set)."""
    if block.header.level == 0:
        return

    from .issuance import IssuanceParams, compute_block_rewards

    # Build IssuanceParams from state, or use defaults.
    p_dict = state.get("issuance_params")
    if p_dict:
        params = IssuanceParams.from_dict(p_dict)
    else:
        params = IssuanceParams()

    validators = state.get("validators", [])
    if not validators:
        return  # no validators → no rewards

    # Rewarded endorsers = the proposer only.
    #
    # Phase B (audit 2, point 4): rewards used to be keyed on the addresses
    # listed in `block.commits`, read WITHOUT checking their signatures
    # (signatures are only checked by the quorum step, which runs after the
    # state root comparison and is skipped when require_quorum=False). A
    # relay could therefore add or drop commit entries and change the
    # reward split. Commits sign the final header hash, which commits to the
    # post-reward state root, so a block's own commits cannot feed its own
    # rewards without circularity anyway. Until parent-based endorsement
    # accounting lands (see docs/consensus-wire.md, limitations), the
    # proposer is the sole rewarded endorser, which is what the proposer's
    # placeholder self-commit already produced in practice.
    committing_addrs = {block.header.proposer}

    endorsers = [v for v in validators if v["address"] in committing_addrs]
    if not endorsers:
        return

    treasury_addr = state.get("treasury_address")
    total_supply = state.get("total_supply", 0)
    staked = _compute_staked(state)

    acc = compute_block_rewards(
        total_supply=total_supply,
        staked=staked,
        proposer_addr=block.header.proposer,
        endorsers=endorsers,
        treasury_addr=treasury_addr or "kn1" + "0" * 33,
        params=params,
    )

    # Credit treasury (if address is configured).
    if treasury_addr and acc.treasury_credit > 0:
        _credit(state, treasury_addr, acc.treasury_credit)

    # Credit each validator — but first split their share with delegators
    # (v1.0-rc: Liquid PoS baking delegation). Validators keep a commission
    # and pro-rata share of their own stake; delegators receive the rest in
    # proportion to their delegated balances. If a validator has no
    # delegators, they keep their full share (backward-compatible).
    from .issuance import split_validator_reward
    for addr, amt in acc.per_validator.items():
        if amt <= 0:
            continue
        # Find this validator's own_stake.
        own_stake = 0
        for v in validators:
            if v["address"] == addr:
                own_stake = v.get("stake", 0)
                break
        # Snapshot delegators at this block (balance at this point in time).
        dels = delegators_of(state, addr)
        if not dels:
            _credit(state, addr, amt)   # no delegators → keep all
            continue
        commission_pct = commission_rate_of(state, addr)
        val_share, del_shares = split_validator_reward(
            reward=amt,
            own_stake=own_stake,
            delegators=dels,
            commission_pct=commission_pct,
        )
        _credit(state, addr, val_share)
        for del_addr, del_amt in del_shares.items():
            _credit(state, del_addr, del_amt)

    # Update total_supply.
    state["total_supply"] = acc.total_supply_after


# --- Governance transaction handlers --------------------------------------

# --- Consensus validator set (Phase C) -------------------------------------

# Length of a consensus epoch, in blocks. The validator set the consensus
# uses (proposer selection, vote weights, quorum and block validation) is a
# snapshot of EFFECTIVE stake (own stake after slashing + bonded
# delegations) taken at each epoch boundary. A new delegation therefore adds
# weight only at the next boundary, so nobody can shift weight into a
# validator just before a vote. Slashing and undelegation lower weight at
# once (Phase E); inside an epoch weight never goes up.
# A chain may override it at genesis through state["epoch_blocks"].
DEFAULT_EPOCH_BLOCKS = 120


def epoch_blocks(state: dict) -> int:
    v = state.get("epoch_blocks")
    if isinstance(v, int) and not isinstance(v, bool) and v > 0:
        return v
    return DEFAULT_EPOCH_BLOCKS


def compute_consensus_set(state: dict) -> List[dict]:
    """Effective validator set from the current state: same order as
    state["validators"], each with address, pubkey and `stake` replaced by
    effective_stake. Pure."""
    return [
        {"address": v["address"], "pubkey": v.get("pubkey", ""),
         "stake": effective_stake(state, v["address"])}
        for v in state.get("validators", [])
    ]


def consensus_validator_set(state: dict) -> List[dict]:
    """THE validator set for consensus on top of `state` (Phase C, review
    point B). Uses the epoch snapshot state["consensus_set"]; a state built
    without one (older test fixtures) falls back to the plain validator
    records. Returns copies."""
    snap = state.get("consensus_set")
    if snap is not None:
        return [dict(v) for v in snap]
    return [dict(v) for v in state.get("validators", [])]


def _epoch_tick(state: dict, level: int) -> None:
    """At an epoch boundary (level % epoch_blocks == 0), refresh the
    consensus snapshot. Called once per block, last, by apply_block and
    propose_block."""
    if level > 0 and level % epoch_blocks(state) == 0 and state.get("validators"):
        state["consensus_set"] = compute_consensus_set(state)


def _load_treasury(gov_state: dict, state: dict, balance: int):
    """Load the treasury track with the canonical delegation view. Any
    legacy delegation copy kept inside the treasury state is ignored: the
    effective validator set already includes delegated balances."""
    from .governance import load_treasury_governance
    gov = load_treasury_governance(gov_state, _governance_validator_set(state), balance)
    gov.delegations = {}
    return gov


def _save_treasury(gov_state: dict, gov) -> None:
    from .governance import save_treasury_governance
    save_treasury_governance(gov_state, gov)
    gov_state.get("treasury", {}).pop("delegations", None)


def _apply_governance_propose(state: dict, tx: Transaction) -> ApplyResult:
    """Handle a GOVERNANCE_PROPOSE transaction.

    Parameters in `tx.params`:
        {"track": "protocol"|"treasury", "payload": {...}, "salt": int}

    Effects:
    - For 'protocol': sender must be a registered validator.
    - For 'treasury': sender can be anyone.
    - A bond is escrowed from the sender (returned on success, partially
      burned on rejection).
    """
    from .governance import (
        DEFAULT_PROTOCOL_BOND, DEFAULT_TREASURY_BOND,
        load_protocol_governance, save_protocol_governance,
        load_treasury_governance, save_treasury_governance,
    )

    params = tx.params or {}
    track = params.get("track")
    payload = params.get("payload")
    salt = params.get("salt", 0)

    if track not in ("protocol", "treasury"):
        return ApplyResult(ok=False, error=f"invalid track: {track}")
    if not isinstance(payload, dict):
        return ApplyResult(ok=False, error="payload must be a dict")

    gov_state = state.setdefault("governance", {
        "protocol": {"proposals": {}, "activated_changes": [], "bonds": {}},
        "treasury": {"proposals": {}, "executions": [], "bonds": {}},
    })

    if track == "protocol":
        bond = DEFAULT_PROTOCOL_BOND
        # Escrow the bond.
        err = _debit(state, tx.sender, bond)
        if err:
            return ApplyResult(ok=False, error=f"cannot post bond: {err}")
        gov = load_protocol_governance(gov_state, _governance_validator_set(state))
        ok, reason, pid = gov.submit(tx.sender, payload, _current_level(state), salt=salt)
        if not ok:
            # Refund the bond if submission was rejected.
            _credit(state, tx.sender, bond)
            return ApplyResult(ok=False, error=reason)
        save_protocol_governance(gov_state, gov)
        gov_state["protocol"]["bonds"][pid] = {"submitter": tx.sender, "amount": bond}
        return ApplyResult(ok=True, gas_used=tx.gas_limit)

    # Treasury track
    bond = DEFAULT_TREASURY_BOND
    err = _debit(state, tx.sender, bond)
    if err:
        return ApplyResult(ok=False, error=f"cannot post bond: {err}")
    treasury_balance = state["balances"].get(state.get("treasury_address") or "", 0)
    tgov = _load_treasury(gov_state, state, treasury_balance)
    ok, reason, pid = tgov.submit(tx.sender, payload, _current_level(state), salt=salt)
    if not ok:
        _credit(state, tx.sender, bond)
        return ApplyResult(ok=False, error=reason)
    _save_treasury(gov_state, tgov)
    gov_state["treasury"]["bonds"][pid] = {"submitter": tx.sender, "amount": bond}
    return ApplyResult(ok=True, gas_used=tx.gas_limit)


def _apply_governance_vote(state: dict, tx: Transaction) -> ApplyResult:
    """Handle a GOVERNANCE_VOTE transaction.

    Parameters: {"track": ..., "proposal_id": ..., "vote": "yes/no/abstain"}

    Sender must be a registered validator (for both tracks)."""
    from .governance import (
        Vote, load_protocol_governance, save_protocol_governance,
        load_treasury_governance, save_treasury_governance,
    )

    params = tx.params or {}
    track = params.get("track")
    pid = params.get("proposal_id")
    vote_str = params.get("vote")

    if track not in ("protocol", "treasury"):
        return ApplyResult(ok=False, error=f"invalid track: {track}")
    if not pid:
        return ApplyResult(ok=False, error="missing proposal_id")
    if vote_str not in ("yes", "no", "abstain"):
        return ApplyResult(ok=False, error=f"invalid vote: {vote_str}")

    gov_state = state.setdefault("governance", {
        "protocol": {"proposals": {}, "activated_changes": [], "bonds": {}},
        "treasury": {"proposals": {}, "executions": [], "bonds": {}},
    })

    if track == "protocol":
        gov = load_protocol_governance(gov_state, _governance_validator_set(state))
        ok, reason = gov.vote(pid, tx.sender, Vote(vote_str), _current_level(state))
        if not ok:
            return ApplyResult(ok=False, error=reason)
        save_protocol_governance(gov_state, gov)
        return ApplyResult(ok=True, gas_used=tx.gas_limit)

    treasury_balance = state["balances"].get(state.get("treasury_address") or "", 0)
    tgov = _load_treasury(gov_state, state, treasury_balance)
    ok, reason = tgov.vote(pid, tx.sender, Vote(vote_str), _current_level(state))
    if not ok:
        return ApplyResult(ok=False, error=reason)
    _save_treasury(gov_state, tgov)
    return ApplyResult(ok=True, gas_used=tx.gas_limit)


# --- Per-block governance tick --------------------------------------------

# --- Slashing constants ---------------------------------------------------

# When equivocation is proven, the validator's stake is reduced by this %.
SLASHING_PERCENTAGE = 30
# The reporter gets a fraction of the slashed amount as a whistleblower reward.
WHISTLEBLOWER_REWARD_PCT = 10


def _apply_slash_equivocation(state: dict, tx: Transaction) -> ApplyResult:
    """Process a slashing report.

    The transaction names a proposal_id and an equivocator. The runtime:
    1. Looks up the proposal in state["governance"]["protocol"]["proposals"]
    2. Verifies the equivocator appears in the proposal's equivocations list
    3. Reduces the equivocator's stake by SLASHING_PERCENTAGE
    4. Pays WHISTLEBLOWER_REWARD_PCT of the slashed amount to the reporter
    5. Burns the remainder
    6. Marks the equivocation as "consumed" so the same evidence can't be
       reused (no double-slashing)
    """
    params = tx.params or {}
    pid = params.get("proposal_id")
    equivocator = params.get("equivocator")

    if not pid or not equivocator:
        return ApplyResult(ok=False, error="missing proposal_id or equivocator")

    gov = state.get("governance", {}).get("protocol", {})
    proposals = gov.get("proposals", {})
    if pid not in proposals:
        return ApplyResult(ok=False, error="proposal not found")

    prop = proposals[pid]
    # Find a non-consumed equivocation for this equivocator.
    evidence = None
    for i, e in enumerate(prop.get("equivocations", [])):
        if e.get("voter") == equivocator and not e.get("consumed"):
            evidence = (i, e)
            break
    if evidence is None:
        return ApplyResult(ok=False, error="no unconsumed equivocation for this voter")

    # The offence is the second, conflicting vote (governance.py records
    # its level as "second_at_level").
    offence_level = evidence[1].get("second_at_level", _current_level(state))
    if not isinstance(offence_level, int) or isinstance(offence_level, bool):
        offence_level = _current_level(state)
    err = _slash_validator(state, equivocator, reporter=tx.sender,
                           offence_level=offence_level)
    if err is not None:
        return ApplyResult(ok=False, error=err)

    # Mark evidence as consumed.
    idx = evidence[0]
    prop["equivocations"][idx]["consumed"] = True
    prop["equivocations"][idx]["slashed_at_level"] = _current_level(state)
    prop["equivocations"][idx]["reporter"] = tx.sender

    return ApplyResult(ok=True, gas_used=tx.gas_limit)


def _lower_consensus_weight(state: dict, validator: str) -> None:
    """Bring the validator's entry in the epoch snapshot down to its
    current effective stake, if that is lower. Never raises it: weight
    only grows at an epoch boundary. Used after a slash (Phase C) and
    after an undelegation (Phase E, E2)."""
    snap = state.get("consensus_set")
    if snap is None:
        return
    now = effective_stake(state, validator)
    for item in snap:
        if item["address"] == validator:
            item["stake"] = min(item["stake"], now)


def _cut_exposed_tranches(entry: dict, offence_level: int) -> int:
    """Slash SLASHING_PERCENTAGE of every tranche of `entry` bonded at or
    before `offence_level`. Updates the tranches and entry["amount"];
    returns the amount cut."""
    tranches = _tranches(entry)
    total_cut = 0
    for t in tranches:
        if t["level"] <= offence_level and t["amount"] > 0:
            cut = t["amount"] * SLASHING_PERCENTAGE // 100
            t["amount"] -= cut
            total_cut += cut
    entry["tranches"] = tranches
    entry["amount"] = sum(t["amount"] for t in tranches)
    return total_cut


def _slash_validator(state: dict, offender: str, reporter: str,
                     offence_level: int) -> Optional[str]:
    """Apply the validator slashing rule to `offender` for an offence
    committed at `offence_level`.

    - SLASHING_PERCENTAGE of the validator's own stake is removed;
      WHISTLEBLOWER_REWARD_PCT of that goes to `reporter`, the rest is
      burned.
    - The same percentage of every bond that was EXPOSED at the offence
      is burned (Phase E, E3): the tranches bonded at or before
      `offence_level`, in live delegations and in unbonding entries that
      started unbonding at or after `offence_level`. A bond created after
      the offence, or one that had already started unbonding before it,
      was not backing the offender and is not touched. Liquid balances
      are never touched.
    - The offender's consensus weight drops at once.

    Returns an error string if nothing at all can be slashed, else None.
    Shared by governance-vote and consensus-vote equivocation."""
    validators = state.get("validators", [])
    val = next((v for v in validators if v["address"] == offender), None)
    if val is None:
        return "equivocator not a current validator"

    own_slash = val.get("stake", 0) * SLASHING_PERCENTAGE // 100
    reward = own_slash * WHISTLEBLOWER_REWARD_PCT // 100
    burned = own_slash - reward

    delegated_slash = 0
    for entry in state.get("delegations", {}).values():
        target, amount = _bond(entry)
        if target == offender and amount > 0 and isinstance(entry, dict):
            delegated_slash += _cut_exposed_tranches(entry, offence_level)
    for entries in state.get("delegation_unbonding", {}).values():
        for entry in entries:
            if entry["validator"] != offender or entry["amount"] <= 0:
                continue
            # Entries written before Phase E carry no start level: treat
            # them as exposed, as Phase D did.
            if int(entry.get("unbonding_from", offence_level)) < offence_level:
                continue
            delegated_slash += _cut_exposed_tranches(entry, offence_level)

    if own_slash == 0 and delegated_slash == 0:
        return "no stake to slash"

    val["stake"] -= own_slash
    _credit(state, reporter, reward)
    state["total_supply"] = max(0, state.get("total_supply", 0) - burned - delegated_slash)

    # The offender's CONSENSUS weight drops at once, without waiting for
    # the epoch boundary (it can only go down here).
    _lower_consensus_weight(state, offender)
    return None


def _apply_slash_consensus_equivocation(state: dict, tx: Transaction) -> ApplyResult:
    """Slash a validator that signed two conflicting consensus votes.

    Phase C (external review, point C): the BFT engine used to log
    equivocations only, and SLASH_EQUIVOCATION only knows governance-vote
    equivocations. This operation takes the two signed ConsensusMessages
    themselves as evidence:

    - both decode strictly and carry valid signatures;
    - same validator, same kind (PREENDORSE or ENDORSE), same (level,
      round), different block_hash;
    - the validator is in the current set and the signing key is its
      registered key;
    - the vote level is not in the future;
    - the same offence (validator, kind, level, round) is slashed once.

    The reporter (tx.sender) receives the whistleblower reward."""
    from .bft import ConsensusMessage, MsgKind, SlashingEvidence

    params = tx.params or {}
    raw_a, raw_b = params.get("msg_a"), params.get("msg_b")
    if not isinstance(raw_a, dict) or not isinstance(raw_b, dict):
        return ApplyResult(ok=False, error="msg_a and msg_b must be consensus message objects")
    msg_a = ConsensusMessage.from_dict(raw_a)  # strict; raises -> rejection
    msg_b = ConsensusMessage.from_dict(raw_b)
    if msg_a.kind not in (MsgKind.PREENDORSE, MsgKind.ENDORSE):
        return ApplyResult(ok=False, error="only PREENDORSE and ENDORSE votes are slashable")
    ok, reason = SlashingEvidence(offender=msg_a.validator, msg_a=msg_a, msg_b=msg_b).verify()
    if not ok:
        return ApplyResult(ok=False, error=f"invalid evidence: {reason}")
    offender = msg_a.validator
    registered = next((v for v in state.get("validators", []) if v["address"] == offender), None)
    if registered is None:
        return ApplyResult(ok=False, error="equivocator not a current validator")
    if registered.get("pubkey") != msg_a.validator_pubkey or registered.get("pubkey") != msg_b.validator_pubkey:
        return ApplyResult(ok=False, error="votes not signed with the validator's registered key")
    if msg_a.level > _current_level(state):
        return ApplyResult(ok=False, error="evidence from a future level")
    # Phase D: evidence is valid for as long as the funds behind the vote
    # are guaranteed to be still locked: the delegation unbonding period.
    if msg_a.level + delegation_unbonding_blocks(state) < _current_level(state):
        return ApplyResult(ok=False, error="evidence expired (older than the unbonding period)")

    key = f"{offender}|{msg_a.kind.value}|{msg_a.level}|{msg_a.round}"
    done = state.setdefault("consensus_slashes", {})
    if key in done:
        return ApplyResult(ok=False, error="offence already slashed")

    err = _slash_validator(state, offender, reporter=tx.sender,
                           offence_level=msg_a.level)
    if err is not None:
        return ApplyResult(ok=False, error=err)
    done[key] ={"reporter": tx.sender, "slashed_at_level": _current_level(state)}
    return ApplyResult(ok=True, gas_used=tx.gas_limit,
                       extra={"offender": offender, "offence": key})


# --- Stake delegation (v1.0-rc, Liquid PoS) ------------------------------

# Default validator commission as percent of delegator rewards. Validators
# can override per-validator via state["commission_rates"][address].
DEFAULT_COMMISSION_PCT = 10


# Phase D: delegation is BONDED. Delegated KRN leave the delegator's
# balance and are held in the delegation record; on undelegation they stay
# locked, and slashable, for this many blocks before returning to the
# balance. Consensus weight (effective_stake) counts bonded amounts only.
# Before Phase D a delegation counted the delegator's LIQUID balance,
# which could be moved away while still weighing in consensus (external
# review, November 2026). Genesis override: state["delegation_unbonding_blocks"].
DEFAULT_DELEGATION_UNBONDING_BLOCKS = 86_400


def delegation_unbonding_blocks(state: dict) -> int:
    v = state.get("delegation_unbonding_blocks")
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return v
    return DEFAULT_DELEGATION_UNBONDING_BLOCKS


def _bond(entry) -> Tuple[Optional[str], int]:
    """(validator, bonded amount) of a delegation record. Records are
    {"validator": addr, "amount": int}; a bare address (pre-Phase D
    format) carries no bonded amount and therefore no weight."""
    if isinstance(entry, dict):
        return entry.get("validator"), int(entry.get("amount", 0))
    if isinstance(entry, str):
        return entry, 0
    return None, 0


def _tranches(entry: dict) -> List[dict]:
    """Copy of the bonded slices of a delegation or unbonding record, each
    {"level": bonded_at_level, "amount": int} (Phase E, E3). A record
    written before Phase E has no slices: its whole amount is one slice
    bonded at level 0, so it stays exposed to any offence, as in Phase D."""
    raw = entry.get("tranches")
    if isinstance(raw, list):
        return [{"level": int(t["level"]), "amount": int(t["amount"])} for t in raw]
    return [{"level": 0, "amount": int(entry.get("amount", 0))}]


def _apply_delegate_stake(state: dict, tx: Transaction) -> ApplyResult:
    """Bond `tx.amount` KRN from the sender's balance to a validator.

    - The amount leaves the sender's balance and is held in
      state["delegations"][sender] = {"validator", "amount"}.
    - Delegating again to the SAME validator adds to the bond. Switching
      to another validator requires UNDELEGATE_STAKE first (the old bond
      must go through its unbonding period).
    - The validator must be in the active set; self-delegation is refused.
    """
    params = tx.params or {}
    validator = params.get("validator")
    if not validator or not isinstance(validator, str):
        return ApplyResult(ok=False, error="missing validator address")
    if validator == tx.sender:
        return ApplyResult(ok=False, error="cannot delegate to self; register as a validator instead")
    if not any(v["address"] == validator for v in state.get("validators", [])):
        return ApplyResult(ok=False, error=f"validator {validator} not in active set")
    amount = tx.amount
    if amount <= 0:
        return ApplyResult(ok=False, error="delegation amount must be positive (tx.amount)")

    delegations = state.setdefault("delegations", {})
    current, bonded = _bond(delegations.get(tx.sender))
    if current is not None and current != validator and bonded > 0:
        return ApplyResult(ok=False, error="already delegating to another validator; undelegate first")
    err = _debit(state, tx.sender, amount)
    if err:
        return ApplyResult(ok=False, error=err)
    # Phase E (E3): remember when each slice was bonded, so a slash only
    # reaches the slices that were exposed at the offence.
    level = _current_level(state)
    previous = delegations.get(tx.sender)
    tranches = _tranches(previous) if isinstance(previous, dict) and bonded > 0 else []
    if tranches and tranches[-1]["level"] == level:
        tranches[-1]["amount"] += amount
    else:
        tranches.append({"level": level, "amount": amount})
    delegations[tx.sender] = {"validator": validator, "amount": bonded + amount,
                              "tranches": tranches}
    return ApplyResult(ok=True, gas_used=tx.gas_limit,
                       extra={"delegated_to": validator, "bonded": bonded + amount})


def _apply_undelegate_stake(state: dict, tx: Transaction) -> ApplyResult:
    """End the sender's delegation. The bond stops counting in consensus
    and rewards at once (Phase E, E2: the epoch snapshot is lowered in the
    same transaction), but stays locked for the unbonding period, slashable
    for offences committed up to the level it started unbonding, then
    returns to the sender's balance."""
    delegations = state.setdefault("delegations", {})
    record = delegations.pop(tx.sender, None)
    validator, bonded = _bond(record)
    release_at = None
    if validator is not None and bonded > 0:
        level = _current_level(state)
        release_at = level + delegation_unbonding_blocks(state)
        queue = state.setdefault("delegation_unbonding", {})
        queue.setdefault(str(release_at), []).append(
            {"delegator": tx.sender, "validator": validator, "amount": bonded,
             "tranches": _tranches(record) if isinstance(record, dict) else [],
             "unbonding_from": level})
        _lower_consensus_weight(state, validator)
    return ApplyResult(ok=True, gas_used=tx.gas_limit,
                       extra={"undelegated_from": validator, "unbonding": bonded,
                              "release_level": release_at})


def _release_matured_delegation_bonds(state: dict, level: int) -> None:
    """Return unbonded delegations whose period ends at or before `level`.
    Deterministic: ascending release level, then insertion order."""
    queue = state.get("delegation_unbonding")
    if not queue:
        return
    for key in sorted(int(k) for k in queue if int(k) <= level):
        for entry in queue.pop(str(key)):
            if entry["amount"] > 0:
                _credit(state, entry["delegator"], entry["amount"])


def effective_stake(state: dict, validator_address: str) -> int:
    """Own stake plus every amount currently BONDED to this validator.

    Phase D: only locked, slashable funds count. A delegator's liquid
    balance never does; unbonding amounts no longer do either (they remain
    slashable but carry no weight)."""
    own = 0
    for v in state.get("validators", []):
        if v["address"] == validator_address:
            own = v.get("stake", 0)
            break
    delegated = 0
    for entry in state.get("delegations", {}).values():
        target, amount = _bond(entry)
        if target == validator_address:
            delegated += amount
    return own + delegated


def delegators_of(state: dict, validator_address: str) -> list:
    """(delegator_address, bonded_amount) for every positive bond to the
    given validator, in record order."""
    result = []
    for delegator_addr, entry in state.get("delegations", {}).items():
        target, amount = _bond(entry)
        if target == validator_address and amount > 0:
            result.append((delegator_addr, amount))
    return result


def commission_rate_of(state: dict, validator_address: str) -> int:
    """Return the commission percentage for a validator. Defaults to
    DEFAULT_COMMISSION_PCT if the validator hasn't set a custom rate."""
    return state.get("commission_rates", {}).get(validator_address, DEFAULT_COMMISSION_PCT)


# --- Slashable attestations (v1.1-rc) -------------------------------------

from .attestation import (
    derive_attestation_id,
    find_equivocation_pair,
    compute_attestation_slash,
    _index_key,
)


def _apply_attest(state: dict, tx: Transaction) -> ApplyResult:
    """Record an attestation: a signed claim by tx.sender (the issuer)
    about a subject under a schema. The optional bond (in tx.amount)
    is debited from the issuer and held with the attestation;
    on equivocation, it is the source of the slash."""
    params = tx.params or {}
    schema_id = params.get("schema_id")
    subject = params.get("subject")
    claim = params.get("claim")
    if not schema_id or not subject or claim is None:
        return ApplyResult(ok=False, error="missing schema_id, subject, or claim")
    if not isinstance(schema_id, str) or not isinstance(subject, str):
        return ApplyResult(ok=False, error="schema_id and subject must be strings")
    if not isinstance(claim, dict):
        return ApplyResult(ok=False, error="claim must be a dict (JSON object)")

    bond = tx.amount
    if bond < 0:
        return ApplyResult(ok=False, error="bond cannot be negative")

    # Debit the bond from the issuer's balance (the fee was already
    # debited in apply_transaction's prologue).
    if bond > 0:
        issuer_balance = state["balances"].get(tx.sender, 0)
        if issuer_balance < bond:
            return ApplyResult(ok=False, error="insufficient balance for bond")
        state["balances"][tx.sender] = issuer_balance - bond

    # Derive deterministic attestation_id from the tx contents.
    attestation_id = derive_attestation_id(
        issuer=tx.sender,
        schema_id=schema_id,
        subject=subject,
        claim=claim,
        attest_nonce=tx.nonce,
    )

    # Reject duplicates (same id = same content = same nonce already issued).
    attestations = state.setdefault("attestations", {})
    if attestation_id in attestations:
        # Refund the bond — we never recorded it
        if bond > 0:
            state["balances"][tx.sender] += bond
        return ApplyResult(ok=False, error=f"attestation {attestation_id} already exists")

    current_level = _current_level(state)
    record = {
        "issuer": tx.sender,
        "schema_id": schema_id,
        "subject": subject,
        "claim": claim,
        "bond": bond,
        "issued_at_level": current_level,
        "revoked_at_level": None,
        "consumed_for_slashing": False,
    }
    attestations[attestation_id] = record

    # Maintain the (issuer, schema_id, subject) reverse index
    index = state.setdefault("attestations_by_subject", {})
    key = _index_key(tx.sender, schema_id, subject)
    index.setdefault(key, []).append(attestation_id)

    return ApplyResult(
        ok=True,
        gas_used=tx.gas_limit,
        extra={"attestation_id": attestation_id},
    )


def _apply_revoke_attestation(state: dict, tx: Transaction) -> ApplyResult:
    """Mark an attestation as revoked and start its unbonding period.

    Phase B (audit 1, findings 1, 2 and 10): the bond is NOT returned at
    revocation any more. It stays locked in the attestation record, and
    remains slashable, until `revoked_at_level + unbonding period`; the
    per-block hook `_release_matured_attestation_bonds` then credits it
    back to the issuer. A bond therefore has exactly one economic owner
    at any time (the record while locked, the issuer once released, the
    slash otherwise), and the invariant

        sum(balances) + sum(locked attestation bonds) + escrowed bonds
            == total_supply

    holds across revoke, slash and release. The record remains on-chain so
    that evidence of past contradictions can still be submitted."""
    from .attestation import attestation_unbonding_blocks

    params = tx.params or {}
    attestation_id = params.get("attestation_id")
    if not attestation_id or not isinstance(attestation_id, str):
        return ApplyResult(ok=False, error="missing attestation_id")

    attestations = state.setdefault("attestations", {})
    att = attestations.get(attestation_id)
    if not att:
        return ApplyResult(ok=False, error=f"attestation {attestation_id} not found")
    if att["issuer"] != tx.sender:
        return ApplyResult(ok=False, error="only the issuer can revoke this attestation")
    if att.get("revoked_at_level") is not None:
        return ApplyResult(ok=False, error="attestation already revoked")
    if att.get("consumed_for_slashing"):
        return ApplyResult(ok=False, error="attestation was slashed; bond cannot be reclaimed")

    level = _current_level(state)
    att["revoked_at_level"] = level
    release_at = level + attestation_unbonding_blocks(state)
    att["bond_release_level"] = release_at
    if att.get("bond", 0) > 0:
        queue = state.setdefault("attestation_unbonding", {})
        queue.setdefault(str(release_at), []).append(attestation_id)

    return ApplyResult(
        ok=True,
        gas_used=tx.gas_limit,
        extra={"bond_locked_until_level": release_at, "bond": att.get("bond", 0)},
    )


def _release_matured_attestation_bonds(state: dict, level: int) -> None:
    """Credit back every revoked attestation bond whose unbonding period
    ends at or before `level`. Called once per block by apply_block (and by
    propose_block via the same path). Bonds already resolved by a slash
    are zero and are skipped. Deterministic: queue keys are visited in
    ascending numeric order, ids in insertion order."""
    queue = state.get("attestation_unbonding")
    if not queue:
        return
    due = sorted(int(k) for k in queue if int(k) <= level)
    attestations = state.get("attestations", {})
    for key in due:
        for att_id in queue.pop(str(key)):
            att = attestations.get(att_id)
            if not att or att.get("consumed_for_slashing"):
                continue
            bond = att.get("bond", 0)
            if bond > 0:
                _credit(state, att["issuer"], bond)
                att["bond"] = 0
                att["bond_released_at_level"] = level


def _apply_slash_attestation_equivocation(state: dict, tx: Transaction) -> ApplyResult:
    """Slash an issuer for signing two contradictory attestations
    about the same (schema_id, subject) tuple. Whistleblower (tx.sender)
    earns 10% of slashed amount; the rest is burned."""
    params = tx.params or {}
    id_1 = params.get("attestation_id_1")
    id_2 = params.get("attestation_id_2")
    if not id_1 or not id_2:
        return ApplyResult(ok=False, error="missing attestation_id_1 or attestation_id_2")

    attestations = state.setdefault("attestations", {})
    att_1 = attestations.get(id_1)
    att_2 = attestations.get(id_2)
    if not att_1 or not att_2:
        return ApplyResult(ok=False, error="one or both attestations not found")

    issuer = att_1["issuer"]
    schema_id = att_1["schema_id"]
    subject = att_1["subject"]

    pair = find_equivocation_pair(
        attestations, issuer, schema_id, subject, id_1, id_2,
    )
    if pair is None:
        return ApplyResult(ok=False, error="attestations do not constitute valid equivocation evidence")

    # Slash from the larger of the two bonds. Both bonds are still held by
    # their records: Phase B made revocation start an unbonding period
    # instead of returning the bond, so a revoked half of the pair is
    # still slashable (audit 1, findings 1 and 2).
    bond_1 = att_1.get("bond", 0)
    bond_2 = att_2.get("bond", 0)
    target_att, other_att = (att_1, att_2) if bond_1 >= bond_2 else (att_2, att_1)
    bond_to_slash_from = target_att.get("bond", 0)
    slash, reward, burn = compute_attestation_slash(bond_to_slash_from)

    if slash == 0:
        return ApplyResult(ok=False, error="no bond to slash (bond was zero on both attestations)")

    # Economic resolution of BOTH bonds (audit 1, finding 10: the second
    # bond used to stay locked forever once both records were consumed):
    #   - `slash` comes out of the larger bond: `reward` to the
    #     whistleblower, `burn` removed from total_supply;
    #   - the rest of the larger bond returns to the issuer;
    #   - the smaller bond returns to the issuer in full.
    # The issuer's loss is exactly `slash`, as documented.
    unslashed_remainder = bond_to_slash_from - slash
    other_bond = other_att.get("bond", 0)
    target_att["bond"] = 0
    other_att["bond"] = 0

    _credit(state, tx.sender, reward)
    refund = unslashed_remainder + other_bond
    if refund > 0:
        _credit(state, issuer, refund)
    state["total_supply"] = max(0, state.get("total_supply", 0) - burn)

    # Mark both attestations as consumed_for_slashing so the same
    # equivocation cannot be re-submitted, revoke is blocked, and any
    # pending unbonding entry for them is ignored at release time.
    att_1["consumed_for_slashing"] = True
    att_2["consumed_for_slashing"] = True

    return ApplyResult(
        ok=True,
        gas_used=tx.gas_limit,
        extra={
            "slashed": slash,
            "whistleblower_reward": reward,
            "burned": burn,
            "refunded_to_issuer": refund,
            "issuer": issuer,
            "schema_id": schema_id,
            "subject": subject,
        },
    )


def _current_level(state: dict) -> int:
    """The level at which we're currently applying changes. Looked up
    from state metadata if present, falls back to 0."""
    return state.get("_current_level", 0)


def _apply_governance_tick(state: dict, current_level: int) -> None:
    """Called once per block, after rewards. Advances any in-flight
    proposals, applies terminal phase effects (bond settlement, parameter
    changes, function swaps, treasury payouts)."""
    from .governance import (
        load_protocol_governance, save_protocol_governance,
        load_treasury_governance, save_treasury_governance,
        resolve_bond,
    )

    state["_current_level"] = current_level

    gov_state = state.setdefault("governance", {
        "protocol": {"proposals": {}, "activated_changes": [], "bonds": {}},
        "treasury": {"proposals": {}, "executions": [], "bonds": {}},
    })

    # ----- Protocol track -----
    activated_count_before = len(gov_state["protocol"].get("activated_changes", []))
    gov = load_protocol_governance(gov_state, _governance_validator_set(state))
    transitions = gov.advance_phases(current_level)
    save_protocol_governance(gov_state, gov)

    # Resolve bonds for any proposals that just terminated.
    for pid, new_phase in transitions:
        if new_phase in ("activated", "rejected", "withdrawn"):
            _settle_bond(state, gov_state["protocol"], pid, new_phase)

    # Apply any new activations (changes that just landed in activated_changes).
    activated_after = gov_state["protocol"].get("activated_changes", [])
    new_changes = activated_after[activated_count_before:]
    for change in new_changes:
        _apply_activated_change(state, change)

    # ----- Treasury track -----
    treasury_addr = state.get("treasury_address")
    treasury_balance = state["balances"].get(treasury_addr or "", 0)
    tgov = _load_treasury(gov_state, state, treasury_balance)
    pre_balance = tgov.treasury_balance
    transitions_t = tgov.advance_phases(current_level)
    _save_treasury(gov_state, tgov)

    # For each EXECUTED treasury proposal: actually move the KRN from the
    # treasury account to the recipients.
    for pid, new_phase in transitions_t:
        if new_phase == "executed":
            execution = next((e for e in tgov.executions if e["proposal_id"] == pid), None)
            if execution and treasury_addr:
                for r in execution["recipients"]:
                    _debit(state, treasury_addr, r["amount"])
                    _credit(state, r["address"], r["amount"])
        if new_phase in ("executed", "rejected", "withdrawn"):
            _settle_bond(state, gov_state["treasury"], pid, new_phase)


def _settle_bond(state: dict, track_state: dict, proposal_id: str,
                 terminal_phase: str) -> None:
    """Refund / burn / pay-to-treasury for a terminated proposal's bond."""
    from .governance import resolve_bond

    bond_entry = track_state.get("bonds", {}).pop(proposal_id, None)
    if bond_entry is None:
        return
    outcome = resolve_bond(bond_entry["amount"], terminal_phase, was_decided_by_vote=True)
    if outcome.refund_to_submitter > 0:
        _credit(state, bond_entry["submitter"], outcome.refund_to_submitter)
    # Burned bond: just reduces total_supply (effectively).
    if outcome.burn > 0:
        state["total_supply"] = max(0, state.get("total_supply", 0) - outcome.burn)
    if outcome.to_treasury > 0 and state.get("treasury_address"):
        _credit(state, state["treasury_address"], outcome.to_treasury)


def _apply_activated_change(state: dict, change: dict) -> None:
    """Apply the effects of an ACTIVATED protocol amendment to chain state."""
    if "params" in change:
        # Route each parameter to its bucket: fee-floor params live in their own
        # dict (a strict IssuanceParams dataclass consumes issuance_params, so
        # unrelated keys must not land there); everything else is an issuance
        # parameter.
        issuance = state.get("issuance_params") or {}
        fees = state.get("fee_params") or {}
        for k, v in change["params"].items():
            if k in FEE_PARAM_KEYS:
                fees[k] = v
            else:
                issuance[k] = v
        state["issuance_params"] = issuance
        if fees:
            state["fee_params"] = fees
    if change.get("swap") == "state_root_function":
        state["state_root_function"] = change["to"]


def apply_block(state: dict, block: Block) -> Tuple[dict, List[ApplyResult]]:
    """Apply all transactions in `block` to `state`, then credit block
    rewards, then advance governance phases. Returns the new state and the
    per-tx results. Pure: does not mutate the input."""
    from .observability import REGISTRY, observe_latency

    with observe_latency("kern_block_apply_seconds"):
        new_state = copy.deepcopy(state)
        # Phase B (audit 1, finding 3): transactions in block N observe
        # level N. The level used to be written only by the governance tick
        # at the END of the block, so every transaction saw N-1 (wrong
        # attestation issue/revoke levels, governance windows shifted).
        new_state["_current_level"] = block.header.level
        results: List[ApplyResult] = []
        for tx in block.transactions:
            r = apply_transaction(new_state, tx, baker=block.header.proposer)
            results.append(r)
            # Per-tx metric.
            counter = "kern_transactions_applied_total" if r.ok else "kern_transactions_rejected_total"
            m = REGISTRY._metrics.get(counter)
            if m is not None:
                m.inc()  # type: ignore
        # Block rewards are credited AFTER transaction processing so that they
        # appear in the post-block state_root commitment.
        _apply_block_rewards(new_state, block)
        # Release attestation bonds and delegation bonds whose unbonding
        # period has ended.
        _release_matured_attestation_bonds(new_state, block.header.level)
        _release_matured_delegation_bonds(new_state, block.header.level)
        # Governance tick: advance any in-flight proposals and apply activations.
        _apply_governance_tick(new_state, block.header.level)
        # Phase C: refresh the consensus validator snapshot at epoch boundaries.
        _epoch_tick(new_state, block.header.level)

    # Update gauges.
    g_height = REGISTRY._metrics.get("kern_chain_height")
    if g_height is not None:
        g_height.set(block.header.level)  # type: ignore
    g_supply = REGISTRY._metrics.get("kern_total_supply_mukrn")
    if g_supply is not None:
        g_supply.set(new_state.get("total_supply", 0))  # type: ignore
    g_vals = REGISTRY._metrics.get("kern_validator_count")
    if g_vals is not None:
        g_vals.set(len(new_state.get("validators", [])))  # type: ignore

    c_blocks = REGISTRY._metrics.get("kern_blocks_applied_total")
    if c_blocks is not None:
        c_blocks.inc()  # type: ignore

    return new_state, results


# ===========================================================================
# Optional L1 fee floor & per-block size cap  (DISABLED by default)
# ===========================================================================
# These are CONSENSUS parameters. When enabled, every validating node must
# apply the identical rule, or the chain forks. They are therefore resolved
# from chain state (state["issuance_params"]) — set at genesis or, on a live
# chain, only via the protocol-governance track — and NEVER from a local or
# environment toggle (which would silently fork the network). When the master
# switch `fee_floor_enabled` is absent or False, behaviour is byte-for-byte
# identical to prior releases, so existing networks and tests are unaffected.
#
# Proposed defaults (calibrated against measured tx sizes ~320-350 bytes, so a
# legitimate transfer's floor stays well under the current 1000-mukrn default
# fee while block-stuffing becomes cost-proportional). All are governance-tunable.
DEFAULT_FEE_FLOOR_BASE = 100          # mukrn: fixed per-transaction anti-spam base
DEFAULT_FEE_FLOOR_PER_BYTE = 2        # mukrn per canonical-encoded byte
DEFAULT_MAX_BLOCK_BYTES = 1_048_576   # 1 MiB: per-block total encoded-size cap

# The governance-settable parameter names that configure this feature. They are
# stored in their own state bucket (state["fee_params"]) rather than in
# issuance_params, which is consumed by a strict IssuanceParams dataclass.
FEE_PARAM_KEYS = frozenset({
    "fee_floor_enabled", "fee_floor_base", "fee_floor_per_byte", "max_block_bytes",
})


def fee_params(state: dict) -> dict:
    """Resolve the (optional) fee-floor / block-cap parameters from chain state.

    `fee_floor_enabled` is the master switch and defaults to False, so a chain
    that never sets it behaves exactly as before. Numeric values fall back to
    the proposed defaults above when unset."""
    fp = state.get("fee_params") or {}
    return {
        "enabled": bool(fp.get("fee_floor_enabled", False)),
        "base": int(fp.get("fee_floor_base", DEFAULT_FEE_FLOOR_BASE)),
        "per_byte": int(fp.get("fee_floor_per_byte", DEFAULT_FEE_FLOOR_PER_BYTE)),
        "max_block_bytes": int(fp.get("max_block_bytes", DEFAULT_MAX_BLOCK_BYTES)),
    }


def tx_min_fee(tx: Transaction, params: dict) -> int:
    """Minimum acceptable fee for `tx` under the given (resolved) fee params:
    a fixed base plus a per-byte charge on the canonical encoded size."""
    return params["base"] + params["per_byte"] * tx.encoded_size()


def check_fee_rules(transactions: List[Transaction], params: dict) -> Optional[str]:
    """Pure consensus check for the fee floor and per-block size cap.

    Returns None when the feature is disabled or the transactions satisfy the
    rules, otherwise a descriptive error string. Deterministic and side-effect
    free, so the SAME function is used by block validation (the consensus gate)
    and may be reused by a block proposer to filter its mempool — both must
    agree by construction."""
    if not params["enabled"]:
        return None
    total_bytes = 0
    for tx in transactions:
        size = tx.encoded_size()
        total_bytes += size
        floor = params["base"] + params["per_byte"] * size
        if tx.fee < floor:
            return (f"transaction {tx.hash_hex()[:8]} below fee floor: "
                    f"fee {tx.fee} < required {floor} (size {size} bytes)")
    cap = params["max_block_bytes"]
    if cap > 0 and total_bytes > cap:
        return f"block exceeds max_block_bytes: {total_bytes} > {cap}"
    return None


def validate_and_apply(
    block: Block,
    parent_header: Optional[BlockHeader],
    state_before: dict,
    validator_set: List[dict],
    *,
    require_quorum: bool = True,
) -> "Tuple[Optional[str], Optional[dict]]":
    """Validate a block against its parent and the prior state, returning
    (error, new_state). new_state is the post-block state when the block
    is valid, else None. Returning the applied state lets the caller
    (Chain.append) reuse it instead of applying the block a second time —
    validation already pays the O(state) apply + state_root cost once.

    Checks:
    1. Header signature is valid.
    2. parent_hash matches the parent's hash (or is "0"*64 at genesis).
    3. level increments by 1.
    4. Proposer is in the validator set and is the proposer selected for
       the header's payload_round (Phase E); cert_round >= payload_round.
    5. txs_root matches the merkle of the included transactions.
    6. Applying the block yields the declared state_root.
    7. (optional) Commit quorum is met: > 2/3 of validator stake has
       produced *cryptographically verified* endorse-schema signatures
       over this block's hash, counted across block.commits (known at
       proposal time, feeds rewards) and block.endorsements (the wire
       quorum certificate gathered after the header was signed).
    """
    if not block.header.verify_signature():
        return "invalid header signature", None

    if parent_header is None:
        if block.header.level != 0:
            return "non-genesis block with no parent", None
        if block.header.parent_hash != "0" * 64:
            return "genesis must have zero parent_hash", None
    else:
        if block.header.level != parent_header.level + 1:
            return (f"non-monotonic level: parent {parent_header.level}, "
                    f"block {block.header.level}"), None
        if block.header.parent_hash != parent_header.hash_hex():
            return "parent_hash mismatch", None

    if not any(v["address"] == block.header.proposer for v in validator_set):
        return "proposer is not in validator set", None

    # Phase E: the header proposer must be THE proposer selected for the
    # payload round. Before, only the node checked this on live proposals;
    # a block arriving by gossip or sync was only checked for membership.
    if parent_header is not None:
        from .consensus import select_proposer
        expected = select_proposer(block.header.parent_hash, validator_set,
                                   block.header.payload_round)
        if expected["address"] != block.header.proposer:
            return (f"proposer {block.header.proposer} is not the selected proposer "
                    f"of round {block.header.payload_round}"), None
    if block.quorum_round() < block.header.payload_round:
        return "cert_round below the payload round", None

    expected_txs_root = txs_merkle_root_hex(block.transactions)
    if block.header.txs_root != expected_txs_root:
        return "txs_root mismatch", None

    # Optional fee floor / block size cap (consensus rule; off by default).
    # Read from the prior state so every node applies the identical rule.
    fee_err = check_fee_rules(block.transactions, fee_params(state_before))
    if fee_err:
        return fee_err, None

    new_state, _ = apply_block(state_before, block)
    if state_root_hex(new_state) != block.header.state_root:
        return "state_root mismatch after applying transactions", None

    if require_quorum and block.header.level > 0:
        from .bft import verify_commits
        total_stake = sum(v["stake"] for v in validator_set)
        payload_round, cert_round = block.header.payload_round, block.quorum_round()
        # Phase E: `endorsements` are signed for cert_round, `commits` (the
        # self-commit of a proposer holding the quorum alone) for the
        # payload round. Both must verify; they are counted together only
        # when the two rounds are the same, since a quorum certificate is
        # made of endorsements of ONE round.
        if cert_round == payload_round:
            committed_stake, err = verify_commits(
                block.hash_hex(), block.header.level, cert_round,
                list(block.commits) + list(block.endorsements), validator_set,
            )
        else:
            _, err = verify_commits(block.hash_hex(), block.header.level,
                                    payload_round, list(block.commits), validator_set)
            if err is None:
                committed_stake, err = verify_commits(
                    block.hash_hex(), block.header.level, cert_round,
                    list(block.endorsements), validator_set,
                )
        if err is not None:
            return err, None
        if committed_stake * 3 <= total_stake * 2:
            return (f"insufficient commit stake: {committed_stake}/{total_stake} "
                    f"(need > 2/3)"), None

    return None, new_state


def validate_block(
    block: Block,
    parent_header: Optional[BlockHeader],
    state_before: dict,
    validator_set: List[dict],
    *,
    require_quorum: bool = True,
) -> Optional[str]:
    """Validate a block; returns None if valid, else an error string.
    Thin wrapper over validate_and_apply for callers that don't need the
    resulting state."""
    err, _ = validate_and_apply(
        block, parent_header, state_before, validator_set,
        require_quorum=require_quorum,
    )
    return err


# --- Chain wrapper --------------------------------------------------------

class Chain:
    """In-memory chain wrapper. Persistence is handled by `storage.py`."""

    def __init__(
        self,
        genesis: Block,
        validators: List[dict],
        *,
        initial_state: Optional[dict] = None,
    ):
        """Create a fresh chain anchored at `genesis`.

        If `initial_state` is provided, it is taken as the post-genesis
        state (allowing pre-funded balances declared in genesis.json to
        be preserved). Otherwise the state starts empty and the genesis
        block's transactions (if any) are applied on top.
        """
        self.blocks: List[Block] = [genesis]
        if initial_state is not None:
            self.state = copy.deepcopy(initial_state)
        else:
            self.state = empty_state()
            self.state["validators"] = list(validators)
            new_state, _ = apply_block(self.state, genesis)
            self.state = new_state
        self._fallback_validators = list(validators)

    @property
    def validators(self) -> List[dict]:
        """The consensus validator set on top of the current head state
        (Phase C, review point B). It used to be the list passed to the
        constructor, frozen forever: slashing and delegation, which live in
        the state, never reached proposer selection, vote weights or block
        validation."""
        if self.state.get("validators") or self.state.get("consensus_set") is not None:
            return consensus_validator_set(self.state)
        return [dict(v) for v in self._fallback_validators]

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return self.head.header.level

    def append(self, block: Block, *, require_quorum: bool = False) -> None:
        """Validate and append a block.

        `require_quorum` defaults to False for library and tooling use
        (single-process chains built in tests, replay of already-validated
        blocks). The live node passes require_quorum=True on every path a
        block can arrive through — self-baked, gossiped, or synced — so
        no networked block is ever accepted without a cryptographically
        verified > 2/3 endorsement quorum. The block is applied exactly
        once: validate_and_apply returns the post-block state."""
        parent = self.head.header
        err, new_state = validate_and_apply(
            block, parent, self.state, self.validators,
            require_quorum=require_quorum,
        )
        if err is not None:
            raise ValueError(f"block invalid: {err}")
        assert new_state is not None
        self.state = new_state
        self.blocks.append(block)
