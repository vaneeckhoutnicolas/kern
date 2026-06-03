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
    state["validators"] = list(genesis.get("validators", []))
    # Total supply at genesis = sum of all pre-funded balances.
    state["total_supply"] = sum(state["balances"].values())
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

    # --- Hot path: TRANSFER cannot leave partial state -> no snapshot.
    if tx.kind == OpKind.TRANSFER:
        assert tx.recipient is not None
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
            assert tx.code is not None
            contract_addr = derive_contract_address(tx.hash())
            # Validate and "compile" the Skald source.
            storage = interpret_origination(tx.code, tx.initial_storage)
            state["contracts"][contract_addr] = {
                "code": tx.code,
                "storage": storage,
            }
            return ApplyResult(ok=True, gas_used=10_000, new_contract=contract_addr)

        if tx.kind == OpKind.CALL:
            assert tx.recipient is not None and tx.entry is not None
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

    except (RuntimeError, SkaldError) as e:
        # Roll back to the post-fee/post-nonce snapshot: the operation is
        # undone but the fee stays debited and the nonce stays bumped.
        state.clear()
        state.update(snapshot)
        return ApplyResult(ok=False, error=str(e), gas_used=tx.gas_limit)

    return ApplyResult(ok=False, error="unknown op kind")

    return ApplyResult(ok=False, error="unknown op kind")


# --- Block application ----------------------------------------------------

def _compute_staked(state: dict) -> int:
    """Sum of all validator stakes — the basis for staking ratio."""
    return sum(v.get("stake", 0) for v in state.get("validators", []))


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
        params = IssuanceParams(**p_dict)
    else:
        params = IssuanceParams()

    validators = state.get("validators", [])
    if not validators:
        return  # no validators → no rewards

    # Endorsers = validators whose commits appear in the block.
    # For single-validator mode this is just the proposer.
    committing_addrs = set()
    for entry in block.commits:
        if ":" in entry:
            addr, _ = entry.split(":", 1)
            committing_addrs.add(addr)
    if not committing_addrs:
        # Fall back: treat the proposer as the sole endorser.
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
        gov = load_protocol_governance(gov_state, state["validators"])
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
    gov = load_treasury_governance(gov_state, state["validators"], treasury_balance)
    ok, reason, pid = gov.submit(tx.sender, payload, _current_level(state), salt=salt)
    if not ok:
        _credit(state, tx.sender, bond)
        return ApplyResult(ok=False, error=reason)
    save_treasury_governance(gov_state, gov)
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
        gov = load_protocol_governance(gov_state, state["validators"])
        ok, reason = gov.vote(pid, tx.sender, Vote(vote_str), _current_level(state))
        if not ok:
            return ApplyResult(ok=False, error=reason)
        save_protocol_governance(gov_state, gov)
        return ApplyResult(ok=True, gas_used=tx.gas_limit)

    treasury_balance = state["balances"].get(state.get("treasury_address") or "", 0)
    gov = load_treasury_governance(gov_state, state["validators"], treasury_balance)
    ok, reason = gov.vote(pid, tx.sender, Vote(vote_str), _current_level(state))
    if not ok:
        return ApplyResult(ok=False, error=reason)
    save_treasury_governance(gov_state, gov)
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

    # Find the equivocator in the validator set and slash.
    validators = state.get("validators", [])
    val = next((v for v in validators if v["address"] == equivocator), None)
    if val is None:
        return ApplyResult(ok=False, error="equivocator not a current validator")

    stake = val.get("stake", 0)
    slash_amount = stake * SLASHING_PERCENTAGE // 100
    if slash_amount == 0:
        return ApplyResult(ok=False, error="no stake to slash")

    reward = slash_amount * WHISTLEBLOWER_REWARD_PCT // 100
    burn = slash_amount - reward

    # Apply effects.
    val["stake"] -= slash_amount
    _credit(state, tx.sender, reward)
    state["total_supply"] = max(0, state.get("total_supply", 0) - burn)

    # v1.0-rc: proportional slashing of delegators. If the equivocator has
    # delegators, they share the slash penalty in proportion to their
    # delegated balance. This is the Tezos "skin in the game" property —
    # delegators can't earn baking yield without exposure to the
    # validator's misconduct.
    delegator_slashes = {}
    dels = delegators_of(state, equivocator)
    if dels:
        # The validator's own slash was applied above. Apply proportional
        # slash to each delegator. Use the same SLASHING_PERCENTAGE on
        # their snapshot balance — this is the simplest defensible model.
        for del_addr, del_balance in dels:
            del_slash = del_balance * SLASHING_PERCENTAGE // 100
            if del_slash > 0:
                # Reduce delegator's balance; the slashed amount is burned
                # (no whistleblower reward on the delegator slice — that's
                # the validator's penalty, not the delegators').
                actual_slash = min(del_slash, state["balances"].get(del_addr, 0))
                state["balances"][del_addr] = state["balances"].get(del_addr, 0) - actual_slash
                state["total_supply"] = max(0, state["total_supply"] - actual_slash)
                if actual_slash > 0:
                    delegator_slashes[del_addr] = actual_slash

    # Mark evidence as consumed.
    idx = evidence[0]
    prop["equivocations"][idx]["consumed"] = True
    prop["equivocations"][idx]["slashed_at_level"] = _current_level(state)
    prop["equivocations"][idx]["reporter"] = tx.sender

    return ApplyResult(ok=True, gas_used=tx.gas_limit)


# --- Stake delegation (v1.0-rc, Liquid PoS) ------------------------------

# Default validator commission as percent of delegator rewards. Validators
# can override per-validator via state["commission_rates"][address].
DEFAULT_COMMISSION_PCT = 10


def _apply_delegate_stake(state: dict, tx: Transaction) -> ApplyResult:
    """Set the sender's stake delegation to the given validator.

    Effects:
    - state["delegations"][sender] = validator
    - If sender was already delegating to a different validator, the
      delegation is switched (one delegation per delegator, latest wins).
    - The validator must be in the active validator set.
    - A delegator cannot delegate to themselves (that would be self-baking
      which is just being a validator; if you want to be a validator,
      register as one — delegation is the alternative to running a node).
    """
    params = tx.params or {}
    validator = params.get("validator")
    if not validator:
        return ApplyResult(ok=False, error="missing validator address")

    if validator == tx.sender:
        return ApplyResult(ok=False, error="cannot delegate to self; register as a validator instead")

    validators = state.get("validators", [])
    if not any(v["address"] == validator for v in validators):
        return ApplyResult(ok=False, error=f"validator {validator} not in active set")

    delegations = state.setdefault("delegations", {})
    delegations[tx.sender] = validator
    return ApplyResult(ok=True, gas_used=tx.gas_limit,
                       extra={"delegated_to": validator})


def _apply_undelegate_stake(state: dict, tx: Transaction) -> ApplyResult:
    """Remove the sender's stake delegation. After this transaction the
    sender's balance no longer counts toward any validator's effective
    stake (and they no longer earn baking rewards, nor are exposed to
    that validator's slashing risk)."""
    delegations = state.setdefault("delegations", {})
    previous = delegations.pop(tx.sender, None)
    return ApplyResult(ok=True, gas_used=tx.gas_limit,
                       extra={"undelegated_from": previous})


def effective_stake(state: dict, validator_address: str) -> int:
    """Compute the effective stake of a validator: own stake + sum of
    balances of all addresses currently delegating to this validator.

    Note: "balance" is the LIQUID balance of the delegator at the moment
    of the call. Delegators do NOT lose custody — their KRN remains
    spendable. The price of that is that the snapshot is taken at the
    moment effective_stake() is called (i.e., per block at reward time)
    so a delegator who drains their account just before reward
    distribution forfeits that block's yield."""
    validators = state.get("validators", [])
    own = 0
    for v in validators:
        if v["address"] == validator_address:
            own = v.get("stake", 0)
            break
    delegated = 0
    delegations = state.get("delegations", {})
    balances = state.get("balances", {})
    for delegator_addr, target in delegations.items():
        if target == validator_address:
            delegated += balances.get(delegator_addr, 0)
    return own + delegated


def delegators_of(state: dict, validator_address: str) -> list:
    """Return the list of (delegator_address, delegated_balance) tuples
    currently delegating to the given validator."""
    delegations = state.get("delegations", {})
    balances = state.get("balances", {})
    result = []
    for delegator_addr, target in delegations.items():
        if target == validator_address:
            bal = balances.get(delegator_addr, 0)
            if bal > 0:
                result.append((delegator_addr, bal))
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
    """Mark an attestation as revoked. Returns the bond to the issuer
    (if any). The attestation record remains on-chain so that slashing
    evidence can still be submitted against it for past contradictions."""
    params = tx.params or {}
    attestation_id = params.get("attestation_id")
    if not attestation_id:
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

    att["revoked_at_level"] = _current_level(state)

    # Return the bond to the issuer
    bond_returned = att["bond"]
    if bond_returned > 0:
        state["balances"][tx.sender] = state["balances"].get(tx.sender, 0) + bond_returned

    return ApplyResult(
        ok=True,
        gas_used=tx.gas_limit,
        extra={"bond_returned": bond_returned},
    )


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

    # Slash from the bond on whichever attestation has more remaining bond.
    # (Typically these are equal; the issuer might have left a smaller bond
    # on the later one in an attempt to limit exposure.)
    bond_to_slash_from = max(att_1["bond"], att_2["bond"])
    slash, reward, burn = compute_attestation_slash(bond_to_slash_from)

    if slash == 0:
        return ApplyResult(ok=False, error="no bond to slash (bond was zero on both attestations)")

    # The attestation's bond was debited from the issuer at attest time.
    # On slashing:
    #   - `slash` is taken out of the bond (split into reward + burn)
    #   - the unslashed remainder is RETURNED to the issuer
    # This fix closes finding S-MAJ-2 from the v1.1-rc internal security
    # review: previously the unslashed portion was permanently locked in
    # the attestation record, creating a supply-vs-balances inconsistency
    # AND meaning the issuer effectively lost 100% of bond rather than 30%
    # as the math implied. With this fix, the issuer's economic loss is
    # exactly `slash` (= 30% of bond by default), matching the documented
    # behavior and matching standard slashing semantics elsewhere in Kern.
    target_att = att_1 if att_1["bond"] >= att_2["bond"] else att_2
    unslashed_remainder = bond_to_slash_from - slash
    target_att["bond"] = 0   # the bond is fully resolved (returned + slashed)

    # Pay reward to whistleblower (tx.sender)
    state["balances"][tx.sender] = state["balances"].get(tx.sender, 0) + reward

    # Refund the unslashed remainder to the issuer
    if unslashed_remainder > 0:
        state["balances"][issuer] = state["balances"].get(issuer, 0) + unslashed_remainder

    # Burn the remainder (reduce total_supply)
    state["total_supply"] = max(0, state.get("total_supply", 0) - burn)

    # Mark both attestations as consumed_for_slashing so the same
    # equivocation cannot be re-submitted (and revoke is blocked).
    att_1["consumed_for_slashing"] = True
    att_2["consumed_for_slashing"] = True

    return ApplyResult(
        ok=True,
        gas_used=tx.gas_limit,
        extra={
            "slashed": slash,
            "whistleblower_reward": reward,
            "burned": burn,
            "refunded_to_issuer": unslashed_remainder,
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
    gov = load_protocol_governance(gov_state, state["validators"])
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
    tgov = load_treasury_governance(gov_state, state["validators"], treasury_balance)
    pre_balance = tgov.treasury_balance
    transitions_t = tgov.advance_phases(current_level)
    save_treasury_governance(gov_state, tgov)

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
        # Governance tick: advance any in-flight proposals and apply activations.
        _apply_governance_tick(new_state, block.header.level)

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


def validate_block(
    block: Block,
    parent_header: Optional[BlockHeader],
    state_before: dict,
    validator_set: List[dict],
    *,
    require_quorum: bool = True,
) -> Optional[str]:
    """Validate a block against its parent and the prior state. Returns
    None if valid, otherwise an error string.

    Checks:
    1. Header signature is valid.
    2. parent_hash matches the parent's hash (or is "0"*64 at genesis).
    3. level increments by 1.
    4. Proposer is in the validator set.
    5. txs_root matches the merkle of the included transactions.
    6. Applying the block yields the declared state_root.
    7. (optional) Commit quorum is met: > 2/3 of validator stake has signed.
    """
    if not block.header.verify_signature():
        return "invalid header signature"

    if parent_header is None:
        if block.header.level != 0:
            return "non-genesis block with no parent"
        if block.header.parent_hash != "0" * 64:
            return "genesis must have zero parent_hash"
    else:
        if block.header.level != parent_header.level + 1:
            return f"non-monotonic level: parent {parent_header.level}, block {block.header.level}"
        if block.header.parent_hash != parent_header.hash_hex():
            return "parent_hash mismatch"

    if not any(v["address"] == block.header.proposer for v in validator_set):
        return "proposer is not in validator set"

    expected_txs_root = txs_merkle_root_hex(block.transactions)
    if block.header.txs_root != expected_txs_root:
        return "txs_root mismatch"

    # Optional fee floor / block size cap (consensus rule; off by default).
    # Read from the prior state so every node applies the identical rule.
    fee_err = check_fee_rules(block.transactions, fee_params(state_before))
    if fee_err:
        return fee_err

    new_state, _ = apply_block(state_before, block)
    if state_root_hex(new_state) != block.header.state_root:
        return "state_root mismatch after applying transactions"

    if require_quorum and block.header.level > 0:
        # 2/3+ stake must have signed.
        total_stake = sum(v["stake"] for v in validator_set)
        # In this reference implementation, we trust commit signatures are
        # validated upstream; we just count them as a proportional weight.
        # A production implementation verifies each commit signature against
        # the block hash and the validator's registered key.
        committed_stake = 0
        signed_by = set()
        # Format: each commit is "kn1...:ksig...". Production: structured.
        for entry in block.commits:
            if ":" in entry:
                addr, _sig = entry.split(":", 1)
                if addr in signed_by:
                    continue
                v = next((v for v in validator_set if v["address"] == addr), None)
                if v:
                    committed_stake += v["stake"]
                    signed_by.add(addr)
        if committed_stake * 3 <= total_stake * 2:
            return f"insufficient commit stake: {committed_stake}/{total_stake} (need > 2/3)"

    return None


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
        self.validators = validators

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return self.head.header.level

    def append(self, block: Block) -> None:
        parent = self.head.header
        err = validate_block(block, parent, self.state, self.validators, require_quorum=False)
        if err is not None:
            raise ValueError(f"block invalid: {err}")
        new_state, _ = apply_block(self.state, block)
        self.state = new_state
        self.blocks.append(block)
