# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""A double vote is kept, the supply counts what exists, the treasury sends nothing.

Four defects of the node, found while the schemas of structure version 1
were written (docs/api-stability.md, section 9), and closed here in the
node as it is, without a change of format:

- a validator that voted two ways on a protocol proposal, by two
  transactions, left no trace. The chain noted the double vote in an object
  that it then threw away, and `slash_equivocation` found nothing to punish;
- a chain whose genesis names no treasury counted the share of the treasury
  in its supply, block after block, and credited it to nobody. The half of
  a lost proposal bond that goes to the treasury was counted the same way;
- a proposer without a stake of its own received the bonus of the proposer
  and nothing else. The rest of the reward was counted and credited to
  nobody, even when the whole weight of that proposer came from delegators;
- the treasury address was an address like any other. Whoever held a key
  for it emptied it by a transfer, without a proposal and without a vote,
  and the genesis of the repository gave it the address of the Foundation.

The rules now:

- on the protocol track the first vote of a validator in a phase stands. A
  later vote that says something else fails, as before, and is kept as a
  double vote, once for that validator and that phase, with the level of
  its block. `slash_equivocation` punishes it, once;
- the supply grows by what a block credits. Without a treasury address the
  share of the treasury is not minted, and the whole of a lost bond is
  burned;
- a proposer without a stake of its own receives what the treasury does
  not, and shares it with its delegators like any reward;
- a transaction sent by the treasury address is refused before anything is
  charged: at the door of a mempool, by a proposer and in a block. What the
  treasury holds leaves it by a treasury vote. A genesis whose treasury is
  one of its validators is refused, and the genesis of the repository gives
  the treasury an address of its own, for which nobody has a key.

A test named `test_control_...` passed before these rules and still does:
it shows that what the others catch is the defect, and not the way they
are written.
"""

from __future__ import annotations

import copy
import json
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_governance_integration import _bake_one_block
from test_mempool_full import node_of
from test_phase_d_bonded_stake import _vote
from test_proposer_selection import chain_of

from kern import chain, governance
from kern.block import Block, BlockHeader, txs_merkle_root_hex
from kern.chain import (
    DEFAULT_COMMISSION_PCT, DROP, admission_error, apply_block, apply_transaction, consensus_validator_set,
    fee_params, initial_state_from_genesis, mempool_pass, mempool_verdict, validate_block,
)
from kern.consensus import propose_block
from kern.crypto import PREFIX_PUBKEY, KernKeypair, address_from_pubkey, address_is_valid, b58check_encode, verify
from kern.governance import DEFAULT_PROTOCOL_BOND, ProtocolGovernance, Vote
from kern.issuance import PPM, distribute_baker_pool, reward_per_block, split_reward
from kern.transaction import (
    OpKind, Transaction, Waiting, make_attest, make_call, make_delegate_stake, make_governance_propose,
    make_governance_vote, make_origination, make_revoke_attestation, make_slash_attestation_equivocation,
    make_slash_consensus_equivocation, make_slash_equivocation, make_transfer, make_undelegate_stake,
)

ROOT = Path(__file__).resolve().parent.parent
KRN = 1_000_000
# What every account of these chains holds at the genesis, and the stake of a
# validator: large enough for a block to mint tens of thousands of mukrn, so
# that no share of a reward is rounded down to nothing.
RICH = 5_000_000 * KRN
STAKE = 10_000_000 * KRN
SENDS_NOTHING = "the treasury address sends no transaction"
DOUBLE_VOTE = "equivocation detected; original vote stands"
A_CHANGE = {"params": {"i_max_ppm": 50_000}}
COUNTER = (ROOT / "kern" / "skald" / "examples" / "counter.skald").read_text(encoding="utf-8")


def key(n: int) -> KernKeypair:
    return KernKeypair.from_seed(bytes([n]) * 32)


BAKER, SECOND = key(0x11), key(0x12)     # the validators; BAKER proposes every block
ALICE, BOB, CAROL, DAVE = key(0xA1), key(0xB1), key(0xCA), key(0xDA)
HOLDER = key(0x7E)                       # has the key of the address that some of these chains name as their treasury
NO_KEY = address_from_pubkey(b"a treasury nobody has a key for")


def a_genesis(stakes=(STAKE,), treasury=NO_KEY, treasury_holds=0, **more) -> dict:
    """What a network of one or two validators starts from. Every account
    holds RICH, and a validator its stake on top."""
    validators = [{"address": kp.address, "pubkey": kp.public_key_b58, "stake": stake}
                  for kp, stake in zip((BAKER, SECOND), stakes)]
    balances = {kp.address: RICH for kp in (BAKER, SECOND, ALICE, BOB, CAROL, DAVE, HOLDER)}
    for validator in validators:
        balances[validator["address"]] += validator["stake"]
    genesis = {"balances": balances, "validators": validators, **more}
    if treasury is not None:
        genesis["treasury_address"] = treasury
        if treasury_holds:
            balances[treasury] = treasury_holds
    return genesis


def first_state(**what) -> dict:
    return initial_state_from_genesis(a_genesis(**what))


def held(state: dict) -> int:
    """What exists in a state: what the balances, the stakes, the
    delegations, live or ended, and the bonds of attestations and of
    proposals hold."""
    governance = state.get("governance", {})
    return (sum(state["balances"].values())
            + sum(validator.get("stake", 0) for validator in state["validators"])
            + sum(entry.get("amount", 0) for entry in state.get("delegations", {}).values())
            + sum(entry.get("amount", 0) for entries in state.get("delegation_unbonding", {}).values()
                  for entry in entries)
            + sum(attestation.get("bond", 0) for attestation in state.get("attestations", {}).values())
            + sum(bond.get("amount", 0) for track in ("protocol", "treasury")
                  for bond in governance.get(track, {}).get("bonds", {}).values()))


def gap(state: dict) -> int:
    """What the supply counts and nobody holds. Zero, always."""
    return state["total_supply"] - held(state)


def step(state: dict, *txs: Transaction):
    """One more block, proposed by BAKER with `txs` waiting: the state after
    it, and what each of them did. The block takes them all."""
    after, block = _bake_one_block(state, BAKER, list(txs))
    assert [tx.hash_hex() for tx in block.transactions] == [tx.hash_hex() for tx in txs]
    _, results = apply_block(state, block)
    return after, results


def run(state: dict, blocks: int = 1) -> dict:
    for _ in range(blocks):
        state, _ = _bake_one_block(state, BAKER)
    return state


def run_to(state: dict, level: int) -> dict:
    """The state after the block of `level`, with empty blocks up to it."""
    return run(state, level - state.get("_current_level", 0))


def proposal(state: dict, pid: str, track: str = "protocol") -> dict:
    return state["governance"][track]["proposals"][pid]


def stake_of(state: dict, validator: KernKeypair) -> int:
    return next(v["stake"] for v in state["validators"] if v["address"] == validator.address)


def voting(state: dict | None = None):
    """A chain whose protocol proposal is in its first vote: the state and
    the proposal."""
    state = first_state() if state is None else state
    state, (proposed,) = step(state, make_governance_propose(BAKER, "protocol", A_CHANGE, nonce=0))
    assert proposed.ok
    (pid,) = state["governance"]["protocol"]["proposals"]
    state = run_to(state, 102)
    assert proposal(state, pid)["phase"] == "exploration"
    return state, pid


def vote(state: dict, voter: KernKeypair, pid: str, choice: str, track: str = "protocol"):
    """`voter` votes in the next block: the state after it, and what the
    vote did."""
    tx = make_governance_vote(voter, track, pid, choice, nonce=state["nonces"].get(voter.address, 0))
    state, (result,) = step(state, tx)
    return state, result


# ---------------------------------------------------------------------------
# A double vote is kept
# ---------------------------------------------------------------------------

def test_a_second_vote_that_says_something_else_is_kept_as_a_double_vote():
    state, pid = voting()
    nonce = state["nonces"][BAKER.address]
    state, first = vote(state, BAKER, pid, "yes")
    state, second = vote(state, BAKER, pid, "no")
    assert first.ok and not second.ok and second.error == DOUBLE_VOTE
    assert state["nonces"][BAKER.address] == nonce + 2                              # both votes paid
    assert proposal(state, pid)["votes"]["exploration"] == {BAKER.address: "yes"}   # and the first one stands
    assert proposal(state, pid)["equivocations"] == [{
        "voter": BAKER.address, "phase": "exploration", "first_vote": "yes", "second_vote": "no",
        "second_at_level": state["_current_level"]}]


def test_a_double_vote_is_punished_once():
    state, pid = voting(first_state(stakes=(STAKE, STAKE // 2)))
    state, _ = vote(state, SECOND, pid, "yes")
    state, _ = vote(state, SECOND, pid, "no")
    stake, carol = stake_of(state, SECOND), state["balances"][CAROL.address]
    cut = stake * 30 // 100
    state, (report,) = step(state, make_slash_equivocation(CAROL, pid, SECOND.address, nonce=0))
    assert report.ok
    assert stake_of(state, SECOND) == stake - cut
    assert state["balances"][CAROL.address] == carol - 1_000 + cut * 10 // 100      # its fee, and a tenth of the cut
    (kept,) = proposal(state, pid)["equivocations"]
    assert (kept["consumed"], kept["reporter"], kept["slashed_at_level"]) == (True, CAROL.address,
                                                                              state["_current_level"])
    assert gap(state) == 0
    state, (again,) = step(state, make_slash_equivocation(CAROL, pid, SECOND.address, nonce=1))
    assert not again.ok and again.error == "no unconsumed equivocation for this voter"
    assert stake_of(state, SECOND) == stake - cut and gap(state) == 0


def test_a_third_vote_adds_nothing():
    state, pid = voting()
    state, _ = vote(state, BAKER, pid, "yes")
    state, _ = vote(state, BAKER, pid, "no")
    kept = copy.deepcopy(proposal(state, pid)["equivocations"])
    answers = []
    for choice in ("abstain", "no", "yes"):
        state, result = vote(state, BAKER, pid, choice)
        answers.append((result.ok, result.error))
    # The first vote, said again, is still a vote. The two others differ from it, like the second one did.
    assert answers == [(False, DOUBLE_VOTE), (False, DOUBLE_VOTE), (True, None)]
    assert len(kept) == 1 and proposal(state, pid)["equivocations"] == kept
    assert proposal(state, pid)["votes"]["exploration"] == {BAKER.address: "yes"}


def test_control_the_same_vote_twice_is_no_double_vote():
    state, pid = voting()
    state, first = vote(state, BAKER, pid, "abstain")
    state, again = vote(state, BAKER, pid, "abstain")
    assert first.ok and again.ok
    assert proposal(state, pid)["equivocations"] == []
    assert proposal(state, pid)["votes"]["exploration"] == {BAKER.address: "abstain"}


def test_a_double_vote_of_the_second_vote_is_kept_and_punished_on_its_own():
    state, pid = voting()
    state, _ = vote(state, BAKER, pid, "yes")
    state, _ = vote(state, BAKER, pid, "no")
    state = run_to(state, 302)
    assert proposal(state, pid)["phase"] == "adoption"
    state, first = vote(state, BAKER, pid, "yes")
    state, second = vote(state, BAKER, pid, "abstain")
    assert first.ok and not second.ok and second.error == DOUBLE_VOTE
    kept = proposal(state, pid)["equivocations"]
    assert [(e["phase"], e["first_vote"], e["second_vote"]) for e in kept] == [
        ("exploration", "yes", "no"), ("adoption", "yes", "abstain")]
    assert kept[0]["second_at_level"] == 104 and kept[1]["second_at_level"] == state["_current_level"] == 304
    stake = stake_of(state, BAKER)
    for nonce in (0, 1):
        state, (report,) = step(state, make_slash_equivocation(CAROL, pid, BAKER.address, nonce=nonce))
        assert report.ok
    once = stake - stake * 30 // 100
    assert stake_of(state, BAKER) == once - once * 30 // 100
    state, (third,) = step(state, make_slash_equivocation(CAROL, pid, BAKER.address, nonce=2))
    assert not third.ok and stake_of(state, BAKER) == once - once * 30 // 100 and gap(state) == 0
    # The first vote of each phase stood: the proposal is adopted.
    assert proposal(run_to(state, 402), pid)["phase"] == "activated"


def test_once_punished_a_voter_has_no_other_double_vote_in_that_phase():
    state, pid = voting()
    state, _ = vote(state, BAKER, pid, "yes")
    state, _ = vote(state, BAKER, pid, "no")
    state, (report,) = step(state, make_slash_equivocation(CAROL, pid, BAKER.address, nonce=0))
    assert report.ok
    stake = stake_of(state, BAKER)
    state, later = vote(state, BAKER, pid, "abstain")
    assert not later.ok and later.error == DOUBLE_VOTE
    assert [e["consumed"] for e in proposal(state, pid)["equivocations"]] == [True]
    state, (again,) = step(state, make_slash_equivocation(CAROL, pid, BAKER.address, nonce=1))
    assert not again.ok and stake_of(state, BAKER) == stake


def test_each_validator_has_its_own_double_vote():
    state, pid = voting(first_state(stakes=(STAKE, STAKE // 2)))
    nonces = {kp.address: state["nonces"].get(kp.address, 0) for kp in (BAKER, SECOND)}
    state, firsts = step(state, make_governance_vote(BAKER, "protocol", pid, "yes", nonces[BAKER.address]),
                         make_governance_vote(SECOND, "protocol", pid, "no", nonces[SECOND.address]))
    state, seconds = step(state, make_governance_vote(BAKER, "protocol", pid, "abstain", nonces[BAKER.address] + 1),
                          make_governance_vote(SECOND, "protocol", pid, "yes", nonces[SECOND.address] + 1))
    assert [r.ok for r in firsts] == [True, True] and [r.error for r in seconds] == [DOUBLE_VOTE, DOUBLE_VOTE]
    assert [(e["voter"], e["first_vote"], e["second_vote"]) for e in proposal(state, pid)["equivocations"]] == [
        (BAKER.address, "yes", "abstain"), (SECOND.address, "no", "yes")]
    assert proposal(state, pid)["votes"]["exploration"] == {BAKER.address: "yes", SECOND.address: "no"}
    stakes = {kp.address: stake_of(state, kp) for kp in (BAKER, SECOND)}
    state, reports = step(state, make_slash_equivocation(CAROL, pid, SECOND.address, nonce=0),
                          make_slash_equivocation(CAROL, pid, BAKER.address, nonce=1))
    assert [r.ok for r in reports] == [True, True] and gap(state) == 0
    assert all(stake_of(state, kp) == stakes[kp.address] - stakes[kp.address] * 30 // 100 for kp in (BAKER, SECOND))


def test_the_object_itself_keeps_one_double_vote_for_a_voter_and_a_phase():
    """Without a chain around it: the object that the chain reads from its
    state and writes back."""
    governance = ProtocolGovernance([{"address": name, "stake": 10} for name in ("kn1a", "kn1b")])
    ok, _, pid = governance.submit("kn1a", A_CHANGE, current_level=0)
    governance.advance_phases(100)
    said = [("kn1a", "yes"), ("kn1a", "no"), ("kn1a", "abstain"), ("kn1b", "no"), ("kn1a", "yes"), ("kn1b", "no"),
            ("kn1b", "abstain")]
    answers = [governance.vote(pid, voter, Vote(choice), level) for level, (voter, choice) in enumerate(said, 101)]
    assert ok and answers == [(True, "ok"), (False, DOUBLE_VOTE), (False, DOUBLE_VOTE), (True, "ok"), (True, "ok"),
                              (True, "ok"), (False, DOUBLE_VOTE)]
    assert governance.proposals[pid].equivocations == [
        {"voter": "kn1a", "phase": "exploration", "first_vote": "yes", "second_vote": "no", "second_at_level": 102},
        {"voter": "kn1b", "phase": "exploration", "first_vote": "no", "second_vote": "abstain",
         "second_at_level": 107}]
    assert governance.proposals[pid].votes["exploration"] == {"kn1a": "yes", "kn1b": "no"}


def test_a_proposer_and_a_validator_agree_on_a_block_that_holds_a_double_vote():
    state, pid = voting()
    state, _ = vote(state, BAKER, pid, "yes")
    second = make_governance_vote(BAKER, "protocol", pid, "no", nonce=state["nonces"][BAKER.address])
    parent = BlockHeader(level=state["_current_level"], payload_round=0, timestamp=1_794_000_000,
                         parent_hash="1" * 64, state_root="", txs_root=txs_merkle_root_hex([]),
                         proposer=BAKER.address, proposer_pubkey=BAKER.public_key_b58)
    parent.sign(BAKER)
    block = propose_block(parent=Block(header=parent, transactions=[], commits=[]), mempool=[second],
                          proposer_keypair=BAKER, proposer_pubkey_b58=BAKER.public_key_b58, state_before=state)
    assert [tx.hash_hex() for tx in block.transactions] == [second.hash_hex()]      # it is charged: it is in the block
    assert validate_block(block, parent, state, consensus_validator_set(state), require_quorum=False) is None
    after, _ = apply_block(state, block)
    assert [e["second_at_level"] for e in proposal(after, pid)["equivocations"]] == [block.header.level]


def test_control_a_vote_refused_for_another_reason_leaves_the_proposals_as_they_were():
    """The chain writes the proposals back after every vote of the protocol
    track, refused or not. What it writes is what it read, but for a double
    vote."""
    state = first_state(stakes=(STAKE, STAKE // 2))
    state, _ = step(state, make_governance_propose(BAKER, "protocol", A_CHANGE, nonce=0))
    (pid,) = state["governance"]["protocol"]["proposals"]
    for when, voter, named, reason in ((state, SECOND, pid, "voting not open in phase submitted"),
                                       (state, SECOND, "00" * 32, "no such proposal"),
                                       (run_to(state, 102), CAROL, pid, "voter not in validator set")):
        after = copy.deepcopy(when)
        refused = apply_transaction(after, make_governance_vote(voter, "protocol", named, "yes", nonce=0),
                                    baker=BAKER.address)
        assert not refused.ok and refused.error == reason
        assert after["governance"] == when["governance"] and after["nonces"][voter.address] == 1


def test_control_on_the_treasury_track_a_later_vote_replaces_the_earlier_one():
    state = first_state(treasury_holds=RICH)
    payment = {"recipients": [{"address": DAVE.address, "amount": 5 * KRN}]}
    state, (proposed,) = step(state, make_governance_propose(CAROL, "treasury", payment, nonce=0))
    (pid,) = state["governance"]["treasury"]["proposals"]
    state = run_to(state, 202)
    assert proposed.ok and proposal(state, pid, "treasury")["phase"] == "voting"
    state, first = vote(state, BAKER, pid, "yes", track="treasury")
    state, second = vote(state, BAKER, pid, "no", track="treasury")
    assert first.ok and second.ok
    assert proposal(state, pid, "treasury")["votes"] == {BAKER.address: "no"}
    assert "equivocations" not in proposal(state, pid, "treasury")


# ---------------------------------------------------------------------------
# The supply counts what exists
# ---------------------------------------------------------------------------

def test_without_a_treasury_its_share_of_a_reward_is_not_minted():
    named, alone = first_state(), first_state(treasury=None)
    assert named["total_supply"] == alone["total_supply"] and gap(alone) == 0
    twin, after = run(named), run(alone)
    share = twin["balances"][NO_KEY]                                    # what the treasury of the twin received
    earned = twin["balances"][BAKER.address] - named["balances"][BAKER.address]
    assert share > 0 and earned > 0
    assert twin["total_supply"] - named["total_supply"] == earned + share
    # Without a treasury the proposer receives the same, and nothing else is minted.
    assert after["balances"][BAKER.address] - alone["balances"][BAKER.address] == earned
    assert after["total_supply"] - alone["total_supply"] == earned
    assert set(after["balances"]) == set(alone["balances"])
    for _ in range(10):
        after = run(after)
        assert gap(after) == 0


QUIET = {"i_min_ppm": 0, "i_max_ppm": 0}          # no reward: the bond alone moves the supply


def a_lost_bond(treasury, bond=DEFAULT_PROTOCOL_BOND):
    """A protocol proposal for which nobody votes, on a chain without
    rewards: the state that holds its bond, and the state after its
    rejection."""
    state = first_state(treasury=treasury, issuance_params=QUIET)
    state, (proposed,) = step(state, make_governance_propose(BAKER, "protocol", A_CHANGE, nonce=0))
    (pid,) = state["governance"]["protocol"]["proposals"]
    assert proposed.ok and state["governance"]["protocol"]["bonds"][pid]["amount"] == bond
    after = run_to(state, 202)
    assert proposal(after, pid)["phase"] == "rejected" and after["governance"]["protocol"]["bonds"] == {}
    return state, after


def test_without_a_treasury_the_whole_of_a_lost_bond_is_burned():
    state, after = a_lost_bond(None)
    assert gap(state) == 0
    assert after["total_supply"] == state["total_supply"] - DEFAULT_PROTOCOL_BOND
    assert after["balances"] == state["balances"] and gap(after) == 0


def test_control_with_a_treasury_half_of_a_lost_bond_is_burned_and_it_keeps_the_other_half():
    state, after = a_lost_bond(NO_KEY)
    assert after["total_supply"] == state["total_supply"] - DEFAULT_PROTOCOL_BOND // 2
    assert after["balances"][NO_KEY] == DEFAULT_PROTOCOL_BOND - DEFAULT_PROTOCOL_BOND // 2
    assert gap(state) == 0 and gap(after) == 0


def test_a_lost_bond_of_an_odd_amount_leaves_nothing_behind(monkeypatch):
    """The two halves of a bond are not equal when its amount is odd: the
    half that is burned is rounded down, and the other is the rest."""
    odd = DEFAULT_PROTOCOL_BOND + 1
    monkeypatch.setattr(governance, "DEFAULT_PROTOCOL_BOND", odd)
    state, after = a_lost_bond(None, odd)
    assert after["total_supply"] == state["total_supply"] - odd and gap(after) == 0
    state, after = a_lost_bond(NO_KEY, odd)
    assert after["total_supply"] == state["total_supply"] - odd // 2 and gap(after) == 0
    assert after["balances"][NO_KEY] == odd - odd // 2 == odd // 2 + 1


EVERY_TABLE = {"delegations", "delegations that have ended", "bonds of attestations", "bonds of protocol proposals",
               "bonds of treasury proposals", "contracts"}


def tables(state: dict) -> set:
    """The tables of a state that hold something, besides the balances of
    accounts and the stakes."""
    governance = state["governance"]
    full = {
        "delegations": any(entry["amount"] for entry in state["delegations"].values()),
        "delegations that have ended": any(entry["amount"] for entries in state.get("delegation_unbonding", {}).values()
                                           for entry in entries),
        "bonds of attestations": any(a.get("bond", 0) for a in state["attestations"].values()),
        "bonds of protocol proposals": bool(governance["protocol"]["bonds"]),
        "bonds of treasury proposals": bool(governance["treasury"]["bonds"]),
        "contracts": any(state["balances"].get(address, 0) for address in state["contracts"]),
    }
    return {name for name, holds in full.items() if holds}


def a_busy_chain(treasury, baker_stake=STAKE):
    """Every state of a chain of 403 blocks that puts something in every
    table, and whether each of its transactions succeeded: transfers, a
    delegation in two parts that ends and comes back, another one, three
    attestations of which two contradict each other and one is revoked, a
    contract that is paid, a protocol proposal and two treasury proposals,
    votes, a double vote, and a report of every kind."""
    states = [first_state(stakes=(baker_stake, STAKE // 2), treasury=treasury, treasury_holds=RICH if treasury else 0,
                          epoch_blocks=5, delegation_unbonding_blocks=10, attestation_unbonding_blocks=8)]
    done: dict = {}

    def nonce(kp, ahead=0):
        return states[-1]["nonces"].get(kp.address, 0) + ahead

    def block(level, txs):
        while states[-1].get("_current_level", 0) < level - 1:
            states.append(run(states[-1]))
        state, results = step(states[-1], *txs.values())
        states.append(state)
        done.update({name: result.ok for name, result in zip(txs, results)})
        return dict(zip(txs, results))

    first = block(1, {
        "a transfer": make_transfer(DAVE, CAROL.address, 5 * KRN, nonce(DAVE)),
        "a transfer of more than its sender holds": make_transfer(DAVE, CAROL.address, 10 * RICH, nonce(DAVE, 1)),
        "a delegation": make_delegate_stake(ALICE, BAKER.address, nonce(ALICE), amount=300 * KRN),
        "an attestation": make_attest(BOB, "kyc", "subject", {"ok": True}, nonce(BOB), bond=50 * KRN),
        "one that contradicts it": make_attest(BOB, "kyc", "subject", {"ok": False}, nonce(BOB, 1), bond=20 * KRN),
        "another attestation": make_attest(BOB, "kyc", "another", {"ok": True}, nonce(BOB, 2), bond=10 * KRN),
    })
    one, two, three = (first[name].extra["attestation_id"]
                       for name in ("an attestation", "one that contradicts it", "another attestation"))
    second = block(2, {
        "more of that delegation": make_delegate_stake(ALICE, BAKER.address, nonce(ALICE), amount=100 * KRN),
        "a protocol proposal": make_governance_propose(BAKER, "protocol", A_CHANGE, nonce(BAKER)),
        "a treasury proposal": make_governance_propose(
            CAROL, "treasury", {"recipients": [{"address": DAVE.address, "amount": 5 * KRN}]}, nonce(CAROL)),
        "a treasury proposal nobody votes for": make_governance_propose(
            CAROL, "treasury", {"recipients": [{"address": CAROL.address, "amount": 1}]}, nonce(CAROL, 1), salt=1),
        "a contract": make_origination(DAVE, COUNTER, {"count": 0, "owner": DAVE.address}, nonce(DAVE)),
    })
    (protocol,) = states[-1]["governance"]["protocol"]["proposals"]
    paid = next(iter(states[-1]["governance"]["treasury"]["proposals"]), "00" * 32)
    block(3, {
        "a call that pays the contract": make_call(DAVE, second["a contract"].new_contract, "increment", {},
                                                   amount=7 * KRN, nonce=nonce(DAVE)),
        "a report of the two attestations": make_slash_attestation_equivocation(CAROL, one, two, nonce(CAROL)),
        "a revocation": make_revoke_attestation(BOB, three, nonce(BOB)),
    })
    block(4, {"a report of two votes of the consensus": make_slash_consensus_equivocation(
        CAROL, _vote(SECOND, "aa" * 32, 3).to_dict(), _vote(SECOND, "bb" * 32, 3).to_dict(), nonce(CAROL))})
    block(5, {"the end of the delegation": make_undelegate_stake(ALICE, nonce(ALICE))})
    block(20, {"a delegation again": make_delegate_stake(ALICE, BAKER.address, nonce(ALICE), amount=300 * KRN)})
    block(103, {"a vote": make_governance_vote(BAKER, "protocol", protocol, "yes", nonce(BAKER)),
                "the vote of the other validator": make_governance_vote(SECOND, "protocol", protocol, "yes",
                                                                        nonce(SECOND))})
    block(104, {"a second vote that differs": make_governance_vote(BAKER, "protocol", protocol, "no", nonce(BAKER))})
    block(105, {"a report of the double vote": make_slash_equivocation(CAROL, protocol, BAKER.address, nonce(CAROL))})
    block(203, {"a treasury vote": make_governance_vote(BAKER, "treasury", paid, "yes", nonce(BAKER)),
                "the treasury vote of the other validator": make_governance_vote(SECOND, "treasury", paid, "yes",
                                                                                 nonce(SECOND))})
    while states[-1]["_current_level"] < 403:
        states.append(run(states[-1]))
    return states, done


def what_a_busy_chain_shows(treasury, baker_stake=STAKE):
    """The supply is what exists after every block of a busy chain, every
    table held something on the way, and what could succeed did."""
    states, done = a_busy_chain(treasury, baker_stake)
    for state in states:
        assert gap(state) == 0, f"level {state.get('_current_level', 0)}: the supply counts {gap(state)} mukrn too many"
    with_treasury = {"a treasury proposal", "a treasury proposal nobody votes for", "a treasury vote",
                     "the treasury vote of the other validator"}
    fail = {"a transfer of more than its sender holds", "a second vote that differs"}
    # A report of the double vote finds it since the double vote is kept: the tests that are not controls say so.
    assert {name for name, ok in done.items() if not ok} - {"a report of the double vote"} == (
        fail if treasury else fail | with_treasury)
    assert set().union(*map(tables, states)) == (
        EVERY_TABLE if treasury else EVERY_TABLE - {"bonds of treasury proposals"})
    last = states[-1]
    assert tables(last) == {"delegations", "contracts"}                                 # every bond has left
    assert stake_of(last, SECOND) == STAKE // 2 - (STAKE // 2) * 30 // 100              # the two votes of the consensus
    assert sum(later["total_supply"] < earlier["total_supply"] for earlier, later in zip(states, states[1:])) >= 3
    return states, done


def test_control_the_supply_is_what_exists_after_every_block_of_a_chain_that_names_a_treasury():
    states, _ = what_a_busy_chain_shows(NO_KEY)
    paid = states[-1]["governance"]["treasury"]["proposals"]
    assert sorted(p["phase"] for p in paid.values()) == ["executed", "rejected"]


def test_the_supply_is_what_exists_after_every_block_of_a_chain_that_names_no_treasury():
    states, done = what_a_busy_chain_shows(None)
    assert done["a report of the double vote"]
    assert stake_of(states[-1], BAKER) == STAKE - STAKE * 30 // 100


def test_the_supply_is_what_exists_after_every_block_when_the_weight_of_the_proposer_is_all_delegated():
    states, done = what_a_busy_chain_shows(NO_KEY, baker_stake=0)
    assert done["a report of the double vote"] and stake_of(states[-1], BAKER) == 0
    # The delegation that backed the double vote lost what a stake would have lost.
    assert states[-1]["delegations"][ALICE.address]["amount"] == 300 * KRN - 300 * KRN * 30 // 100


# ---------------------------------------------------------------------------
# A proposer without a stake of its own
# ---------------------------------------------------------------------------

def a_reward(state: dict, staked: int):
    """What the next block of `state` mints, what the treasury receives of
    it, and the rest."""
    total = reward_per_block(state["total_supply"], staked * PPM // state["total_supply"])
    share, rest = split_reward(total)
    assert share > 0 and rest > share
    return total, share, rest


def test_a_proposer_without_a_stake_of_its_own_receives_what_the_treasury_does_not():
    state = first_state(stakes=(0, STAKE // 2))
    total, share, rest = a_reward(state, staked=STAKE // 2)
    after = run(state)
    assert after["balances"][BAKER.address] - state["balances"][BAKER.address] == rest
    assert after["balances"][NO_KEY] == share
    assert after["total_supply"] == state["total_supply"] + total and gap(after) == 0
    assert gap(run(after, 10)) == 0


def test_a_proposer_whose_weight_is_all_delegated_shares_the_reward_with_its_delegators():
    state = first_state(stakes=(0, STAKE // 2))
    state, (bonded,) = step(state, make_delegate_stake(ALICE, BAKER.address, nonce=0, amount=400 * KRN))
    assert bonded.ok and gap(state) == 0
    total, share, rest = a_reward(state, staked=STAKE // 2 + 400 * KRN)
    commission = rest * DEFAULT_COMMISSION_PCT // 100
    after = run(state)
    assert after["balances"][BAKER.address] - state["balances"][BAKER.address] == commission
    assert after["balances"][ALICE.address] - state["balances"][ALICE.address] == rest - commission
    assert after["balances"][NO_KEY] - state["balances"][NO_KEY] == share
    assert after["total_supply"] == state["total_supply"] + total and gap(after) == 0


def test_the_part_of_the_validators_is_given_out_whole_whatever_their_stakes():
    assert distribute_baker_pool(1_000, "v0", [{"address": "v0", "stake": 0}]) == {"v0": 1_000}
    nobody_staked = [{"address": "v0", "stake": 0}, {"address": "v1", "stake": 0}]
    assert distribute_baker_pool(1_000, "v0", nobody_staked) == {"v0": 1_000}
    assert distribute_baker_pool(1_000, "v1", nobody_staked) == {"v1": 1_000}       # the proposer, listed or not first
    assert distribute_baker_pool(0, "v0", [{"address": "v0", "stake": 0}]) == {}
    rng = random.Random(20261117)
    for _ in range(2_000):
        endorsers = [{"address": f"v{n}", "stake": rng.choice((0, 0, 1, rng.randrange(10**12)))}
                     for n in range(rng.randrange(1, 5))]
        pool = rng.randrange(1, 10**9)
        assert sum(distribute_baker_pool(pool, "v0", endorsers).values()) == pool, (pool, endorsers)


# ---------------------------------------------------------------------------
# The treasury sends nothing
# ---------------------------------------------------------------------------

def a_treasury_someone_has_a_key_for() -> dict:
    """A state whose treasury is the address of HOLDER, the way the genesis
    of the repository gave the treasury the address of the Foundation."""
    state = first_state(treasury=HOLDER.address, treasury_holds=RICH)
    state["_current_level"] = 5
    return state


def one_of_each_kind(sender: KernKeypair) -> dict:
    """A first transaction of `sender` of every kind, and two proposals."""
    votes = [_vote(SECOND, block * 32, 1).to_dict() for block in ("aa", "bb")]
    payment = {"recipients": [{"address": DAVE.address, "amount": 5 * KRN}]}
    return {
        "a transfer": make_transfer(sender, DAVE.address, 999 * KRN, nonce=0),
        "an origination": make_origination(sender, COUNTER, {"count": 0, "owner": sender.address}, nonce=0),
        "a call": make_call(sender, DAVE.address, "increment", {}, amount=5, nonce=0),
        "a protocol proposal": make_governance_propose(sender, "protocol", A_CHANGE, nonce=0),
        "a treasury proposal": make_governance_propose(sender, "treasury", payment, nonce=0),
        "a vote": make_governance_vote(sender, "protocol", "00" * 32, "yes", nonce=0),
        "a report of a double vote": make_slash_equivocation(sender, "00" * 32, BAKER.address, nonce=0),
        "a report of two votes of the consensus": make_slash_consensus_equivocation(sender, *votes, nonce=0),
        "a delegation": make_delegate_stake(sender, BAKER.address, nonce=0, amount=500 * KRN),
        "the end of a delegation": make_undelegate_stake(sender, nonce=0),
        "an attestation": make_attest(sender, "kyc", "subject", {"ok": True}, nonce=0, bond=100 * KRN),
        "a revocation": make_revoke_attestation(sender, "00" * 32, nonce=0),
        "a report of two attestations": make_slash_attestation_equivocation(sender, "00" * 32, "11" * 32, nonce=0),
    }


KINDS = list(one_of_each_kind(HOLDER))


@pytest.mark.parametrize("name", KINDS)
def test_whatever_the_treasury_address_sends_is_refused_and_changes_nothing(name):
    state = a_treasury_someone_has_a_key_for()
    before = copy.deepcopy(state)
    result = apply_transaction(state, one_of_each_kind(HOLDER)[name], baker=BAKER.address)
    assert not result.ok and result.error == SENDS_NOTHING
    assert state == before


def test_control_the_same_transactions_of_an_account_are_charged():
    """Every kind is tried, and each of these transactions is one a block
    charges when its sender is not the treasury."""
    assert {tx.kind for tx in one_of_each_kind(HOLDER).values()} == set(OpKind)
    for name, tx in one_of_each_kind(HOLDER).items():
        state = first_state()
        state["_current_level"] = 5
        apply_transaction(state, tx, baker=BAKER.address)
        assert state["nonces"].get(HOLDER.address) == 1, name
        assert state["balances"][BAKER.address] == RICH + tx.fee, name


def test_a_fee_as_large_as_what_the_treasury_holds_moves_nothing():
    """Charged, such a transaction emptied the treasury into the balance of
    the proposer, whatever its operation then did."""
    state = a_treasury_someone_has_a_key_for()
    before = copy.deepcopy(state)
    result = apply_transaction(state, make_transfer(HOLDER, DAVE.address, 1, nonce=0, fee=RICH), baker=BAKER.address)
    assert not result.ok and result.error == SENDS_NOTHING and state == before


def test_it_is_refused_for_what_it_is_whatever_its_signature_and_its_nonce():
    """The door of a mempool looks at no signature, and it refuses this
    sender before it looks at a nonce. A block gives the same reason as the
    door for the same transaction."""
    state = a_treasury_someone_has_a_key_for()
    before = copy.deepcopy(state)
    forged, ahead = make_transfer(HOLDER, DAVE.address, 1, nonce=0), make_transfer(HOLDER, DAVE.address, 1, nonce=3)
    forged.amount = 999 * KRN
    assert not forged.verify_signature() and ahead.verify_signature()
    for tx in (forged, ahead):
        result = apply_transaction(state, tx, baker=BAKER.address)
        assert not result.ok and result.error == SENDS_NOTHING == admission_error(tx, state)
    assert state == before


def test_the_reason_has_one_wording():
    assert chain.TREASURY_SENDS_NOTHING == SENDS_NOTHING


def test_control_anyone_gives_to_the_treasury():
    state = a_treasury_someone_has_a_key_for()
    result = apply_transaction(state, make_transfer(DAVE, HOLDER.address, 5, nonce=0), baker=BAKER.address)
    assert result.ok and state["balances"][HOLDER.address] == RICH + 5


def test_the_door_of_a_mempool_refuses_it_and_a_pass_removes_it():
    state = a_treasury_someone_has_a_key_for()
    fees = fee_params(state)
    sent, given = make_transfer(HOLDER, DAVE.address, 1, nonce=0), make_transfer(DAVE, HOLDER.address, 1, nonce=0)
    assert admission_error(sent, state) == SENDS_NOTHING and admission_error(given, state) is None
    assert mempool_verdict(sent.sender, sent.nonce, sent.fee, sent.encoded_size(), state, fees) == (DROP, SENDS_NOTHING)
    # Whatever its nonce: it does not wait for a turn that cannot come.
    assert mempool_verdict(sent.sender, 7, sent.fee, sent.encoded_size(), state, fees) == (DROP, SENDS_NOTHING)
    dead, waits = mempool_pass([Waiting.of(sent), Waiting.of(given)], state, fees)
    assert dead == [sent.hash_hex()] and waits == []


def test_a_node_refuses_it_at_its_door_and_keeps_nothing_of_it(tmp_path):
    node, storage = node_of(tmp_path, balances={HOLDER.address: RICH, DAVE.address: RICH})
    node.chain.state["treasury_address"] = HOLDER.address
    assert node.admit_transaction(make_transfer(HOLDER, DAVE.address, 1, nonce=0)) == SENDS_NOTHING
    assert node.admit_transaction(make_transfer(HOLDER, DAVE.address, 1, nonce=3)) == SENDS_NOTHING
    assert node.admit_transaction(make_transfer(DAVE, HOLDER.address, 1, nonce=0)) is None
    assert [(row.sender, row.nonce) for row in storage.waiting()] == [(DAVE.address, 0)]
    storage.close()


def test_a_proposer_leaves_it_out_of_its_block_and_takes_it_out_of_its_mempool():
    state = a_treasury_someone_has_a_key_for()
    sent = make_transfer(HOLDER, DAVE.address, 999 * KRN, nonce=0, fee=KRN)
    honest = make_transfer(DAVE, CAROL.address, 1, nonce=0)
    parent, _ = chain_of()
    evicted: list = []
    block = propose_block(parent=parent, mempool=[sent, honest], proposer_keypair=BAKER,
                          proposer_pubkey_b58=BAKER.public_key_b58, state_before=state, evict_out=evicted)
    assert [tx.hash_hex() for tx in block.transactions] == [honest.hash_hex()] and evicted == [sent.hash_hex()]


def test_a_block_that_carries_it_does_what_the_same_block_without_it_does():
    """A block that carries a transaction it cannot charge is still valid
    today; structure version 1 makes it invalid. The transaction changes
    nothing: the treasury keeps what it holds, and the proposer earns no
    fee."""
    state = a_treasury_someone_has_a_key_for()
    sent = make_transfer(HOLDER, DAVE.address, 999 * KRN, nonce=0, fee=KRN)

    def a_block(*txs):
        header = BlockHeader(level=6, payload_round=0, timestamp=1_794_000_000, parent_hash="1" * 64, state_root="",
                             txs_root=txs_merkle_root_hex(list(txs)), proposer=BAKER.address,
                             proposer_pubkey=BAKER.public_key_b58)
        return apply_block(state, Block(header=header, transactions=list(txs), commits=[]))

    with_it, (result,) = a_block(sent)
    without, _ = a_block()
    assert not result.ok and result.error == SENDS_NOTHING
    assert with_it == without and with_it["balances"][HOLDER.address] > RICH        # its share of the reward


def test_control_a_treasury_without_a_key_pays_what_a_vote_decides():
    state = first_state(treasury_holds=RICH)
    payment = {"recipients": [{"address": DAVE.address, "amount": 5 * KRN}]}
    state, (proposed,) = step(state, make_governance_propose(CAROL, "treasury", payment, nonce=0))
    (pid,) = state["governance"]["treasury"]["proposals"]
    state, said = vote(run_to(state, 202), BAKER, pid, "yes", track="treasury")
    dave = state["balances"][DAVE.address]
    state = run_to(state, 302)
    assert proposed.ok and said.ok and proposal(state, pid, "treasury")["phase"] == "executed"
    assert state["balances"][DAVE.address] == dave + 5 * KRN
    assert state["nonces"].get(NO_KEY, 0) == 0 and gap(state) == 0


def test_a_genesis_whose_treasury_is_one_of_its_validators_is_refused():
    for validator in (BAKER, SECOND):
        with pytest.raises(ValueError, match="treasury_address .* is the address of a validator"):
            first_state(stakes=(STAKE, STAKE), treasury=validator.address)
    # SECOND is no validator of this one.
    assert first_state(stakes=(STAKE,), treasury=SECOND.address)["treasury_address"] == SECOND.address


# ---------------------------------------------------------------------------
# The genesis of the repository
# ---------------------------------------------------------------------------

def the_builder():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_v1_genesis
    return build_v1_genesis


def the_genesis_of_the_repository() -> dict:
    return json.loads((ROOT / "genesis.json").read_text(encoding="utf-8"))


def test_the_genesis_of_the_repository_gives_the_treasury_an_address_of_its_own():
    built = the_builder().build_genesis()
    treasury = built["treasury_address"]
    assert address_is_valid(treasury)
    assert treasury not in built["balances"]                                # it starts empty
    assert treasury not in built["pool_addresses"].values()                 # it is not the Foundation, nor any pool
    assert treasury not in [validator["address"] for validator in built["validators"]]
    assert sum(built["balances"].values()) == built["total_supply"] == 100_000_000 * KRN
    # The file is what the builder writes.
    assert (ROOT / "genesis.json").read_text(encoding="utf-8") == json.dumps(built, indent=2, sort_keys=True)


def test_nobody_has_a_key_for_the_treasury_address_of_the_repository():
    builder = the_builder()
    treasury, text = the_genesis_of_the_repository()["treasury_address"], builder.TREASURY_TEXT
    # It is the hash of a text where an account has the hash of a key, and a key is 32 bytes.
    assert treasury == builder.treasury_address() == address_from_pubkey(text) and len(text) != 32
    # None of the seeds of one repeated byte, of which the builder takes its keys, leads to it.
    assert treasury not in {key(n).address for n in range(256)}
    # A transaction that gives the text as its key is not signed, on a chain that names no treasury either.
    forged = make_transfer(HOLDER, DAVE.address, 1, nonce=0)
    forged.sender, forged.sender_pubkey = treasury, b58check_encode(PREFIX_PUBKEY, text)
    assert not forged.verify_signature() and not verify(text, b"anything", bytes(64))
    state = first_state(treasury=None)
    state["balances"][treasury] = RICH
    before = copy.deepcopy(state)
    result = apply_transaction(state, forged, baker=BAKER.address)
    assert not result.ok and result.error == "invalid signature" and state == before


def test_on_the_genesis_of_the_repository_the_treasury_fills_from_nothing_and_the_foundation_keeps_its_own():
    genesis = the_genesis_of_the_repository()
    treasury, foundation = genesis["treasury_address"], genesis["pool_addresses"]["foundation"]
    state = initial_state_from_genesis(genesis)
    assert state["balances"].get(treasury, 0) == 0 and state["balances"][foundation] == 14_000_000 * KRN
    after, _ = _bake_one_block(state, key(0xB0))                            # the placeholder key of its only validator
    assert after["balances"][treasury] > 0 and after["balances"][foundation] == 14_000_000 * KRN
    assert after["total_supply"] > state["total_supply"] and gap(after) == 0
