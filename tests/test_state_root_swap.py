# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Integration test: governance amendment switches the chain's state-root
function from JSON to trie.

This is the v0.5 demonstration that protocol evolution happens through
on-chain rails — the chain replaces a core function of itself via a
governance vote, not via a hard fork.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.chain import state_root_hex, empty_state
from kern.governance import ProtocolGovernance, ProtocolPhase, Vote
from kern.trie import state_root_trie_hex


def _validators(stakes):
    return [
        {"address": f"kn1v{i:03d}{'a' * 30}"[:36],
         "pubkey": f"9XYepk{i:03d}",
         "stake": s}
        for i, s in enumerate(stakes)
    ]


def _drive_to_activation(gov, pid):
    """Helper: walk a proposal through the full 5-phase cycle, with
    unanimous yes votes."""
    prop = gov.proposals[pid]
    # SUBMITTED → EXPLORATION
    gov.advance_phases(prop.proposal_blocks)
    # Unanimous yes during exploration
    for v in gov.validator_set:
        gov.vote(pid, v["address"], Vote.YES, prop.proposal_blocks + 1)
    # EXPLORATION → COOLDOWN
    end_exp = prop.proposal_blocks + prop.exploration_blocks
    gov.advance_phases(end_exp)
    # COOLDOWN → ADOPTION
    end_cooldown = end_exp + prop.cooldown_blocks
    gov.advance_phases(end_cooldown)
    # Unanimous yes during adoption
    for v in gov.validator_set:
        gov.vote(pid, v["address"], Vote.YES, end_cooldown + 1)
    # ADOPTION → ACTIVATED
    end_adoption = end_cooldown + prop.adoption_blocks
    gov.advance_phases(end_adoption)


def test_default_state_root_is_json():
    state = empty_state()
    state["balances"] = {"kn1a": 1000}
    assert state.get("state_root_function") == "json"
    # Verify it's the JSON root, not the trie root.
    assert state_root_hex(state) != state_root_trie_hex(state)


def test_state_root_after_governance_swap():
    state = empty_state()
    state["balances"] = {"kn1a": 1000, "kn1b": 2000}

    # Pre-swap root should equal the JSON-based root.
    root_before = state_root_hex(state)

    # Simulate a successful governance vote: just toggle the field.
    # (In a real chain, this happens via apply_block reading
    # gov.active_swap("state_root_function") and updating state.)
    state["state_root_function"] = "trie"
    root_after = state_root_hex(state)

    # The new root should equal the trie-based root.
    assert root_after == state_root_trie_hex(state)

    # And it should differ from the pre-swap root.
    assert root_before != root_after


def test_e2e_governance_drives_swap():
    """The full flow: validators submit + vote a swap proposal; once
    activated, the chain's state-root function changes."""
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)

    # Initial state uses JSON.
    state = empty_state()
    state["balances"] = {"kn1a": 1000}
    state["validators"] = vs
    assert state.get("state_root_function") == "json"

    # Submit a state-root-function swap proposal.
    ok, _, pid = gov.submit(
        submitter=vs[0]["address"],
        payload={"swap": "state_root_function", "to": "trie"},
        current_level=0,
    )
    assert ok

    # Drive it through the full cycle.
    _drive_to_activation(gov, pid)
    assert gov.proposals[pid].phase == ProtocolPhase.ACTIVATED

    # The governance object exposes the active swap.
    assert gov.active_swap("state_root_function") == "trie"

    # Apply that swap to state (in a real chain, apply_block would do this
    # automatically when it sees a new activation).
    new_swap = gov.active_swap("state_root_function")
    if new_swap:
        state["state_root_function"] = new_swap

    # State-root function is now trie-based.
    assert state["state_root_function"] == "trie"
    assert state_root_hex(state) == state_root_trie_hex(state)


def test_rejected_swap_keeps_old_root():
    """A failed governance vote does NOT swap the state-root function."""
    vs = _validators([1000, 1000, 1000])
    gov = ProtocolGovernance(vs)

    ok, _, pid = gov.submit(
        submitter=vs[0]["address"],
        payload={"swap": "state_root_function", "to": "trie"},
        current_level=0,
    )
    prop = gov.proposals[pid]
    gov.advance_phases(prop.proposal_blocks)

    # All validators vote NO during exploration.
    for v in vs:
        gov.vote(pid, v["address"], Vote.NO, prop.proposal_blocks + 1)

    gov.advance_phases(prop.proposal_blocks + prop.exploration_blocks)
    assert prop.phase == ProtocolPhase.REJECTED
    assert gov.active_swap("state_root_function") is None


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} swap-integration tests passed.")
