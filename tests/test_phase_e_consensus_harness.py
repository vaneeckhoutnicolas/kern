# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, E1: network harness for consensus safety and liveness.

Step 1 reproduced the fork found on 7 November 2026: with four honest
validators and no equivocation, a message delay at the end of round 0 let
one node finalize block B at round 0 while the three others finalized
block C at a later round of the same level. Those tests were marked
xfail(strict=True) until the fix of docs/consensus-locking.md landed;
they are now regression tests.

Step 3 adds the acceptance criteria of consensus-locking.md section 9.4,
run on real `kern.bft.BftEngine` instances (tests/bft_sim.py models the
node and the network). Safety tests are paired, where it makes sense,
with a check that the harness detects the fork when the rule under test
is removed, so that a passing test means the rule works, not that the
scenario is harmless."""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

import kern.bft as bft
from bft_sim import Decided, Simulation, random_policy
from kern.bft import ConsensusMessage, MsgKind

RANDOM_SEEDS = range(200)


def _endorsements_only_reach(node: int):
    """Round 0 runs normally except that ENDORSE messages reach only `node`,
    and its announcement of the finalized block is lost."""
    def policy(src, dst, t, payload):
        if (isinstance(payload, ConsensusMessage) and payload.kind == MsgKind.ENDORSE
                and payload.round == 0 and dst != node):
            return None
        if isinstance(payload, Decided) and payload.round == 0:
            return None
        return 0.01
    return policy


def _round1_proposer_missed_the_certificate(sim: Simulation):
    """Round 0: every validator pre-endorses B, but the pre-endorsements of
    the others never reach the proposer of round 1, so it sees no
    certificate and is neither locked nor aware of a valid block. The
    endorsements reach one other node only, which finalizes B; its
    announcement is lost. Without the lock, the round 1 proposer offers a
    new block C and the two remaining validators pre-endorse it: C becomes
    final on three nodes, B on one."""
    p1 = sim.proposer_of(1)
    finisher = (p1 + 1) % len(sim.nodes)

    def policy(src, dst, t, payload):
        if isinstance(payload, ConsensusMessage) and payload.round == 0:
            if payload.kind == MsgKind.PREENDORSE and dst == p1 and src != p1:
                return None
            if payload.kind == MsgKind.ENDORSE and dst != finisher:
                return None
        if isinstance(payload, Decided) and payload.round == 0:
            return None
        return 0.01
    return policy


def _reordering(seed: int):
    """Every message is delivered, in a random order: delays up to 1.5 s."""
    rng = random.Random(seed)
    return lambda src, dst, t, payload: rng.uniform(0.0, 1.5)


# --------------------------------------------------------------- step 1 tests

def test_healthy_network_finalizes_one_block_in_round_0():
    sim = Simulation().run()
    assert sim.all_decided() and not sim.forked()
    assert {round_ for _, _, _, round_, _ in sim.decisions} == {0}


def test_the_reproduced_scenario_involves_no_equivocation():
    """Nobody signs two votes in one round: the fork of step 1 came from the
    protocol, not from a faulty validator."""
    sim = Simulation(policy=_endorsements_only_reach(0)).run()
    assert sim.all_decided()
    assert all(not n.engine.pending_evidence for n in sim.nodes)


@pytest.mark.parametrize("isolated", [0, 1, 2, 3])
def test_endorsement_delay_at_a_round_change_does_not_fork(isolated):
    sim = Simulation(policy=_endorsements_only_reach(isolated)).run()
    assert sim.all_decided()
    assert not sim.forked(), sim.decided_hashes()


def test_random_asynchronous_schedules_never_fork():
    forked = [seed for seed in RANDOM_SEEDS
              if Simulation(policy=random_policy(seed)).run(60).forked()]
    assert forked == []


def test_random_schedules_always_finalize_after_stabilization():
    """Liveness: after the network stabilizes (GST at t=15 s), every node
    finalizes the level within the run."""
    stuck = [seed for seed in RANDOM_SEEDS
             if not Simulation(policy=random_policy(seed)).run(60).all_decided()]
    assert stuck == []


# ---------------------------------------------------- the rules have teeth

def test_late_votes_would_fork_the_random_schedules(monkeypatch):
    """Rule 1 (vote only in the current round) is what closes the random
    forks: allowing votes in any round brings them back."""
    monkeypatch.setattr(bft.BftEngine, "_is_current", lambda self, r: True)
    assert any(Simulation(policy=random_policy(seed)).run(60).forked() for seed in range(60))


def test_lock_prevents_the_fork_when_the_next_proposer_missed_the_certificate():
    sim = Simulation()
    sim.policy = _round1_proposer_missed_the_certificate(sim)
    sim.run(30)
    assert sim.all_decided()
    assert not sim.forked(), sim.decided_hashes()
    # Same payload everywhere, finalized at different rounds by different
    # nodes: cert_round may differ, the block does not.
    assert len({r for _, _, _, r, _ in sim.decisions}) > 1


def test_without_the_lock_that_scenario_forks(monkeypatch):
    monkeypatch.setattr(bft.BftEngine, "_may_preendorse", lambda self, state: True)
    sim = Simulation()
    sim.policy = _round1_proposer_missed_the_certificate(sim)
    sim.run(30)
    assert sim.forked()


# ------------------------------------------- acceptance, section 9.4

def test_reordered_messages_never_fork_and_always_finalize():
    for seed in range(60):
        sim = Simulation(policy=_reordering(seed)).run(60)
        assert sim.all_decided(), seed
        assert not sim.forked(), seed


def test_heavy_losses_before_stabilization_still_finalize():
    for seed in range(60):
        sim = Simulation(policy=random_policy(seed, drop=0.4)).run(90)
        assert sim.all_decided(), seed
        assert not sim.forked(), seed


@pytest.mark.parametrize("mode", ["equivocate", "silent"])
def test_one_quarter_of_the_stake_byzantine(mode):
    """One validator out of four breaks every rule (two proposals per
    round, votes for every block it hears of, ignoring locks) or withholds
    everything. The three honest validators never fork and still finish."""
    for seed in range(60):
        sim = Simulation(policy=random_policy(seed), byzantine={3: mode}).run(90)
        assert not sim.forked(), seed
        assert sim.all_decided(), seed


def test_byzantine_votes_are_detected_as_evidence():
    sim = Simulation(policy=random_policy(1), byzantine={3: "equivocate"}).run(90)
    ev = sim.evidence_against(3)
    assert ev and all(e.verify()[0] for e in ev)


@pytest.mark.parametrize("stakes,byzantine", [
    ([40, 25, 20, 15], {}),
    ([40, 30, 15, 15], {1: "equivocate"}),     # 30 % byzantine, under one third
    ([10, 10, 10, 10, 10, 10, 40], {0: "equivocate", 1: "equivocate"}),
])
def test_unequal_stakes(stakes, byzantine):
    for seed in range(40):
        sim = Simulation(n=len(stakes), stakes=stakes, policy=random_policy(seed),
                         byzantine=byzantine).run(90)
        assert not sim.forked(), (seed, sim.decided_hashes())
        assert sim.all_decided(), seed


def test_reproposal_with_a_valid_round_finalizes_the_level():
    """In the step 1 scenario the level is finalized by proposing the
    round 0 block again, with its valid round and certificate."""
    sim = Simulation(policy=_endorsements_only_reach(0)).run()
    assert any(vr >= 0 for _, _, _, vr in sim.proposals_sent)
    assert sim.all_decided() and not sim.forked()
    assert len(set(sim.decided_hashes().values())) == 1


def test_proposal_equivocation_is_detected_and_kept():
    """A byzantine proposer sends one block to half of the network and
    another block to the other half. The node re-gossips proposals, so
    honest nodes see both signed PROPOSE messages and keep them."""
    sim = Simulation(policy=random_policy(5), byzantine={0: "equivocate"}).run(90)
    evidence = [e for n in sim.honest for e in n.engine.proposal_evidence]
    assert evidence
    assert all(e.offender == sim.validators[0]["address"] and e.verify()[0] for e in evidence)
    assert not sim.forked()


def _crash_scenario(tmp_path=None):
    sim = Simulation(journal_dir=str(tmp_path) if tmp_path is not None else None)
    sim.policy = _round1_proposer_missed_the_certificate(sim)
    victim = (sim.proposer_of(1) + 2) % 4           # endorsed B, did not finalize it
    return sim, victim, sim.nodes[victim]


def test_crash_after_endorsing_then_restart(tmp_path):
    """A validator endorses B at round 0, crashes before B is final, and
    restarts with a fresh engine restored from its signing journal: it is
    still locked on B, signs nothing conflicting, and B is final everywhere."""
    sim, victim, node = _crash_scenario(tmp_path)
    seen = {}

    def crash_and_restart():
        before = node.engine.level_state(1)
        seen["before"] = (before.locked_round, before.locked_hash)
        node.crash()
        node.restart(sim.now)
        after = node.engine.level_state(1)
        seen["after"] = (after.locked_round, after.locked_hash)

    sim.at(0.2, crash_and_restart)
    sim.run(30)
    assert seen["before"][0] == 0 and seen["before"][1] is not None
    assert seen["after"] == seen["before"]
    assert sim.all_decided() and not sim.forked()
    assert sim.evidence_against(victim) == []


def test_without_the_journal_a_restarted_validator_loses_its_lock():
    """Control for the test above: the same restart without a journal
    forgets the lock (which is what the journal is for)."""
    sim, victim, node = _crash_scenario()
    seen = {}

    def crash_and_restart():
        node.crash()
        node.restart(sim.now)
        seen["after"] = node.engine.level_state(1).locked_round

    sim.at(0.2, crash_and_restart)
    sim.run(30)
    assert seen["after"] == -1


def test_crash_while_down_then_restart_keeps_finalizing(tmp_path):
    """A validator stays down for several rounds and comes back: the level
    finalizes with the three others and it catches up."""
    sim = Simulation(policy=random_policy(3), journal_dir=str(tmp_path), levels=3)
    node = sim.nodes[2]
    sim.at(0.5, node.crash).at(8.0, lambda: node.restart(sim.now))
    sim.run(120)
    assert sim.all_decided() and not sim.forked()
    assert sim.evidence_against(2) == []


@pytest.mark.parametrize("byzantine", [{}, {2: "equivocate"}])
def test_several_consecutive_levels(byzantine):
    """Five levels in a row: no fork at any level, every node follows the
    same parent chain, and every level starts again at round 0 (the
    proposer of each level depends only on the parent hash and the round,
    never on the cert_round a node happened to store)."""
    for seed in range(30):
        sim = Simulation(policy=random_policy(seed), levels=5, byzantine=byzantine).run(200)
        assert sim.all_decided(), seed
        assert not sim.forked(), seed
        chains = {tuple(n.decisions[lvl].block_hash for lvl in range(1, 6)) for n in sim.honest}
        assert len(chains) == 1, seed
    healthy = Simulation(levels=5).run(60)
    assert {r for _, _, _, r, _ in healthy.decisions} == {0}
