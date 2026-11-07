# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Phase E, E1 step 1: network harness for consensus safety and liveness.

Reproduces the fork found on 7 November 2026: with four honest validators
and no equivocation, a message delay at the end of round 0 lets one node
finalize block B at round 0 while the three others finalize block C at a
later round of the same level. The engine has no lock and no nil vote.

The two safety tests are marked xfail(strict=True): they fail today, as
they must. When the fix designed in docs/consensus-locking.md lands, they
will pass, strict mode will turn that into a failure of the suite, and the
markers must be removed: from then on they are regression tests.

The liveness test must pass both before and after the fix: a correct
lock must not turn the fork into a stuck level."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from bft_sim import Decided, Simulation, random_policy
from kern.bft import ConsensusMessage, MsgKind

RANDOM_SEEDS = range(200)
E1_REASON = ("E1: no lock / valid round in kern.bft; a round change under delay "
             "can finalize two blocks at one level (docs/consensus-locking.md)")


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


def test_healthy_network_finalizes_one_block_in_round_0():
    sim = Simulation().run()
    assert sim.all_decided() and not sim.forked()
    assert {round_ for _, _, round_, _ in sim.decisions} == {0}


def test_the_reproduced_fork_involves_no_equivocation():
    """Nobody signs two votes in one round, so there is nothing to slash:
    the fork comes from the protocol, not from a faulty validator."""
    sim = Simulation(policy=_endorsements_only_reach(0)).run()
    assert sim.all_decided()
    assert all(not n.engine.pending_evidence for n in sim.nodes)


@pytest.mark.xfail(strict=True, reason=E1_REASON)
@pytest.mark.parametrize("isolated", [0, 1, 2, 3])
def test_endorsement_delay_at_a_round_change_does_not_fork(isolated):
    sim = Simulation(policy=_endorsements_only_reach(isolated)).run()
    assert sim.all_decided()
    assert not sim.forked(), sim.decided_hashes()


@pytest.mark.xfail(strict=True, reason=E1_REASON)
def test_random_asynchronous_schedules_never_fork():
    forked = [seed for seed in RANDOM_SEEDS
              if Simulation(policy=random_policy(seed)).run(60).forked()]
    assert forked == []


def test_random_schedules_always_finalize_after_stabilization():
    """Liveness: after the network stabilizes (GST at t=15 s), every node
    finalizes the level within the run. Must keep passing after E1."""
    stuck = [seed for seed in RANDOM_SEEDS
             if not Simulation(policy=random_policy(seed)).run(60).all_decided()]
    assert stuck == []
