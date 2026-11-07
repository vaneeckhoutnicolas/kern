# Consensus locking: design for review (Phase E, E1)

Status: **design, not implemented.** This document must be reviewed before any code is written. Section 8 lists the decisions the reviewer is asked to make.

## 1. The defect

`kern/bft.py` forms a pre-endorsement certificate (more than two thirds of stake for one block in one round), endorses, and finalizes on an endorsement certificate. It keeps no memory of what a validator endorsed in an earlier round. With four honest validators of equal stake:

1. Round 0: all four pre-endorse block B, see the pre-endorsement certificate, and endorse B.
2. The endorsements reach only validator 0, which finalizes B. Its announcement of B is delayed.
3. The other three time out, move to round 1, pre-endorse and endorse the round 1 block C, and finalize C.

Two blocks are final at level 1. Nobody signed two votes in one round, so there is no slashable fault. Message delay alone is enough.

Evidence, from `tests/test_phase_e_consensus_harness.py` (simulator in `tests/bft_sim.py`, real `BftEngine` instances, deterministic network):

| Scenario | Current engine |
|---|---|
| Endorsements of round 0 reach one node only (each of the 4 nodes in turn) | 4 forks out of 4 |
| 200 random schedules: random delays up to 2 s and 10% loss until t = 15 s, then delivery within 50 ms | 41 forks, 0 stuck levels |

## 2. Why a lock alone is not enough

The textbook fix is the Tendermint lock: a validator that endorsed B in round r pre-endorses nothing else afterwards, unless it sees a more recent pre-endorsement certificate for another block. A scratch experiment (not delivered) added only that lock to the engine and ran the same harness:

| Scenario | Lock only |
|---|---|
| Scripted scenario | no fork, but the three other nodes never finalize (still running at round 114) |
| 200 random schedules | 22 forks, 8 stuck levels |

Two causes, both confirmed in the experiment:

- **B cannot be proposed again.** The block hash covers `header.round` and `header.proposer`, so the round 1 proposer can only offer a new block. Validators locked on B refuse it, and the level stalls.
- **The engine votes in past rounds.** Nothing ties a vote to the node's current round: when a late pre-endorsement certificate for round 0 arrives, the engine endorses in round 0 even if the node is already in round 1 and has pre-endorsed C there. In the random runs the engines emitted 386 pre-endorsements and 720 endorsements for rounds older than the node's round, and every one of the 22 forks involved such a late vote.

## 3. Requirements

1. **Safety**: two honest nodes never finalize different blocks at the same level, as long as validators holding more than two thirds of the stake follow the protocol, whatever the message delays and losses.
2. **Liveness**: after the network stabilizes, every honest node finalizes the level.
3. Votes stay slashable exactly as today (same kinds, same evidence format).
4. The state transition does not depend on the round at which a block is finalized.
5. Every rule can be ported to `kern-go` without ambiguity.

## 4. Proposed design

The design follows Tendermint (locked round, valid round, proof of lock) and Tenderbake (the block payload keeps its identity across rounds).

### 4.1 Block identity independent of the finalization round

- `BlockHeader.round` is renamed `payload_round`: the round at which this payload was first proposed. It stays inside the signed, hashed header. The header's `proposer` must be `select_proposer(parent_hash, validators, payload_round)`.
- The block hash therefore no longer changes when the same payload is offered again in a later round.
- A new body field `cert_round` (not hashed, like `endorsements`) records the round of the endorsement certificate that finalized the block. `cert_round >= payload_round`.
- The state transition is unchanged: fees and rewards go to `header.proposer`, the producer of the payload (requirement 4). A validator that re-proposes someone else's payload earns nothing extra (see question Q3).

### 4.2 Proposal message

A new signed consensus message, sent with the block body by the proposer of round r:

```
PROPOSAL {level, round r, block_hash, valid_round, proposer, proposer_pubkey, signature}
         + proof: pre-endorsement certificate for block_hash at valid_round (when valid_round >= 0)
```

- `valid_round = -1` for a new payload (then `payload_round == r`).
- `0 <= valid_round < r` for a re-proposed payload, with a pre-endorsement certificate for that block at `valid_round` as proof.
- `proposer` must be `select_proposer(parent_hash, validators, r)`; the block's own `header.proposer` may differ.
- Two different PROPOSAL messages signed for the same (level, round) are evidence of proposal equivocation (question Q5).

### 4.3 Engine state per level

```
round          current round of the node, supplied by the node
locked_round   -1, or the round in which this node last endorsed
locked_hash    the block it endorsed then
valid_round    -1, or the highest round in which this node saw a pre-endorsement certificate
valid_hash     the block of that certificate
```

### 4.4 Rules

1. **Vote only in the current round.** The engine emits a PREENDORSE or ENDORSE only for `round == current round`. Votes for other rounds are still recorded and still count toward certificates and evidence.
2. **Pre-endorse** the proposal of the current round for block X when the proposal is valid (legitimate proposer, block validates), and either
   - `locked_round == -1` or `locked_hash == X`, or
   - the proposal carries `valid_round > locked_round` with a valid proof for X at `valid_round` (this is how a lock is released).
   Otherwise do not pre-endorse in this round.
3. **Endorse and lock.** On a pre-endorsement certificate for X in the current round, with the proposal for X seen: set `locked = (round, X)`, `valid = (round, X)`, and endorse X. At most once per round.
4. **Track the valid block.** On a pre-endorsement certificate for X at any round r' greater than `valid_round` (and not above the current round), set `valid = (r', X)`.
5. **Propose.** The proposer of round r proposes `valid_hash` with `valid_round` and its proof if `valid_round >= 0`; otherwise it builds a new payload.
6. **Finalize** X at the level when an endorsement certificate for X exists at any round. Store `cert_round`.
7. **Timeouts grow with the round**: `timeout(r) = base + r * step`, so that after stabilization a round eventually lasts long enough for a whole round trip.

Why this closes the fork: if X is finalized in round r, more than two thirds of stake endorsed X in r and are locked on X from r. A pre-endorsement certificate for another block Y in a later round needs more than two thirds of stake, so it needs at least one honest validator locked on X, which only pre-endorses Y with a proof for Y from a round after r. By induction on the rounds after r, no such proof exists, so no certificate for Y forms after round r. Rule 1 prevents the late votes found in section 2. This is the standard Tendermint argument; the reviewer is asked to check that the Kern specifics (stake weights from the epoch snapshot, certificates bound to the proposed block since Phase C) do not break it.

### 4.5 Chain validation

- `verify_commits` checks endorsements over `(block_hash, level, cert_round)` instead of `header.round`.
- `validate_and_apply` additionally checks `header.proposer == select_proposer(parent_hash, validator_set, header.payload_round)`. Today only the node checks the proposer of a proposal; a block arriving by gossip or sync is only checked for proposer membership. This is a separate gap found while preparing this design.
- The node's rule "a proposal's round must be at least the parent's round plus one" applies to `payload_round` against the parent's `cert_round` (question Q4).

## 5. Files affected

| File | Change |
|---|---|
| `kern/block.py` | `round` becomes `payload_round`; body gains `cert_round`; strict decoding of both |
| `kern/bft.py` | PROPOSAL message and proof; per-level lock and valid state; current-round voting; certificate kept per round |
| `kern/consensus.py` | `propose_block` sets `payload_round`; growing timeout |
| `kern/node.py` | `_propose` re-proposes the valid block; `_on_proposal_msg` checks the proposal message and its proof; `_try_finalize` writes `cert_round`; round driver passes the current round to the engine |
| `kern/chain.py` | `validate_and_apply` proposer check and `cert_round` in quorum verification |
| `docs/consensus-wire.md` | new message, new field, voting rules |
| `docs/go-port-breakpoints.md` | new section with the exact rules |
| `tests/bft_sim.py` | the simulated proposer follows rule 5; block hash from `payload_round` |

The block format changes, so a devnet must be reset, as after Phases C and D.

## 6. Acceptance on the harness

- The five tests now marked `xfail(strict=True)` in `tests/test_phase_e_consensus_harness.py` pass; the markers are removed.
- `test_random_schedules_always_finalize_after_stabilization` keeps passing.
- New scenarios added with the code: a lock released by a later proof; a proposer that re-proposes the valid block; one validator out of four equivocating on purpose (at most one third of stake faulty); unequal stakes; several consecutive levels.

## 7. Out of scope

- Rewarding the network endorsers (still proposer-only).
- Nil votes. Tendermint's nil votes let a round end early when no block can gather a certificate; they help liveness, not safety. Question Q2.

## 8. Questions for the reviewer

- **Q1.** Block identity: `payload_round` in the hashed header plus `cert_round` in the body (this document), or Tenderbake's approach of voting on a payload hash while the header keeps the round of the round's proposer?
- **Q2.** Nil votes in this phase, or later?
- **Q3.** Should the validator that re-proposes a payload earn anything, given that fees and rewards follow the payload producer?
- **Q4.** Round numbering: Kern starts a level at the parent's round plus one instead of round 0. Keep it (based on `cert_round`), or restart each level at round 0?
- **Q5.** Make proposal equivocation slashable now, or log it only?
