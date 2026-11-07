# Consensus locking: design for review (Phase E, E1)

Status: **design reviewed and implemented on 7 November 2026** (E1 step 3). The reviewer's answers and additions are in section 9; where they change sections 4 to 7, section 9 prevails. Section 10 records what the implementation adds to the reviewed text and the results. Not yet run on several machines with independent operators, not audited.

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
- Every level restarts at round 0; the node's rule "a proposal's round must be at least the parent's round plus one" is removed (decided in section 9.1).

## 5. Files affected

| File | Change |
|---|---|
| `kern/block.py` | `round` becomes `payload_round`; body gains `cert_round`; strict decoding of both |
| `kern/bft.py` | PROPOSAL message and proof; per-level lock and valid state; current-round voting; certificate kept per round |
| `kern/consensus.py` | `propose_block` sets `payload_round`; growing timeout |
| `kern/node.py` | `_propose` re-proposes the valid block; `_on_proposal_msg` checks the proposal message and its proof; `_try_finalize` writes `cert_round`; round driver passes the current round to the engine |
| `kern/chain.py` | `validate_and_apply` proposer check and `cert_round` in quorum verification |
| `kern/storage.py` (or a new module) | persistent signing journal, flushed before each signature is released (section 9.2) |
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

## 9. Review decisions (7 November 2026)

| Question | Decision |
|---|---|
| Q1 Block identity | `payload_round` in the hashed header, `cert_round` in the body, as in section 4.1. |
| Q2 Nil votes | Later, after E1 is validated. |
| Q3 Re-proposer reward | None in E1: fees and rewards follow the payload producer only. |
| Q4 Round numbering | **Every level restarts at round 0.** |
| Q5 Proposal equivocation | Detect it and keep both signed messages as evidence in E1; make it slashable in a later step. |

### 9.1 Rounds restart at 0 at every level

Two honest nodes can finalize the same payload with certificates from different rounds (one sees the round 0 certificate, the other only the round 1 certificate), so they can store different `cert_round` values for the same block. If the next level started at the parent's `cert_round + 1`, the two nodes would start the next level at different rounds and could disagree on the proposer, which `select_proposer` derives from the parent hash and the round. Continuous numbering would also keep timeouts (`base + r * step`) high after one slow level. Restarting at 0 removes both problems.

Consequences: the node's rule "a proposal's round must be at least the parent's round plus one" is removed; `Node._round` starts at 0 after each finalized block (today `chain.head.header.round + 1`); `cert_round` is never used to derive anything for the next level.

### 9.2 Persistent signing journal

Today `Node.__init__` builds a fresh `BftEngine` at start, with all consensus state in memory. A validator that endorses B, crashes before B is final, and restarts has lost its lock and its record of what it signed: it could sign a conflicting vote, which reintroduces what the lock prevents (and, for two votes in one round, gets it slashed).

E1 therefore adds an append-only signing journal in the node's data directory:

- One record per message the node is about to sign: `chain_id`, `kind`, `level`, `round`, `block_hash`, and the engine's `locked_round`, `locked_hash`, `valid_round`, `valid_hash` after the step.
- The record is written and flushed to disk (`fsync`) **before** the signature is released to the network.
- At start, the node replays the journal before signing anything: it restores the lock and valid state of the current level, and refuses to sign any (kind, level, round) already in the journal for a different block.
- Records below the finalized height can be compacted away.
- A validator whose journal is missing or unreadable does not sign until it has seen the level it was working on finalized by others (the operator documentation says so).

### 9.3 Proposal equivocation

Two PROPOSAL messages signed by the same proposer for the same (level, round) and different blocks are detected by the engine and kept, both messages, as verifiable evidence, in the same way as vote equivocation evidence. Slashing them is a later step. Safety never depends on this: the two-thirds threshold and the lock rules are enough.

### 9.4 Acceptance criteria

The five tests now marked `xfail(strict=True)` become normal regression tests. In addition:

| Test | Expected result |
|---|---|
| Endorsement delay at a round change | No fork |
| Messages reordered | No fork |
| Messages lost before stabilization | Every node finalizes after stabilization |
| One quarter of the stake Byzantine (equivocating, withholding) | Safety holds |
| Unequal stakes | Safety holds |
| Re-proposal with a valid round | The level finalizes |
| Proposal equivocation | Evidence detected and kept |
| Crash after endorsing, then restart | No conflicting vote after restart |
| Several consecutive levels | No fork, no divergence of rounds or proposers |
| New node syncing from scratch | Verifies finality of every block independently |

`tests/bft_sim.py` drives real `BftEngine` instances but models the node and the network itself. The simulated results must be confirmed by a multi-process integration test that runs complete `Node` processes over the real network layer.

## 10. Implementation (7 November 2026)

The code follows sections 4 and 9. Four points were added or made precise while implementing; they are submitted to the reviewer with this delivery.

### 10.1 The proposer's self-commit was an endorsement outside the lock rules

`propose_block` signed an ENDORSE over its own block at proposal time, before any pre-endorsement certificate, and the block carried it in `commits`. That signature is an ordinary endorsement: anyone can copy it into a certificate. With unequal stakes it breaks safety without any lock being involved: a proposer holding 40% of the stake signs its block B, a byzantine validator holding 30% adds its endorsement, and B has 70% of endorsements in that round while no honest validator is locked on B. The honest validators can then finalize another block later.

Fix: the self-commit is signed only when the proposer alone holds more than two thirds of the consensus stake, so that it is a complete certificate on its own (single-validator operation). With several validators, `commits` is empty and the quorum always comes from the wire. When the self-commit is signed, the node passes it through the engine (`adopt_self_commit`: journal, lock) before the block is shown. In validation, `commits` are verified at the payload round and counted with `endorsements` only when `cert_round == payload_round`.

### 10.2 Round skip on one third of the stake

The node also moves to a later round when validators holding more than one third of the stake have already voted there (Tendermint's rule). At least one honest validator is in that round, so a byzantine minority cannot make honest nodes jump. A valid proposal for a later round moves the node only within the engine window (8 rounds), so a byzantine proposer of a far round cannot push timeouts up.

### 10.3 Details fixed by the implementation

- Timeout: `base + r * base / 2`, `base = max(2 s, 4 × block_time)`.
- Proposals travel as an envelope `{"block", "proposal", "proof"}` on the existing `proposal` channel; `valid_round` is inside the PROPOSE signature, vote signatures are unchanged.
- Rounds are bounded by `2**32 - 1` at decoding (proposer selection encodes the round on 4 bytes).
- The engine accepts a proof for a re-proposal either from the envelope or from a pre-endorsement certificate it saw itself.
- Proposals are re-gossiped by every node, which is what makes proposal equivocation visible to everyone.
- A missing journal on a chain past genesis is treated like an unreadable one (no signature at the level in progress). A fresh validator joining a running chain therefore waits one level.
- The proposer re-proposes the valid block only if it holds the block body; otherwise it proposes a new payload, which costs liveness for that round, not safety.

### 10.4 Results

| Scenario (`tests/test_phase_e_consensus_harness.py`) | Before E1 | Lock only (section 2) | E1 |
|---|---|---|---|
| Endorsements of round 0 reach one node only (4 variants) | 4 forks | no fork, 3 nodes stuck | no fork, all finalize the same block |
| 200 random schedules (delays, 10% loss, then stabilization) | 41 forks, 0 stuck | 22 forks, 8 stuck | 0 forks, 0 stuck |
| Round 1 proposer missed the round 0 certificate | | | no fork |
| Reordering, 40% loss before stabilization, one quarter byzantine (equivocating or silent), unequal stakes with 30% byzantine, 7 validators with 2 byzantine, five consecutive levels, crash and restart with journal | | | no fork, all finalize |

Each rule was checked to matter: allowing votes in any round brings back forks in the random schedules, and removing the lock forks the "round 1 proposer missed the certificate" scenario. Without its journal, a restarted validator loses its lock.

`tests/test_phase_e_multiprocess.py` runs four complete `kern.node` processes over the real network layer on one machine: all agree on every block, a fresh verifier checks every quorum from the blocks alone, three validators keep finalizing while the fourth is stopped, and the fourth restarts from its journal and catches up, with no equivocation.

What this does not establish: behaviour on several machines with independent operators and real network conditions, and an external audit of the implementation. Nil votes (Q2) and slashing of proposal equivocation (Q5) remain later steps.

### 10.5 Review of the implementation (f24564b)

A review of the merged code found three points, all confirmed in the code and fixed with tests that fail on f24564b.

**P1, self-commit recovery after a crash (liveness).** The block a validator prepared lived only in memory, while its lock was synced to the journal. A validator holding more than two thirds of the stake that crashed after its self-commit restarted locked on a hash whose block it no longer had: it rebuilt another block (different timestamp, different hash), the lock refused it, and the other validators could not finalize without it. The level stayed stuck. Validators that had received the proposal ignored the self-commit it carried in `commits`, so they could not finalize it either.

Fix:
- Every block the node is about to sign for (its own proposal, or a validated proposal from another validator) is written to `signing_journal.blocks.jsonl` and synced before any signature over it. The lock and the block it names are therefore always on disk together.
- At start, the node restores these blocks, validates them again, and, when it is locked on its own block and holds the quorum alone, counts its self-commit again: the block is final, and the node finalizes it.
- A validator that receives a proposal counts the endorsements in `commits` as ENDORSE votes of the payload round (checked by the engine like any vote). If the proposer dies after broadcasting, the others finalize from its self-commit.

**P2, the journal did not cover every signed field of PROPOSE.** It indexed (kind, level, round) to the block hash only, while a PROPOSE also signs `valid_round`. It now records and compares `signed_valid_round`; a second proposal for one (level, round) with another valid round is refused.

**P2, defence in depth.** `BftEngine.adopt_self_commit` now checks the signature with the validator's own key and that the validator holds strictly more than two thirds of the stake, instead of relying on `propose_block`.

Tests: `tests/test_phase_e_self_commit_recovery.py` (crash after the journal sync, crash during the broadcast, receiver finalizing from the self-commit, journal and engine checks). `tests/test_phase_e_multiprocess.py` adds two weighted (90/10) tests with real processes: four outright kills of the dominant validator at varied moments, and crashes placed exactly through failpoints (`kern/failpoints.py`, off unless a test sets `KERN_FAILPOINT`): after the self-commit is synced, after the PROPOSE is signed, after the proposal is broadcast and before finalization. With the restore and the commit counting disabled, the three failpoint tests stay stuck; with them, the crashed level is finalized with the payload named by the lock, on both nodes.

