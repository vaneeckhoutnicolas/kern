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

### 10.6 Review of 3f2b200: certificates after a whole-cluster restart, journal format

A second review found two more points; the first was reproduced before being fixed.

**P1, liveness after every validator restarts.** The journal restored the lock, the valid round and the kept blocks, but not the pre-endorsement certificate that proves the valid round. Reproduction (`tests/test_phase_e_multiprocess.py::test_whole_cluster_crash_after_endorsing_then_restart`): four validators of equal stake pre-endorse block B, see the certificate, sign and journal their ENDORSE, and all die before sending it, through the `before_endorse_broadcast` failpoint. After the restart every validator is locked on B. The proposers of the following rounds propose new payloads (valid round -1), which the locked validators refuse, and nobody holds the certificate that would let B be proposed again. On 3f2b200 the chain made no progress for two minutes; with the fix it finalizes B in a few seconds.

Fix: every journal record carries `valid_qc`, the pre-endorsement certificate of its valid round when the engine holds it, in the same synced write as the signature that depends on it (the ENDORSE that locks on B carries the certificate for B). At start, `BftEngine.restore_lock` checks the certificate (kind, level, round and block of the valid round; more than two thirds of the current stake; every signature) and puts its votes back into the round's state. A certificate that does not check is ignored: the lock stays, and the loss costs liveness, never safety. The proposer can then propose B again with its proof, and every locked validator accepts it.

**P2, the journal fails closed.** Records now carry a format version (`v: 2`), and the chain id, `signed_valid_round` and every other field are required and type-checked: `signed_valid_round` must be -1 for votes and lower than the round for proposals, a lock or valid hash must be present exactly when its round is. A journal in the older format, for another chain, or with any malformed record is unreadable: the node moves it aside and does not sign at the level in progress. There is no automatic migration, because the older format did not record what a proposal signed; since the block format changed in Phase E, a devnet is reset anyway. The journal also refuses to write a record that it would not accept on reading.

Tests: `tests/test_phase_e_qc_persistence.py` (certificate in the ENDORSE record, whole-cluster restart able to propose the locked block again, control without the certificate, five kinds of bad certificate ignored, thirteen malformed journals refused, node refusing to sign with an untrusted journal, node restoring the certificate at start); 24 of its 26 tests fail on 3f2b200.

### 10.7 Review of 84cbbcc: block file, conflicting proposals, evidence bounds

A third review of the implementation found three more points, each confirmed with a test that fails on 84cbbcc.

**P1, the block file could lose a block after a cut write.** The main journal removed a final line cut by a crash; the block file (`signing_journal.blocks.jsonl`) only skipped it. The next block was then appended right after the fragment, on the same line, and was lost at the following restart, although the node had treated it as kept on disk before signing. Fix: a cut final line is removed at start, and every append checks that the file ends with a newline and starts a fresh line otherwise.

**P2, conflicting proposals consumed resources.** The proposer of a round could sign many different valid blocks for that round; the node validated each in full, kept it in memory and wrote it to disk before the engine saw the conflict (20 blocks, 20 full validations on 84cbbcc). Fix: the node records the first block seen for each (level, round), once its PROPOSE signature and proposer have been checked. A different block for the same (level, round) is not validated, stored or kept: the engine checks the PROPOSE signature and keeps both messages as proposal equivocation evidence, and the node relays the conflict once so that other nodes see it. Only the proposer selected for the round can occupy that slot, so nobody else can block a round this way. A re-proposal belongs to a later round and is not affected.

**P2, evidence grew without bound.** The deduplication keys of vote evidence are now dropped with their level (`prune_below`); messages below the engine's window never reach it anyway. Proposal equivocation evidence, which is kept but not slashable yet, is capped at `MAX_PROPOSAL_EVIDENCE` (256) entries, oldest dropped first.

**Clarifications requested by the review.**

- *Malformed record versus invalid certificate.* These are two different cases. A malformed journal record (wrong format version, other chain, missing or mistyped field) makes the whole journal unreadable: the node moves it aside and does not sign at the level in progress (fail closed). A certificate (`valid_qc`) that is well formed but does not verify cryptographically, or names another level, round or block, is ignored on its own: the rest of the journal is used, the lock is kept, and only the ability to propose the locked block again is lost.
- *Which validator set verifies a restored certificate.* The journal is restored for the level in progress, `head + 1`, and the certificate is verified against `Chain.validators`, the consensus set in the state after the head block. That is exactly the set that weighs the votes of that level (section 4, Phase C), so a certificate is never checked against the stake of another level.

Tests: `tests/test_phase_e_hardening.py`; all five fail on 84cbbcc.

### 10.8 Review of e67ed17: an invalid first proposal

**P1, a vote on a block never validated.** The fix of section 10.7 reserved the (level, round) for the first block hash before validating that block. Scenario: a byzantine proposer signs an invalid block A and a valid block B for the same round, and a validator receives A first. A fails validation and never reaches the engine; B is then a conflicting proposal, which the node passed to `BftEngine.on_proposal` without validating it, only to record the evidence. The engine had no proposal for that round, took B as the first one, and could pre-endorse it: on e67ed17 the validator's signing journal holds a PREENDORSE for B. The vote was not broadcast (the node discarded the engine's output on that path), but it was signed and journalled, and the rule is that an honest validator never signs a vote for a block it has not validated. The equivocation was also lost, since the engine never had the PROPOSE message of A.

Fix: the engine gains `record_proposal_equivocation(msg_a, msg_b)`, which checks the two signed PROPOSE messages and keeps them as evidence without touching the round state and without voting. The node keeps the first signed PROPOSE of each (level, round), with its envelope, whether or not the block turns out valid. A later, different block for that round goes only to `record_proposal_equivocation`; both proposals are relayed once so that the other nodes can keep the same evidence. A block that failed validation is remembered and not validated again. `on_proposal`, the only path that can lead to a vote, is called only for a block the node has validated.

Effect on liveness: a validator that saw an invalid first proposal does not vote in that round, as in Tendermint when the first proposal received is invalid. The other validators may still finalize B; the validator then receives the finalized block with its certificate and checks it in full. If B gathers a pre-endorsement certificate, a later proposer can propose it again with its proof, in a new round where it is validated normally.

Tests: `tests/test_phase_e_invalid_first_proposal.py` (no vote and no lock after an invalid first proposal; evidence kept with both signatures; both proposals relayed and the evidence rebuilt by another node; an invalid block validated once; control with the valid block first; the engine API keeps evidence without voting and refuses four kinds of non evidence); 9 of its 10 tests fail on e67ed17, the control passes on both.

### 10.9 Review of 0695a80: evidence behind a bad valid round, rounds without finalization

The review confirmed the fix of section 10.8 in the code and raised two points, each reproduced with a test that fails on 0695a80.

**P2, evidence lost when the first proposal fails its valid round checks.** The node checked the valid round and its proof before recording the first signed PROPOSE of the (level, round). A proposer could sign a proposal A whose valid round does not fit its block (a new proposal, valid round -1, for a block whose payload round is another round), or whose proof is below two thirds, then a different block B for the same round: A was refused without being recorded, B became the first proposal, and the two conflicting signatures were not kept. Safety was not at stake, since B was still validated in full before any vote.

Fix: the first signed PROPOSE of the selected proposer occupies its (level, round) as soon as its signature and its proposer are checked, before the valid round checks, as section 10.8 does for a block that fails validation. A later, different block for that round is only evidence, relayed once with the first proposal. A proposal whose signed valid round does not fit its block is the proposer's fault: the validator does not vote in that round. The proof is the exception, because the proposer does not sign it and a relay may strip or damage it: a refused proof does not mark the proposal as seen, and the same signed proposal arriving later with a valid proof is validated and pre-endorsed normally, with no evidence made up. A valid round not lower than the round was already refused when the message is decoded; such a message is malformed, not evidence.

**P2, rounds without finalization filled the engine's state.** The engine kept at most `MAX_ROUND_STATES` (256) round states, and `prune_below` dropped only whole levels. After enough rounds at one level, `in_window` refused every new round, and the level could not finalize even once the network was stable. With a 4 second base timeout, 256 rounds take about 18 hours; a single validator signing votes at every round the window accepts, the next two levels included, filled the cap after about 80 rounds (under two hours). Restarting the node cleared it, since this state is in memory only. The node also kept one proposal and one block per round until the level finalized.

Fix: `BftEngine.prune_rounds`, called whenever the node enters a round, drops the state of every round more than `MAX_ROUND_DISTANCE` (8) away from the current round, at every level, except the lock and the valid round of that level (`kept_rounds`): the valid round's certificate is what lets the node propose its valid block again and proves a later re-proposal. `in_window` already refused every message for the dropped rounds, so nothing they held could grow; a block finalized in such a round reaches the node with its certificate and is checked in full. The node prunes its own data the same way (`Node._prune_round_data`): proposals of rounds outside the window, except the lock and the valid round, and the blocks, invalid hashes and relayed conflicts that no kept proposal, lock or valid round refers to. At most 3 levels of 17 rounds, plus the kept rounds, remain in memory; `MAX_ROUND_STATES` stays as a backstop.

Not changed: the block file of the signing journal still receives one block per round in which the validator signs; it is compacted with the journal (`JOURNAL_COMPACT_EVERY` levels).

Tests: `tests/test_phase_e_review_0695a80.py` (evidence kept when the first proposal has an impossible valid round, or a proof below two thirds, with no vote in that round; a level that finalizes after 260 rounds without finalization, and after a validator voted ahead at every accepted round of three levels, with at most 51 states kept; the lock and valid round and their certificate kept after 60 rounds; the node's proposals and blocks following the window); 6 of its 8 tests fail on 0695a80. The two controls (a stripped or weakened proof followed by the same proposal with its valid proof) pass on both.

