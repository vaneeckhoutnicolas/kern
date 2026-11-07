# Consensus on the wire

This document specifies how the three-phase BFT consensus (`kern/bft.py`)
travels over the peer-to-peer network (`kern/network.py`) and how the node
(`kern/node.py`) drives it. It is the normative reference for any second
client implementation (see `docs/go-port-breakpoints.md`).

Status: implemented in v1.1-rc Phase A hardening. Every block accepted by
a live node — self-baked, gossiped, or synced — is validated with
`require_quorum=True`: a cryptographically verified endorsement quorum of
strictly more than 2/3 of validator stake.

> **Safety warning (Phase E).** A verified quorum is necessary but not sufficient for safety. The engine has no lock and no nil vote: under message delay alone, with every validator honest, round 0 can finalize block B on one node while round 1 finalizes block C on the others, at the same level. The fix is designed in [consensus-locking.md](consensus-locking.md) and is not implemented yet. Until it is, multi-validator safety is not established; `tests/test_phase_e_consensus_harness.py` reproduces the fork.

## Message kinds

Each peer connection is a length-prefixed (4-byte big-endian) JSON
message stream. Seven kinds exist:

| Kind          | Payload                          | Purpose                              |
|---------------|----------------------------------|--------------------------------------|
| `hello`       | `{"level": N}`                   | Sent by both sides on connect        |
| `proposal`    | `{"block": {...}}`               | Candidate block, pre-quorum          |
| `consensus`   | `{"msg": {...}}`                 | Signed PREENDORSE / ENDORSE          |
| `block`       | `{"block": {...}}`               | Finalized block carrying its quorum  |
| `transaction` | `{"tx": {...}}`                  | Mempool gossip                       |
| `get_blocks`  | `{"from": A, "to": B}`           | Catch-up sync request                |
| `blocks`      | `{"blocks": [{...}, ...]}`       | Catch-up sync response               |

Hardening caps at this layer: 16 MiB per message, 128 concurrent
connections, 512 blocks per sync reply. Malformed frames close the
connection; a handler error on one message is logged and does not kill
the connection.

All inner payloads are decoded by the strict typed `from_dict`
constructors (`Transaction`, `BlockHeader`, `Block`, `ConsensusMessage`),
which raise field-specific `ValueError`s on any type or bounds violation.
The network layer never interprets payloads itself.

## Proposals travel as full blocks

The BFT engine defines a PROPOSE message kind, but PROPOSE never rides
the consensus channel. Proposals are broadcast as full blocks on the
`proposal` channel, and a validator only calls `BftEngine.on_proposal`
— which emits its pre-endorsement — after fully validating the proposal:
header signature, parent linkage, proposer legitimacy for the claimed
round, txs root, fee rules, and state root, via
`validate_and_apply(..., require_quorum=False)`. Bare PROPOSE messages
arriving on the wire are dropped. This guarantees no validator ever
pre-endorses a hash whose block it has not executed.

Proposer legitimacy: the proposal's `header.round` must be at least
`parent.round + 1`, and `select_proposer(parent_hash, validators, round)`
must return the block's proposer. Anything else is discarded before
validation.

## commits vs endorsements

A finalized block carries two signature lists, both made of
`"<kn1 address>:<base58 signature>"` entries in the ENDORSE message
schema, both verified by `bft.verify_commits` and counted together for
the quorum:

- `commits` — endorse-schema signatures known to the proposer **at
  proposal time**. In practice this is the proposer's own
  self-endorsement. Phase B: reward accounting no longer reads `commits`
  at all (see below).
- `endorsements` — the endorsement quorum certificate gathered **on the
  wire after** the header was signed. Excluded from the header hash and
  from reward accounting: including them in either would be circular,
  because endorsers sign the block hash, which covers the state root,
  which would then depend on the endorsement set. Entries are sorted for
  a deterministic encoding. Two honest nodes may store different (but
  overlapping) valid quorum sets for the same block; the block identity
  is the header hash, which is unaffected.

Verification (`chain.validate_and_apply` with `require_quorum=True`):
every entry across both lists is reconstructed as an ENDORSE
`ConsensusMessage` over `(level, round, block_hash)` with the validator's
registered public key and its signature verified. Any malformed or forged
entry is a hard rejection. Duplicate addresses count once. The verified
stake must satisfy `stake * 3 > total_stake * 2`.

Solo mode: a single validator holds 100% of stake, so its self-commit
alone satisfies the strict quorum — one schema, one verifier, no special
case.

Known limitation, deliberate: the proposer is the sole rewarded endorser.
Phase B (audit 2, point 4) made this explicit in `_apply_block_rewards`:
it used to derive the endorser set from the addresses in `commits`
without verifying their signatures (signatures are checked only by the
quorum step, after the state root comparison), so a relay could add an
entry and change the reward split. Wire endorsers are quorum evidence
and do not earn endorsement rewards in this version. Moving endorsement rewards to
parent-block accounting (rewarding at level N+1 the endorsers of level
N, the standard resolution) is a consensus rule change tracked for a
future protocol version.

## Node flow

Proposer (its turn per `select_proposer`, cadence `block_time`):

1. Build the block from the mempool (`propose_block`, which trial-applies
   and skips failing transactions; the mempool read is non-destructive).
2. Store it in the pending map, broadcast it on `proposal`.
3. Self-deliver to its own engine: `on_proposal` emits its PREENDORSE,
   which loops through `_ingest_consensus` exactly like a wire message.

Every validator, on a valid proposal or consensus message:

1. Deduplicate by `(kind, level, round, validator)`.
2. Feed `BftEngine.on_message`; broadcast and self-ingest any outbound
   messages it returns (PREENDORSE quorum → own ENDORSE).
3. Re-gossip newly seen wire messages for mesh propagation.
4. Try to finalize: if `get_endorse_qc(level, round)` matches a pending
   block's hash, set `endorsements` from the QC, then
   `chain.append(block, require_quorum=True)`, persist, purge included
   transactions from the mempool, prune engine state, broadcast the
   finalized block.

Followers (no validator key) skip the engine entirely and accept only
finalized blocks, which carry their quorum with them.

## Rounds and timeouts

The node tracks one current round for the level being decided,
initialized to `parent.round + 1`. If no block finalizes within
`max(2 s, 4 × block_time)`, the round advances and the proposer of the
new round may propose. A valid proposal for a higher round adopts that
round and resets the deadline. Rounds never move backwards. Equivocation
(two conflicting signed messages of the same kind at the same level and
round) is detected by the engine and is slashable evidence
(`SlashingEvidence`).

## Catch-up sync

Both sides of a new connection send `hello` with their head level. A node
that learns of a higher peer level — from `hello`, or from a gossiped
finalized block more than one level ahead — requests the missing range
with `get_blocks` (rate-limited to one request per 2 s). Replies stream
at most 512 blocks, applied strictly in order through the same
`require_quorum=True` path as gossiped blocks. Deduplication sets are
advisory only; correctness never depends on them (stale blocks are
rejected by level, duplicate transactions by the mempool key, repeated
consensus messages are idempotent in the engine).

## Persistence

State snapshots are periodic, not per-block: `Storage.maybe_save_state`
writes every `snapshot_interval` blocks (default 16) and the node writes
a final exact snapshot on clean shutdown. On startup, `load_chain` loads
the latest snapshot and deterministically replays the stored blocks
above it through `apply_block`. Legacy databases without a snapshot
level load as-is. This bounds the per-block persistence cost; state-root
computation itself remains O(state) per block under the default `json`
root function and is bounded by the governance-swappable `trie` root
(see `docs/merkle-trie.md`).

## Test coverage

`tests/test_consensus_wire.py` pins this contract: solo strict quorum,
forged-commit hard rejection, non-validator rejection, 3-validator
engine round trip to an accepted QC, 2-of-3 equal-stake insufficiency,
duplicate-entry dedup, network consensus relay + catch-up sync over
localhost sockets, and snapshot + replay state equality.


## Phase C: certificate binding, equivocation slashing, one validator set

These rules close the three consensus findings of the November 2026
external review. They are consensus rules; kern-go must port them
(see [go-port-breakpoints.md](go-port-breakpoints.md) §8).

**Certificates are bound to the proposed block.** A validator's first
vote per (kind, level, round) is stored with its block hash. A quorum is
weighed only over votes whose hash equals the round's proposed block, the
certificate contains only those votes, and it is stored only after
`QuorumCertificate.verify` succeeds against the validator set. Until a
valid certificate exists, every new vote or the late arrival of the
proposal re-evaluates the round. A vote for another block can therefore
neither poison a certificate nor freeze a round.

**Equivocation is visible and punishable.** The node's message
deduplication key includes the block hash, so a second, conflicting vote
reaches the engine and is re-gossiped. The engine turns it into
`SlashingEvidence` once per offence; the validator's node files a
`SLASH_CONSENSUS_EQUIVOCATION` transaction carrying both signed votes.
The chain accepts it when both votes decode strictly, are signed with the
offender's registered key, share kind (PREENDORSE or ENDORSE), level and
round, differ in block hash, are not from a future level, and the
offence (validator, kind, level, round) was not slashed before. The slash
is the same as for governance equivocation: 30% of own stake, 10% of that
to the reporter, the rest burned, delegators slashed proportionally. The
offender's consensus weight drops in the same block.

**One validator set.** `Chain.validators` is no longer the list given at
start-up. It is `consensus_validator_set(state)`: the snapshot
`state["consensus_set"]` of effective stake, written at genesis and
refreshed at the end of every block whose level is a multiple of
`epoch_blocks` (default 120, genesis override). Proposer selection, BFT
vote weights, quorum verification and block validation all read it from
the parent state, so every node uses the same set for the same height.
