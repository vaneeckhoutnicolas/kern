# Multi-validator BFT

This document specifies Kern's multi-validator consensus protocol — the full three-phase BFT message exchange that the v0.2 reference implementation in [`kern/bft.py`](../kern/bft.py) realizes.

The single-validator view (where the lone baker self-commits) lives in [`consensus.md`](consensus.md). This document picks up where that one stops.

---

## The three phases

Every round of the consensus protocol exchanges three message types between validators:

```
                     ┌─────────────────────────────────────────┐
                     │   level L, round R: select proposer P   │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                          ╔═══════════════════════════════════╗
                          ║         PROPOSE                    ║
                          ║   P broadcasts a candidate block   ║
                          ║   to all validators                 ║
                          ╚═══════════════╤═══════════════════╝
                                          │
                                          ▼
                          ╔═══════════════════════════════════╗
                          ║         PRE-ENDORSE                ║
                          ║   Each validator broadcasts a      ║
                          ║   signature over (L, R, hash)      ║
                          ╚═══════════════╤═══════════════════╝
                                          │
              ┌───────────────────────────┴───────────────────────┐
              │ stake_signed * 3 > total_stake * 2 ?               │
              └───┬───────────────────────────────┬───────────────┘
                  │ yes                            │ no
                  ▼                                ▼
   ╔═══════════════════════╗            ┌─────────────────────────┐
   ║      ENDORSE           ║            │ Round R times out;       │
   ║ Each validator emits   ║            │ advance to round R+1     │
   ║ a second signature     ║            └─────────────────────────┘
   ╚═══════════╤═══════════╝
               │
               ▼
   ┌───────────────────────┐
   │ Endorsement quorum    │
   │ certificate (EQC)     │
   │ included in NEXT block│
   │ — block at L is final │
   └───────────────────────┘
```

**The two-phase commit pattern is what gives BFT consensus its safety property.** In the pre-endorsement phase, validators commit to a particular block at a particular (level, round) — they cannot pre-endorse a different block at the same (level, round) without being slashed. Only after seeing > 2/3 of stake committed in the pre-endorsement phase do validators endorse. This guarantees that two contradicting blocks cannot both gather endorsement quorums, because that would require > 2/3 stake to have pre-endorsed both — but pre-endorsing two different blocks at the same (level, round) is a slashable offense.

## Message format

Every consensus message is a small JSON object signed with the validator's Ed25519 key:

```python
ConsensusMessage(
    kind="propose" | "preendorse" | "endorse",
    level=L,              # int
    round=R,              # int
    block_hash=hex,       # the header hash being voted on
    validator=kn1...,     # the signing validator's address
    validator_pubkey=kpk..., # for verification
    signature=ksig...,    # Ed25519 over the canonical JSON of the above
)
```

The signature is verified against the validator's registered public key in the active validator set; messages from non-validators are dropped on receipt.

## The quorum certificate

A quorum certificate (QC) is a collection of signed messages of the same kind, level, round, and block_hash, from validators whose combined stake exceeds 2/3 of the total active stake:

```python
QuorumCertificate(
    kind="preendorse" | "endorse",
    level=L,
    round=R,
    block_hash=hex,
    signatures={kn1...: ksig..., ...},
)
```

Two important QCs:

- **Pre-endorsement QC (PQC):** > 2/3 stake pre-endorsed the same block at (L, R). The PQC must be included in the block (or in the round's proposal payload, depending on the variant).
- **Endorsement QC (EQC):** > 2/3 stake endorsed the same block at (L, R). The EQC is included in the *next* block (L+1) by its proposer, finalizing block L.

The QC carries enough signatures for any verifier — including a light client — to check finality independently. Stake-weighted summation: if the total stake registered in the validator set at level L is `S`, a QC is valid iff `sum(stake(v) for v in QC.signatures) * 3 > S * 2`.

## Round timing

| Phase           | Default duration | Purpose                                      |
|-----------------|------------------|----------------------------------------------|
| Propose         | 250 ms           | Proposer assembles & broadcasts the block    |
| Pre-endorse     | 250 ms           | Validators exchange pre-endorsements         |
| Endorse         | 250 ms           | Validators exchange endorsements             |
| Round buffer    | 250 ms           | Gossip propagation slack                     |
| **Round total** | **1 second**     | Target block time                            |

If a round elapses without an endorsement quorum, the next round begins with an incremented round number. The proposer for round R+1 is selected via the same VRF-style function as round R, but with `round=R+1` mixed into the seed. Round duration is exponentially padded: round 1 takes 2s, round 2 takes 4s, and so on, to allow recovery from network partitions without thrashing.

## Equivocation and slashing

Two specific offenses are detectable from on-chain messages alone:

### 1. Double-baking

A validator V proposes two different blocks at the same (level, round). Evidence: two `PROPOSE` messages or two signed block headers from V at the same (L, R) with distinct block hashes.

### 2. Double-endorsing (or double-pre-endorsing)

A validator V signs two contradictory pre-endorsements (or endorsements) at the same (L, R) — two messages with the same kind, level, round, and validator, but distinct `block_hash`.

The reference implementation provides the `SlashingEvidence` dataclass:

```python
@dataclass
class SlashingEvidence:
    offender: str
    msg_a: ConsensusMessage
    msg_b: ConsensusMessage

    def verify(self) -> tuple[bool, str]:
        # Returns (True, "valid") iff:
        # - both messages come from offender
        # - same kind, level, round
        # - distinct block_hash
        # - both signatures valid
```

Any third party can construct and submit this evidence on-chain. The protocol's slashing operation:

1. Verifies the evidence.
2. Confiscates 50% of the offender's bonded stake.
3. Burns 50% of the confiscated amount.
4. Pays 50% of the confiscated amount to the submitter as a bug bounty.

Delegated funds are slashed proportionally to the validator's stake — delegators are economically tied to their chosen validator's behavior, which is what makes the LPoS reward structure work.

## Liveness and view changes

Under normal operation, every round finalizes in ~1 second. Liveness assumes:

- **Honest majority by stake.** No more than 1/3 of stake is byzantine.
- **Partial synchrony.** Network delays are eventually bounded.

When these assumptions hold, the protocol is live: every level finalizes within a bounded number of rounds. When they fail:

- **Network partition (< 1/3 cut off):** the larger partition continues to finalize blocks. The smaller partition stalls. On healing, the smaller partition fast-forwards to the canonical chain.
- **Network partition (≥ 1/3 cut off on both sides):** both sides stall. Neither can produce blocks. This is the BFT safety-vs-liveness trade-off: when stake is split too evenly, the protocol prioritizes safety (no conflicting blocks finalized) over liveness (some blocks finalize).
- **Persistent byzantine behavior:** offenders are slashed over time, eventually removing their stake from the active set.

There is no separate "view change" protocol — the round timer mechanism handles it implicitly. A failing proposer causes the round to time out; the next round's proposer takes over.

## What this means concretely for finality

- **Block at level L** is **committed** when its endorsement quorum certificate exists. The validators who endorsed it cannot revert without being slashed.
- **Block at level L** is **final** when block at L+1 has been committed on top of it. At this point any attempt to revert L would require building an alternative L+1 *with the same parent*, which would require contradictory pre-endorsements at (L+1, R) — a slashable offense.

In the steady state: block at level L is final approximately 2 seconds after its creation (one second to produce L+1, plus the gossip + verification cycle).

## Comparison with other BFT chains

| Chain      | Algorithm    | Phases | Finality      | Slashing condition                |
|------------|--------------|--------|---------------|-----------------------------------|
| Tezos      | Tenderbake   | 3      | 2 blocks ~ 16s| Double-baking, double-endorsing   |
| Ethereum   | Gasper       | 2      | ~12 min       | Double-vote, surround-vote        |
| Cosmos     | Tendermint   | 3      | 1 block ~6s   | Double-sign                       |
| Aptos      | DiemBFT v4   | 3      | ~1s           | Double-sign                       |
| **Kern**   | **BFT (3-phase)** | **3** | **~2s** | **Double-baking, double-endorsing** |

Kern's design choices (3-phase, ~2s finality, double-X slashing) sit within the established BFT-with-slashing family. The embedded governance + Skald story are not properties of the consensus algorithm itself.

## Reference implementation

[`kern/bft.py`](../kern/bft.py) provides:

- `ConsensusMessage` — signed message with sign/verify methods
- `QuorumCertificate` — collection of signatures with `verify(validator_set)` method
- `BftEngine` — per-node state machine with `on_proposal()`, `on_message()` callbacks
- `RoundState` — per-(level, round) state
- `SlashingEvidence` — equivocation proof with `verify()` method

Tested in [`tests/test_bft.py`](../tests/test_bft.py) with 9 scenarios covering:

- Message sign/verify round-trips
- Three-validator quorum reaching pre-endorsement → endorsement
- Insufficient-stake QCs being rejected
- QCs containing non-validators being rejected
- Equivocation evidence verification (positive and negative cases)
- State pruning for finalized levels
