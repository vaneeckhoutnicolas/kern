# v1.1-rc Phase C: consensus hardening

Phase C fixes the three consensus findings of an independent external
review received in November 2026 (not a professional security audit).
All three were confirmed in the code before being fixed. Each changes a
consensus rule; client implementers find the exact rules in
[go-port-breakpoints.md](go-port-breakpoints.md) §8 and the protocol
description in [consensus-wire.md](consensus-wire.md).

| Point | Finding | Fix |
|---|---|---|
| A | The BFT engine counted every vote of a round towards the quorum, whatever block it was for, and froze the first certificate it built. A certificate could carry a signature over another block; block validation then rejected it and nothing rebuilt it. One faulty validator out of four could stop a round from finalizing. The same held for pre-endorsements. | Votes are stored with their block hash. A certificate is built only from votes for the proposed block and stored only after it verifies. Rounds re-evaluate on every new vote and when a late proposal arrives. |
| B | `Chain.validators` was the list given at start-up. Slashing and delegation lived in chain state and never reached proposer selection, vote weights or block validation. `docs/consensus.md` claimed the opposite. | One consensus set: `state["consensus_set"]`, a snapshot of effective stake (own stake after slashing plus delegated liquid balances), written at genesis and refreshed every `epoch_blocks` blocks (default 120). Delegation moves weight at the next boundary; a slash lowers weight immediately. `Chain.validators` and the BFT engine read it. |
| C | The node deduplicated consensus messages without the block hash, so a conflicting vote never reached the engine; the engine only logged equivocation; no transaction could submit consensus equivocation evidence. | The dedup key includes the block hash. The engine produces `SlashingEvidence` once per offence; the node files a `SLASH_CONSENSUS_EQUIVOCATION` transaction; the chain verifies both signed votes against the registered key and slashes each offence once. |

Also corrected: `docs/consensus.md` described delegator rewards as
"enforced socially"; the protocol has split rewards with delegators since
v1.0-rc.

## Still open

- Evidence has no expiry window: a valid equivocation can be reported at
  any later height while the offender is a validator.
- Wire endorsers are still not rewarded (proposer-only rewards).
- No multi-machine network with independent validators has run this code
  yet; the BFT logic is exercised by in-process and loopback tests.
