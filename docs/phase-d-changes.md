# v1.1-rc Phase D: consensus weight backed by slashable collateral

> **Superseded in part by [Phase E](phase-e-changes.md).** The table below says `UNDELEGATE_STAKE` "removes the weight at once"; in the Phase D code it removed the bond from `effective_stake` but left the epoch snapshot unchanged until the next boundary. Phase E fixes that and limits slashing to the stake exposed at the offence. **Consensus safety warning:** with several validators, the engine can finalize two blocks at the same level under message delay alone (no lock, no nil vote); multi-validator safety is not established until the fix designed in [consensus-locking.md](consensus-locking.md) is delivered.

Phase D answers a fourth independent external review (November 2026, not
a professional security audit) of the Phase C code. Its main finding was
economic, not cryptographic: consensus weight could exist without funds
exposed to slashing. Every point below was confirmed in the code before
being fixed. All of them change consensus rules; client implementers find
the exact rules in [go-port-breakpoints.md](go-port-breakpoints.md) §9.

| Point | Finding | Fix |
|---|---|---|
| Delegation | A delegation counted the delegator's LIQUID balance in the epoch snapshot. A holder could delegate before a boundary, move the funds the next block, and leave weight with no collateral. The slash hit current balances, not the funds behind the weight; a validator without own stake could not be slashed at all. | Delegation is bonded: `DELEGATE_STAKE` moves `tx.amount` out of the balance into the delegation record. `UNDELEGATE_STAKE` removes the weight at once but keeps the funds locked and slashable for `delegation_unbonding_blocks` (default 86 400, never shorter than an epoch), then releases them. Effective stake counts bonded amounts only. Slashing burns 30% of bonds and unbonding amounts to the offender, and works with zero own stake. Switching validator requires undelegating first. |
| Own stake (found while fixing) | A genesis validator's stake was a number declared next to an equal, fully spendable balance. | At genesis the stake is bonded out of the balance; a genesis without the balance to back a stake is refused. `total_supply` is unchanged. |
| Evidence window | Equivocation evidence had no expiry. | Accepted for `delegation_unbonding_blocks` after the vote, i.e. as long as the funds behind it are guaranteed to be locked. |
| BFT memory | Any signed message created a `RoundState` for any (level, round). | Messages are dropped unless the level is within `min_level .. min_level + 2`, the round within 8 of the node's round, and fewer than 256 states are kept. |
| Report nonces | Several reports filed before inclusion reused the same nonce. | The node keeps a local next-nonce for its own reports. |

## Behaviour changes

- `make_delegate_stake(..., amount=...)` and `kern_wallet.py delegate --amount` are now required to delegate.
- The README, staking, tokenomics, delegator and consensus documents no longer describe delegation as liquid or lock-up free.
- Phase D changes consensus rules and the state layout (delegation records are `{"validator", "amount"}`, new `delegation_unbonding` queue): a running devnet must be reset.

## Still open

- Slashing applies to bonds present at slashing time, including bonds
  created after the offence (no per-bond "since" level yet).
- Wire endorsers are still not rewarded (proposer-only rewards).
- No multi-machine network with independent validators has run this code.
