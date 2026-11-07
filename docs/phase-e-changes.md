# v1.1-rc Phase E: bond timing, documentation, consensus harness

Phase E answers the external review of Phase D (November 2026, not a professional security audit). Each point was confirmed in the code before being fixed, and each fix starts with a test that fails on the Phase D code.

> **Consensus safety warning.** With several validators, the engine can finalize two blocks at the same level under message delay alone, with every validator honest (no lock, no nil vote). Phase E reproduces this in an automated harness and designs the fix in [consensus-locking.md](consensus-locking.md); the fix itself is **not implemented** and waits for review of that design. Until it lands, multi-validator safety is not established.

| Point | Finding | Fix |
|---|---|---|
| E2 Undelegation weight | `UNDELEGATE_STAKE` removed the bond from `effective_stake` but left `state["consensus_set"]` unchanged, so the bond kept weighing in consensus until the next epoch boundary, contrary to what Phase D documented. | The validator's snapshot entry is lowered to `min(entry, effective_stake)` in the same transaction, as after a slash. No operation raises an entry inside an epoch. |
| E3 Slashing exposure | A slash cut every bond present when the evidence landed, including bonds created after the offence; Tezos and CometBFT slash the stake that was exposed. | Each bond records tranches `{"level", "amount"}`, one per top-up. A slash for an offence at level `L` cuts 30% of the tranches bonded at or before `L`, in live bonds and in unbonding entries that started unbonding at or after `L`. `L` is the vote level for consensus equivocation and the level of the second vote for governance equivocation. Records written before Phase E read as one tranche at level 0. |
| E4 Documentation | `staking.md` still described liquid, spendable delegation, a `register_validator` transaction, a 14-day validator unbonding and double-baking slashing, none of which exist in the code. The README, consensus, summary and index pages also described liquid delegation or guaranteed finality; the README delegation example omitted the now required amount. | `staking.md` rewritten from the code. README, `consensus.md`, `executive-summary.md`, `index.md` corrected; safety warning added to `consensus-wire.md`, `consensus.md`, `phase-d-changes.md`. Wallet usage text now shows `--amount`. |
| E1 Consensus safety (step 1 and 2 of 3) | Fork between two rounds of one level without any faulty validator. | `tests/bft_sim.py`: deterministic network simulator driving real `BftEngine` instances with delays, losses and reordering. `tests/test_phase_e_consensus_harness.py`: the fork as `xfail(strict=True)` tests (scripted, and 200 random schedules: 41 forks today), plus a liveness test that must keep passing. Design for review: [consensus-locking.md](consensus-locking.md). |

## Behaviour changes

- Undelegating lowers the validator's consensus weight in the same block.
- A delegator who bonds after an offence, or who started unbonding before it, is not slashed for it.
- Delegation and unbonding records gain `tranches` (and `unbonding_from` for unbonding entries): the state layout changes, so a running devnet must be reset.
- The test suite now reports 5 expected failures (`xfailed`): the consensus safety tests that E1 step 3 must turn green.

## Still open

- E1 step 3: implement the design once reviewed.
- `validate_and_apply` checks that the proposer is a validator, not that it is the proposer `select_proposer` designates for the round; only the node checks that on proposals. Covered by the design (section 4.5).
- The website (`kern_site/`) and the white paper still use the term "Liquid Proof-of-Stake"; whether to keep that wording is a positioning decision.
- Wire endorsers are still not rewarded. No multi-machine network with independent validators has run this code.

Rules for client implementers: [go-port-breakpoints.md](go-port-breakpoints.md) §10.
