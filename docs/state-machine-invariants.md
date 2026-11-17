# State-machine invariants

These are the equations the Kern state machine must preserve after every
transaction and every block. Each one is enforced by code and pinned by
an adversarial test; a change that breaks a test below has reintroduced
the corresponding defect.

Notation: `B` = `state["balances"]`, `A` = `state["attestations"]`,
`S` = `state["total_supply"]`, all amounts in mukrn.

## 1. Supply conservation

```
S == sum(B.values())
   + sum(a["bond"] for a in A.values())
   + sum(escrowed governance bonds)
   + sum(v["stake"] for v in validators)            # bonded own stake (Phase D)
   + sum(d["amount"] for d in delegations)          # bonded delegations (Phase D)
   + sum(e["amount"] for e in delegation_unbonding) # unbonding delegations (Phase D)
```

Every mukrn is in exactly one place: a balance, a locked attestation bond,
a governance proposal bond, a bonded stake or a bonded delegation, live or
unbonding. Issuance adds to `S` what it credits, in the same step; burns
(slashing, rejected proposals) subtract from `S` and from the place the
funds were taken.

- A block mints what it credits. On a chain whose genesis names no
  treasury, the treasury share of a reward is not minted, and the half of
  a rejected proposal's bond that a treasury keeps is burned with the
  other half. A proposer without a stake of its own receives everything
  the treasury does not, and shares it with its delegators like any reward.

- Attestation bonds have a single economic owner at any time: the record
  while locked (including during the unbonding period after revocation),
  the issuer once released, the slash otherwise. A slash resolves both
  bonds of the contradicting pair.
- Pinned by `tests/test_phase_b_bond_lifecycle.py`, including the audit
  sequence "revoke both halves, then get slashed", and by
  `tests/test_treasury_and_supply.py`, which checks the equation after
  every block of a chain that puts something in each of its terms: with a
  treasury, without one, and with a proposer whose weight is all delegated.

## 2. Nonce monotonicity

For every sender, `state["nonces"][sender]` increases by exactly one for
each transaction that passes the signature, chain_id, nonce and fee
checks, whether the operation then succeeds or fails. A transaction that
fails before the fee debit changes nothing.

Pinned by `tests/test_phase_b_exception_boundary.py::test_every_poison_tx_is_rejected_not_raised`.

## 3. Exception boundary

`apply_transaction` never raises. Any failure after the fee debit rolls
the state back to the post-fee, post-nonce snapshot and returns
`ok=False`. `propose_block` never raises because of a transaction.

Pinned by `tests/test_phase_b_exception_boundary.py`.

## 4. Determinism of the state root

Applying the same block to the same state yields the same state root on
every node. Inputs that could differ between nodes are excluded from
consensus code: wall-clock time (only header timestamps), local
configuration (fee rules come from state), optional libraries (RIPEMD-160
has a portable implementation; BN254 pairings refuse to run without
py_ecc instead of guessing).

Pinned by `tests/test_phase_b_exception_boundary.py::test_block_containing_poison_tx_validates_deterministically`
and `tests/test_phase_b_precompiles.py`.

## 5. One view of stake

```
effective_stake(v) = v.stake + sum(bond.amount for bond in delegations if bond.validator == v)
staked             = sum(effective_stake(v) for v in validators)
```

The same `effective_stake` drives the issuance staking ratio, reward
splitting, slashing exposure, and the vote weight on both governance
tracks. `state["delegations"]` is the only delegation record.

Pinned by `tests/test_phase_b_state_rules.py`.

## 6. Level

Every transaction in block `N` observes `_current_level == N`.

Pinned by `tests/test_phase_b_state_rules.py::test_transactions_see_the_level_of_their_block`.

## 7. Network binding

If `state["chain_id"]` is set, every applied transaction carries exactly
that `chain_id` in its signed payload.

Pinned by `tests/test_phase_b_state_rules.py`.

## 8. Quorum

With `require_quorum=True`, a block at level > 0 is accepted only if
validators holding more than two thirds of stake produced verified
ENDORSE signatures over its hash (see [consensus-wire.md](consensus-wire.md)).
Rewards never depend on unverified signature lists.

Pinned by `tests/test_consensus_wire.py` and
`tests/test_phase_b_exception_boundary.py::test_extra_commit_entries_do_not_change_rewards`.

## 9. One consensus validator set

The validator set used for block N (proposer selection, vote weights,
quorum, validation) is `consensus_validator_set(state after N-1)`. It
changes only at epoch boundaries or, downwards only, when a validator is
slashed or a bond to it is undelegated (Phase E). A quorum certificate only ever contains verified votes for the
block it certifies.

Pinned by `tests/test_phase_c_bft_quorum.py` and
`tests/test_phase_c_slashing_and_validator_set.py`.

## 10. Weight is collateral

Every unit of consensus weight is backed by funds that are locked and
slashable: bonded own stake and bonded delegations. Liquid balances carry
no weight. Funds that leave a bond stay slashable for the unbonding
period, which is never shorter than an epoch, and slashing evidence is
accepted for that same period.

A slash for an offence at level `L` reaches exactly the stake exposed at
`L` (Phase E): the validator's own stake, and every delegated tranche
bonded at or before `L` whose bond had not started unbonding before `L`.
For every delegation and unbonding record,
`amount == sum(t["amount"] for t in tranches)`.

Pinned by `tests/test_phase_d_bonded_stake.py` and
`tests/test_phase_e_bond_timing.py`.

## 11. The treasury sends nothing

A transaction whose sender is `state["treasury_address"]` is refused before
the fee debit, whatever its kind, its nonce and its fee: it changes
nothing. A mempool refuses it at its door and removes it when it goes
through what waits, and a proposer leaves it out of its block
(`chain.mempool_verdict`). What the treasury holds leaves it when a
treasury proposal is executed, and in no other way. A genesis whose
treasury address is the address of one of its validators is refused.

A block that carries such a transaction is still valid, like any block
that carries a transaction it cannot charge. Structure version 1 makes it
invalid ([api-stability.md](api-stability.md), section 9.16).

Pinned by `tests/test_treasury_and_supply.py`.

## 12. A double vote is kept

On the protocol track the first vote of a validator in a phase stands. A
later vote of that validator in that phase that says something else is
refused, pays its fee, and stays in the state as a double vote, once for
that validator and that phase, with the level of its block.
`SLASH_EQUIVOCATION` punishes a double vote once, as an offence of that
level (invariant 10). A later vote that says the same thing is a vote like
the first. On the treasury track a later vote replaces the earlier one.

Pinned by `tests/test_treasury_and_supply.py`.
