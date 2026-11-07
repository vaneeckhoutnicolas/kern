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
```

Every mukrn is in exactly one place: a balance, a locked attestation bond,
or a governance proposal bond. Issuance adds to `S` and to balances in the
same step; burns (slashing, rejected proposals) subtract from `S` and from
the place the funds were taken.

- Attestation bonds have a single economic owner at any time: the record
  while locked (including during the unbonding period after revocation),
  the issuer once released, the slash otherwise. A slash resolves both
  bonds of the contradicting pair.
- Pinned by `tests/test_phase_b_bond_lifecycle.py`, including the audit
  sequence "revoke both halves, then get slashed".

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
effective_stake(v) = v.stake + sum(B[d] for d, target in delegations if target == v)
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
slashed. A quorum certificate only ever contains verified votes for the
block it certifies.

Pinned by `tests/test_phase_c_bft_quorum.py` and
`tests/test_phase_c_slashing_and_validator_set.py`.
