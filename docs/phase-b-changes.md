# v1.1-rc Phase B: external audit fixes

Phase B fixes every finding of the two external reviews received in
September 2026: a state-machine review (audit 1, ten findings) and a
claims-versus-code review (audit 2, seven points). Several changes alter
consensus rules; they are listed for client implementers in
[go-port-breakpoints.md](go-port-breakpoints.md) §7, and the invariants
they protect are in [state-machine-invariants.md](state-machine-invariants.md).

## Audit 1: state machine

| # | Finding | Fix | Consensus rule changed |
|---|---|---|---|
| 1, 2, 10 | Revoked attestation bond returned yet still slashable; slash paid out of a returned bond (balances > supply); second bond of a slashed pair frozen | Revocation starts an unbonding period (default 86 400 blocks, genesis override `attestation_unbonding_blocks`) during which the bond stays locked and slashable, then is released automatically. A slash resolves both bonds: the slash comes out of the larger one, everything else returns to the issuer. | Yes |
| 3 | `_current_level` was the previous level during transactions | Set to the block level before the first transaction | Yes |
| 4 | Delegation ignored in the issuance staking ratio | Staking ratio uses effective stake (own + delegated liquid balances) | Yes |
| 5, 6 | Delegator vote weight inconsistent; three delegation records | `state["delegations"]` is the only record; both governance tracks weigh effective stake; the treasury copy is ignored and dropped | Yes |
| 7 | Uncaught Python exceptions in handlers; a signed transfer without recipient halted every baker | Strict field types at construction; kind presence checks replace `assert`; every handler exception is a rejection with rollback; `propose_block` guards each transaction; never-valid transactions are evicted from the mempool | Yes (rejections instead of crashes) |
| 8 | Declared genesis `total_supply` ignored | A genesis whose declared supply differs from its balances is refused | Genesis only |
| 9 | `chain_id` signed but never enforced | `chain_id` stored in state; transactions for another network, or unbound, are rejected; wallets fetch the node's `chain_id` from `/chain/health` | Yes |

## Audit 2: claims versus code

| Point | Finding | Fix |
|---|---|---|
| 1, 2 | STO transfer moves nothing; header articles did not match the body | Header cites the securities regime (Prospectus Regulation Art. 3, MiFID II Art. 16(9), MAR Art. 14); the "replaces annual audits" sentence is removed; limits stated in the header; transfer entries renamed to compliance gates (`check_transfer_compliance`, `check_secondary_trade_compliance`) |
| 3 | `verify_zk_claim` returned True | Real Groth16 verification on BN254 against a registered verifier key that must hash to the claimed `verifier_key_hash`; the structural check is `check_zk_claim_shape` |
| 4 | Commit quorum did not verify signatures | Closed by Phase A (`bft.verify_commits`, `require_quorum=True` on live nodes); Phase B also stops reward accounting from reading unverified commit addresses |
| 5 | Genesis labelled mainnet with public keys | Renamed `kern-devnet-placeholder` and marked `placeholder_keys`; the builder refuses mainnet names; the node refuses a mainnet genesis that funds placeholder-seed addresses |
| 6 | Rollup fraud recognised by shape; revert without executed step | Challenges run a bisection and end only through `resolve_challenge`, which re-executes the disputed step with `single_step_verify`; the batch program is bound by `program_hash` |
| 7 | RIPEMD-160 and ECRECOVER returned zeros on missing libraries | Portable RIPEMD-160; ECRECOVER documented as the Ed25519 verifier it is and fails loudly without PyNaCl; BN254 pairing raises without py_ecc and the node refuses to start |

The BN254 pairing now runs on py_ecc's `optimized_bn128` module (iterative
field exponentiation, one final exponentiation for the whole product). The
former recursive implementation overflowed Windows' thread stack; the
Windows-only xfail on `test_pairing_with_real_implementation_basic_property`
is removed.

## Also in this phase

- CodeQL alert py/partial-ssrf in `kern_explorer/client.py`: every value
  placed in an RPC URL path is checked against a strict format and
  percent-encoded.
- README states the project's stage: a Layer-1 protocol with a Python
  reference implementation, at devnet stage, no public network in
  operation.
- Genesis distribution figures aligned on `genesis.json`
  (70 / 10 / 14 / 3 / 2 / 1) across the documentation.

## Not in this phase (documented limitations)

- Endorsement rewards for wire endorsers (parent-block accounting).
- Rollup operations are not L1 transaction kinds; bonds, bounties and
  response deadlines of the challenge game are not wired.
- No circuits, trusted setup or prover ship with the ZK module.
- Skald has no mapping types, so STO templates cannot hold token
  balances.
