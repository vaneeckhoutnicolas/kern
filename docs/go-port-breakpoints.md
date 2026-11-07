# kern-go port breakpoints

This document inventories every place where a naive Go translation of
this Python reference implementation would silently diverge — producing
different bytes, different hashes, or different state roots — and states
the required resolution. It exists because the Python implementation is
the **executable specification**: kern-go must reproduce its consensus
outputs bit-for-bit before it can be called a reference client (see
`roadmap.md`, Track 4).

Sites are referenced by module and function name rather than line number.

## 1. Integer semantics

Python integers are arbitrary precision. Go's are fixed-width. Three
distinct hazards:

**1a. Products that exceed int64 (~9.22e18).**

| Site | Product | Magnitude |
|---|---|---|
| `issuance.reward_per_block` | `total_supply * rate_ppm` | ~6e18 at 100M KRN genesis supply, **grows with issuance** — will cross int64 |
| `issuance.distribute_baker_pool` | `remainder * stake` | up to ~1e23 |
| `issuance.split_validator_reward` | `remaining * balance` | up to ~1e23 |
| `issuance._smoothstep_ppm` | `x * x * (3*PPM - 2*x)` | up to 3e18 — under int64 today, no headroom |
| `governance` quadratic tallies (`_isqrt` inputs) | stake²-scale | > int64 |

Resolution: all consensus-visible arithmetic in kern-go uses
`math/bits.Mul64`/`Div64` pairs or `math/big.Int`. Never bare `*` on
amounts. The issuance module docstring carries the same warning.

**1b. JSON numbers decode to float64 by default in Go.**
`encoding/json` unmarshals numbers into `float64` unless told otherwise;
integers above 2^53 (9.007e15) lose precision silently. Genesis supply in
mukrn is 1e14 — safe today by two orders of magnitude, not safe by
design. Resolution: decode with `json.Decoder.UseNumber()` or into
typed structs with `int64`/`big.Int` fields, and **reject** any number
token containing `.`, `e`, or `E` in consensus objects (the strict
`from_dict` decoders on the Python side already reject non-int types;
kern-go must reject float syntax at the same boundary).

**1c. Division and modulo.** Python `//` floors; Go `/` truncates toward
zero. All consensus quantities here are non-negative, where floor and
truncation coincide — but any future signed arithmetic must use explicit
floor division. Keep amounts unsigned end-to-end.

## 2. Canonical JSON encoding

Every signed payload and every hash preimage in this codebase is
produced by:

```python
json.dumps(d, sort_keys=True, separators=(",", ":"))
```

(`transaction`, `block`, `bft.ConsensusMessage`, `chain.state_root_hex`
under the default `json` root function.) Python's default
`ensure_ascii=True` escapes every non-ASCII character as `\uXXXX`;
Go's `encoding/json` instead emits UTF-8 and additionally escapes
`<`, `>`, `&` for HTML safety. These produce **different bytes for the
same value**, hence different hashes.

Resolution: kern-go implements a dedicated canonical marshaller (no
`encoding/json` for hash preimages) with the exact rules: keys sorted
bytewise; separators `,` and `:` with no whitespace; strings escaped
exactly as Python's `ensure_ascii=True` does (`"`, `\`, control chars,
and all code points ≥ U+0080 as `\uXXXX` with lowercase hex, surrogate
pairs for astral plane); integers in base 10 with no sign for zero;
**no floats anywhere** (Phase A removed the last consensus float —
issuance is ppm integer fixed-point). Both clients validate against the
shared vectors in §6. Protocol rule to preserve: consensus-hashed string
fields are ASCII by construction (addresses, base58, hex); Skald
sources and storage values that may contain non-ASCII are covered by
the escape rules above.

## 3. Map iteration order

Go randomizes map iteration; Python 3.7+ dicts preserve insertion order.
Any consensus-visible iteration must be explicitly ordered in kern-go:

- Validator sets and endorser lists are **lists** here, and
  `issuance.distribute_baker_pool` documents that distribution follows
  validator-set list order — port as slices, never maps.
- Reward crediting iterates `per_validator` dicts; state mutation order
  is invisible to the state root (the root serializes sorted), but any
  future event/receipt stream must sort explicitly.
- `block.endorsements` entries are sorted lexicographically at
  finalization (`node._try_finalize`) — preserve.

## 4. Cryptography

| Primitive | Python | Go | Note |
|---|---|---|---|
| Ed25519 | PyNaCl (libsodium) | `crypto/ed25519` | Both RFC 8032; interop verified via shared vectors |
| Hashing | `hashlib.blake2b` with domain keys (e.g. `kern.merkle`) and digest sizes 8/32 | `golang.org/x/crypto/blake2b` | Keyed mode + digest size must match exactly |
| Base58 | custom alphabet in `crypto` | port the same table | Address/pubkey/signature prefixes are part of the format |
| BN254 pairing | `py_ecc` (pure Python) | **`gnark-crypto` (bn254 package)** | **blst is BLS12-381-only and cannot implement BN254** — earlier notes suggesting a py_ecc→blst swap are corrected in this repo. gnark-crypto is maintained, audited, and constant-time where it matters. A compiled BN254 backend also sidesteps py_ecc's deep-recursion issue on Windows. |

## 5. Concurrency model

The Python node is effectively single-threaded: one asyncio loop owns
chain state, and handlers never run concurrently with each other. The
Go node will have real parallelism. Rule: a single goroutine owns
`Chain` mutation (apply/append); network handlers communicate with it
over channels; read-only RPC takes snapshots or a RWMutex. The BFT
engine (`bft.BftEngine`) is a pure state machine — port it as one and
keep it inside the owner goroutine. Deadlines use the monotonic clock
(`time.monotonic()` here, Go `time.Now()` monotonic reading), never
wall-clock arithmetic; block timestamps are integer unix seconds.

## 6. Differential testing protocol

kern-go earns "reference client" status only after passing cross-client
vectors generated from this repo:

1. **Encoding vectors**: canonical bytes + blake2b hashes for a corpus
   of transactions, headers, blocks (with commits and endorsements),
   and consensus messages — including non-ASCII Skald sources and
   maximal integer values.
2. **Issuance vectors**: `reward_per_block(1e15, 300_000) == 720_587`
   is pinned in `tests/test_issuance.py`; extend to a sweep of
   (supply, ratio_ppm) pairs including values past int64.
3. **State roots**: scripted block sequences (transfers, originations,
   delegation, governance, slashing) with expected roots after each
   block, under both `json` and `trie` root functions.
4. **Quorum vectors**: blocks with valid/forged/duplicate/insufficient
   endorsement sets and the exact accept/reject verdict
   (`tests/test_consensus_wire.py` is the source of truth).

Divergence anywhere is a kern-go bug by definition until proven to be a
specification bug here — in which case this repo is fixed **first** and
the vectors regenerated (see `roadmap.md`: changes land in the
specification before the port).

## 7. Phase B consensus rule changes (port these exactly)

Each item below changes what a valid block is or what state it produces.
The source of truth is the code and the named tests; see
[phase-b-changes.md](phase-b-changes.md) for the rationale.

| Rule | Python reference | Pinned by |
|---|---|---|
| Any exception raised while applying an operation is a deterministic rejection after fee and nonce (state rolled back to post-fee). Kind-specific presence rules (`_malformed_reason`) run after the fee debit. | `chain.apply_transaction`, `chain._malformed_reason` | `tests/test_phase_b_exception_boundary.py` |
| Transaction field types are checked at construction (`Transaction.__post_init__`), not only in `from_dict`. | `transaction.Transaction.__post_init__` | same |
| `_current_level` is set to the block level before the first transaction. | `chain.apply_block`, `consensus.propose_block` | `tests/test_phase_b_state_rules.py` |
| Rewarded endorser set = `{proposer}`; `commits` are never read for rewards. | `chain._apply_block_rewards` | `tests/test_phase_b_exception_boundary.py::test_extra_commit_entries_do_not_change_rewards` |
| Staking ratio and both governance tracks use effective stake (bonded own stake + bonded delegations since Phase D); the treasury track has no delegation copy. | `chain._compute_staked`, `chain._governance_validator_set` | `tests/test_phase_b_state_rules.py` |
| If state carries `chain_id`, a transaction must carry the same `chain_id` (null rejected); checked before any mutation. | `chain._check_signature_and_nonce` | same |
| Genesis: declared `total_supply` must equal the sum of balances; `chain_id` is copied into state. | `chain.initial_state_from_genesis` | same |
| Attestation revoke starts an unbonding period (`attestation_unbonding_blocks`, default 86 400); bonds are released at the end of the block, after rewards and before the governance tick, in ascending release level then insertion order. A slash resolves both bonds. | `chain._apply_revoke_attestation`, `chain._release_matured_attestation_bonds`, `chain._apply_slash_attestation_equivocation` | `tests/test_phase_b_bond_lifecycle.py` |
| RIPEMD-160 precompile always returns the real digest; ECRECOVER is an Ed25519 verifier. | `evm.frames` | `tests/test_phase_b_precompiles.py` |


## 8. Phase C consensus rule changes

| Rule | Python reference | Pinned by |
|---|---|---|
| A QC counts and contains only votes for the round's proposed hash; it is stored only after verification; rounds re-evaluate until a valid QC exists | `bft.BftEngine._build_qc`, `_advance`, `_record_vote` | `tests/test_phase_c_bft_quorum.py` |
| Consensus message dedup key = (kind, level, round, validator, block_hash) | `node.Node._ingest_consensus` | `tests/test_phase_c_slashing_and_validator_set.py` |
| New operation `slash_consensus_equivocation` with params `{msg_a, msg_b}` (ConsensusMessage dicts); offence key `"<addr>|<kind>|<level>|<round>"` in `state["consensus_slashes"]` | `chain._apply_slash_consensus_equivocation`, `chain._slash_validator` | same |
| `state["consensus_set"]` written at genesis and at the end of each block with `level % epoch_blocks == 0` (after the governance tick); a slash lowers the offender's entry to `min(entry, effective_stake)` immediately | `chain.compute_consensus_set`, `chain._epoch_tick`, `chain._slash_validator` | same |
| The consensus set for block N is the one in the state after block N-1 | `chain.Chain.validators` | same |


## 9. Phase D consensus rule changes

| Rule | Python reference | Pinned by |
|---|---|---|
| Genesis bonds each validator's stake out of its balance (refused if insufficient); `delegation_unbonding_blocks >= epoch_blocks` | `chain.initial_state_from_genesis` | `tests/test_phase_d_bonded_stake.py` |
| Delegation records are `{"validator", "amount"}`; `DELEGATE_STAKE` debits `tx.amount` (must be > 0, same validator only); `UNDELEGATE_STAKE` queues the bond in `delegation_unbonding[str(level + unbonding)]` | `chain._apply_delegate_stake`, `chain._apply_undelegate_stake` | same |
| Unbonding releases run at the end of the block, after attestation releases, before the governance tick | `chain._release_matured_delegation_bonds` | same |
| effective_stake counts bonded amounts only | `chain.effective_stake`, `chain.delegators_of` | same |
| Slash: 30% of own stake (10% of it to the reporter, rest burned) and 30% of each bond and unbonding entry to the offender (burned); refused only if all are zero | `chain._slash_validator` | same |
| Consensus equivocation evidence older than `delegation_unbonding_blocks` is rejected | `chain._apply_slash_consensus_equivocation` | same |

## 10. Phase E consensus rule changes

| Rule | Python reference | Pinned by |
|---|---|---|
| `UNDELEGATE_STAKE` lowers the validator's entry in `consensus_set` to `min(entry, effective_stake)` in the same transaction; no operation raises an entry inside an epoch | `chain._apply_undelegate_stake`, `chain._lower_consensus_weight` | `tests/test_phase_e_bond_timing.py` |
| Delegation records are `{"validator", "amount", "tranches"}`, each tranche `{"level", "amount"}`; a top-up at the level of the last tranche merges into it, otherwise appends; records without `tranches` read as one tranche at level 0 | `chain._apply_delegate_stake`, `chain._tranches` | same |
| Unbonding entries are `{"delegator", "validator", "amount", "tranches", "unbonding_from"}`; entries without `unbonding_from` are treated as exposed | `chain._apply_undelegate_stake` | same |
| Slash for an offence at level `L`: 30% (integer division, per tranche) of each tranche with `level <= L`, in live bonds and in unbonding entries with `unbonding_from >= L`; `amount` is recomputed as the sum of the tranches | `chain._slash_validator`, `chain._cut_exposed_tranches` | same |
| `L` is the vote level for `SLASH_CONSENSUS_EQUIVOCATION`, and `second_at_level` of the equivocation record for `SLASH_EQUIVOCATION` (current level if missing) | `chain._apply_slash_consensus_equivocation`, `chain._apply_slash_equivocation` | same |

## 11. Phase E, E1: lock, valid round, signed proposals

Design: [consensus-locking.md](consensus-locking.md). Wire: [consensus-wire.md](consensus-wire.md), section "Phase E". The block format changes, so a devnet must be reset.

| Rule | Python reference | Pinned by |
|---|---|---|
| Header field `round` is renamed `payload_round` (signed, hashed, wire key `"payload_round"`); body field `cert_round` (not hashed; absent or null means `payload_round`); both integers in `[0, 2**32 - 1]`; a header carrying `round` is refused | `block.BlockHeader`, `block.Block.quorum_round`, `block.MAX_ROUND` | `tests/test_phase_e_locking.py` |
| `validate_and_apply`, for every non-genesis block: `header.proposer == select_proposer(parent_hash, validator_set, payload_round)`; `cert_round >= payload_round` | `chain.validate_and_apply` | same |
| Quorum check: `endorsements` verified as ENDORSE at `(level, cert_round, hash)`, `commits` at `(level, payload_round, hash)`; any bad entry is fatal; stake counted over both lists (address deduplicated) when `cert_round == payload_round`, over `endorsements` only otherwise; need `stake * 3 > total * 2` | `chain.validate_and_apply`, `bft.verify_commits` | same |
| PROPOSE message signed payload = vote payload plus `"valid_round"` (canonical JSON, sorted keys); votes keep the Phase D payload; `valid_round` in `[-1, round - 1]` for PROPOSE, absent or -1 for votes | `bft.ConsensusMessage` | same |
| Proposal envelope `{"block", "proposal", "proof"}`; acceptance checks in the order of consensus-wire.md "Proposals travel as full blocks" | `node.Node._on_proposal_msg`, `node.Node._envelope` | `tests/test_phase_e_locking.py`, `tests/test_phase_e_multiprocess.py` |
| `propose_block` signs the self-commit only if the proposer's stake `* 3 > total * 2` in `consensus_validator_set(state_before)` (or the set is empty); otherwise `commits = []` | `consensus.propose_block`, `consensus.holds_quorum_alone` | `tests/test_phase_e_locking.py` |
| Every level starts at round 0; `round_timeout(base, r) = base + r * base / 2`, `base = max(2, 4 * block_time)` seconds; move to round r' when stake voting at r' `* 3 > total` (r' above the current round) or on a valid proposal for r' within 8 rounds | `consensus.round_timeout`, `bft.BftEngine.round_to_skip_to`, `node.Node._consensus_loop` | `tests/test_phase_e_consensus_harness.py` |
| Engine: vote only in the current round; pre-endorse rule 2, endorse and lock rule 3, valid round rule 4 (never above the current round), finalize at any round (consensus-wire.md, "Voting rules") | `bft.BftEngine._advance`, `_may_preendorse`, `_proof_ok`, `find_endorse_qc` | `tests/test_phase_e_locking.py`, `tests/test_phase_e_consensus_harness.py` |
| Proposer re-proposes `valid_hash` with `valid_round` and the PREENDORSE certificate as proof when it holds the block; otherwise a new payload | `node.Node._propose` | same |
| Two different PROPOSE messages from one proposer for one (level, round): `ProposalEquivocation`, kept, not slashable; the chain still only slashes PREENDORSE and ENDORSE | `bft.ProposalEquivocation`, `chain._apply_slash_consensus_equivocation` | same |
| Signing journal: JSON lines `{chain_id, kind, level, round, block_hash, locked_round, locked_hash, valid_round, valid_hash}`, written and fsynced before signing; same (kind, level, round) with another hash refused; cut final line ignored, any other bad line makes the journal unreadable; unreadable or missing (height > 0) suspends signing for the level in progress | `signing_journal.SigningJournal`, `bft.BftEngine._sign`, `node.Node._open_signing_journal` | `tests/test_phase_e_locking.py` |
