# Kern v0.6 — what changed

This document summarizes the v0.6 changes made on top of v0.5. The headline change is **governance now runs through chain transactions, not Python calls**. The v0.5 release shipped governance as a working state machine that was *invoked manually* by tests; v0.6 makes it the chain's normal operation.

Three pieces:

1. **Governance as transactions** — `GOVERNANCE_PROPOSE` and `GOVERNANCE_VOTE` are real Kern operations, signed and sequenced like transfers.
2. **Governance wired into `apply_block`** — every block advances governance phases and applies any new activations to chain state.
3. **Proposal bonds** + **remaining precompiles** — anti-spam economics for governance; RIPEMD160, MODEXP, BLAKE2F for the EVM.

For deeper context see [`governance.md`](governance.md) (the spec, updated for v0.6) and [`multi-frame-evm.md`](multi-frame-evm.md) (the EVM, now with more precompiles).

---

## 1. Governance as transactions

The biggest architectural change in v0.6 is that **governance proposals and votes are now first-class operations on the chain** — they go through the mempool, get signed, get sequenced, get included in blocks, and get processed by `apply_transaction` exactly like transfers and calls.

### Two new OpKinds

```python
class OpKind(str, Enum):
    TRANSFER = "transfer"
    ORIGINATE = "originate"
    CALL = "call"
    GOVERNANCE_PROPOSE = "governance_propose"   # v0.6
    GOVERNANCE_VOTE = "governance_vote"         # v0.6
```

Both new ops use the existing `params` field (a generic `Any`) to carry their data, preserving the canonical transaction encoding from earlier versions.

### Builders

```python
from kern.transaction import make_governance_propose, make_governance_vote

# Submit a protocol amendment
propose_tx = make_governance_propose(
    sender_kp=baker_kp,
    track="protocol",
    payload={"params": {"i_max": 0.05}},
    nonce=0,
)

# Cast a vote
vote_tx = make_governance_vote(
    sender_kp=baker_kp,
    track="protocol",
    proposal_id=pid,
    vote="yes",
    nonce=1,
)
```

These transactions are injected into the mempool via the same RPC endpoint as everything else. From the network's perspective, governance is just another kind of activity.

### What this enables

- **No special channel.** Governance doesn't need its own message format, its own gossip protocol, or its own validation rules. Any feature that works for transfers (signature verification, nonce ordering, fee debiting, fraud-proof inclusion in batches) works for governance.
- **Reproducible history.** The full sequence of who proposed what, who voted how, and when each phase transitioned is a permanent on-chain record reproducible from genesis.
- **Programmatic submission.** DApps can submit proposals (e.g., "this DEX wants 500K KRN from treasury for an incentive program") through the same client libraries used for transfers.

## 2. Governance wired into `apply_block`

The second change is that `apply_block` now drives the governance state machine automatically.

### What changed in `chain.py`

```python
def apply_block(state, block):
    new_state = copy.deepcopy(state)
    for tx in block.transactions:
        apply_transaction(new_state, tx, baker=block.header.proposer)
    _apply_block_rewards(new_state, block)
    _apply_governance_tick(new_state, block.header.level)   # ← v0.6
    return new_state, results
```

`_apply_governance_tick` does three things in every block:

1. **Advance phases.** Calls `gov.advance_phases(current_level)` on both tracks. Proposals whose phase windows have elapsed move on (e.g., SUBMITTED → EXPLORATION, EXPLORATION → COOLDOWN or REJECTED).

2. **Apply activations.** When a protocol proposal reaches ACTIVATED, the new change is applied to chain state immediately:
   - `{"params": {...}}` → merges into `state["issuance_params"]`
   - `{"swap": "state_root_function", "to": "trie"}` → sets `state["state_root_function"] = "trie"`

3. **Settle bonds.** For every proposal that terminated this block, resolve its bond per the matrix below.

### Governance state in the chain state dict

```python
state["governance"] = {
    "protocol": {
        "proposals": {pid: serialized_proposal_dict, ...},
        "activated_changes": [list of dicts],
        "bonds": {pid: {"submitter": addr, "amount": int}, ...},
    },
    "treasury": {
        "proposals": {pid: serialized_proposal_dict, ...},
        "executions": [...],
        "bonds": {...},
    },
}
```

The governance state is part of the chain state dict, so it's covered by the state-root commitment (whichever function is active). When the state root is computed via the binary trie, governance state is included transparently — no special handling needed.

### Treasury payouts move real KRN

When a treasury proposal reaches EXECUTED, the governance tick actually moves KRN from the treasury account to the recipients:

```python
if new_phase == "executed":
    for r in execution["recipients"]:
        _debit(state, treasury_addr, r["amount"])
        _credit(state, r["address"], r["amount"])
```

This is the first time treasury-funded ecosystem payments actually happen on-chain through governance. v0.5 had the state machine but didn't move money; v0.6 does.

## 3. Proposal bonds (anti-spam)

To prevent spam, every governance proposal requires escrowing a bond at submission time. The bond is held in escrow until the proposal terminates.

### Defaults

| Track | Bond amount | When you'd get it back |
|---|---:|---|
| Protocol amendment | 100 KRN (100_000_000 mukrn) | Refunded if ACTIVATED or WITHDRAWN |
| Treasury allocation | 10 KRN (10_000_000 mukrn) | Refunded if EXECUTED or WITHDRAWN |

### Settlement matrix

```
                       refund   burn    treasury
ACTIVATED / EXECUTED   100%     0%      0%
WITHDRAWN              100%     0%      0%
REJECTED               0%       50%     50%
```

If your proposal is rejected by vote, you lose your bond. Half is burned (`state["total_supply"]` decreases); half goes to the treasury account. This makes spamming proposals economically expensive: a coordinated spam attack would funnel KRN into the treasury and dilute the spammer's holdings.

### Why these specific values

The protocol-amendment bond is intentionally higher than the treasury bond because:
- Protocol changes affect everyone; a frivolous one wastes everyone's attention.
- The 5-phase cycle is long (~25 days), so the bond is tied up longer.
- Treasury proposals are normal operational events; their bond should be a small friction cost, not a serious barrier.

Both values are amendable through protocol governance: a future proposal can change `DEFAULT_PROTOCOL_BOND` and `DEFAULT_TREASURY_BOND` once the network has real economic data on whether the defaults are too high or too low.

## 4. Remaining EVM precompiles

The v0.5 release shipped 3 of the 9 standard Ethereum precompiles (ECRECOVER at 0x01 using Ed25519, SHA256 at 0x02, IDENTITY at 0x04). v0.6 adds three more:

| Address | Name | Status in v0.6 |
|---|---|---|
| 0x01 | ECRECOVER (Ed25519) | Shipped in v0.5 |
| 0x02 | SHA256 | Shipped in v0.5 |
| 0x03 | RIPEMD160 | **v0.6** — full impl (with graceful fallback on systems without OpenSSL legacy) |
| 0x04 | IDENTITY | Shipped in v0.5 |
| 0x05 | MODEXP | **v0.6** — full impl, with input-size guards |
| 0x06-0x08 | BN254 ops | Stubs — v0.7 |
| 0x09 | BLAKE2F | **v0.6** — simplified stand-in; full F-compression in v0.7 |

The not-yet-implemented BN254 ops (point addition, scalar multiplication, pairing check) are the prerequisites for on-chain zkSNARK verification. They're substantial and merit a dedicated milestone.

## End-to-end demonstration

The integration test [`tests/test_governance_integration.py::test_e2e_state_root_function_swap_via_tx`](../tests/test_governance_integration.py) drives the full v0.6 flow:

1. A validator injects a `GOVERNANCE_PROPOSE` transaction with payload `{"swap": "state_root_function", "to": "trie"}`.
2. The next block includes the transaction; the proposal appears in `state["governance"]["protocol"]["proposals"]`. The submitter's bond is escrowed.
3. Blocks are baked until the SUBMITTED window passes (default 100 blocks); the per-block governance tick advances the proposal to EXPLORATION.
4. A `GOVERNANCE_VOTE` transaction with vote "yes" is included.
5. More blocks pass; the proposal advances through COOLDOWN, then ADOPTION, then a second vote, then activation.
6. On the activation block, `_apply_activated_change` sets `state["state_root_function"] = "trie"`.
7. From that block onward, `state_root_hex(state)` uses the binary trie commitment — light-client proofs become available for all subsequent blocks.

The test asserts the final state has `state["state_root_function"] == "trie"`, demonstrating the full loop closing through the chain's own rails.

## Tests

v0.6 brings the test count to **244 tests** (up from 221 in v0.5):

| Module | v0.5 | v0.6 |
|---|---:|---:|
| crypto, transaction, block/chain | 19 | 19 |
| skald + typecheck | 29 | 29 |
| bft, rollup, forced_inclusion | 34 | 34 |
| issuance | 18 | 18 |
| evm (v0.3 + v0.4 + v0.5) | 68 | 68 |
| trie | 21 | 21 |
| governance | 28 | 28 |
| state_root_swap (unit-level) | 4 | 4 |
| **governance_integration (e2e via tx)** | — | **8** |
| **v06_additions (precompiles + bonds)** | — | **15** |
| **Total** | **221** | **244** |

## File summary

**New files**:
- `tests/test_governance_integration.py` — 8 end-to-end tests
- `tests/test_v06_additions.py` — 15 tests for new precompiles and bond resolution
- `docs/v06-changes.md` — this file

**Modified files**:
- `kern/transaction.py` — new OpKinds + builders
- `kern/governance.py` — `from_dict` methods, bond constants and `resolve_bond`, state-roundtrip helpers
- `kern/chain.py` — governance dispatch in `apply_transaction`, `_apply_governance_tick`, `_apply_activated_change`, `_settle_bond`
- `kern/consensus.py` — `propose_block` now invokes `_apply_governance_tick` so proposed blocks match what validation produces
- `kern/evm/frames.py` — RIPEMD160, MODEXP, BLAKE2F precompiles

## Roadmap update

| Phase | Scope | Status |
|---|---|---|
| v0.1 | Single-baker chain + Skald interpreter | ✅ |
| v0.2 | Multi-validator BFT + Static Skald + Rollup framework | ✅ |
| v0.3 | Mini-EVM + bisection + forced inclusion + adaptive issuance | ✅ |
| v0.4 | Issuance live in production + Merkle trie + EVM extensions | ✅ |
| v0.5 | Governance live + trie swap-in + multi-frame EVM | ✅ |
| **v0.6** | **Governance via transactions + apply_block wiring + bonds + more precompiles** | **✅ (this version)** |
| v0.7 | BN254 precompiles; dynamic gas costs matching Ethereum Yellow Paper; quadratic treasury voting; delegated voting | 🟡 Next |
| v1.0 | Testnet audited | 🔵 |
| v2.0 | Mainnet + KRN genesis | 🔵 |
