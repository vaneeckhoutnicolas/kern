# Slashable Attestations

This document specifies Kern's **slashable attestation primitive** introduced in v1.1-rc.

The primitive generalizes the equivocation-detection-and-punishment pattern (already used for governance equivocation in v1.0-rc) to any signed claim about the world. An *attestation* is a signed claim by an issuer about a subject under a schema. If the issuer later signs a CONTRADICTORY claim about the same (schema_id, subject) pair, anyone can submit slashing evidence to punish the issuer and earn a whistleblower reward.

This is the foundation for Kern's oracle network (see [`oracle-network.md`](oracle-network.md)) and for the on-chain compliance attestations used in STO contracts (see [`sto-mica.md`](sto-mica.md)).

---

## 1. Why this exists

Most oracle and attestation systems today (Chainlink, EAS, UMA's optimistic oracles) rely on cryptoeconomic *reputation* off-chain: nodes that lie lose business over time. This works at the limit but is:

- **Slow** — reputation takes months to update
- **Expensive** — operators must be paid handsomely to maintain reputation
- **Coordinative-failure-prone** — a coalition can attack short-term

Kern's primitive moves the punishment **on-chain and immediate**:

1. Issuer posts a bond when attesting
2. Issuer signs a claim (price, KYC status, identity, energy measurement, telco subscriber count — anything)
3. If the issuer later contradicts itself for the same (schema, subject) pair, the contradiction is mathematically proven on-chain
4. Anyone can submit the proof; the issuer's bond is slashed; the prover earns 10% of the slashed amount

This makes equivocation **automatically expensive** in a way that doesn't depend on social consensus or reputation systems.

---

## 2. The mental model

An attestation is **(issuer, schema_id, subject, claim, bond)**:

- **issuer**: the kn1 address making the claim. Must sign the attestation transaction.
- **schema_id**: an open string identifying the schema, dotted-namespace convention (e.g., `price.btc-usd`, `kyc.aml-screening`, `energy.grid-frequency-hz`).
- **subject**: what the claim is about (e.g., `BTC`, `kn1userAddress`, `EU-grid-region-CWE`).
- **claim**: the actual data (any JSON object).
- **bond**: KRN locked alongside the attestation. The bond is the issuer's stake. Optional but recommended for high-trust use cases.

**Equivocation** means: same `(issuer, schema_id, subject)` with two attestations whose claims differ, whose validity windows overlap (neither was revoked before the other was issued).

If equivocation is proven via the `SLASH_ATTESTATION_EQUIVOCATION` transaction, the issuer loses 30% of the higher bond, the prover earns 10% of the slashed amount, the rest is burned.

---

## 3. Transactions

### `ATTEST`

Issue an attestation.

```python
from kern.transaction import make_attest

tx = make_attest(
    sender_kp=issuer_keypair,
    schema_id="price.btc-usd",
    subject="BTC",
    claim={"price_usd": 70000, "timestamp": 1730000000},
    nonce=42,
    bond=1_000_000,    # 1 KRN locked
)
```

The bond is debited from the issuer's balance and held with the attestation record. The attestation_id is **deterministic** — computed from the attestation contents:

```python
from kern.attestation import derive_attestation_id

att_id = derive_attestation_id(
    issuer="kn1xxx",
    schema_id="price.btc-usd",
    subject="BTC",
    claim={"price_usd": 70000, "timestamp": 1730000000},
    attest_nonce=42,
)
# att_id is a 32-character hex string
```

This means: anyone can compute the ID without trusting the chain; two distinct attestations always have distinct IDs (the issuer's nonce ensures uniqueness); the ID is content-addressed and acts as the canonical key.

### `REVOKE_ATTESTATION`

Mark a previously issued attestation as revoked. Returns the bond to the issuer.

```python
from kern.transaction import make_revoke_attestation

tx = make_revoke_attestation(
    sender_kp=issuer_keypair,
    attestation_id=att_id,
    nonce=43,
)
```

**Important**: revocation does NOT prevent slashing for past equivocation. If you contradicted yourself before revoking, the evidence remains submittable. Revocation only stops the attestation from being considered "currently valid" for forward-looking purposes.

If the attestation was already consumed for slashing, revocation fails (the bond is gone).

### `SLASH_ATTESTATION_EQUIVOCATION`

Submit slashing evidence.

```python
from kern.transaction import make_slash_attestation_equivocation

tx = make_slash_attestation_equivocation(
    sender_kp=whistleblower_keypair,
    attestation_id_1=earlier_attestation_id,
    attestation_id_2=contradicting_attestation_id,
    nonce=0,
)
```

Anyone can submit. The runtime verifies that:

1. Both attestation_ids exist on-chain
2. Both have the same issuer
3. Both have the same `schema_id` and `subject`
4. The claims differ
5. The validity windows overlap (neither was revoked before the other was issued)
6. Neither has been consumed for slashing already

On success:
- Issuer's remaining bond on the higher-bonded attestation is slashed 30%
- Whistleblower receives 10% of the slashed amount
- The rest is burned (reduces total supply)
- Both attestations are marked `consumed_for_slashing` (no double-slashing)

---

## 4. State layout

```python
state["attestations"] = {
    attestation_id: {
        "issuer":               kn1_address,
        "schema_id":            "price.btc-usd",
        "subject":              "BTC",
        "claim":                {"price_usd": 70000, ...},
        "bond":                 1_000_000,
        "issued_at_level":      12345,
        "revoked_at_level":     None,    # or int
        "consumed_for_slashing": False,
    },
    ...
}

state["attestations_by_subject"] = {
    "{issuer}|{schema_id}|{subject}": [attestation_id, ...],
    ...
}
```

The reverse index lets the slashing handler find equivocating attestations in O(1) on `(issuer, schema_id, subject)`, rather than scanning the entire attestation list.

---

## 5. Slashing math

The numbers match the existing governance slashing (consistency with the rest of the protocol):

| Parameter | Value | Source |
|---|---:|---|
| Slashing percentage | 30% | `kern.attestation.ATTESTATION_SLASHING_PERCENTAGE` |
| Whistleblower reward | 10% of slash | `kern.attestation.ATTESTATION_WHISTLEBLOWER_REWARD_PCT` |
| Burn | rest of slash | (slash − reward) |

Example: bond of 1 000 000 mukrn (1 KRN) → slash = 300 000 → reward = 30 000 → burn = 270 000.

---

## 6. Reading attestations

To query the latest valid attestation by an issuer for a given subject:

```python
from kern.attestation import latest_attestation

latest = latest_attestation(state, issuer, schema_id, subject)
if latest is not None:
    print(f"Current claim: {latest['claim']}")
    print(f"Bond backing it: {latest['bond']} mukrn")
```

To enumerate all attestations by an issuer for a subject (for audit / dispute discovery):

```python
from kern.attestation import attestations_for

all_ids = attestations_for(state, issuer, schema_id, subject)
for att_id in all_ids:
    record = state["attestations"][att_id]
    print(record)
```

---

## 7. Common schemas

These are conventional but not enforced. Anyone can use any string.

| Schema ID | Subject | Claim shape | Use case |
|---|---|---|---|
| `price.fiat-usd` | symbol (e.g., `"BTC"`) | `{"price": int, "timestamp": int}` | DeFi price oracles |
| `price.fiat-eur` | symbol | `{"price": int, "timestamp": int}` | DeFi price oracles |
| `kyc.aml-screening` | user kn1 address | `{"status": "passed"\|"failed", "level": "individual"\|"corporate"}` | STO compliance |
| `kyc.accredited-investor` | user kn1 address | `{"is_accredited": bool, "jurisdiction": str}` | STO investor qualification |
| `identity.proof-of-personhood` | user kn1 address | `{"is_human": bool, "method": "biometric"\|"vouching"}` | Quadratic funding Sybil resistance |
| `energy.grid-frequency-hz` | grid region | `{"frequency_hz": float, "timestamp": int}` | Energy market settlement |
| `energy.consumption-kwh` | meter id | `{"kwh": int, "interval_start": int, "interval_end": int}` | Smart-grid billing |
| `telco.subscriber-count` | operator id | `{"count": int, "as_of": int}` | Inter-operator settlement |
| `weather.temperature-c` | location id | `{"temp_c": float, "timestamp": int}` | Parametric insurance |
| `reputation.contributor-score` | user kn1 address | `{"score": int}` | Web-of-trust |

For schemas that should evolve (versioned), append a version: `price.fiat-usd.v2`.

---

## 8. Design choices and tradeoffs

### Why no per-schema authorization?

The protocol allows ANY address to attest under ANY schema. This is deliberate:

- Consumers of attestations decide which issuers they trust (off-chain or via a Skald contract). The protocol doesn't pick winners.
- The slashing penalty is the protocol-level enforcement, not access control.
- Schema marketplaces (a layer above this primitive) can publish lists of "approved issuers per schema" if needed.

### Why content-addressed IDs instead of monotonic indices?

Deterministic IDs let off-chain systems precompute the ID before submission. Useful for: receipt management, mempool deduplication, light-client proofs.

### Why bond is optional?

Different schemas have different stakes:
- Price oracle: high bond essential
- Public reputation: low bond OK (reputation IS the stake)
- One-off audit attestation: bond may be unnecessary

The protocol allows zero-bond attestations but consumers of attestations should weight low-bond claims accordingly.

### Why does revocation NOT prevent past-equivocation slashing?

If revocation cleared slashing risk, an issuer could:
1. Attest claim A
2. Realize they want to flip to claim B
3. Revoke A and immediately attest B
4. Avoid slashing despite having committed to both

Revocation marks "no longer current" but keeps the historical evidence preserved for accountability.

### Why `consumed_for_slashing` instead of deleting the record?

Light clients and historical queries need the data. Marking-as-consumed is sufficient to prevent double-slashing without losing the audit trail.

---

## 9. Composing with Skald contracts

A Skald contract can read attestations via the standard storage-access pattern. Pattern:

```skald
contract PriceConsumer {
    storage {
        oracle_issuer: address,
        last_price: int,
        last_update_level: int,
    }

    // Called periodically — refreshes the price from the attestation registry.
    entry refresh_price() {
        // Read the latest attestation by oracle_issuer for "price.btc-usd"/"BTC"
        let latest = attestation_latest(oracle_issuer, "price.btc-usd", "BTC");
        require latest.bond >= 100000 with "oracle bond too low for trust";
        require latest.issued_at_level > last_update_level with "stale";
        last_price = latest.claim.price;
        last_update_level = latest.issued_at_level;
    }
}
```

(The `attestation_latest` Skald builtin is introduced in v1.1-rc as part of the standard library. See [`skald-language.md`](skald-language.md) for the full builtin reference.)

---

## 10. Limitations and future work

### v1.1-rc scope (this release)

- Single-issuer registry, per-attestation bond
- Strict equality for contradiction detection
- No on-chain schema validation (claims are opaque dicts to the protocol)

### Planned for v1.2 (schema marketplace)

A separate Skald contract layer where:
- Anyone can publish a *schema definition* (JSON schema or similar)
- Schemas can mandate a minimum bond
- Schemas can mandate a tolerance band (e.g., for prices, claims within 0.1% are "consistent")
- Schemas can mandate verification rules (e.g., "must be one of these N approved issuers")

This is built ON TOP of the v1.1-rc primitive — the protocol stays simple, the marketplace is application-level.

### Planned for v1.3 (verifiable claims with ZK)

For attestations about sensitive subjects (e.g., individual KYC), the claim itself might be private but the attestation must still be verifiable.

Pattern: the claim field contains a zk-SNARK that proves a property (e.g., "this user is over 18") without revealing the underlying data. The schema specifies the verifying key, and the Kern BN254 precompile validates the proof on submission.

This is a v1.3 milestone; for v1.1-rc the claim is plain JSON.

---

## 11. Reference

- **Implementation**: [`kern/attestation.py`](../kern/attestation.py) (primitives), [`kern/chain.py`](../kern/chain.py) (handlers `_apply_attest`, `_apply_revoke_attestation`, `_apply_slash_attestation_equivocation`)
- **Transactions**: [`kern/transaction.py`](../kern/transaction.py) (builders `make_attest`, `make_revoke_attestation`, `make_slash_attestation_equivocation`)
- **Tests**: [`tests/test_attestations.py`](../tests/test_attestations.py) (25 tests covering math, state, slashing edge cases)
- **API stability**: [`api-stability.md`](api-stability.md) §2.1 — three new Frozen OpKinds
- **Oracle use case**: [`oracle-network.md`](oracle-network.md)
- **STO compliance use case**: [`sto-mica.md`](sto-mica.md)
- **Public goods funding use case**: [`public-goods-funding.md`](public-goods-funding.md)
