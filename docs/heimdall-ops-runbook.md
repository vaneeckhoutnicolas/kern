# Heimdall ops runbook

This runbook covers incident response for every alert defined in `kern_explorer/monitoring/alerts/kern-alerts.yml`. Each section is reachable directly via the `runbook_url` annotation embedded in each alert.

**Maintainer**: Nicolas Van Eeckhout (founder). **Audience**: anyone on the on-call rotation for a Kern network (devnet, Yggdrasil testnet, Midgard mainnet).

**General response protocol**:

1. Acknowledge the alert in your paging tool to stop re-paging
2. Open Heimdall `/health` and `/metrics` to confirm the symptom
3. Apply the runbook step-by-step. **Stop at the first fix that resolves the symptom.**
4. Once resolved, record in the incident log: what fired, root cause, what fixed it, what could prevent recurrence
5. If you escalate, hand off the incident log so the next responder doesn't repeat your steps

---

## L1 baseline

### `KernConsensusHaltSuspected`  {#consensus-halt}

**Severity**: critical · **Team**: validators

**Symptom**: `kern_chain_head_age_seconds > 30` for at least 1 minute.

**What this means**: the chain head has not advanced for 30+ seconds. Either consensus has stalled or Heimdall lost its view of the chain. Under normal operation, head age stays under 2 seconds.

**Triage in order**:

1. **Is Heimdall the issue, or the chain?** Open `http://heimdall:8800/health`. If `node_reachable: false`, the chain is fine but Heimdall lost RPC — restart Heimdall and confirm the node URL in `KERN_RPC` env var. The chain is producing blocks, you're just not seeing them.

2. **Is the indexer stuck while the node is fine?** If `node_reachable: true` and `indexer_lag_blocks > 0` and growing, the chain is advancing but Heimdall is not keeping up. Check Heimdall logs for SQLite errors or RPC timeouts. Restart Heimdall.

3. **Is consensus genuinely halted?** If `node_reachable: true` and `node_head_level` equals `indexed_head_level` and neither is advancing, the chain itself has stalled. Continue to step 4.

4. **Validator count check**. Open `/validators` on Heimdall. Are enough validators online to reach BFT 2/3 supermajority? If validators have dropped, page the validator on-call rotation. Consensus needs 2/3 of the active stake online to make progress.

5. **Validator coordination**. If validators are online but consensus still stalls, this is a P0 incident. Convene the validator coordination channel. The most likely cause is a network partition (validators online but not seeing each other) or a software bug triggered on a specific block payload.

6. **Last resort**. If a software bug is suspected and root-cause analysis takes time, prepare a coordinated restart: have validators stop, then restart together with a coordinated genesis-fork marker if needed. Document everything.

**Prevention**:
- Maintain ≥ 5 validators for safety margin (the `KernValidatorCountLow` alert warns at < 5)
- Monitor `kern_chain_head_age_seconds` for slow trends, not just spikes — the `KernConsensusSlow` alert catches early degradation

---

### `KernConsensusSlow`

**Severity**: warning · **Team**: validators

**Symptom**: `kern_chain_head_age_seconds > 5` for at least 5 minutes.

**What this means**: blocks are still being produced but slower than the ~1 s target. May be a precursor to a full halt.

**Triage**:
- Check validator hosts for CPU / network saturation
- Check P2P connectivity between validators (some validators may have lost a peer)
- Check for unusually large blocks (a fuzz tx that triggered an O(n²) code path)

If the issue is one slow validator, ask them to investigate or restart. The chain tolerates < 1/3 of stake being slow or offline; if multiple validators are slow simultaneously, escalate to `KernConsensusHaltSuspected` workflow.

---

### `KernValidatorCountLow`

**Severity**: warning · **Team**: foundation

**Symptom**: `kern_validators_count < 5` for at least 5 minutes.

**What this means**: too few active validators for the safety margin we target (5+ to tolerate the loss of any one without dropping below BFT minimum).

**Triage**:
- Check `/validators` — which validators have we lost vs. our active set?
- Reach out to those validators (channels documented in the Foundation validator registry)
- If validators have permanently left, the Foundation should recruit replacements from the [`setup-validator.md`](setup-validator.md) pipeline

---

### `HeimdallIndexerStuck`  {#heimdall-indexer-stuck}

**Severity**: warning · **Team**: ops

**Symptom**: `rate(heimdall_indexed_blocks_total[5m]) == 0` for at least 5 minutes.

**What this means**: Heimdall's indexer has not advanced. The chain may or may not be healthy — this is specifically about Heimdall.

**Triage**:

1. Open `/health`. Is the node reachable?
2. If yes and `indexer_lag_blocks` is large and not shrinking, Heimdall is failing to ingest. Check logs for:
   - SQLite errors (disk full, permissions, WAL file corruption)
   - RPC timeouts (the node is slow to respond to `/chain/block/{level}`)
   - Python exception in `_index_block` (likely a malformed tx the indexer doesn't handle — file a bug)
3. Restart Heimdall. It resumes from the last persisted cursor.
4. If the issue persists across restart, the indexer DB may be corrupt. Stop Heimdall, back up `heimdall.sqlite`, delete it, and let the indexer rebuild from genesis. This takes hours for a mature chain — only do it if you have no alternative.

---

## Attestation registry (vertical 1)

### `KernAttestationSlashingDetected`  {#attestation-slashing}

**Severity**: warning · **Team**: foundation

**Symptom**: `increase(kern_attestation_slashings_total[5m]) > 0`.

**What this means**: the slashable attestation primitive functioned as designed. An issuer produced two contradictory signed claims, a whistleblower submitted evidence, and the issuer's bond was slashed.

**Triage**:

1. Open `/attestations` on Heimdall. The most recent slashing is at the top of the Recent slashings table.
2. Click the slashed issuer to see all their attestations and other slashings (if any).
3. Click the schema to see how broadly used it is. A slashing on a high-traffic schema is more disruptive than on an obscure one.
4. **Decide whether this is a single mistake or a pattern**:
   - **One-off operator error**: no further action beyond logging
   - **Pattern (multiple slashings from the same issuer or against the same schema)**: open a coordination thread. Possible actions:
     - Notify the schema's recognized-issuer registry (if there is one) to consider de-listing
     - Notify downstream consumers (STOs, DeFi contracts) reading attestations from this issuer/schema
     - If the slashed issuer is a regulated entity, the slashing is a regulatory-reportable event in some jurisdictions

5. The slashing is final on-chain. There is no "rollback" — only social and reputational follow-up.

**Prevention**: schema marketplace operators should set bond minimums high enough to deter casual errors. Issuers should run their attestation pipelines with non-equivocation guarantees (deterministic monotonic counters per schema-subject pair).

---

### `KernAttestationActiveBondHigh`

**Severity**: info · **Team**: foundation

**Symptom**: `kern_attestations_total_bond_locked_mukrn > 1e12` (1 M KRN locked) for 10+ minutes.

**What this means**: substantial KRN is locked as collateral in active attestations. This is healthy — high values mean the attestation primitive is being used at scale.

**Triage**: no action required. Note it in the next standup and consider whether the Foundation's KRN economy modelling needs to account for this lock-up.

---

## Oracle networks (vertical 3)

### `KernOracleCircuitBreakerTripped`  {#oracle-circuit-breaker}

**Severity**: critical · **Team**: oracle-ops

**Symptom**: `kern_oracle_feeds_circuit_breaker_tripped > 0` for at least 1 minute.

**What this means**: one or more oracle feeds have stopped accepting new data because the aggregator detected anomalies (typically: feeder values diverge beyond the configured tolerance, or a feeder has not posted within the heartbeat window).

**Impact**: downstream consumers reading from the tripped feed will:
- Receive `STALE_DATA` if their consumer logic checks freshness, OR
- Read the last cached value, which may be incorrect

DeFi contracts and STOs reading these feeds may have their own circuit breakers tied to the oracle's status — review them too.

**Triage**:

1. Open `/oracle-health` on Heimdall. Identify the tripped feed(s).
2. Click into the feed's `/contract/{address}` page to see the last known value and the feeders.
3. **Identify why the breaker tripped**:
   - **Single feeder diverged**: that feeder's last submission is the outlier. Investigate why — bug, MEV attempt, real-world data anomaly?
   - **Multiple feeders posted similar outliers**: the real-world value moved significantly. The circuit breaker is doing its job; the question is whether the threshold needs adjustment or whether the move is legitimate (and the breaker should be manually reset).
   - **A feeder dropped offline**: heartbeat expired. Contact the feeder operator.
4. **Reset the breaker**: the contract has a `reset` entry callable by the admin (typically the schema marketplace operator or a multisig). Use it ONLY after confirming the issue is resolved.
5. **Consider slashing**: if a feeder posted contradictory signed values (equivocation), submit slashing evidence via `SLASH_ATTESTATION_EQUIVOCATION`. This earns you 10% of their bond and protects downstream consumers from the same operator repeating the mistake.

**Prevention**: oracle feed designers should set the circuit breaker tolerance to the smallest value that doesn't false-trip on legitimate volatility. Too tight = constant tripping; too loose = breaker doesn't protect.

---

### `KernOracleAnomalyRateHigh`

**Severity**: warning · **Team**: oracle-ops

**Symptom**: `rate(kern_oracle_anomalies_total[15m]) > 0.01` (one anomaly per 100 seconds or more) for 10+ minutes.

**What this means**: anomalies are being recorded but not (yet) tripping circuit breakers. Either the threshold is well-tuned and tolerating real-world noise, or a slow-burn issue is developing.

**Triage**:
- Open `/oracle-health` and look for feeds with elevated `anomaly_count`
- Compare to the same metric 24 hours ago. Is this a new pattern?
- If a specific feeder is consistently in the anomaly list, investigate them specifically. If they're contributing wrong values without diverging far enough to trip the breaker, that's a subtle Sybil/manipulation signal.

---

## STO compliance (vertical 2)

### `KernStoNonCompliantContract`  {#sto-noncompliant}

**Severity**: critical · **Team**: foundation

**Symptom**: `(kern_sto_contracts_count - kern_sto_contracts_compliant) > 0` for at least 5 minutes.

**What this means**: at least one originated STO contract is in a state where Heimdall's heuristic securities compliance check returns `false`. The most common reasons:

- **Whitepaper not registered + issued supply > 0**: Prospectus Regulation Art. 3 violation. The issuer issued tokens before publishing the white paper.
- **AIFMD depositary == AIFM**: for institutional funds, the depositary must be an independent entity (AIFMD Art. 21).
- **Real-estate over-distribution**: `rental_income_distributed_mukrn > rental_income_received_mukrn` (Ponzi pattern).

**Triage**:

1. Open `/sto-dashboard` on Heimdall. The non-compliant contracts have a red `✗ Check storage` badge.
2. Click into each to view the live storage. Read the specific field that's wrong.
3. **Decide whether this is a real STO or a test deployment**:
   - **Test on devnet/Yggdrasil**: ignore, but consider whether the test contract should be removed or labelled
   - **Real production STO on Midgard**: this is a regulator-reportable event in jurisdictions where EU securities law applies (EU). Notify:
     - The Foundation's compliance counsel
     - The STO issuer (they may not be aware their storage drifted)
     - The relevant regulator (FSMA in Belgium, AMF in France, BaFin in Germany, etc.) per the issuer's home regulator
4. The STO contract has compliance-restoring entries (e.g. `register_whitepaper`, `pause_trading`, `replace_depositary`). The issuer should execute the appropriate remediation transaction.
5. Once the storage reflects the fix and the indexer refreshes (within ~1 block), the alert auto-resolves.

**Prevention**: STO issuers should run the Heimdall metrics as part of their own monitoring stack, not wait for the Foundation to alert them. Each STO should have its own internal compliance dashboard.

---

### `KernStoTradingPaused`

**Severity**: warning · **Team**: foundation

**Symptom**: `kern_sto_contracts_trading_paused > 0` for at least 1 minute.

**What this means**: a deployed STO has its trading or secondary market in paused state. This may be planned (weekend settlement, scheduled corporate action) or unplanned (compliance investigation, software bug).

**Triage**:
- Open `/sto-dashboard` and identify which contract is paused
- Check with the STO issuer whether the pause is planned
- If unplanned, the issuer should investigate and unpause as soon as the underlying issue is resolved

---

## Escalation matrix

| Severity | Action | Escalate to |
|---|---|---|
| `critical` L1 | Page immediately | Validator on-call → Foundation tech lead if not acknowledged in 15 min |
| `critical` STO | Compliance team within 1 hour | Foundation compliance counsel |
| `critical` Oracle | Oracle-ops within 30 min | Schema marketplace operator + affected consumers |
| `warning` any | Acknowledge in standup channel within 4 hours | None unless persists > 24 hours |
| `info` any | Review at the weekly ops standup | None |

---

## Recovery commands

These are the commands you'll run most often during incidents. Adjust paths as appropriate for your deployment.

**Restart Heimdall**:
```bash
docker-compose -f kern_explorer/monitoring/docker/docker-compose.monitoring.yml restart heimdall
# Or systemd: systemctl restart heimdall
```

**Reset Heimdall indexer (last resort, hours of rebuild)**:
```bash
docker-compose -f docker-compose.monitoring.yml stop heimdall
docker volume rm docker_heimdall_data       # adjust name to your compose project
docker-compose -f docker-compose.monitoring.yml up -d heimdall
```

**Tail Heimdall logs**:
```bash
docker-compose -f docker-compose.monitoring.yml logs -f heimdall
```

**Force re-evaluation of all alerts** (clears stuck firing-but-resolved alerts):
```bash
curl -X POST http://prometheus:9090/-/reload
```

**Check which alerts are firing**:
```bash
curl http://prometheus:9090/api/v1/alerts | jq '.data.alerts[] | {name: .labels.alertname, state, severity: .labels.severity}'
```

**Inspect a specific contract's vertical_summary** (debugging STO/Oracle alerts):
```bash
curl http://heimdall:8800/api/contracts | jq '.[] | select(.address == "kn1...")'
```

---

## See also

- [`setup-heimdall-operator.md`](setup-heimdall-operator.md) — installation and configuration
- [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md) — when SQLite is no longer enough (Midgard mainnet)
- [`setup-validator.md`](setup-validator.md) — validator-side operations
- [`attestations.md`](attestations.md) — slashable attestation primitive spec
- [`sto-mica.md`](sto-mica.md) — STO compliance specification
- [`oracle-network.md`](oracle-network.md) — oracle network design

---

*This runbook is part of the Heimdall delivery (Session 3/4). Founder: Nicolas Van Eeckhout. License: Apache-2.0.*
