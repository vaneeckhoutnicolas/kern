# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern_explorer.metrics
=====================

Prometheus metrics exported by Heimdall.

Three categories:
1. **L1 baseline** — chain head, block production rate, mempool size,
   validator count
2. **v1.1-rc verticals** — active attestations, slashing events,
   STO compliance state, oracle health, governance state
3. **Heimdall internals** — indexer lag, request latency

The metrics are computed lazily on /metrics scrape, by querying SQLite.
For higher scrape volumes a background cache could materialize them, but
SQLite on a small testnet is plenty fast for 15-30s scrape intervals.

We use the Prometheus text exposition format directly (no client
library dependency) — it's a stable, simple format and we already have
metrics infrastructure in kern.observability we could reuse.
"""

from __future__ import annotations

import io
import json
import time

from .db import open_db


def render_metrics(db_path: str) -> str:
    """Build a Prometheus text-format metrics body."""
    conn = open_db(db_path)
    try:
        return _render(conn)
    finally:
        conn.close()


def _render(conn) -> str:
    buf = io.StringIO()
    now = int(time.time())

    # --- L1 baseline -----------------------------------------------------
    head_row = conn.execute("SELECT MAX(level) AS lvl, MAX(timestamp) AS ts FROM blocks").fetchone()
    head_level = head_row["lvl"] if head_row and head_row["lvl"] is not None else 0
    head_ts = head_row["ts"] if head_row and head_row["ts"] is not None else 0

    _write(buf, "kern_chain_head_level",
           "Latest block level indexed by Heimdall.",
           "gauge", head_level)
    _write(buf, "kern_chain_head_timestamp_seconds",
           "Unix timestamp of the latest block.",
           "gauge", head_ts)
    _write(buf, "kern_chain_head_age_seconds",
           "Seconds since the latest block was produced.",
           "gauge", max(0, now - head_ts) if head_ts else 0)

    n_txs = conn.execute("SELECT COUNT(*) AS c FROM txs").fetchone()["c"]
    _write(buf, "kern_indexed_transactions_total",
           "Total transactions indexed by Heimdall.",
           "counter", n_txs)

    n_accounts = conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
    _write(buf, "kern_indexed_accounts_total",
           "Total distinct accounts seen.",
           "gauge", n_accounts)

    n_validators = conn.execute(
        "SELECT COUNT(*) AS c FROM accounts WHERE is_validator = 1"
    ).fetchone()["c"]
    _write(buf, "kern_validators_count",
           "Validators that have produced at least one block.",
           "gauge", n_validators)

    n_contracts = conn.execute("SELECT COUNT(*) AS c FROM contracts").fetchone()["c"]
    _write(buf, "kern_originated_contracts_total",
           "Originated Skald contracts.",
           "gauge", n_contracts)

    # Per-kind tx counters
    by_kind = conn.execute(
        "SELECT kind, COUNT(*) AS c FROM txs GROUP BY kind"
    ).fetchall()
    buf.write("# HELP kern_indexed_transactions_by_kind_total Transactions partitioned by kind.\n")
    buf.write("# TYPE kern_indexed_transactions_by_kind_total counter\n")
    for r in by_kind:
        buf.write(f'kern_indexed_transactions_by_kind_total{{kind="{r["kind"]}"}} {r["c"]}\n')

    # --- Attestations (v1.1-rc, vertical 1) ------------------------------
    active = conn.execute(
        "SELECT COUNT(*) AS c FROM attestations "
        "WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0"
    ).fetchone()["c"]
    _write(buf, "kern_attestations_active",
           "Active attestations (not revoked and not consumed by slashing).",
           "gauge", active)

    total_att = conn.execute("SELECT COUNT(*) AS c FROM attestations").fetchone()["c"]
    _write(buf, "kern_attestations_total",
           "Total attestations ever issued.",
           "counter", total_att)

    by_schema = conn.execute(
        "SELECT schema_id, COUNT(*) AS c FROM attestations "
        "WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0 "
        "GROUP BY schema_id"
    ).fetchall()
    buf.write("# HELP kern_attestations_active_by_schema Active attestations per schema_id.\n")
    buf.write("# TYPE kern_attestations_active_by_schema gauge\n")
    for r in by_schema:
        sid = _escape(r["schema_id"])
        buf.write(f'kern_attestations_active_by_schema{{schema_id="{sid}"}} {r["c"]}\n')

    # Total bond locked
    total_bond = conn.execute(
        "SELECT COALESCE(SUM(bond), 0) AS s FROM attestations "
        "WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0"
    ).fetchone()["s"]
    _write(buf, "kern_attestations_total_bond_locked_mukrn",
           "Total mukrn locked in active attestation bonds.",
           "gauge", total_bond)

    # Slashings
    n_slashings = conn.execute("SELECT COUNT(*) AS c FROM slashings").fetchone()["c"]
    _write(buf, "kern_attestation_slashings_total",
           "Successful SLASH_ATTESTATION_EQUIVOCATION transactions.",
           "counter", n_slashings)

    total_slashed = conn.execute(
        "SELECT COALESCE(SUM(slashed_amount), 0) AS s FROM slashings"
    ).fetchone()["s"]
    _write(buf, "kern_attestation_slashed_amount_total_mukrn",
           "Total mukrn slashed from equivocating attestation issuers.",
           "counter", total_slashed)

    total_burned = conn.execute(
        "SELECT COALESCE(SUM(burned_amount), 0) AS s FROM slashings"
    ).fetchone()["s"]
    _write(buf, "kern_attestation_burned_amount_total_mukrn",
           "Total mukrn burned via attestation slashing.",
           "counter", total_burned)

    total_rewards = conn.execute(
        "SELECT COALESCE(SUM(whistleblower_reward), 0) AS s FROM slashings"
    ).fetchone()["s"]
    _write(buf, "kern_attestation_whistleblower_rewards_total_mukrn",
           "Total mukrn paid out to whistleblowers as slashing rewards.",
           "counter", total_rewards)

    # --- Contracts by template (verticals 1, 2, 3) -----------------------
    by_template = conn.execute(
        "SELECT skald_template, COUNT(*) AS c FROM contracts "
        "WHERE skald_template IS NOT NULL GROUP BY skald_template"
    ).fetchall()
    buf.write("# HELP kern_originated_contracts_by_template Originated contracts per detected Skald template.\n")
    buf.write("# TYPE kern_originated_contracts_by_template gauge\n")
    for r in by_template:
        tmpl = _escape(r["skald_template"])
        buf.write(f'kern_originated_contracts_by_template{{template="{tmpl}"}} {r["c"]}\n')

    # --- ZK claims (vertical 4) ------------------------------------------
    n_zk = conn.execute(
        "SELECT COUNT(*) AS c FROM attestations WHERE is_zk = 1"
    ).fetchone()["c"]
    _write(buf, "kern_zk_attestations_total",
           "Attestations carrying ZK-claim payloads.",
           "counter", n_zk)

    # --- STO compliance dashboard metrics --------------------------------
    # Compute securities compliance status across all STO contracts
    sto_rows = conn.execute(
        "SELECT skald_template, vertical_summary_json FROM contracts "
        "WHERE skald_template IN ('sto-startup-equity', 'sto-institutional-fund', 'sto-real-estate') "
        "AND vertical_summary_json IS NOT NULL"
    ).fetchall()
    sto_count = len(sto_rows)
    sto_compliant = 0
    sto_paused = 0
    sto_total_issued = 0
    for r in sto_rows:
        try:
            v = json.loads(r["vertical_summary_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        if v.get("compliant"):
            sto_compliant += 1
        if v.get("trading_paused") or v.get("secondary_market_paused"):
            sto_paused += 1
        sto_total_issued += int(v.get("total_supply_issued", 0) or 0)
    _write(buf, "kern_sto_contracts_count",
           "STO contracts originated (securities-template contracts).",
           "gauge", sto_count)
    _write(buf, "kern_sto_contracts_compliant",
           "STO contracts currently passing the securities compliance check (derived from storage).",
           "gauge", sto_compliant)
    _write(buf, "kern_sto_contracts_trading_paused",
           "STO contracts where trading or secondary market is currently paused.",
           "gauge", sto_paused)
    _write(buf, "kern_sto_total_supply_issued_units",
           "Sum of total_supply_issued across all STO contracts (denominated in token units, not mukrn).",
           "gauge", sto_total_issued)

    # --- Oracle health metrics -------------------------------------------
    oracle_rows = conn.execute(
        "SELECT skald_template, vertical_summary_json FROM contracts "
        "WHERE skald_template IN ('generic-data-oracle', 'defi-price-oracle') "
        "AND vertical_summary_json IS NOT NULL"
    ).fetchall()
    oracle_count = len(oracle_rows)
    oracle_tripped = 0
    total_anomalies = 0
    total_feeders = 0
    for r in oracle_rows:
        try:
            v = json.loads(r["vertical_summary_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        if v.get("circuit_breaker_tripped"):
            oracle_tripped += 1
        total_anomalies += int(v.get("anomaly_count", 0) or 0)
        total_feeders += int(v.get("feeder_count", 0) or 0)
    _write(buf, "kern_oracle_feeds_count",
           "Oracle feed contracts (generic-data-oracle + defi-price-oracle).",
           "gauge", oracle_count)
    _write(buf, "kern_oracle_feeds_circuit_breaker_tripped",
           "Oracle feeds currently in a circuit-breaker-tripped state.",
           "gauge", oracle_tripped)
    _write(buf, "kern_oracle_anomalies_total",
           "Sum of recorded anomalies across all oracle feeds.",
           "counter", total_anomalies)
    _write(buf, "kern_oracle_feeders_total",
           "Sum of feeder counts across all oracle feeds (a feeder may participate in multiple feeds).",
           "gauge", total_feeders)

    # --- PGF metrics ------------------------------------------------------
    qf_rows = conn.execute(
        "SELECT vertical_summary_json FROM contracts "
        "WHERE skald_template = 'quadratic-funding' "
        "AND vertical_summary_json IS NOT NULL"
    ).fetchall()
    qf_count = len(qf_rows)
    qf_contributors = 0
    qf_raised = 0
    for r in qf_rows:
        try:
            v = json.loads(r["vertical_summary_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        qf_contributors += int(v.get("contributors_count", 0) or 0)
        qf_raised += int(v.get("total_received_mukrn", 0) or 0)
    _write(buf, "kern_pgf_quadratic_funding_projects",
           "Quadratic Funding projects originated.",
           "gauge", qf_count)
    _write(buf, "kern_pgf_quadratic_funding_contributors_total",
           "Sum of contributors across all QF projects.",
           "gauge", qf_contributors)
    _write(buf, "kern_pgf_quadratic_funding_raised_mukrn",
           "Sum of mukrn raised across all QF projects (before matching).",
           "gauge", qf_raised)

    rpgf_count = conn.execute(
        "SELECT COUNT(*) AS c FROM contracts WHERE skald_template = 'retroactive-pgf'"
    ).fetchone()["c"]
    _write(buf, "kern_pgf_retroactive_nominations",
           "Retroactive PGF nominations originated.",
           "gauge", rpgf_count)

    # --- Heimdall internals ----------------------------------------------
    n_blocks = conn.execute("SELECT COUNT(*) AS c FROM blocks").fetchone()["c"]
    _write(buf, "heimdall_indexed_blocks_total",
           "Total blocks ingested by the Heimdall indexer.",
           "counter", n_blocks)

    return buf.getvalue()


def _write(buf, name: str, help_text: str, mtype: str, value) -> None:
    buf.write(f"# HELP {name} {help_text}\n")
    buf.write(f"# TYPE {name} {mtype}\n")
    buf.write(f"{name} {value}\n")


def _escape(s: str) -> str:
    """Escape a string for use as a Prometheus label value."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
