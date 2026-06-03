# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for Heimdall Session 2 — per-vertical dashboards.

Covers:
- compute_vertical_summary() for each known Skald template
- DB helpers added in S2 (get_attestation, list_attestations, list_schemas,
  list_slashings, update_contract_storage)
- The 6 new routes: /attestations (full), /attestation/{id}, /schema/{id},
  /sto-dashboard, /public-goods, /oracle-health
- The new metrics (kern_sto_*, kern_oracle_*, kern_pgf_*)
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern_explorer.db import (
    get_attestation,
    init_schema,
    list_attestations,
    list_schemas,
    list_slashings,
    open_db,
    transaction,
    update_contract_storage,
)
from kern_explorer.indexer import compute_vertical_summary
from kern_explorer.metrics import render_metrics


# ===========================================================================
# Vertical summary extraction
# ===========================================================================

class TestVerticalSummary:
    def test_none_for_unknown_template(self):
        assert compute_vertical_summary(None, {"x": 1}) is None
        assert compute_vertical_summary("unknown-template", {"x": 1}) is None

    def test_none_for_non_dict_storage(self):
        assert compute_vertical_summary("sto-startup-equity", None) is None
        assert compute_vertical_summary("sto-startup-equity", [1, 2, 3]) is None
        assert compute_vertical_summary("sto-startup-equity", 42) is None

    def test_sto_startup_compliant(self):
        s = compute_vertical_summary("sto-startup-equity", {
            "whitepaper_registered": True,
            "total_supply_issued": 50_000,
            "total_supply_cap": 100_000,
            "trading_paused": False,
        })
        assert s["compliant"] is True
        assert s["whitepaper_registered"] is True
        assert s["total_supply_issued"] == 50_000
        assert s["supply_utilization_pct"] == 50.0
        assert s["trading_paused"] is False

    def test_sto_startup_pre_whitepaper_zero_supply_ok(self):
        # Prospectus Regulation Art. 3 allows zero supply before whitepaper registration
        s = compute_vertical_summary("sto-startup-equity", {
            "whitepaper_registered": False,
            "total_supply_issued": 0,
            "total_supply_cap": 100_000,
        })
        assert s["compliant"] is True  # zero supply is OK

    def test_sto_startup_issued_without_whitepaper_noncompliant(self):
        # Issuing tokens without a whitepaper is a Prospectus Regulation Art. 3 violation
        s = compute_vertical_summary("sto-startup-equity", {
            "whitepaper_registered": False,
            "total_supply_issued": 1_000,
            "total_supply_cap": 100_000,
        })
        assert s["compliant"] is False

    def test_sto_institutional_fund_depositary_independent(self):
        s = compute_vertical_summary("sto-institutional-fund", {
            "whitepaper_registered": True,
            "total_supply_issued": 0,
            "total_supply_cap": 1_000_000,
            "depositary": "kn1depA",
            "aifm": "kn1aifmB",
            "latest_nav_per_share_mukrn": 1_500_000,
            "nav_published_at_level": 100,
        })
        assert s["depositary_independent"] is True
        assert s["depositary"] == "kn1depA"
        assert s["aifm"] == "kn1aifmB"

    def test_sto_institutional_fund_depositary_conflict(self):
        # AIFMD Art 21: depositary MUST be independent from AIFM
        s = compute_vertical_summary("sto-institutional-fund", {
            "whitepaper_registered": True,
            "total_supply_issued": 0,
            "total_supply_cap": 1_000_000,
            "depositary": "kn1same",
            "aifm": "kn1same",
        })
        assert s["depositary_independent"] is False

    def test_sto_real_estate_anti_ponzi_ok(self):
        s = compute_vertical_summary("sto-real-estate", {
            "rental_income_received_mukrn": 1_000_000,
            "rental_income_distributed_mukrn": 800_000,
            "title_attestation_notary": "kn1notary",
            "secondary_market_paused": False,
        })
        assert s["anti_ponzi_invariant_ok"] is True
        assert s["rental_distribution_utilization_pct"] == 80.0
        assert s["title_attested"] is True

    def test_sto_real_estate_anti_ponzi_violation(self):
        # Distributing more than received = Ponzi pattern
        s = compute_vertical_summary("sto-real-estate", {
            "rental_income_received_mukrn": 1_000_000,
            "rental_income_distributed_mukrn": 1_200_000,
        })
        assert s["anti_ponzi_invariant_ok"] is False

    def test_quadratic_funding_summary(self):
        s = compute_vertical_summary("quadratic-funding", {
            "contributors_count": 12,
            "sum_of_sqrt_contributions": 80,
            "total_received_mukrn": 3_500_000,
            "round_end_level": 500,
            "admin_approved": True,
        })
        assert s["contributors_count"] == 12
        # Matching estimate = (sum_sqrt)^2 = 6400
        assert s["matching_estimate_mukrn"] == 6400
        assert s["admin_approved"] is True

    def test_retroactive_pgf_summary(self):
        s = compute_vertical_summary("retroactive-pgf", {
            "score_sum": 450,
            "score_count": 5,
            "nominated_by": "kn1nominator",
            "payout_executed": False,
        })
        assert s["average_score"] == 90.0
        assert s["score_count"] == 5
        assert s["payout_executed"] is False

    def test_generic_data_oracle_summary(self):
        s = compute_vertical_summary("generic-data-oracle", {
            "feeders": ["kn1f1", "kn1f2", "kn1f3"],
            "latest_aggregated_value": 42,
            "latest_aggregation_level": 99,
            "circuit_breaker_tripped": False,
            "anomaly_count": 2,
            "heartbeat_levels": 10,
        })
        assert s["feeder_count"] == 3
        assert s["latest_value"] == 42
        assert s["circuit_breaker_tripped"] is False
        assert s["anomaly_count"] == 2

    def test_defi_price_oracle_with_decimals(self):
        s = compute_vertical_summary("defi-price-oracle", {
            "feeders": ["kn1f1", "kn1f2"],
            "latest_aggregated_value": 25_000_000,    # 2500.0 with 4 decimals
            "decimals": 4,
            "base_asset": "BTC",
            "quote_asset": "EUR",
            "circuit_breaker_tripped": False,
        })
        assert s["base_asset"] == "BTC"
        assert s["quote_asset"] == "EUR"
        assert s["human_price"] == 2500.0

    def test_defi_oracle_with_circuit_tripped(self):
        s = compute_vertical_summary("defi-price-oracle", {
            "feeders": ["kn1f1"],
            "circuit_breaker_tripped": True,
            "anomaly_count": 8,
            "decimals": 2,
        })
        assert s["circuit_breaker_tripped"] is True
        assert s["anomaly_count"] == 8

    def test_schema_marketplace_summary(self):
        s = compute_vertical_summary("schema-marketplace", {
            "schema_id": "kyc.over_18_v1",
            "recognized_issuer": "kn1onfido",
            "minimum_bond_mukrn": 5_000_000,
            "is_active": True,
        })
        assert s["schema_id"] == "kyc.over_18_v1"
        assert s["minimum_bond_mukrn"] == 5_000_000
        assert s["is_active"] is True

    def test_handles_missing_fields_gracefully(self):
        # Empty storage should still produce a summary with defaults
        s = compute_vertical_summary("sto-startup-equity", {})
        assert s is not None
        assert s["compliant"] is True  # 0 issued = compliant
        assert s["total_supply_issued"] == 0
        assert s["supply_utilization_pct"] == 0.0


# ===========================================================================
# DB helpers added in Session 2
# ===========================================================================

@pytest.fixture
def db_with_attestations(tmp_path: Path):
    p = tmp_path / "s2.sqlite"
    conn = open_db(str(p))
    init_schema(conn)
    now = int(time.time())
    with transaction(conn):
        # Schema A: 2 active, 1 revoked, 1 slashed
        for i, (att_id, revoked, consumed, bond) in enumerate([
            ("a" * 32, None, 0, 1_000_000),
            ("b" * 32, None, 0, 2_000_000),
            ("c" * 32, 50, 0, 500_000),
            ("d" * 32, None, 1, 3_000_000),
        ]):
            conn.execute(
                "INSERT INTO attestations(attestation_id, issuer, schema_id, subject, "
                "claim_json, bond, issued_at_level, issued_at_ts, revoked_at_level, "
                "consumed_for_slashing, is_zk) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (att_id, "kn1issA", "schema.A", f"subj{i}", "{}",
                 bond, 10 + i, now, revoked, consumed, 0),
            )
        # Schema B: 1 active ZK
        conn.execute(
            "INSERT INTO attestations(attestation_id, issuer, schema_id, subject, "
            "claim_json, bond, issued_at_level, issued_at_ts, is_zk) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("e" * 32, "kn1issB", "schema.B.zk", "subjzk", "{}",
             100_000, 20, now, 1),
        )
        # One slashing on schema A
        conn.execute(
            "INSERT INTO slashings(tx_hash, block_level, block_ts, issuer, schema_id, "
            "subject, whistleblower, slashed_amount, whistleblower_reward, burned_amount, "
            "refunded_to_issuer) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("tx_slash_A", 25, now, "kn1issA", "schema.A", "subj_eq",
             "kn1prover", 900_000, 90_000, 810_000, 2_100_000),
        )
    yield conn, str(p)
    conn.close()


class TestDBSession2:
    def test_get_attestation(self, db_with_attestations):
        conn, _ = db_with_attestations
        a = get_attestation(conn, "a" * 32)
        assert a is not None
        assert a["issuer"] == "kn1issA"
        assert a["bond"] == 1_000_000
        assert a.get("claim") == {}     # decoded from claim_json
        assert get_attestation(conn, "z" * 32) is None

    def test_list_attestations_active_only(self, db_with_attestations):
        conn, _ = db_with_attestations
        atts = list_attestations(conn, active_only=True)
        # Schema A: 2 active; Schema B: 1 active = 3 total
        assert len(atts) == 3
        assert all(a["revoked_at_level"] is None and not a["consumed_for_slashing"]
                   for a in atts)

    def test_list_attestations_includes_inactive(self, db_with_attestations):
        conn, _ = db_with_attestations
        atts = list_attestations(conn, active_only=False)
        # All 5 attestations
        assert len(atts) == 5

    def test_list_attestations_filter_by_schema(self, db_with_attestations):
        conn, _ = db_with_attestations
        atts = list_attestations(conn, schema_id="schema.A", active_only=True)
        assert len(atts) == 2
        assert all(a["schema_id"] == "schema.A" for a in atts)

    def test_list_attestations_filter_by_issuer(self, db_with_attestations):
        conn, _ = db_with_attestations
        atts = list_attestations(conn, issuer="kn1issB", active_only=True)
        assert len(atts) == 1
        assert atts[0]["schema_id"] == "schema.B.zk"

    def test_list_schemas_aggregation(self, db_with_attestations):
        conn, _ = db_with_attestations
        schemas = list_schemas(conn)
        by_id = {s["schema_id"]: s for s in schemas}
        # Schema A: 4 total, 2 active, bond_locked = 1M + 2M
        assert by_id["schema.A"]["attestation_count"] == 4
        assert by_id["schema.A"]["active_count"] == 2
        assert by_id["schema.A"]["active_bond_locked"] == 3_000_000
        # Schema B: 1 total, 1 active, 1 ZK
        assert by_id["schema.B.zk"]["zk_count"] == 1
        assert by_id["schema.B.zk"]["active_count"] == 1

    def test_list_slashings_no_filter(self, db_with_attestations):
        conn, _ = db_with_attestations
        sls = list_slashings(conn)
        assert len(sls) == 1
        assert sls[0]["issuer"] == "kn1issA"
        assert sls[0]["slashed_amount"] == 900_000

    def test_list_slashings_filter_by_schema(self, db_with_attestations):
        conn, _ = db_with_attestations
        assert len(list_slashings(conn, schema_id="schema.A")) == 1
        assert len(list_slashings(conn, schema_id="schema.B.zk")) == 0

    def test_update_contract_storage(self, db_with_attestations):
        conn, _ = db_with_attestations
        # Seed a contract row
        conn.execute(
            "INSERT INTO contracts(address, skald_template, originated_at_level, "
            "last_refreshed_at_level) VALUES(?, ?, ?, ?)",
            ("kn1c", "sto-startup-equity", 10, 10),
        )
        conn.commit()
        # Refresh storage
        update_contract_storage(
            conn, "kn1c",
            storage={"total_supply_issued": 5_000, "whitepaper_registered": True},
            vertical_summary={"compliant": True, "total_supply_issued": 5_000},
            level=20,
        )
        row = conn.execute(
            "SELECT storage_json, vertical_summary_json, last_refreshed_at_level "
            "FROM contracts WHERE address = ?", ("kn1c",)
        ).fetchone()
        assert json.loads(row["storage_json"])["total_supply_issued"] == 5_000
        assert json.loads(row["vertical_summary_json"])["compliant"] is True
        assert row["last_refreshed_at_level"] == 20


# ===========================================================================
# New routes — empty + populated
# ===========================================================================

@pytest.fixture
def app_with_db(tmp_path: Path):
    p = tmp_path / "app.sqlite"
    os.environ["HEIMDALL_DB"] = str(p)
    os.environ["HEIMDALL_INDEXER"] = "0"
    import importlib
    import kern_explorer.app as app_module
    importlib.reload(app_module)
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as client:
        yield client, str(p)


@pytest.fixture
def app_with_verticals(app_with_db):
    """App backed by a DB with sample STO / QF / Oracle contracts."""
    client, db_path = app_with_db
    conn = open_db(db_path)
    now = int(time.time())
    with transaction(conn):
        # STO compliant
        conn.execute(
            "INSERT INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level, vertical_summary_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            ("kn1sto_ok", "contract StoStartupEquity { }", "{}",
             "sto-startup-equity", 10, "kn1dep", 10,
             json.dumps({"kind": "sto-startup-equity", "compliant": True,
                         "whitepaper_registered": True,
                         "total_supply_issued": 5000, "total_supply_cap": 10000,
                         "supply_utilization_pct": 50.0, "trading_paused": False})),
        )
        # STO non-compliant
        conn.execute(
            "INSERT INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level, vertical_summary_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            ("kn1sto_bad", "contract StoStartupEquity { }", "{}",
             "sto-startup-equity", 11, "kn1dep", 11,
             json.dumps({"kind": "sto-startup-equity", "compliant": False,
                         "whitepaper_registered": False,
                         "total_supply_issued": 1000, "total_supply_cap": 10000,
                         "trading_paused": False})),
        )
        # QF
        conn.execute(
            "INSERT INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level, vertical_summary_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            ("kn1qf", "contract QuadraticFundingProject { }", "{}",
             "quadratic-funding", 12, "kn1dep", 12,
             json.dumps({"kind": "quadratic-funding", "contributors_count": 8,
                         "sum_of_sqrt_contributions": 50, "total_received_mukrn": 2_000_000,
                         "matching_estimate_mukrn": 2500, "admin_approved": True})),
        )
        # Oracle tripped
        conn.execute(
            "INSERT INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level, vertical_summary_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            ("kn1oracle", "contract DefiPriceOracle { }", "{}",
             "defi-price-oracle", 13, "kn1dep", 13,
             json.dumps({"kind": "defi-price-oracle", "feeder_count": 5,
                         "latest_value": 100, "latest_aggregation_level": 13,
                         "circuit_breaker_tripped": True, "anomaly_count": 7,
                         "base_asset": "BTC", "quote_asset": "EUR",
                         "decimals": 2, "human_price": 1.0})),
        )
        # An attestation + a slashing for the attestations page
        conn.execute(
            "INSERT INTO attestations(attestation_id, issuer, schema_id, subject, "
            "claim_json, bond, issued_at_level, issued_at_ts, is_zk) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("aa" * 16, "kn1issuer", "kyc.over_18_v1", "kn1user", "{}",
             1_000_000, 14, now, 0),
        )
    conn.close()
    return client, db_path


class TestNewRoutesEmpty:
    @pytest.mark.parametrize("path", [
        "/attestations",
        "/sto-dashboard",
        "/public-goods",
        "/oracle-health",
    ])
    def test_route_200_empty(self, app_with_db, path):
        client, _ = app_with_db
        r = client.get(path)
        assert r.status_code == 200

    def test_attestation_404(self, app_with_db):
        client, _ = app_with_db
        r = client.get("/attestation/" + "z" * 32)
        assert r.status_code == 404

    def test_schema_page_empty(self, app_with_db):
        client, _ = app_with_db
        r = client.get("/schema/any.schema.id")
        assert r.status_code == 200


class TestNewRoutesPopulated:
    def test_attestations_full_dashboard(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/attestations")
        assert r.status_code == 200
        assert "kyc.over_18_v1" in r.text

    def test_attestation_detail(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/attestation/" + "aa" * 16)
        assert r.status_code == 200
        assert "kn1issuer" in r.text
        assert "kyc.over_18_v1" in r.text

    def test_schema_page_populated(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/schema/kyc.over_18_v1")
        assert r.status_code == 200
        assert "kyc.over_18_v1" in r.text

    def test_sto_dashboard_shows_both_contracts(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/sto-dashboard")
        assert r.status_code == 200
        assert "kn1sto_ok" in r.text
        assert "kn1sto_bad" in r.text
        # Compliance badges
        assert "Compliant" in r.text or "Check storage" in r.text

    def test_public_goods_shows_qf(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/public-goods")
        assert r.status_code == 200
        assert "kn1qf" in r.text

    def test_oracle_health_shows_tripped_oracle(self, app_with_verticals):
        client, _ = app_with_verticals
        r = client.get("/oracle-health")
        assert r.status_code == 200
        assert "kn1oracle" in r.text
        assert "TRIPPED" in r.text


# ===========================================================================
# Vertical metrics
# ===========================================================================

class TestVerticalMetrics:
    def test_sto_metrics_present(self, app_with_verticals):
        client, db_path = app_with_verticals
        body = render_metrics(db_path)
        assert "kern_sto_contracts_count 2" in body
        assert "kern_sto_contracts_compliant 1" in body

    def test_oracle_metrics_present(self, app_with_verticals):
        client, db_path = app_with_verticals
        body = render_metrics(db_path)
        assert "kern_oracle_feeds_count 1" in body
        assert "kern_oracle_feeds_circuit_breaker_tripped 1" in body
        assert "kern_oracle_anomalies_total 7" in body

    def test_pgf_metrics_present(self, app_with_verticals):
        client, db_path = app_with_verticals
        body = render_metrics(db_path)
        assert "kern_pgf_quadratic_funding_projects 1" in body
        assert "kern_pgf_quadratic_funding_contributors_total 8" in body
        assert "kern_pgf_quadratic_funding_raised_mukrn 2000000" in body
        assert "kern_pgf_retroactive_nominations 0" in body
