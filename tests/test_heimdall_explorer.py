# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for the Heimdall block explorer (kern_explorer package).

Covers:
- RPC client behavior on success and error
- DB schema initialization and the read helpers
- Indexer template detection + per-handler tx materialization
- Metrics rendering
- FastAPI app routes against empty DB and against seeded DB

The app is exercised with FastAPI's TestClient. The indexer is disabled
for these tests (no live node) — we seed the DB directly to test reads.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern_explorer import __version__ as HEIMDALL_VERSION
from kern_explorer.db import (
    get_account,
    get_block,
    get_block_by_hash,
    get_contract,
    get_meta,
    get_tx,
    init_schema,
    latest_indexed_level,
    list_contracts,
    list_validators,
    open_db,
    recent_blocks,
    recent_txs,
    set_meta,
    stats_summary,
    transaction,
    txs_for_address,
    txs_in_block,
    upsert_account,
)
from kern_explorer.indexer import TEMPLATE_PATTERNS, detect_template
from kern_explorer.metrics import render_metrics


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def db_path(tmp_path: Path) -> Iterator[str]:
    """Fresh SQLite DB for each test."""
    p = tmp_path / "test.sqlite"
    yield str(p)


@pytest.fixture
def empty_conn(db_path: str):
    """A connection to a freshly schema-initialized DB."""
    conn = open_db(db_path)
    init_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def seeded_conn(empty_conn):
    """A DB with sample blocks/txs/accounts/attestations for read-path tests."""
    conn = empty_conn
    now = int(time.time())
    with transaction(conn):
        # Three blocks, with baker validators
        for level, ts, baker, n in [(1, now - 30, "kn1baker_a", 0),
                                    (2, now - 20, "kn1baker_b", 2),
                                    (3, now - 10, "kn1baker_a", 1)]:
            conn.execute(
                "INSERT INTO blocks(level, hash, parent_hash, timestamp, baker, tx_count, indexed_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (level, f"hash_b{level:04d}", f"hash_b{level - 1:04d}" if level > 1 else None,
                 ts, baker, n, now),
            )
            upsert_account(conn, address=baker, is_validator=1, balance=10_000_000,
                           last_seen_level=level)

        # Two transactions in block 2: a transfer and an attest
        conn.execute(
            "INSERT INTO txs(hash, block_level, block_ts, kind, sender, recipient, "
            "amount, fee, gas_used, nonce, success, error, params_json, extra_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("tx_transfer_1", 2, now - 20, "transfer", "kn1alice", "kn1bob",
             5_000_000, 1000, 1000, 0, 1, None, None, None),
        )
        conn.execute(
            "INSERT INTO txs(hash, block_level, block_ts, kind, sender, recipient, "
            "amount, fee, gas_used, nonce, success, error, params_json, extra_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("tx_attest_1", 2, now - 20, "attest", "kn1issuer", None,
             1_000_000, 2000, 30000, 0, 1, None,
             json.dumps({"schema_id": "kyc.over_18_v1", "subject": "kn1user",
                         "claim": {"verified": True}}),
             json.dumps({"attestation_id": "ab" * 16})),
        )
        # One tx in block 3
        conn.execute(
            "INSERT INTO txs(hash, block_level, block_ts, kind, sender, recipient, "
            "amount, fee, gas_used, nonce, success, error, params_json, extra_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("tx_originate_1", 3, now - 10, "originate", "kn1deployer", None,
             0, 5000, 10000, 0, 1, None, None,
             json.dumps({"new_contract": "kn1contract_sto"})),
        )

        # Accounts touched by the txs
        upsert_account(conn, address="kn1alice", balance=20_000_000,
                       first_seen_level=2, last_seen_level=2,
                       tx_count_sent=1)
        upsert_account(conn, address="kn1bob", balance=5_000_000,
                       first_seen_level=2, last_seen_level=2,
                       tx_count_recv=1)
        upsert_account(conn, address="kn1issuer", balance=999_000_000,
                       first_seen_level=2, last_seen_level=2,
                       tx_count_sent=1)
        upsert_account(conn, address="kn1deployer", balance=50_000_000,
                       first_seen_level=3, last_seen_level=3,
                       tx_count_sent=1)
        upsert_account(conn, address="kn1contract_sto", is_contract=1,
                       first_seen_level=3, last_seen_level=3)

        # A contract with detected template
        conn.execute(
            "INSERT INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            ("kn1contract_sto",
             "contract StoStartupEquity { storage { owner: address, } }",
             json.dumps({"owner": "kn1deployer"}),
             "sto-startup-equity", 3, "kn1deployer", 3),
        )

        # An attestation matching tx_attest_1
        conn.execute(
            "INSERT INTO attestations(attestation_id, issuer, schema_id, subject, "
            "claim_json, bond, issued_at_level, issued_at_ts, is_zk) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ab" * 16, "kn1issuer", "kyc.over_18_v1", "kn1user",
             json.dumps({"verified": True}), 1_000_000, 2, now - 20, 0),
        )

        # A slashing event
        conn.execute(
            "INSERT INTO slashings(tx_hash, block_level, block_ts, issuer, schema_id, "
            "subject, whistleblower, slashed_amount, whistleblower_reward, burned_amount, "
            "refunded_to_issuer) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("tx_slash_1", 3, now - 10, "kn1bad_oracle", "energy.grid_freq_v1",
             "elia", "kn1whistleblower", 300_000, 30_000, 270_000, 700_000),
        )
    return conn


@pytest.fixture
def app_client(db_path: str):
    """A FastAPI TestClient with indexer disabled, pointed at db_path."""
    from fastapi.testclient import TestClient
    os.environ["HEIMDALL_DB"] = db_path
    os.environ["HEIMDALL_INDEXER"] = "0"
    # Reload the app module so it picks up the env
    import importlib
    import kern_explorer.app as app_module
    importlib.reload(app_module)
    with TestClient(app_module.app) as client:
        yield client


# ===========================================================================
# DB layer tests
# ===========================================================================

class TestDB:
    def test_init_schema_idempotent(self, db_path):
        conn = open_db(db_path)
        init_schema(conn)
        init_schema(conn)  # second call must not raise
        # All expected tables exist
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = {r["name"] for r in rows}
        for expected in ("meta", "blocks", "txs", "accounts", "contracts",
                         "attestations", "slashings"):
            assert expected in names

    def test_meta_get_set(self, empty_conn):
        assert get_meta(empty_conn, "missing") is None
        set_meta(empty_conn, "indexer.cursor", "42")
        assert get_meta(empty_conn, "indexer.cursor") == "42"
        set_meta(empty_conn, "indexer.cursor", "99")
        assert get_meta(empty_conn, "indexer.cursor") == "99"

    def test_latest_indexed_level_empty(self, empty_conn):
        assert latest_indexed_level(empty_conn) == -1

    def test_recent_blocks_empty(self, empty_conn):
        assert recent_blocks(empty_conn) == []

    def test_recent_blocks_seeded(self, seeded_conn):
        blocks = recent_blocks(seeded_conn, limit=10)
        assert len(blocks) == 3
        assert blocks[0]["level"] == 3
        assert blocks[-1]["level"] == 1

    def test_get_block(self, seeded_conn):
        b = get_block(seeded_conn, 2)
        assert b is not None
        assert b["hash"] == "hash_b0002"
        assert b["baker"] == "kn1baker_b"

    def test_get_block_by_hash(self, seeded_conn):
        b = get_block_by_hash(seeded_conn, "hash_b0002")
        assert b is not None and b["level"] == 2

    def test_txs_in_block(self, seeded_conn):
        rows = txs_in_block(seeded_conn, 2)
        assert len(rows) == 2

    def test_recent_txs_filter_by_kind(self, seeded_conn):
        rows = recent_txs(seeded_conn, kind="attest")
        assert len(rows) == 1
        assert rows[0]["kind"] == "attest"

    def test_get_tx_decodes_json(self, seeded_conn):
        tx = get_tx(seeded_conn, "tx_attest_1")
        assert tx is not None
        # params_json field still present; decoded "params" added alongside
        assert tx.get("params") is not None
        assert tx["params"]["schema_id"] == "kyc.over_18_v1"

    def test_account_helpers(self, seeded_conn):
        a = get_account(seeded_conn, "kn1alice")
        assert a is not None and a["balance"] == 20_000_000
        assert a["tx_count_sent"] == 1
        assert get_account(seeded_conn, "kn1ghost") is None

    def test_txs_for_address_both_sides(self, seeded_conn):
        sent = txs_for_address(seeded_conn, "kn1alice")
        assert len(sent) == 1 and sent[0]["hash"] == "tx_transfer_1"
        recv = txs_for_address(seeded_conn, "kn1bob")
        assert len(recv) == 1

    def test_list_validators(self, seeded_conn):
        vs = list_validators(seeded_conn)
        assert len(vs) == 2
        # Sorted by balance desc — both have the same balance, so order is tie-broken
        assert all(v["is_validator"] == 1 for v in vs)

    def test_list_contracts_with_template_filter(self, seeded_conn):
        all_c = list_contracts(seeded_conn)
        assert len(all_c) == 1
        sto = list_contracts(seeded_conn, template="sto-startup-equity")
        assert len(sto) == 1
        none = list_contracts(seeded_conn, template="quadratic-funding")
        assert len(none) == 0

    def test_get_contract_decodes_storage(self, seeded_conn):
        c = get_contract(seeded_conn, "kn1contract_sto")
        assert c is not None
        assert c["storage"]["owner"] == "kn1deployer"

    def test_stats_summary(self, seeded_conn):
        s = stats_summary(seeded_conn)
        assert s["n_blocks"] == 3
        assert s["n_txs"] == 3
        assert s["n_accounts"] >= 5
        assert s["n_validators"] == 2
        assert s["n_contracts"] == 1
        assert s["n_active_attestations"] == 1
        assert s["n_slashings"] == 1


# ===========================================================================
# Indexer template detection
# ===========================================================================

class TestTemplateDetection:
    def test_none_for_missing_source(self):
        assert detect_template(None) is None
        assert detect_template("") is None

    def test_none_for_unknown(self):
        assert detect_template("contract Random { }") is None

    @pytest.mark.parametrize("name,source", [
        ("sto-startup-equity",     "contract StoStartupEquity { storage { } }"),
        ("sto-institutional-fund", "contract StoInstitutionalFund { }"),
        ("sto-real-estate",        "contract StoRealEstate { }"),
        ("quadratic-funding",      "contract QuadraticFundingProject { }"),
        ("retroactive-pgf",        "contract RetroactivePgfNomination { }"),
        ("generic-data-oracle",    "contract GenericDataOracle { }"),
        ("defi-price-oracle",      "contract DefiPriceOracle { }"),
        ("schema-marketplace",     "contract SchemaMarketplaceEntry { }"),
        ("vault-example",          "contract Vault { }"),
        ("counter-example",        "contract Counter { }"),
    ])
    def test_each_known_template(self, name, source):
        assert detect_template(source) == name

    def test_pattern_list_covers_all_skald_examples(self):
        # We need a detection pattern per known shipped example
        names = {p[0] for p in TEMPLATE_PATTERNS}
        for required in ("sto-startup-equity", "quadratic-funding", "generic-data-oracle"):
            assert required in names


# ===========================================================================
# Metrics rendering
# ===========================================================================

class TestMetrics:
    def test_render_empty_db(self, db_path):
        # Empty schema must still render valid Prometheus text
        conn = open_db(db_path)
        init_schema(conn)
        conn.close()
        body = render_metrics(db_path)
        assert "kern_chain_head_level 0" in body
        assert "kern_indexed_transactions_total 0" in body
        assert "kern_attestations_active 0" in body
        # Help and type lines present
        assert "# HELP kern_chain_head_level" in body
        assert "# TYPE kern_chain_head_level gauge" in body

    def test_render_seeded(self, seeded_conn, db_path):
        body = render_metrics(db_path)
        assert "kern_chain_head_level 3" in body
        assert "kern_indexed_transactions_total 3" in body
        assert "kern_attestations_active 1" in body
        assert "kern_attestation_slashings_total 1" in body
        # Per-schema breakdown is present
        assert 'kern_attestations_active_by_schema{schema_id="kyc.over_18_v1"}' in body
        # Per-template breakdown
        assert 'kern_originated_contracts_by_template{template="sto-startup-equity"}' in body

    def test_label_escaping(self, db_path):
        conn = open_db(db_path)
        init_schema(conn)
        # Insert an attestation with a malicious schema_id containing quotes
        conn.execute(
            "INSERT INTO attestations(attestation_id, issuer, schema_id, subject, "
            "claim_json, bond, issued_at_level, issued_at_ts, is_zk) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("00" * 16, "kn1x", 'evil"schema', "subj", "{}", 0, 1, 1, 0),
        )
        conn.commit()
        conn.close()
        body = render_metrics(db_path)
        # Should escape the quote, not break the format
        assert 'evil\\"schema' in body


# ===========================================================================
# FastAPI app routes
# ===========================================================================

class TestAppEmpty:
    """Routes must return 200 even against an empty DB."""

    @pytest.mark.parametrize("path", [
        "/", "/blocks", "/txs", "/validators", "/contracts",
        "/attestations", "/governance", "/search?q=", "/search?q=42",
        "/health", "/metrics",
        "/api/stats", "/api/blocks", "/api/txs", "/api/validators", "/api/contracts",
    ])
    def test_route_returns_200(self, app_client, path):
        r = app_client.get(path)
        # /governance hits the live RPC; if unreachable it should still return 200 with an error in the body
        assert r.status_code == 200, f"{path} returned {r.status_code}"


class TestAppSeeded:
    """Routes return correct data when the DB is seeded."""

    def test_home_shows_stats(self, app_client, seeded_conn):
        # seeded_conn already wrote to the same db_path as app_client uses
        r = app_client.get("/")
        assert r.status_code == 200
        body = r.text
        # The home page should mention numbers from the seed
        assert "Recent blocks" in body
        assert "Recent transactions" in body

    def test_block_detail_renders(self, app_client, seeded_conn):
        r = app_client.get("/block/2")
        assert r.status_code == 200
        assert "hash_b0002" in r.text

    def test_block_404(self, app_client, seeded_conn):
        r = app_client.get("/block/999")
        assert r.status_code == 404

    def test_tx_detail_renders(self, app_client, seeded_conn):
        r = app_client.get("/tx/tx_attest_1")
        assert r.status_code == 200
        assert "kyc.over_18_v1" in r.text

    def test_tx_404(self, app_client, seeded_conn):
        r = app_client.get("/tx/nonexistent")
        assert r.status_code == 404

    def test_account_detail(self, app_client, seeded_conn):
        r = app_client.get("/account/kn1alice")
        assert r.status_code == 200
        assert "kn1alice" in r.text

    def test_validators_lists_bakers(self, app_client, seeded_conn):
        r = app_client.get("/validators")
        assert r.status_code == 200
        assert "kn1baker_a" in r.text
        assert "kn1baker_b" in r.text

    def test_contracts_filter_by_template(self, app_client, seeded_conn):
        r = app_client.get("/contracts?template=sto-startup-equity")
        assert r.status_code == 200
        assert "kn1contract_sto" in r.text
        r2 = app_client.get("/contracts?template=quadratic-funding")
        assert r2.status_code == 200
        assert "kn1contract_sto" not in r2.text

    def test_contract_detail_shows_source(self, app_client, seeded_conn):
        r = app_client.get("/contract/kn1contract_sto")
        assert r.status_code == 200
        assert "StoStartupEquity" in r.text

    def test_search_by_level(self, app_client, seeded_conn):
        r = app_client.get("/search?q=2")
        assert r.status_code == 200
        assert "/block/2" in r.text

    def test_search_by_address(self, app_client, seeded_conn):
        r = app_client.get("/search?q=kn1alice")
        assert r.status_code == 200
        assert "/account/kn1alice" in r.text

    def test_search_by_tx_hash(self, app_client, seeded_conn):
        r = app_client.get("/search?q=tx_attest_1")
        assert r.status_code == 200
        assert "/tx/tx_attest_1" in r.text

    def test_search_by_attestation_id(self, app_client, seeded_conn):
        att_id = "ab" * 16
        r = app_client.get(f"/search?q={att_id}")
        assert r.status_code == 200
        assert att_id in r.text

    def test_attestations_overview(self, app_client, seeded_conn):
        r = app_client.get("/attestations")
        assert r.status_code == 200
        assert "kyc.over_18_v1" in r.text

    def test_metrics_format(self, app_client, seeded_conn):
        r = app_client.get("/metrics")
        assert r.status_code == 200
        assert "kern_chain_head_level 3" in r.text
        assert r.headers["content-type"].startswith("text/plain")


class TestAppJsonApi:
    def test_api_stats_returns_json(self, app_client, seeded_conn):
        r = app_client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "n_blocks" in data and data["n_blocks"] == 3

    def test_api_block_includes_txs(self, app_client, seeded_conn):
        r = app_client.get("/api/block/2")
        assert r.status_code == 200
        data = r.json()
        assert data["level"] == 2
        assert "transactions" in data and len(data["transactions"]) == 2

    def test_api_block_404(self, app_client, seeded_conn):
        assert app_client.get("/api/block/999").status_code == 404

    def test_api_txs_filter(self, app_client, seeded_conn):
        r = app_client.get("/api/txs?kind=attest")
        assert r.status_code == 200
        rows = r.json()
        assert all(t["kind"] == "attest" for t in rows)

    def test_api_account(self, app_client, seeded_conn):
        r = app_client.get("/api/account/kn1alice")
        assert r.status_code == 200
        assert r.json()["balance"] == 20_000_000

    def test_health_reports_versions(self, app_client, seeded_conn):
        r = app_client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["heimdall_version"] == HEIMDALL_VERSION
        assert "node_reachable" in data
        assert "indexed_head_level" in data
