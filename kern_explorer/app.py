# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern_explorer.app
=================

The FastAPI application for Heimdall.

Routes:
- GET /              — home dashboard (stats + recent blocks + recent txs)
- GET /blocks        — list of recent blocks
- GET /block/{level} — block detail + its transactions
- GET /txs?kind=     — list of recent transactions, optionally filtered
- GET /tx/{hash}     — transaction detail
- GET /account/{addr}— account detail with tx history
- GET /validators    — list of active bakers
- GET /contracts?template= — list of contracts, optionally filtered
- GET /contract/{addr}     — contract detail with code + storage
- GET /attestations  — attestation registry overview (full dashboard in session 2)
- GET /governance    — live governance state from RPC
- GET /search?q=     — universal search (block level / tx hash / address / attestation id)
- GET /health        — JSON health probe
- GET /metrics       — Prometheus text format (on the same port for simplicity; in production
                      use a reverse proxy to expose this on a separate port if desired)
- GET /api/...       — JSON variants of the HTML routes for programmatic access
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .client import KernRpcClient, KernRpcError
from .db import (
    get_account,
    get_block,
    get_block_by_hash,
    get_contract,
    get_tx,
    init_schema,
    latest_indexed_level,
    list_contracts,
    list_validators,
    open_db,
    recent_blocks,
    recent_txs,
    stats_summary,
    txs_for_address,
    txs_in_block,
)
from .indexer import Indexer, TEMPLATE_PATTERNS
from .metrics import render_metrics


logger = logging.getLogger("heimdall.app")


# Configuration (overridable via env)
DB_PATH = os.environ.get("HEIMDALL_DB", "heimdall.sqlite")
RPC_URL = os.environ.get("KERN_RPC", "http://127.0.0.1:8732")
ENABLE_INDEXER = os.environ.get("HEIMDALL_INDEXER", "1") not in ("0", "false", "False")

MUKRN_PER_KRN = 1_000_000


# ---------------------------------------------------------------------------
# Jinja2 environment
# ---------------------------------------------------------------------------

TEMPLATE_DIR = Path(__file__).parent / "templates"
env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)


def render(template_name: str, **ctx) -> str:
    """Render a template with global context (rpc_url, version, indexed head)."""
    conn = open_db(DB_PATH)
    try:
        indexed_head = latest_indexed_level(conn)
    finally:
        conn.close()
    global_ctx = {
        "heimdall_version": __version__,
        "rpc_url": RPC_URL,
        "indexed_head": indexed_head if indexed_head >= 0 else None,
    }
    global_ctx.update(ctx)
    return env.get_template(template_name).render(**global_ctx)


# ---------------------------------------------------------------------------
# Lifespan management — start the indexer in the background
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the background indexer at app startup, stop it at shutdown."""
    # Always initialize schema, so read endpoints work even if the indexer
    # is disabled or has not yet ingested any block.
    conn = open_db(DB_PATH)
    try:
        init_schema(conn)
    finally:
        conn.close()

    indexer_task = None
    indexer = None
    if ENABLE_INDEXER:
        indexer = Indexer(DB_PATH, RPC_URL)
        indexer_task = asyncio.create_task(indexer.run())
        logger.info("Heimdall indexer started (db=%s, rpc=%s)", DB_PATH, RPC_URL)
    yield
    if indexer is not None:
        indexer.stop()
        if indexer_task is not None:
            try:
                await asyncio.wait_for(indexer_task, timeout=5.0)
            except asyncio.TimeoutError:
                indexer_task.cancel()


app = FastAPI(
    title="Heimdall",
    description="Kern block explorer + monitoring stack.",
    version=__version__,
    lifespan=lifespan,
)


# Mount static for the very rare static asset (we mostly rely on CDN)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _amount_krn(mukrn: int) -> str:
    """Format mukrn as a KRN string with up to 6 decimals."""
    if mukrn is None:
        return "0"
    return f"{mukrn / MUKRN_PER_KRN:.6f}".rstrip("0").rstrip(".") or "0"


def _age(ts: Optional[int]) -> str:
    """Human-readable age."""
    if not ts:
        return "—"
    diff = max(0, int(time.time()) - int(ts))
    if diff < 60:
        return f"{diff}s"
    if diff < 3600:
        return f"{diff // 60}m"
    if diff < 86400:
        return f"{diff // 3600}h"
    return f"{diff // 86400}d"


def _enrich_tx(tx: dict) -> dict:
    tx["amount_krn"] = _amount_krn(tx.get("amount", 0))
    return tx


def _enrich_block(b: dict) -> dict:
    b["age"] = _age(b.get("timestamp"))
    return b


def _enrich_account(a: dict) -> dict:
    a["balance_krn"] = _amount_krn(a.get("balance", 0))
    return a


def _make_pagination(page: int, per_page: int, total: int, qs: str = "") -> dict:
    """Build a pagination context for templates.

    Returns:
        {
            page: current 1-indexed page,
            per_page: items per page,
            total: total item count,
            total_pages: ceil(total / per_page),
            has_prev / has_next: booleans,
            prev_page / next_page: ints (or None),
            qs: extra query-string fragment to preserve filters (e.g. "&kind=attest"),
        }
    """
    total_pages = max(1, (total + per_page - 1) // per_page)
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1 if page > 1 else None,
        "next_page": page + 1 if page < total_pages else None,
        "qs": qs,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    conn = open_db(DB_PATH)
    try:
        stats = stats_summary(conn)
        blocks = [_enrich_block(b) for b in recent_blocks(conn, 10)]
        txs = [_enrich_tx(t) for t in recent_txs(conn, 10)]
    finally:
        conn.close()

    stat_cards = [
        ("Blocks", stats["n_blocks"], "/blocks"),
        ("Transactions", stats["n_txs"], "/txs"),
        ("Accounts", stats["n_accounts"], None),
        ("Validators", stats["n_validators"], "/validators"),
        ("Contracts", stats["n_contracts"], "/contracts"),
        ("Active attestations", stats["n_active_attestations"], "/attestations"),
        ("Slashings", stats["n_slashings"], "/attestations"),
    ]

    # v1.1-rc vertical cards — quick access to the per-vertical dashboards
    n_sto = conn = open_db(DB_PATH)
    try:
        n_sto = conn.execute(
            "SELECT COUNT(*) AS c FROM contracts WHERE skald_template IN "
            "('sto-startup-equity', 'sto-institutional-fund', 'sto-real-estate')"
        ).fetchone()["c"]
        n_qf = conn.execute(
            "SELECT COUNT(*) AS c FROM contracts WHERE skald_template = 'quadratic-funding'"
        ).fetchone()["c"]
        n_rpgf = conn.execute(
            "SELECT COUNT(*) AS c FROM contracts WHERE skald_template = 'retroactive-pgf'"
        ).fetchone()["c"]
        n_oracle = conn.execute(
            "SELECT COUNT(*) AS c FROM contracts WHERE skald_template IN "
            "('generic-data-oracle', 'defi-price-oracle')"
        ).fetchone()["c"]
    finally:
        conn.close()

    vertical_cards = [
        ("STO compliance", n_sto, "/sto-dashboard",
         "Tokenized-securities offerings"),
        ("Public goods", n_qf + n_rpgf, "/public-goods",
         "Quadratic Funding + Retroactive PGF rounds"),
        ("Oracle health", n_oracle, "/oracle-health",
         "Decentralized data feeds with slashable feeders"),
    ]

    return render("home.html", stat_cards=stat_cards, vertical_cards=vertical_cards,
                  recent_blocks=blocks, recent_txs=txs)


@app.get("/blocks", response_class=HTMLResponse)
async def blocks_list(page: int = Query(1, ge=1), per_page: int = Query(50, ge=10, le=200)) -> str:
    conn = open_db(DB_PATH)
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM blocks").fetchone()["c"]
        offset = (page - 1) * per_page
        rows = conn.execute(
            "SELECT * FROM blocks ORDER BY level DESC LIMIT ? OFFSET ?",
            (per_page, offset),
        ).fetchall()
        blocks = [_enrich_block(dict(r)) for r in rows]
        pagination = _make_pagination(page, per_page, total)
    finally:
        conn.close()
    return render("blocks.html", blocks=blocks, pagination=pagination)


@app.get("/block/{level}", response_class=HTMLResponse)
async def block_detail(level: int) -> str:
    conn = open_db(DB_PATH)
    try:
        b = get_block(conn, level)
        if not b:
            raise HTTPException(status_code=404, detail=f"Block {level} not found")
        block = _enrich_block(b)
        txs = [_enrich_tx(t) for t in txs_in_block(conn, level)]
    finally:
        conn.close()
    return render("block.html", block=block, txs=txs)


@app.get("/txs", response_class=HTMLResponse)
async def txs_list(kind: Optional[str] = None,
                   page: int = Query(1, ge=1),
                   per_page: int = Query(50, ge=10, le=200)) -> str:
    conn = open_db(DB_PATH)
    try:
        if kind:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM txs WHERE kind = ?", (kind,)
            ).fetchone()["c"]
            rows = conn.execute(
                "SELECT * FROM txs WHERE kind = ? ORDER BY block_level DESC LIMIT ? OFFSET ?",
                (kind, per_page, (page - 1) * per_page),
            ).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) AS c FROM txs").fetchone()["c"]
            rows = conn.execute(
                "SELECT * FROM txs ORDER BY block_level DESC LIMIT ? OFFSET ?",
                (per_page, (page - 1) * per_page),
            ).fetchall()
        txs = [_enrich_tx(dict(r)) for r in rows]
        pagination = _make_pagination(page, per_page, total, qs=f"&kind={kind}" if kind else "")
    finally:
        conn.close()
    # Known kinds for the filter pills (matches OpKind enum)
    known_kinds = [
        "transfer", "originate", "call",
        "delegate_stake", "undelegate_stake",
        "governance_propose", "governance_vote", "slash_equivocation",
        "attest", "revoke_attestation", "slash_attestation_equivocation",
    ]
    return render("txs.html", txs=txs, known_kinds=known_kinds, kind_filter=kind,
                  pagination=pagination)


@app.get("/tx/{tx_hash}", response_class=HTMLResponse)
async def tx_detail(tx_hash: str) -> str:
    conn = open_db(DB_PATH)
    try:
        tx = get_tx(conn, tx_hash)
        if not tx:
            raise HTTPException(status_code=404, detail=f"Tx {tx_hash} not found")
        tx = _enrich_tx(tx)
    finally:
        conn.close()
    return render("tx.html", tx=tx)


@app.get("/account/{address}", response_class=HTMLResponse)
async def account_detail(address: str) -> str:
    conn = open_db(DB_PATH)
    try:
        a = get_account(conn, address)
        if not a:
            # Stub a row from the live RPC if not yet indexed
            try:
                async with KernRpcClient(RPC_URL) as rpc:
                    bal = await rpc.balance(address)
                    nce = await rpc.nonce(address)
                a = {
                    "address": address,
                    "balance": bal.get("balance", 0),
                    "nonce": nce.get("nonce", 0),
                    "is_validator": 0, "is_contract": 0,
                    "tx_count_sent": 0, "tx_count_recv": 0,
                    "first_seen_level": None, "last_seen_level": None,
                }
            except KernRpcError:
                raise HTTPException(status_code=404, detail=f"Account {address} not found")
        account = _enrich_account(a)
        txs = [_enrich_tx(t) for t in txs_for_address(conn, address, 50)]
    finally:
        conn.close()
    return render("account.html", account=account, txs=txs)


@app.get("/validators", response_class=HTMLResponse)
async def validators_list() -> str:
    conn = open_db(DB_PATH)
    try:
        validators = [_enrich_account(v) for v in list_validators(conn)]
    finally:
        conn.close()
    return render("validators.html", validators=validators)


@app.get("/contracts", response_class=HTMLResponse)
async def contracts_list(template: Optional[str] = None,
                         q: Optional[str] = None,
                         page: int = Query(1, ge=1),
                         per_page: int = Query(50, ge=10, le=200)) -> str:
    """List contracts, with optional template filter and full-text search on Skald source.

    The `q` parameter searches the contract `code` column (case-insensitive
    substring). For Skald source above 1 MB total, performance is acceptable
    on SQLite up to ~10k contracts; for larger sizes consider FTS5 or
    migrating to Postgres (see heimdall-postgres-migration.md).
    """
    conn = open_db(DB_PATH)
    try:
        where_parts = []
        params: list = []
        if template:
            where_parts.append("skald_template = ?")
            params.append(template)
        if q:
            where_parts.append("code LIKE ?")
            params.append(f"%{q}%")
        where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
        # Count
        count_sql = f"SELECT COUNT(*) AS c FROM contracts {where}"
        total = conn.execute(count_sql, tuple(params)).fetchone()["c"]
        # Page
        page_sql = (
            f"SELECT * FROM contracts {where} "
            f"ORDER BY originated_at_level DESC LIMIT ? OFFSET ?"
        )
        rows = conn.execute(page_sql, tuple(params) + (per_page, (page - 1) * per_page)).fetchall()
        contracts = [dict(r) for r in rows]
        # Build qs to preserve filters across page links
        qs_parts = []
        if template:
            qs_parts.append(f"template={template}")
        if q:
            qs_parts.append(f"q={q}")
        qs = ("&" + "&".join(qs_parts)) if qs_parts else ""
        pagination = _make_pagination(page, per_page, total, qs=qs)
    finally:
        conn.close()
    known = [t[0] for t in TEMPLATE_PATTERNS]
    return render("contracts.html", contracts=contracts,
                  known_templates=known, template_filter=template,
                  q=q or "", pagination=pagination)


@app.get("/contract/{address}", response_class=HTMLResponse)
async def contract_detail(address: str) -> str:
    conn = open_db(DB_PATH)
    try:
        c = get_contract(conn, address)
        if not c:
            raise HTTPException(status_code=404, detail=f"Contract {address} not found")
    finally:
        conn.close()
    return render("contract.html", contract=c)


@app.get("/attestations", response_class=HTMLResponse)
async def attestations_overview() -> str:
    conn = open_db(DB_PATH)
    try:
        from .db import list_attestations, list_schemas, list_slashings
        stats = stats_summary(conn)
        total_atts = conn.execute("SELECT COUNT(*) AS c FROM attestations").fetchone()["c"]
        total_bond = conn.execute(
            "SELECT COALESCE(SUM(bond), 0) AS s FROM attestations "
            "WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0"
        ).fetchone()["s"]
        schemas = list_schemas(conn, limit=50)
        for s in schemas:
            s["bond_locked_krn"] = _amount_krn(s.get("active_bond_locked") or 0)
        slashings = list_slashings(conn, limit=20)
        for s in slashings:
            s["slashed_amount_krn"] = _amount_krn(s["slashed_amount"])
        attestations = list_attestations(conn, active_only=True, limit=30)
        for a in attestations:
            a["bond_krn"] = _amount_krn(a["bond"])
    finally:
        conn.close()
    return render("attestations.html",
                  stats={
                      "active": stats["n_active_attestations"],
                      "total": total_atts,
                      "total_bond_krn": _amount_krn(total_bond),
                      "slashings": stats["n_slashings"],
                  },
                  schemas=schemas, slashings=slashings, attestations=attestations)


@app.get("/attestation/{attestation_id}", response_class=HTMLResponse)
async def attestation_detail(attestation_id: str) -> str:
    conn = open_db(DB_PATH)
    try:
        from .db import get_attestation, list_slashings
        a = get_attestation(conn, attestation_id)
        if not a:
            raise HTTPException(status_code=404, detail=f"Attestation {attestation_id} not found")
        a["bond_krn"] = _amount_krn(a["bond"])
        # Find slashings that consumed this attestation
        rows = conn.execute(
            "SELECT * FROM slashings WHERE attestation_id_1 = ? OR attestation_id_2 = ? "
            "ORDER BY block_level DESC",
            (attestation_id, attestation_id),
        ).fetchall()
        slashings = []
        for r in rows:
            d = dict(r)
            d["slashed_amount_krn"] = _amount_krn(d["slashed_amount"])
            slashings.append(d)
    finally:
        conn.close()
    return render("attestation.html", attestation=a, slashings=slashings)


@app.get("/schema/{schema_id}", response_class=HTMLResponse)
async def schema_detail(schema_id: str) -> str:
    conn = open_db(DB_PATH)
    try:
        from .db import list_attestations, list_slashings
        rows = conn.execute(
            "SELECT COUNT(*) AS total, "
            "       SUM(CASE WHEN revoked_at_level IS NULL AND consumed_for_slashing = 0 "
            "                THEN 1 ELSE 0 END) AS active, "
            "       SUM(CASE WHEN revoked_at_level IS NULL AND consumed_for_slashing = 0 "
            "                THEN bond ELSE 0 END) AS bond "
            "FROM attestations WHERE schema_id = ?",
            (schema_id,)
        ).fetchone()
        slash_count = conn.execute(
            "SELECT COUNT(*) AS c FROM slashings WHERE schema_id = ?", (schema_id,)
        ).fetchone()["c"]

        summary = {
            "active": rows["active"] or 0 if rows else 0,
            "total": rows["total"] or 0 if rows else 0,
            "bond_locked_krn": _amount_krn(rows["bond"] or 0 if rows else 0),
            "slashings": slash_count,
        }
        attestations = list_attestations(conn, schema_id=schema_id, active_only=True, limit=100)
        for a in attestations:
            a["bond_krn"] = _amount_krn(a["bond"])
        slashings = list_slashings(conn, schema_id=schema_id, limit=50)
        for s in slashings:
            s["slashed_amount_krn"] = _amount_krn(s["slashed_amount"])
    finally:
        conn.close()
    return render("schema.html", schema_id=schema_id, summary=summary,
                  attestations=attestations, slashings=slashings)


@app.get("/sto-dashboard", response_class=HTMLResponse)
async def sto_dashboard() -> str:
    conn = open_db(DB_PATH)
    try:
        contracts = []
        for tmpl in ("sto-startup-equity", "sto-institutional-fund", "sto-real-estate"):
            contracts.extend(list_contracts(conn, template=tmpl, limit=200))
        # Decode the vertical_summary for each
        for c in contracts:
            if c.get("vertical_summary_json"):
                try:
                    c["vertical_summary"] = json.loads(c["vertical_summary_json"])
                except json.JSONDecodeError:
                    c["vertical_summary"] = None
        # Summary
        compliant = sum(
            1 for c in contracts
            if c.get("vertical_summary") and c["vertical_summary"].get("compliant")
        )
        flagged = len(contracts) - compliant
        total_issued = sum(
            int((c.get("vertical_summary") or {}).get("total_supply_issued", 0) or 0)
            for c in contracts
        )
        summary = {
            "total": len(contracts),
            "compliant": compliant,
            "flagged": flagged,
            "total_issued_krn": f"{total_issued:,}",
        }
    finally:
        conn.close()
    return render("sto_dashboard.html", contracts=contracts, summary=summary)


@app.get("/public-goods", response_class=HTMLResponse)
async def public_goods_dashboard() -> str:
    conn = open_db(DB_PATH)
    try:
        qf_projects = list_contracts(conn, template="quadratic-funding", limit=200)
        rpgf_nominations = list_contracts(conn, template="retroactive-pgf", limit=200)
        for c in qf_projects + rpgf_nominations:
            if c.get("vertical_summary_json"):
                try:
                    c["vertical_summary"] = json.loads(c["vertical_summary_json"])
                except json.JSONDecodeError:
                    c["vertical_summary"] = None
        # Decorate QF
        qf_raised_total = 0
        qf_contributors_total = 0
        for c in qf_projects:
            v = c.get("vertical_summary") or {}
            raised = int(v.get("total_received_mukrn", 0) or 0)
            c["raised_krn"] = _amount_krn(raised)
            c["matching_estimate_krn"] = _amount_krn(int(v.get("matching_estimate_mukrn", 0) or 0))
            qf_raised_total += raised
            qf_contributors_total += int(v.get("contributors_count", 0) or 0)
        summary = {
            "qf_count": len(qf_projects),
            "qf_contributors_total": qf_contributors_total,
            "qf_raised_krn": _amount_krn(qf_raised_total),
            "rpgf_count": len(rpgf_nominations),
        }
    finally:
        conn.close()
    return render("public_goods.html", qf_projects=qf_projects,
                  rpgf_nominations=rpgf_nominations, summary=summary)


@app.get("/oracle-health", response_class=HTMLResponse)
async def oracle_health_dashboard() -> str:
    conn = open_db(DB_PATH)
    try:
        oracles = []
        for tmpl in ("generic-data-oracle", "defi-price-oracle"):
            oracles.extend(list_contracts(conn, template=tmpl, limit=200))
        for c in oracles:
            if c.get("vertical_summary_json"):
                try:
                    c["vertical_summary"] = json.loads(c["vertical_summary_json"])
                except json.JSONDecodeError:
                    c["vertical_summary"] = None
        # Summary
        tripped = sum(
            1 for c in oracles
            if c.get("vertical_summary") and c["vertical_summary"].get("circuit_breaker_tripped")
        )
        healthy = len(oracles) - tripped
        total_anomalies = sum(
            int((c.get("vertical_summary") or {}).get("anomaly_count", 0) or 0)
            for c in oracles
        )
        summary = {
            "total": len(oracles),
            "healthy": healthy,
            "tripped": tripped,
            "total_anomalies": total_anomalies,
        }
    finally:
        conn.close()
    return render("oracle_health.html", oracles=oracles, summary=summary)


@app.get("/governance", response_class=HTMLResponse)
async def governance_view() -> str:
    try:
        async with KernRpcClient(RPC_URL) as rpc:
            gov = await rpc.governance()
    except KernRpcError as e:
        gov = {"error": str(e)}
    return render("governance.html", governance=gov)


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = "") -> str:
    q = q.strip()
    if not q:
        return render("search_results.html", q=q, results=[], no_results=True)

    results = []
    conn = open_db(DB_PATH)
    try:
        # Try block level (integer)
        if q.isdigit():
            level = int(q)
            b = get_block(conn, level)
            if b:
                results.append({
                    "kind": "Block",
                    "title": f"Block #{level}",
                    "subtitle": b["hash"],
                    "url": f"/block/{level}",
                })

        # Try block hash
        b = get_block_by_hash(conn, q)
        if b:
            results.append({
                "kind": "Block (by hash)",
                "title": f"Block #{b['level']}",
                "subtitle": b["hash"],
                "url": f"/block/{b['level']}",
            })

        # Try tx hash
        tx = get_tx(conn, q)
        if tx:
            results.append({
                "kind": "Transaction",
                "title": f"{tx['kind']} tx",
                "subtitle": tx["hash"],
                "url": f"/tx/{q}",
            })

        # Try address (kn1...)
        if q.startswith("kn1"):
            a = get_account(conn, q)
            results.append({
                "kind": "Account",
                "title": f"Balance {_amount_krn(a['balance']) if a else '—'} KRN",
                "subtitle": q,
                "url": f"/account/{q}",
            })

        # Try attestation id (hex 32 chars)
        if len(q) == 32 and all(c in "0123456789abcdef" for c in q.lower()):
            r = conn.execute(
                "SELECT issuer, schema_id, subject FROM attestations WHERE attestation_id = ?",
                (q,)
            ).fetchone()
            if r:
                results.append({
                    "kind": "Attestation",
                    "title": f"{r['schema_id']} on {r['subject']}",
                    "subtitle": q,
                    "url": f"/attestations#{q}",   # session 2 will add a per-attestation page
                })
    finally:
        conn.close()

    return render("search_results.html", q=q, results=results, no_results=not results)


# ---------------------------------------------------------------------------
# Health + metrics + JSON API
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> JSONResponse:
    try:
        async with KernRpcClient(RPC_URL) as rpc:
            head = await rpc.head()
        node_ok = True
        node_head_level = head.get("level")
    except KernRpcError:
        node_ok = False
        node_head_level = None
    conn = open_db(DB_PATH)
    try:
        indexed_head = latest_indexed_level(conn)
    finally:
        conn.close()
    lag = (node_head_level - indexed_head) if (node_ok and node_head_level is not None) else None
    return JSONResponse({
        "heimdall_version": __version__,
        "rpc_url": RPC_URL,
        "node_reachable": node_ok,
        "node_head_level": node_head_level,
        "indexed_head_level": indexed_head if indexed_head >= 0 else None,
        "indexer_lag_blocks": lag,
        "db_path": DB_PATH,
    })


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    return render_metrics(DB_PATH)


# JSON API mirrors of the HTML routes — same data, easier for programmatic clients
@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        return JSONResponse(stats_summary(conn))
    finally:
        conn.close()


@app.get("/api/blocks")
async def api_blocks(limit: int = Query(20, ge=1, le=200)) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        return JSONResponse(recent_blocks(conn, limit))
    finally:
        conn.close()


@app.get("/api/block/{level}")
async def api_block(level: int) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        b = get_block(conn, level)
        if not b:
            raise HTTPException(status_code=404, detail="not found")
        b["transactions"] = txs_in_block(conn, level)
        return JSONResponse(b)
    finally:
        conn.close()


@app.get("/api/txs")
async def api_txs(limit: int = Query(20, ge=1, le=200), kind: Optional[str] = None) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        return JSONResponse(recent_txs(conn, limit, kind=kind))
    finally:
        conn.close()


@app.get("/api/tx/{tx_hash}")
async def api_tx(tx_hash: str) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        tx = get_tx(conn, tx_hash)
        if not tx:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse(tx)
    finally:
        conn.close()


@app.get("/api/account/{address}")
async def api_account(address: str) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        a = get_account(conn, address)
        if not a:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse(a)
    finally:
        conn.close()


@app.get("/api/validators")
async def api_validators() -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        return JSONResponse(list_validators(conn))
    finally:
        conn.close()


@app.get("/api/contracts")
async def api_contracts(template: Optional[str] = None,
                        limit: int = Query(50, ge=1, le=500)) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        return JSONResponse(list_contracts(conn, template=template, limit=limit))
    finally:
        conn.close()


@app.get("/api/attestation/{attestation_id}")
async def api_attestation(attestation_id: str) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        from .db import get_attestation
        a = get_attestation(conn, attestation_id)
        if not a:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse(a)
    finally:
        conn.close()


@app.get("/api/schemas")
async def api_schemas(limit: int = Query(100, ge=1, le=500)) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        from .db import list_schemas
        return JSONResponse(list_schemas(conn, limit=limit))
    finally:
        conn.close()


@app.get("/api/attestations")
async def api_attestations(schema_id: Optional[str] = None,
                            issuer: Optional[str] = None,
                            active_only: bool = True,
                            limit: int = Query(100, ge=1, le=500)) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        from .db import list_attestations
        return JSONResponse(list_attestations(
            conn, schema_id=schema_id, issuer=issuer,
            active_only=active_only, limit=limit,
        ))
    finally:
        conn.close()


@app.get("/api/slashings")
async def api_slashings(schema_id: Optional[str] = None,
                         issuer: Optional[str] = None,
                         limit: int = Query(50, ge=1, le=500)) -> JSONResponse:
    conn = open_db(DB_PATH)
    try:
        from .db import list_slashings
        return JSONResponse(list_slashings(
            conn, schema_id=schema_id, issuer=issuer, limit=limit,
        ))
    finally:
        conn.close()


# Convenience: a CLI entry point so users can `python -m kern_explorer`
def main() -> None:
    """Run Heimdall via uvicorn."""
    import uvicorn
    host = os.environ.get("HEIMDALL_HOST", "127.0.0.1")
    port = int(os.environ.get("HEIMDALL_PORT", "8800"))
    uvicorn.run("kern_explorer.app:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
