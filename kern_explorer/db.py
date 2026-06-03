# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern_explorer.db
================

SQLite schema and query helpers for Heimdall.

Why SQLite (and not Postgres) by default:
- Zero-config: an explorer for a devnet or small testnet must work with
  a single `pip install` step. Postgres setup is friction.
- Sufficient for devnet/testnet sizes (millions of rows, not billions).
- The schema is documented; switching to Postgres for Midgard mainnet
  is a configuration change, not a redesign. See setup-heimdall-operator.md.

Schema design notes:
- We denormalize liberally to keep queries simple — every transaction
  row contains the block's level and timestamp for fast filtering
- All amounts are stored as INTEGER mukrn (no floating point)
- All hashes/addresses are TEXT (hex or base58check as appropriate)
- The four v1.1-rc verticals get their own tables:
    attestations, attestation_slashings, contracts (with skald_template
    column for STO/QF/Oracle classification)
- WAL journal mode is enabled for concurrent reader (web) + writer
  (indexer) without locking

Threading: the indexer writes from one task; the web app reads from
many. SQLite WAL handles this safely if each consumer opens its own
connection (which we do).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Blocks: one row per indexed block
CREATE TABLE IF NOT EXISTS blocks (
    level         INTEGER PRIMARY KEY,
    hash          TEXT NOT NULL UNIQUE,
    parent_hash   TEXT,
    timestamp     INTEGER NOT NULL,         -- unix seconds
    baker         TEXT,
    tx_count      INTEGER NOT NULL DEFAULT 0,
    indexed_at    INTEGER NOT NULL          -- our local timestamp when indexed
);
CREATE INDEX IF NOT EXISTS idx_blocks_baker ON blocks(baker);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(timestamp DESC);

-- Transactions: every tx in every block, regardless of kind
CREATE TABLE IF NOT EXISTS txs (
    hash          TEXT PRIMARY KEY,
    block_level   INTEGER NOT NULL,
    block_ts      INTEGER NOT NULL,
    kind          TEXT NOT NULL,           -- transfer, attest, governance_vote, etc.
    sender        TEXT NOT NULL,
    recipient     TEXT,
    amount        INTEGER NOT NULL DEFAULT 0,
    fee           INTEGER NOT NULL DEFAULT 0,
    gas_used      INTEGER NOT NULL DEFAULT 0,
    nonce         INTEGER NOT NULL,
    success       INTEGER NOT NULL DEFAULT 1,
    error         TEXT,
    params_json   TEXT,                    -- raw JSON of params for any kind
    extra_json    TEXT,                    -- handler extra result (e.g. attestation_id, slash details)
    FOREIGN KEY (block_level) REFERENCES blocks(level)
);
CREATE INDEX IF NOT EXISTS idx_txs_block ON txs(block_level);
CREATE INDEX IF NOT EXISTS idx_txs_sender ON txs(sender);
CREATE INDEX IF NOT EXISTS idx_txs_recipient ON txs(recipient);
CREATE INDEX IF NOT EXISTS idx_txs_kind ON txs(kind);
CREATE INDEX IF NOT EXISTS idx_txs_ts ON txs(block_ts DESC);

-- Accounts: lightweight cache of last-known balances + tx counts
-- (the chain RPC is the source of truth; this is for fast list/search)
CREATE TABLE IF NOT EXISTS accounts (
    address       TEXT PRIMARY KEY,
    balance       INTEGER NOT NULL DEFAULT 0,
    nonce         INTEGER NOT NULL DEFAULT 0,
    is_validator  INTEGER NOT NULL DEFAULT 0,
    is_contract   INTEGER NOT NULL DEFAULT 0,
    tx_count_sent INTEGER NOT NULL DEFAULT 0,
    tx_count_recv INTEGER NOT NULL DEFAULT 0,
    first_seen_level INTEGER,
    last_seen_level  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_accounts_balance ON accounts(balance DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_validator ON accounts(is_validator);

-- Contracts: code + storage snapshot at indexer's last refresh
CREATE TABLE IF NOT EXISTS contracts (
    address           TEXT PRIMARY KEY,
    code              TEXT,                -- Skald source
    storage_json      TEXT,                -- last known storage
    skald_template    TEXT,                -- detected template name for classification:
                                           -- e.g. "sto-startup-equity", "quadratic-funding",
                                           -- "generic-data-oracle", or NULL if unrecognized
    originated_at_level INTEGER,
    originated_by     TEXT,                -- the originator address
    last_refreshed_at_level INTEGER,
    -- Vertical-specific summary computed at indexing time from the
    -- storage snapshot. JSON object whose shape depends on skald_template:
    --   sto-* templates: {is_compliant, kyc_verified_holders_count, total_supply_issued, ...}
    --   quadratic-funding: {round_status, contributors, eligible_matching_mukrn, ...}
    --   *-oracle: {feeder_count, last_value, is_fresh, anomaly_count, ...}
    vertical_summary_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_contracts_template ON contracts(skald_template);

-- Attestations (v1.1-rc): every ATTEST tx materialized for fast lookup
CREATE TABLE IF NOT EXISTS attestations (
    attestation_id    TEXT PRIMARY KEY,
    issuer            TEXT NOT NULL,
    schema_id         TEXT NOT NULL,
    subject           TEXT NOT NULL,
    claim_json        TEXT NOT NULL,
    bond              INTEGER NOT NULL DEFAULT 0,
    issued_at_level   INTEGER NOT NULL,
    issued_at_ts      INTEGER NOT NULL,
    revoked_at_level  INTEGER,
    consumed_for_slashing INTEGER NOT NULL DEFAULT 0,
    is_zk             INTEGER NOT NULL DEFAULT 0   -- 1 if claim is a ZK payload
);
CREATE INDEX IF NOT EXISTS idx_att_issuer ON attestations(issuer);
CREATE INDEX IF NOT EXISTS idx_att_schema ON attestations(schema_id);
CREATE INDEX IF NOT EXISTS idx_att_subject ON attestations(subject);
CREATE INDEX IF NOT EXISTS idx_att_active
    ON attestations(revoked_at_level, consumed_for_slashing)
    WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0;

-- Slashings (v1.1-rc): every successful SLASH_ATTESTATION_EQUIVOCATION
CREATE TABLE IF NOT EXISTS slashings (
    tx_hash           TEXT PRIMARY KEY,
    block_level       INTEGER NOT NULL,
    block_ts          INTEGER NOT NULL,
    issuer            TEXT NOT NULL,     -- the slashed party
    schema_id         TEXT NOT NULL,
    subject           TEXT NOT NULL,
    whistleblower     TEXT NOT NULL,     -- the prover (tx sender)
    slashed_amount    INTEGER NOT NULL,
    whistleblower_reward INTEGER NOT NULL,
    burned_amount     INTEGER NOT NULL,
    refunded_to_issuer INTEGER NOT NULL DEFAULT 0,
    attestation_id_1  TEXT,
    attestation_id_2  TEXT
);
CREATE INDEX IF NOT EXISTS idx_slash_issuer ON slashings(issuer);
CREATE INDEX IF NOT EXISTS idx_slash_schema ON slashings(schema_id);
CREATE INDEX IF NOT EXISTS idx_slash_ts ON slashings(block_ts DESC);
"""


def open_db(path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode enabled.

    Each consumer (indexer task, each web request) should open its own
    connection — SQLite handles concurrent readers + 1 writer cleanly
    with WAL mode.
    """
    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit off; we use explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")   # wait up to 5s for a lock
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they don't exist (idempotent)."""
    with conn:
        conn.executescript(SCHEMA_SQL)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Wrap a block of writes in a transaction."""
    conn.execute("BEGIN")
    try:
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# Read helpers — used by the web app
# ---------------------------------------------------------------------------

def get_meta(conn: sqlite3.Connection, key: str, default: Optional[str] = None) -> Optional[str]:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    with conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def latest_indexed_level(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(level) AS m FROM blocks").fetchone()
    return row["m"] if row and row["m"] is not None else -1


def get_block(conn: sqlite3.Connection, level: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM blocks WHERE level = ?", (level,)).fetchone()
    return dict(row) if row else None


def get_block_by_hash(conn: sqlite3.Connection, h: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM blocks WHERE hash = ?", (h,)).fetchone()
    return dict(row) if row else None


def recent_blocks(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM blocks ORDER BY level DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_tx(conn: sqlite3.Connection, h: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM txs WHERE hash = ?", (h,)).fetchone()
    if not row:
        return None
    d = dict(row)
    # Deserialize JSON columns for caller convenience
    for j in ("params_json", "extra_json"):
        if d.get(j):
            try:
                d[j[:-5]] = json.loads(d[j])
            except json.JSONDecodeError:
                pass
    return d


def txs_in_block(conn: sqlite3.Connection, level: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM txs WHERE block_level = ? ORDER BY hash", (level,)
    ).fetchall()
    return [dict(r) for r in rows]


def recent_txs(conn: sqlite3.Connection, limit: int = 20, kind: Optional[str] = None) -> list[dict]:
    if kind:
        rows = conn.execute(
            "SELECT * FROM txs WHERE kind = ? ORDER BY block_level DESC LIMIT ?",
            (kind, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM txs ORDER BY block_level DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_account(conn: sqlite3.Connection, address: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM accounts WHERE address = ?", (address,)).fetchone()
    return dict(row) if row else None


def upsert_account(conn: sqlite3.Connection, **fields: Any) -> None:
    """INSERT OR UPDATE an account row. The 'address' field is required."""
    assert "address" in fields, "address required"
    cols = list(fields.keys())
    placeholders = ", ".join("?" for _ in cols)
    update_clause = ", ".join(f"{c} = excluded.{c}" for c in cols if c != "address")
    sql = (
        f"INSERT INTO accounts({', '.join(cols)}) VALUES({placeholders}) "
        f"ON CONFLICT(address) DO UPDATE SET {update_clause}"
    )
    conn.execute(sql, tuple(fields[c] for c in cols))


def txs_for_address(conn: sqlite3.Connection, address: str, limit: int = 50) -> list[dict]:
    """All txs where address is sender OR recipient."""
    rows = conn.execute(
        "SELECT * FROM txs WHERE sender = ? OR recipient = ? "
        "ORDER BY block_level DESC LIMIT ?",
        (address, address, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_validators(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM accounts WHERE is_validator = 1 ORDER BY balance DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def list_contracts(conn: sqlite3.Connection, template: Optional[str] = None,
                   limit: int = 50) -> list[dict]:
    if template:
        rows = conn.execute(
            "SELECT * FROM contracts WHERE skald_template = ? "
            "ORDER BY originated_at_level DESC LIMIT ?",
            (template, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM contracts ORDER BY originated_at_level DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_contract(conn: sqlite3.Connection, address: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM contracts WHERE address = ?", (address,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("storage_json"):
        try:
            d["storage"] = json.loads(d["storage_json"])
        except json.JSONDecodeError:
            d["storage"] = None
    if d.get("vertical_summary_json"):
        try:
            d["vertical_summary"] = json.loads(d["vertical_summary_json"])
        except json.JSONDecodeError:
            d["vertical_summary"] = None
    return d


def stats_summary(conn: sqlite3.Connection) -> dict:
    """High-level chain stats for the home page."""
    r = conn.execute("SELECT COUNT(*) AS c FROM blocks").fetchone()
    n_blocks = r["c"] if r else 0
    r = conn.execute("SELECT COUNT(*) AS c FROM txs").fetchone()
    n_txs = r["c"] if r else 0
    r = conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()
    n_accounts = r["c"] if r else 0
    r = conn.execute("SELECT COUNT(*) AS c FROM accounts WHERE is_validator = 1").fetchone()
    n_validators = r["c"] if r else 0
    r = conn.execute("SELECT COUNT(*) AS c FROM contracts").fetchone()
    n_contracts = r["c"] if r else 0
    r = conn.execute(
        "SELECT COUNT(*) AS c FROM attestations "
        "WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0"
    ).fetchone()
    n_active_attestations = r["c"] if r else 0
    r = conn.execute("SELECT COUNT(*) AS c FROM slashings").fetchone()
    n_slashings = r["c"] if r else 0
    return {
        "n_blocks": n_blocks,
        "n_txs": n_txs,
        "n_accounts": n_accounts,
        "n_validators": n_validators,
        "n_contracts": n_contracts,
        "n_active_attestations": n_active_attestations,
        "n_slashings": n_slashings,
    }


# ---------------------------------------------------------------------------
# Attestation registry helpers (vertical 1)
# ---------------------------------------------------------------------------

def get_attestation(conn: sqlite3.Connection, attestation_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM attestations WHERE attestation_id = ?", (attestation_id,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("claim_json"):
        try:
            d["claim"] = json.loads(d["claim_json"])
        except json.JSONDecodeError:
            d["claim"] = None
    return d


def list_attestations(conn: sqlite3.Connection,
                      schema_id: Optional[str] = None,
                      issuer: Optional[str] = None,
                      active_only: bool = True,
                      limit: int = 100) -> list[dict]:
    """List attestations optionally filtered by schema or issuer."""
    where_parts = []
    params: list[Any] = []
    if schema_id is not None:
        where_parts.append("schema_id = ?")
        params.append(schema_id)
    if issuer is not None:
        where_parts.append("issuer = ?")
        params.append(issuer)
    if active_only:
        where_parts.append("revoked_at_level IS NULL")
        where_parts.append("consumed_for_slashing = 0")
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM attestations {where} ORDER BY issued_at_level DESC LIMIT ?",
        tuple(params),
    ).fetchall()
    return [dict(r) for r in rows]


def list_schemas(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    """List distinct schemas with their attestation count and bond locked."""
    rows = conn.execute(
        "SELECT schema_id, COUNT(*) AS attestation_count, "
        "       SUM(CASE WHEN revoked_at_level IS NULL AND consumed_for_slashing = 0 "
        "                THEN 1 ELSE 0 END) AS active_count, "
        "       SUM(CASE WHEN revoked_at_level IS NULL AND consumed_for_slashing = 0 "
        "                THEN bond ELSE 0 END) AS active_bond_locked, "
        "       SUM(is_zk) AS zk_count "
        "FROM attestations GROUP BY schema_id ORDER BY active_count DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def list_slashings(conn: sqlite3.Connection,
                   schema_id: Optional[str] = None,
                   issuer: Optional[str] = None,
                   limit: int = 50) -> list[dict]:
    where_parts = []
    params: list[Any] = []
    if schema_id is not None:
        where_parts.append("schema_id = ?")
        params.append(schema_id)
    if issuer is not None:
        where_parts.append("issuer = ?")
        params.append(issuer)
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM slashings {where} ORDER BY block_level DESC LIMIT ?",
        tuple(params),
    ).fetchall()
    return [dict(r) for r in rows]


def update_contract_storage(conn: sqlite3.Connection, address: str,
                            storage: Any, vertical_summary: Optional[dict],
                            level: int) -> None:
    """Refresh a contract's storage snapshot and vertical summary."""
    conn.execute(
        "UPDATE contracts SET storage_json = ?, vertical_summary_json = ?, "
        "last_refreshed_at_level = ? WHERE address = ?",
        (
            json.dumps(storage) if storage is not None else None,
            json.dumps(vertical_summary) if vertical_summary is not None else None,
            level, address,
        ),
    )
