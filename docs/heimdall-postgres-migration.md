# Heimdall — SQLite to Postgres migration

This guide covers migrating Heimdall's indexer database from the default **SQLite** backend (excellent for devnet / Yggdrasil testnet) to **Postgres** (recommended for Midgard mainnet at scale).

**Maintainer**: Nicolas Van Eeckhout (founder).
**Audience**: anyone operating Heimdall at Midgard mainnet scale or expecting > 50 GB of indexed data, > 100 concurrent web reads, or multi-instance replication.

---

## When you need this migration

Stay on SQLite if **all** of these are true:
- Indexed data fits in one server's local SSD (~50 GB cap, comfortably)
- Web-app traffic is a few requests per second
- One Heimdall instance is enough (no need for multiple readers behind a load balancer)
- You're on devnet, a small testnet, or a private deployment

Migrate to Postgres if **any** of these are true:
- You're on Midgard mainnet (or a large Yggdrasil testnet)
- You expect > 50 GB of chain data
- You want multiple Heimdall web instances (one indexer + N read-only replicas)
- You want online backup / point-in-time recovery
- You want SQL replication to a long-term archive

Heimdall was designed for SQLite by default precisely because the alternative is configuration friction. Migrating only when needed keeps the smaller deployments simple.

---

## What changes architecturally

| Aspect | SQLite | Postgres |
|---|---|---|
| Indexer + web in one process | ✓ | ✓ |
| Single writer, many readers | ✓ (via WAL) | ✓ (native MVCC) |
| Multi-host replicas of the web app | ✗ (SQLite is local) | ✓ (all read from same Postgres) |
| Online backup | hot-copy WAL trick | `pg_dump` / streaming replication |
| Connection pooling | N/A (file-based) | needed at scale (PgBouncer recommended) |
| Schema differences | partial indexes via `WHERE`, INTEGER for all sizes | partial indexes work the same, BIGINT for large counters |

---

## Phase 1 — Prepare the Postgres instance

For Midgard production, use **Postgres 15+**. Smaller deployments are fine on 13+.

**Sizing guidance** (rough):
- 4 vCPU, 16 GB RAM, 200 GB SSD for first 6 months
- 8 vCPU, 32 GB RAM, 500 GB SSD for year 2-3
- Use a managed Postgres (RDS, Cloud SQL, Crunchy Data, Aiven) unless you have DBA capacity in-house

**Required Postgres settings** (`postgresql.conf` deltas vs. defaults):

```ini
shared_buffers = 4GB                  # 25% of RAM
effective_cache_size = 12GB           # 75% of RAM
work_mem = 64MB                       # per query op
maintenance_work_mem = 1GB            # for index builds during migration
max_connections = 200                 # PgBouncer recommended at higher load
wal_level = replica                   # enables streaming replication later
max_wal_size = 4GB
checkpoint_timeout = 15min
```

Create a dedicated user and database:

```bash
sudo -u postgres psql <<SQL
CREATE USER heimdall WITH PASSWORD 'REPLACE_WITH_STRONG_PASSWORD';
CREATE DATABASE heimdall_midgard OWNER heimdall;
GRANT ALL PRIVILEGES ON DATABASE heimdall_midgard TO heimdall;
SQL
```

---

## Phase 2 — Translate the schema

Heimdall's schema is defined in `kern_explorer/db.py` (`SCHEMA_SQL`). For Postgres you need the following adaptations.

**SQLite `INTEGER` PRIMARY KEY → Postgres `BIGINT`**: SQLite's INTEGER auto-widens; Postgres needs explicit BIGINT for block levels and amounts (mukrn sums easily exceed INT4_MAX).

**SQLite implicit `ROWID` → Postgres `SERIAL`**: not used in our schema, but mention it if you add tables.

**SQLite `TEXT` → Postgres `TEXT`** (same type, no width limit needed).

**Partial indexes** (`CREATE INDEX … WHERE …`): the syntax is identical in Postgres. Our `idx_att_active` partial index works as-is.

**`PRAGMA` directives**: ignored in Postgres (no equivalent). Drop them from the migration script.

**`INSERT OR REPLACE INTO`**: rewrite as `INSERT … ON CONFLICT (pk) DO UPDATE SET …` (Postgres UPSERT).

**Concrete schema for Postgres** — save as `heimdall-schema.pg.sql`:

```sql
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE blocks (
    level         BIGINT PRIMARY KEY,
    hash          TEXT NOT NULL UNIQUE,
    parent_hash   TEXT,
    timestamp     BIGINT NOT NULL,
    baker         TEXT,
    tx_count      INTEGER NOT NULL DEFAULT 0,
    indexed_at    BIGINT NOT NULL
);
CREATE INDEX idx_blocks_baker ON blocks(baker);
CREATE INDEX idx_blocks_ts ON blocks(timestamp DESC);

CREATE TABLE txs (
    hash          TEXT PRIMARY KEY,
    block_level   BIGINT NOT NULL REFERENCES blocks(level),
    block_ts      BIGINT NOT NULL,
    kind          TEXT NOT NULL,
    sender        TEXT NOT NULL,
    recipient     TEXT,
    amount        BIGINT NOT NULL DEFAULT 0,
    fee           BIGINT NOT NULL DEFAULT 0,
    gas_used      BIGINT NOT NULL DEFAULT 0,
    nonce         BIGINT NOT NULL,
    success       SMALLINT NOT NULL DEFAULT 1,
    error         TEXT,
    params_json   JSONB,                      -- prefer JSONB over TEXT for querying
    extra_json    JSONB
);
CREATE INDEX idx_txs_block ON txs(block_level);
CREATE INDEX idx_txs_sender ON txs(sender);
CREATE INDEX idx_txs_recipient ON txs(recipient);
CREATE INDEX idx_txs_kind ON txs(kind);
CREATE INDEX idx_txs_ts ON txs(block_ts DESC);

CREATE TABLE accounts (
    address           TEXT PRIMARY KEY,
    balance           BIGINT NOT NULL DEFAULT 0,
    nonce             BIGINT NOT NULL DEFAULT 0,
    is_validator      SMALLINT NOT NULL DEFAULT 0,
    is_contract       SMALLINT NOT NULL DEFAULT 0,
    tx_count_sent     BIGINT NOT NULL DEFAULT 0,
    tx_count_recv     BIGINT NOT NULL DEFAULT 0,
    first_seen_level  BIGINT,
    last_seen_level   BIGINT
);
CREATE INDEX idx_accounts_balance ON accounts(balance DESC);
CREATE INDEX idx_accounts_validator ON accounts(is_validator);

CREATE TABLE contracts (
    address                   TEXT PRIMARY KEY,
    code                      TEXT,
    storage_json              JSONB,
    skald_template            TEXT,
    originated_at_level       BIGINT,
    originated_by             TEXT,
    last_refreshed_at_level   BIGINT,
    vertical_summary_json     JSONB
);
CREATE INDEX idx_contracts_template ON contracts(skald_template);

CREATE TABLE attestations (
    attestation_id        TEXT PRIMARY KEY,
    issuer                TEXT NOT NULL,
    schema_id             TEXT NOT NULL,
    subject               TEXT NOT NULL,
    claim_json            JSONB NOT NULL,
    bond                  BIGINT NOT NULL DEFAULT 0,
    issued_at_level       BIGINT NOT NULL,
    issued_at_ts          BIGINT NOT NULL,
    revoked_at_level      BIGINT,
    consumed_for_slashing SMALLINT NOT NULL DEFAULT 0,
    is_zk                 SMALLINT NOT NULL DEFAULT 0
);
CREATE INDEX idx_att_issuer ON attestations(issuer);
CREATE INDEX idx_att_schema ON attestations(schema_id);
CREATE INDEX idx_att_subject ON attestations(subject);
CREATE INDEX idx_att_active
    ON attestations(revoked_at_level, consumed_for_slashing)
    WHERE revoked_at_level IS NULL AND consumed_for_slashing = 0;

CREATE TABLE slashings (
    tx_hash                 TEXT PRIMARY KEY,
    block_level             BIGINT NOT NULL,
    block_ts                BIGINT NOT NULL,
    issuer                  TEXT NOT NULL,
    schema_id               TEXT NOT NULL,
    subject                 TEXT NOT NULL,
    whistleblower           TEXT NOT NULL,
    slashed_amount          BIGINT NOT NULL,
    whistleblower_reward    BIGINT NOT NULL,
    burned_amount           BIGINT NOT NULL,
    refunded_to_issuer      BIGINT NOT NULL DEFAULT 0,
    attestation_id_1        TEXT,
    attestation_id_2        TEXT
);
CREATE INDEX idx_slash_issuer ON slashings(issuer);
CREATE INDEX idx_slash_schema ON slashings(schema_id);
CREATE INDEX idx_slash_ts ON slashings(block_ts DESC);
```

Apply it:

```bash
psql -U heimdall -d heimdall_midgard -f heimdall-schema.pg.sql
```

---

## Phase 3 — Migrate the data

For a fresh start, **don't bother migrating**: just point a fresh Heimdall at Postgres and let the indexer rebuild from genesis. This is the cleanest path and on devnet/Yggdrasil takes minutes to hours.

For Midgard or any chain with significant indexed data, **dump and load**:

**Step 3.1 — Stop the indexer**:
```bash
docker-compose -f docker-compose.monitoring.yml stop heimdall
```

**Step 3.2 — Export from SQLite**:

```bash
# Per-table CSV export (we use CSV to handle the JSON columns properly)
sqlite3 heimdall.sqlite <<'SQL'
.mode csv
.headers on
.output blocks.csv
SELECT * FROM blocks;
.output txs.csv
SELECT * FROM txs;
.output accounts.csv
SELECT * FROM accounts;
.output contracts.csv
SELECT * FROM contracts;
.output attestations.csv
SELECT * FROM attestations;
.output slashings.csv
SELECT * FROM slashings;
.output meta.csv
SELECT * FROM meta;
.quit
SQL
```

**Step 3.3 — Load into Postgres**:

```bash
psql -U heimdall -d heimdall_midgard <<'SQL'
\copy blocks       FROM 'blocks.csv'       WITH CSV HEADER
\copy txs          FROM 'txs.csv'          WITH CSV HEADER
\copy accounts     FROM 'accounts.csv'     WITH CSV HEADER
\copy contracts    FROM 'contracts.csv'    WITH CSV HEADER
\copy attestations FROM 'attestations.csv' WITH CSV HEADER
\copy slashings    FROM 'slashings.csv'    WITH CSV HEADER
\copy meta         FROM 'meta.csv'         WITH CSV HEADER
SQL
```

**Step 3.4 — Verify counts match**:

```bash
sqlite3 heimdall.sqlite "SELECT 'blocks', COUNT(*) FROM blocks
                          UNION ALL SELECT 'txs', COUNT(*) FROM txs
                          UNION ALL SELECT 'attestations', COUNT(*) FROM attestations;"

psql -U heimdall -d heimdall_midgard -c "SELECT 'blocks', COUNT(*) FROM blocks
                                         UNION ALL SELECT 'txs', COUNT(*) FROM txs
                                         UNION ALL SELECT 'attestations', COUNT(*) FROM attestations;"
```

Numbers should be identical. If not, the `\copy` had errors — check Postgres logs.

---

## Phase 4 — Adapt Heimdall to Postgres

Heimdall's current implementation (v0.3, Session 3) uses the `sqlite3` standard library directly. A Postgres-capable build is **planned for Session 4** (and is one of the open Heimdall contribution areas — see `contributors-program.md`).

The adaptation is small in scope (Heimdall is ~2,200 LOC):

1. Add `psycopg[binary]>=3.1` to the `explorer` extra in `pyproject.toml`
2. Replace `kern_explorer/db.py:open_db()` to return a psycopg connection when `HEIMDALL_DB_URL` starts with `postgresql://`, else the SQLite connection
3. Rewrite the few SQLite-specific queries:
   - `INSERT OR REPLACE INTO` → `INSERT … ON CONFLICT … DO UPDATE`
   - Boolean comparisons stay valid (Postgres treats SMALLINT 0/1 like SQLite)
   - The `PRAGMA` calls in `open_db` are no-ops in Postgres — wrap them
4. Connection pooling: instead of `open_db()` per request, use `psycopg_pool.ConnectionPool` initialized at app startup

Until that work lands, **for production today**: run the indexer process against SQLite and use a separate ETL job to mirror to Postgres for analytics. The Heimdall web app would still serve from SQLite. This is a stopgap, not the recommended end state.

---

## Phase 5 — Production hardening

Once on Postgres:

**Connection pooling**: deploy PgBouncer in front of Postgres. Configure transaction-level pooling for the read-heavy web app, session pooling for the indexer. Target `max_client_conn = 1000`, `default_pool_size = 50`.

**Backups**:
```bash
# Daily logical backup
pg_dump -U heimdall -d heimdall_midgard -F c -f /backups/heimdall-$(date +%F).dump

# Streaming replication to a hot standby — see Postgres docs on physical replication
```

**Monitoring**: scrape Postgres metrics via `postgres_exporter` (`prometheus-community/postgres_exporter`). Add the relevant alerts to `kern-alerts.yml`:
- `pg_up == 0` → DB unreachable (critical)
- `pg_stat_activity_count > 150` → connection saturation (warning)
- `pg_database_size_bytes` growth rate → capacity planning

**Vertical replicas**: with Postgres, you can run multiple Heimdall web instances. Run **one** with `HEIMDALL_INDEXER=1` and **N** with `HEIMDALL_INDEXER=0`, all pointing at the same Postgres URL. Put them behind any standard load balancer.

---

## Rollback

If something goes wrong post-migration, rollback is trivial because **the SQLite file is untouched** during the migration (you only read from it). Just point Heimdall back at SQLite via `HEIMDALL_DB=heimdall.sqlite` and restart.

The downside: any blocks indexed by the Postgres-backed Heimdall between the migration and the rollback are lost from the SQLite. You'll re-index them when the indexer resumes from the SQLite cursor — typically a few minutes of catch-up.

---

## See also

- [`setup-heimdall-operator.md`](setup-heimdall-operator.md) — installation and base configuration
- [`heimdall-ops-runbook.md`](heimdall-ops-runbook.md) — incident response procedures
- [`post-code-roadmap.md`](post-code-roadmap.md) — phase 6 (Mainnet) mentions managed Postgres budget

---

*This guide is part of the Heimdall delivery (Session 3/4). Founder: Nicolas Van Eeckhout. License: Apache-2.0.*
