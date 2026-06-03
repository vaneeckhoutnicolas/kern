# Setup guide: Heimdall operator

This guide is for **anyone running an instance of Heimdall** — the Kern block explorer + monitoring stack — pointing at a Kern node (devnet, testnet, or eventually Midgard mainnet).

This is the v0.1 of the guide, shipped with Heimdall v0.1 (Session 1 of the Heimdall delivery plan). The full guide ships in Heimdall v1.0 (Session 4) and will add: production deployment patterns (systemd unit, nginx reverse proxy, log rotation), Postgres migration steps, multi-instance topology, Grafana dashboards JSON, and alerting rules.

---

## What Heimdall is

Heimdall is the Kern protocol's **block explorer and monitoring stack**. Named after the Norse god who watches the nine worlds from Bifröst.

It does what generic block explorers do — surface blocks, transactions, accounts, validators, contracts — and additionally surfaces what is **distinctive to Kern**: the slashable attestation registry, the STO compliance state, the public goods funding round dashboards, and the oracle network health. These institutional-legibility features are the reason Kern exists; an explorer that doesn't show them would fail the regulator, the auditor, and the institutional adopter.

Architecturally Heimdall consists of three layers running in one Python process:

1. An **indexer** that follows the Kern node's RPC, parses each block, and writes denormalized rows into SQLite for fast queries.
2. A **FastAPI web app** that serves HTML pages and a JSON API, querying the SQLite cache for cold data and the live RPC for fresh data (mempool, current governance state).
3. A **Prometheus metrics endpoint** that exposes the L1 baseline + v1.1-rc vertical metrics for scraping by your monitoring stack.

## Prerequisites

- Python 3.11+
- A running Kern node with its RPC accessible
- Network access from the Heimdall host to the node's RPC port (default 8732)
- 1 GB of disk for the SQLite cache on devnet/testnet; budget 50 GB+ for mainnet (will migrate to Postgres for mainnet — see Session 4)

## Installation

```bash
# From a freshly cloned Kern repo
cd kern
pip install -e ".[explorer]"
```

This installs the additional dependencies (`fastapi`, `uvicorn`, `httpx`, `jinja2`) declared in `pyproject.toml`'s `explorer` extra. It also exposes a `heimdall` CLI entry point.

## Configuration

Heimdall is configured via environment variables :

| Variable | Default | Purpose |
|---|---|---|
| `KERN_RPC` | `http://127.0.0.1:8732` | Where to reach the Kern node's RPC. Use `http://NODE_HOST:8732` for a remote node. |
| `HEIMDALL_DB` | `heimdall.sqlite` | Path to the SQLite indexer database. Will be created if absent. |
| `HEIMDALL_INDEXER` | `1` | Set to `0` to disable the background indexer (e.g., for read-only replicas). |
| `HEIMDALL_HOST` | `127.0.0.1` | The bind address for the FastAPI app. Use `0.0.0.0` to expose on all interfaces. |
| `HEIMDALL_PORT` | `8800` | The port for the FastAPI app. |

## Running

The simplest way :

```bash
heimdall
```

This starts the FastAPI app on `http://127.0.0.1:8800`, with the indexer following the Kern node at `http://127.0.0.1:8732` and storing data in `heimdall.sqlite` in the working directory.

For a remote Kern node :

```bash
KERN_RPC=http://192.0.2.1:8732 HEIMDALL_HOST=0.0.0.0 heimdall
```

For a read-only replica (useful in monitoring setups where one indexer feeds N web replicas) :

```bash
HEIMDALL_INDEXER=0 HEIMDALL_DB=/var/data/heimdall.sqlite heimdall
```

## What you can do once it's running

Open `http://127.0.0.1:8800/` in a browser. You should see :

- The **home dashboard** with stat cards for blocks, transactions, accounts, validators, contracts, active attestations, and slashings
- **Recent blocks** and **recent transactions** tables
- A **search bar** that accepts block levels, tx hashes, addresses, attestation IDs

Other pages :

- `/blocks` — paginated block list
- `/block/N` — block detail with all its transactions
- `/txs?kind=attest` — transactions filtered by kind (transfer, attest, governance_vote, etc.)
- `/tx/HASH` — transaction detail with full params and handler result
- `/account/kn1...` — account detail with balance, nonce, recent transactions
- `/validators` — active bakers
- `/contracts?template=sto-startup-equity` — originated contracts, classified by detected Skald template
- `/contract/kn1...` — contract detail with Skald source and current storage

**v1.1-rc vertical-specific dashboards:**

- `/attestations` — slashable attestation registry overview: active schemas, slashing history, recent attestations
- `/attestation/{id}` — single attestation: claim payload, bond, slashing evidence, ZK badge if applicable
- `/schema/{schema_id}` — all attestations under a schema with slashing history
- `/sto-dashboard` — tokenized-securities offerings (MiFID II / Prospectus Regulation / AIFMD, *not* MiCA) with live compliance state per contract (whitepaper registered, depositary independence for AIFMD, anti-Ponzi for real estate)
- `/public-goods` — Quadratic Funding projects + Retroactive PGF nominations with contributors, matching estimate, voting state
- `/oracle-health` — Oracle feeds with feeder count, latest value, circuit breaker state, anomaly counts
- `/governance` — live governance state from RPC

Programmatic access :

- `/api/stats`, `/api/blocks`, `/api/block/N`, `/api/txs`, `/api/tx/HASH`, `/api/account/A`, `/api/validators`, `/api/contracts` — L1 baseline
- `/api/attestation/{id}`, `/api/attestations?schema_id=&issuer=&active_only=`, `/api/schemas`, `/api/slashings?schema_id=&issuer=` — attestation registry JSON API
- `/health` — JSON probe with versions, indexer lag, node reachability
- `/metrics` — Prometheus text format scrape endpoint

## Prometheus scraping

Heimdall exposes its metrics on `/metrics` on the same port as the web app. For a quick local Prometheus setup, add to your `prometheus.yml` :

```yaml
scrape_configs:
  - job_name: heimdall
    static_configs:
      - targets: ['localhost:8800']
    scrape_interval: 15s
    metrics_path: /metrics
```

Metrics currently exposed (will grow in Session 3) :

- **L1 baseline** : `kern_chain_head_level`, `kern_chain_head_age_seconds`, `kern_indexed_transactions_total`, `kern_validators_count`, `kern_originated_contracts_total`, `kern_indexed_transactions_by_kind_total{kind=…}`
- **Attestations (v1.1-rc)** : `kern_attestations_active`, `kern_attestations_total`, `kern_attestations_active_by_schema{schema_id=…}`, `kern_attestations_total_bond_locked_mukrn`, `kern_attestation_slashings_total`, `kern_attestation_slashed_amount_total_mukrn`, `kern_attestation_burned_amount_total_mukrn`, `kern_attestation_whistleblower_rewards_total_mukrn`
- **Verticals classification** : `kern_originated_contracts_by_template{template=…}` covering all v1.1-rc Skald templates
- **STO compliance (v1.1-rc, S2)** : `kern_sto_contracts_count`, `kern_sto_contracts_compliant`, `kern_sto_contracts_trading_paused`, `kern_sto_total_supply_issued_units`
- **Oracle health (v1.1-rc, S2)** : `kern_oracle_feeds_count`, `kern_oracle_feeds_circuit_breaker_tripped`, `kern_oracle_anomalies_total`, `kern_oracle_feeders_total`
- **Public goods (v1.1-rc, S2)** : `kern_pgf_quadratic_funding_projects`, `kern_pgf_quadratic_funding_contributors_total`, `kern_pgf_quadratic_funding_raised_mukrn`, `kern_pgf_retroactive_nominations`
- **ZK claims** : `kern_zk_attestations_total`
- **Heimdall internals** : `heimdall_indexed_blocks_total`

For production you want Grafana dashboards on top of these — and they ship now in Session 3. See `kern_explorer/monitoring/`.

## Production monitoring stack (Session 3)

Heimdall ships with a turn-key monitoring stack: 7 Grafana dashboards, Prometheus alerting rules, AlertManager config, and a docker-compose file to bring it all up locally.

### Quick start — full stack with docker-compose

```bash
cd kern_explorer/monitoring/docker
docker-compose -f docker-compose.monitoring.yml up -d
```

Then open:
- **Grafana** — http://localhost:3000 (admin / admin on first login). Dashboards auto-provision under the `Kern` folder.
- **Prometheus** — http://localhost:9090
- **AlertManager** — http://localhost:9093
- **Heimdall** — http://localhost:8800

The compose file assumes a Kern node accessible at `host.docker.internal:8732`. Replace `KERN_RPC` in the compose file if your node lives elsewhere.

### What ships in `kern_explorer/monitoring/`

```
monitoring/
├── grafana/                                 # 7 dashboards JSON
│   ├── network-health.json                  # L1 head age, validators, tx rate
│   ├── attestations.json                    # Active attestations, slashings, ZK
│   ├── oracles.json                         # Feeds, circuit breakers, anomalies
│   ├── sto-compliance.json                  # compliance pass rate, paused contracts
│   ├── public-goods.json                    # QF momentum, RPGF nominations
│   ├── governance.json                      # Proposals, votes, equivocations
│   └── heimdall-internals.json              # Indexer health, ingest rate
├── alerts/
│   └── kern-alerts.yml                      # Prometheus AlertManager rules
└── docker/
    ├── docker-compose.monitoring.yml        # Full stack for dev / small teams
    ├── prometheus.yml                       # Scrape config + alert file ref
    ├── alertmanager.yml                     # Sample receivers (webhook → stdout)
    ├── grafana-datasources.yml              # Datasource auto-provisioning
    └── grafana-dashboards-provider.yml      # Dashboard auto-provisioning
```

### Alerts shipped

11 alerts across 4 groups, with severity tagging and runbook URLs:

- **L1 baseline** (`l1`): `KernConsensusHaltSuspected` (critical), `KernConsensusSlow` (warning), `KernValidatorCountLow` (warning), `HeimdallIndexerStuck` (warning)
- **Attestation registry** (`attestations`): `KernAttestationSlashingDetected` (warning, fires immediately on any slashing), `KernAttestationActiveBondHigh` (info)
- **Oracle networks** (`oracles`): `KernOracleCircuitBreakerTripped` (critical), `KernOracleAnomalyRateHigh` (warning)
- **STO compliance** (`sto`): `KernStoNonCompliantContract` (critical, regulator-reportable in EU), `KernStoTradingPaused` (warning)

Each critical alert references the [ops runbook](heimdall-ops-runbook.md) for triage and recovery procedures.

### Customizing for your deployment

The shipped configs are deliberately minimal — they cover the Heimdall metrics surface but assume you'll plug in your own receivers (Slack, PagerDuty, OpsGenie). Edit:

- `docker/alertmanager.yml` — replace the webhook receivers with your production endpoints
- `docker/prometheus.yml` — add `external_labels` matching your network (`kern-devnet` / `kern-yggdrasil` / `kern-midgard`); add additional scrape targets for node-exporter, validator-specific exporters, etc.

For Midgard mainnet at scale, also see [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md) — SQLite is fine for devnet/Yggdrasil but Postgres becomes necessary above a certain size and concurrency.

## Tests

The Heimdall suite is in `tests/test_heimdall_*.py` and runs as part of the standard Kern test suite :

```bash
pytest tests/test_heimdall_explorer.py tests/test_heimdall_session2.py tests/test_heimdall_session3.py
```

Currently **159 tests** covering the RPC client, DB helpers, indexer template detection + vertical summary extraction, metrics rendering (L1 baseline + 4 verticals), all web routes against empty and seeded databases, the JSON API, all 7 Grafana dashboards (parse + metric reference consistency), the Prometheus alerting rules (structure + metric refs + runbook anchor consistency), and the docker-compose monitoring stack (services + volume mounts).

## What's NOT yet in this release

Heimdall v0.4 covers Sessions 1+2+3+4 — the full delivery plan is complete. Open contribution areas for v0.5+ are tracked in [contributors-program.md](contributors-program.md) and include :

- Postgres backend implementation (the schema and migration plan are documented in [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md), the code adaptation is the remaining work)
- Per-attestation issuer reputation scoring (cross-schema view of slashing history)
- WebSocket live updates for the home page (today the page is pull-only on refresh)
- A read-only public deployment under the Foundation (post-Yggdrasil launch)
- The next-generation explorer per the RFP — see [`heimdall-rfp-next-gen.md`](heimdall-rfp-next-gen.md)

## Production deployment

The default `heimdall` command starts a single process bound to `127.0.0.1:8800`. That's enough for devnet and local testing. For Yggdrasil testnet (small public network) and Midgard mainnet (production), follow the patterns below.

### Topology choices

There are three production topologies, in order of operational complexity :

**T1 — Single instance (Yggdrasil and small networks)**:
One Heimdall process behind a reverse proxy. Indexer + web app in the same process. SQLite backend. Fine for chains up to ~10 GB of indexed data and traffic up to ~100 req/s.

**T2 — Indexer + read replicas (mid-scale)**:
One Heimdall process with `HEIMDALL_INDEXER=1` writes to a shared file system or shared SQLite (NFS, or migrate to Postgres — see [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md)). N Heimdall processes with `HEIMDALL_INDEXER=0` serve web traffic, all reading the same DB. Reverse proxy load-balances across the read replicas.

**T3 — Postgres + horizontal scale (Midgard mainnet)**:
Migrate the indexer DB to Postgres ([guide](heimdall-postgres-migration.md)). One indexer process, N web replicas — all connect to the Postgres pool via PgBouncer. Add `postgres_exporter` to scrape Postgres metrics alongside Heimdall's.

Start with T1. Move to T2 when one process can't keep up with read traffic. Move to T3 when SQLite hits its concurrency or size limits, or when you need cross-region HA.

### Systemd unit (Linux)

For non-containerized deployments, run Heimdall under systemd. Save as `/etc/systemd/system/heimdall.service` :

```ini
[Unit]
Description=Heimdall — Kern block explorer
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=heimdall
Group=heimdall
WorkingDirectory=/opt/heimdall
Environment="KERN_RPC=http://127.0.0.1:8732"
Environment="HEIMDALL_DB=/var/lib/heimdall/heimdall.sqlite"
Environment="HEIMDALL_HOST=127.0.0.1"
Environment="HEIMDALL_PORT=8800"
Environment="HEIMDALL_INDEXER=1"
ExecStart=/opt/heimdall/.venv/bin/heimdall
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/heimdall
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

Then :
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now heimdall
sudo systemctl status heimdall
sudo journalctl -u heimdall -f
```

For a read-replica unit, copy the file to `heimdall-replica@.service`, set `Environment="HEIMDALL_INDEXER=0"` and `HEIMDALL_PORT=88%i`, then enable instances:

```bash
sudo systemctl enable --now heimdall-replica@01 heimdall-replica@02 heimdall-replica@03
# Replicas now listen on :8801, :8802, :8803
```

### nginx reverse proxy with HTTPS

The recommended pattern is HTTPS termination at nginx, plain HTTP between nginx and Heimdall.

```nginx
upstream heimdall_backend {
    # T1 (single instance)
    server 127.0.0.1:8800;

    # T2 (read replicas) — uncomment, comment the line above
    # server 127.0.0.1:8801;
    # server 127.0.0.1:8802;
    # server 127.0.0.1:8803;
    # least_conn;

    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name explorer.kern.example;

    # Standard Let's Encrypt cert paths
    ssl_certificate     /etc/letsencrypt/live/explorer.kern.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/explorer.kern.example/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy
        "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self';" always;

    # Hide /metrics from the public Internet — expose only on the
    # private monitoring network
    location = /metrics {
        deny all;
        return 403;
    }

    # Optional: gentle rate limit on the API
    limit_req_zone $binary_remote_addr zone=heimdall_api:10m rate=10r/s;
    location /api/ {
        limit_req zone=heimdall_api burst=20 nodelay;
        proxy_pass http://heimdall_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://heimdall_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;

        # Health check timeout
        proxy_connect_timeout 5s;
    }
}

server {
    listen 80;
    server_name explorer.kern.example;
    return 301 https://$server_name$request_uri;
}
```

Separately, expose `/metrics` to your monitoring stack only:

```nginx
# /etc/nginx/conf.d/heimdall-metrics.conf — on a private interface
server {
    listen 10.0.0.1:8801;        # bind to your private monitoring network
    server_name metrics.kern.internal;
    location /metrics {
        proxy_pass http://127.0.0.1:8800/metrics;
        # Optional: HTTP basic auth or IP allowlist
        allow 10.0.0.0/8;
        deny all;
    }
}
```

### Log rotation

If you use systemd's journal (the default in the unit file above), rotation is handled by journald — configure `/etc/systemd/journald.conf` for retention.

If you redirect logs to a file (`StandardOutput=file:/var/log/heimdall.log`), use logrotate:

```
# /etc/logrotate.d/heimdall
/var/log/heimdall.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 heimdall heimdall
    postrotate
        systemctl reload heimdall > /dev/null 2>&1 || true
    endscript
}
```

### Backups

For the SQLite indexer DB, the simplest correct backup is :

```bash
# In a cron:
sqlite3 /var/lib/heimdall/heimdall.sqlite ".backup /backups/heimdall-$(date +\%F).sqlite"
gzip /backups/heimdall-$(date +%F).sqlite
```

SQLite's `.backup` command is online — safe to run while the indexer is writing. Retain at least 7 daily snapshots and 4 weekly ones.

For Postgres backups, see [`heimdall-postgres-migration.md`](heimdall-postgres-migration.md) §"Phase 5 — Production hardening".

### Capacity planning

Rough sizing for a Heimdall single-instance deployment :

| Chain age | Indexed DB size (SQLite) | RAM | Disk SSD |
|---|---|---|---|
| Devnet (days) | < 100 MB | 1 GB | 10 GB |
| Small testnet (months) | 1–5 GB | 2 GB | 50 GB |
| Yggdrasil (year+) | 5–50 GB | 4 GB | 200 GB |
| Midgard (mainnet) | 50 GB+ → migrate to Postgres | per Postgres sizing | per Postgres sizing |

Heimdall itself is light (one Python process, ~150 MB resident); the constraint is the SQLite file size and the index lookup cost.

### Multi-network operation (running explorer for several Kern networks)

If you operate explorers for several Kern networks (devnet + Yggdrasil + Midgard), the recommended pattern is one Heimdall instance per network, each with its own DB and port :

```
/etc/systemd/system/heimdall@devnet.service
/etc/systemd/system/heimdall@yggdrasil.service
/etc/systemd/system/heimdall@midgard.service
```

Each unit sets its own `KERN_RPC`, `HEIMDALL_DB`, `HEIMDALL_PORT`. The `external_labels: network: kern-<name>` in `prometheus.yml` is what lets Grafana dashboards distinguish them.

## Troubleshooting

**Indexer doesn't catch up** :
- Check `/health` — `node_reachable` must be `true` and `indexer_lag_blocks` should decrease over time
- Inspect logs (Heimdall logs to stdout with the `heimdall.indexer` logger)
- If `node_reachable` is false, the indexer will retry with exponential backoff up to 30 s

**SQLite "database is locked"** :
- WAL mode is enabled by default — concurrent reads + 1 writer should not lock
- If you see this error, you likely have two `heimdall` processes running on the same DB file. Run only one indexer per DB; replicas should use `HEIMDALL_INDEXER=0`.

**Empty pages** :
- Confirm the indexer is running (`HEIMDALL_INDEXER=1`, the default)
- Confirm the indexer can reach the node (`KERN_RPC` is correct)
- Wait for the indexer to ingest at least one block (look at `/health` `indexed_head_level`)

**Full-text search on contracts is slow** :
- For chains with > 10k originated contracts, the `LIKE '%query%'` search on `code` becomes slow. Consider enabling SQLite's FTS5 extension (an optional dependency that can be added in a future Heimdall version) or migrating to Postgres where `gin_trgm_ops` indexes handle this efficiently.

**Alerts firing without obvious cause** :
- See [`heimdall-ops-runbook.md`](heimdall-ops-runbook.md) for per-alert triage steps.

## Related guides

- [`setup-developer.md`](setup-developer.md) — for building / running the Kern node itself
- [`setup-validator.md`](setup-validator.md) — for running a baker
- [`setup-explorer-ops.md`](setup-explorer-ops.md) — the broader "I'm operating chain-data infrastructure" guide (Heimdall is one of several products fitting this profile)

---

*Heimdall is part of the Kern reference implementation, published under Apache-2.0. Originality and attribution policy in [`originality-and-attribution.md`](originality-and-attribution.md). The whitepaper §13 (technical entry points) lists every role-specific guide.*

*Founder: Nicolas Van Eeckhout. License: Apache-2.0.*
