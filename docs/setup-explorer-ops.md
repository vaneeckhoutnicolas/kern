# Setup Guide — Public Infrastructure Operator

**Audience**: Anyone building publicly-accessible Kern infrastructure — block explorer, public RPC node, faucet, indexer, wallet backend.

**Maintainer**: Nicolas Van Eeckhout (founder).

> **Note**: Kern ships with **Heimdall**, an official block explorer + monitoring stack (FastAPI + SQLite indexer + Prometheus metrics + 13 HTML pages including dedicated views for the v1.1-rc verticals: attestations, STO compliance, oracle health, public goods funding). If you want to run the canonical Kern explorer rather than build your own, see [`setup-heimdall-operator.md`](setup-heimdall-operator.md). This present guide covers the broader case: any public infrastructure (custom explorer, faucet, archive node, public RPC, wallet backend, etc.) and includes the read-only node setup that Heimdall requires.

**Prerequisites**:
- A reliable Kern node (see [setup-validator.md](setup-validator.md) Steps 1-8, sans the validator key — you only need a read-only node)
- Linux server, 8 GB RAM, 100 GB+ SSD
- A domain name with DNS control
- HTTPS certificate management (Let's Encrypt / Caddy)
- Familiarity with reverse proxies, rate limiting, web hosting

**What this guide covers**: Set up a non-validating Kern node, expose its RPC publicly behind a reverse proxy with HTTPS and rate limiting. Then point your indexer or explorer at it.

**Estimated time**: 2-3 hours for the read-only node + public RPC; building a block explorer or faucet on top is additional work.

**Cost**: ~$30-100/month VPS, plus storage cost growth (~100 MB chain DB growth per month).

---

## Step 1 — Provision the host

Same as [setup-validator.md](setup-validator.md) Steps 1-2. Use a dedicated user, harden SSH, set up firewall:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 9732/tcp comment 'Kern P2P'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 80/tcp comment 'HTTP (cert renewal only)'
# Note: 8732 stays internal (only the reverse proxy on the same machine reads it)
sudo ufw enable
```

---

## Step 2 — Install Kern in read-only mode

```bash
sudo useradd --create-home --shell /bin/bash kern
sudo -iu kern

git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern
git checkout v1.0.0rc1

python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .

# Download canonical genesis for the target network
curl -sL https://docs.kern.protocol/networks/yggdrasil/genesis.json -o ~/.kern/genesis.json
mkdir -p /var/lib/kern/data
python -m kern.node init --genesis ~/.kern/genesis.json --data-dir /var/lib/kern/data
```

---

## Step 3 — Run the node WITHOUT a baker key

This is the difference from a validator: no `--baker-key`. The node syncs and serves RPC, doesn't propose blocks.

Test manually first:

```bash
python -m kern.node start \
    --data-dir /var/lib/kern/data \
    --rpc-port 8732 --rpc-bind 127.0.0.1 \
    --p2p-port 9732 --p2p-bind 0.0.0.0
```

**Verification**:

```bash
curl -s http://127.0.0.1:8732/chain/health | jq
# Expected: {"ok": true, "level": <N>, ...}

# Confirm we're synced to current network head
curl -s http://127.0.0.1:8732/chain/head | jq '.level'
# Compare against another node's head
```

Stop with Ctrl+C, then deploy as systemd (same template as validator, just remove the `--baker-key` line):

```bash
sudo tee /etc/systemd/system/kern-rpc.service <<'EOF'
[Unit]
Description=Kern Public RPC Node (read-only)
After=network-online.target

[Service]
Type=simple
User=kern
Group=kern
WorkingDirectory=/home/kern/kern
ExecStart=/home/kern/kern/.venv/bin/python -m kern.node start \
    --data-dir /var/lib/kern/data \
    --rpc-port 8732 --rpc-bind 127.0.0.1 \
    --p2p-port 9732 --p2p-bind 0.0.0.0
Restart=always
RestartSec=10
MemoryMax=8G
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kern-rpc
sudo systemctl start kern-rpc
```

---

## Step 4 — Set up a reverse proxy with rate limiting

The Kern RPC has no built-in auth or rate limiting. **Never expose port 8732 directly to the internet.** Instead, front it with Caddy (or Nginx) for HTTPS termination, rate limits, and request logging.

Caddy is simpler — install:

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

Configure:

```bash
sudo tee /etc/caddy/Caddyfile <<'EOF'
rpc.yourdomain.com {
    # Automatic HTTPS via Let's Encrypt
    encode gzip

    # Rate limit: 30 req/sec per IP
    @per_ip {
        not remote_ip 127.0.0.1
    }
    rate_limit @per_ip {
        zone rpc_zone {
            key {client_ip}
            events 30
            window 1s
        }
    }

    # Whitelist read-only endpoints
    @readonly {
        method GET
        path /chain/head /chain/block/* /chain/balance/* /chain/nonce/* \
             /chain/contract/* /chain/mempool /chain/validators \
             /chain/health /chain/governance /metrics
    }
    handle @readonly {
        reverse_proxy 127.0.0.1:8732
    }

    # Allow transaction injection but with extra rate limiting
    @inject {
        method POST
        path /chain/inject_transaction
    }
    handle @inject {
        rate_limit @per_ip {
            zone inject_zone {
                key {client_ip}
                events 5
                window 1s
            }
        }
        reverse_proxy 127.0.0.1:8732
    }

    # Block anything else
    respond 404
}
EOF

sudo systemctl reload caddy
```

Note: the `rate_limit` directive requires the Caddy rate-limit plugin (`xcaddy build --with github.com/mholt/caddy-ratelimit`) or you can use `caddy-l4`. If that's too complex, start with `cloudflare` in front for free rate limiting and DDoS protection.

**Verification**:

```bash
# From an external client
curl https://rpc.yourdomain.com/chain/head
# Expected: same JSON as the local query
```

---

## Step 5 — Set up monitoring

Same Prometheus scrape as the validator:

```yaml
scrape_configs:
  - job_name: kern-rpc
    static_configs:
      - targets: ['127.0.0.1:8732']
    metrics_path: /metrics
```

Plus public-facing alerts:
- HTTP 5xx rate on the reverse proxy
- Sustained request rate near the rate limit ceiling (capacity planning signal)
- Disk usage approaching 80% of available

---

## Step 6 — Build a block explorer (optional, advanced)

A block explorer indexes the chain so users can browse blocks, transactions, contracts, and accounts. Three options:

### Option A — Fork Blockscout

Blockscout is an open-source Ethereum explorer. Forking and adapting for Kern requires:

1. Implementing a Kern-flavored "ETH RPC" shim that translates Blockscout's expected RPC calls to Kern's
2. Adapting the address format (Kern uses `kn1...` not `0x...`)
3. Adapting transaction kinds (Kern has 8 OpKinds; Blockscout assumes Ethereum)
4. Replacing Solidity decompilation with Skald rendering

Realistic estimate: 6-12 weeks of engineering for an MVP.

### Option B — Build minimal from scratch

A minimal explorer can be built in 2-4 weeks:

- Backend: poll the Kern RPC every block, store in PostgreSQL, expose REST API
- Frontend: simple React app (or just server-rendered HTML)
- Pages: home (last 10 blocks), block detail, tx detail, address detail (balance + recent txs), contract detail (storage view)

This is a great Foundation-grant target. See [contributors-program.md](contributors-program.md) for funding via the Foundation pool.

### Option C — Use an indexer service

When SaaS indexers add Kern support (TBD), they'll provide a hosted explorer for free or low cost.

---

## Step 7 — Build a faucet (Yggdrasil testnet only)

A faucet dispenses KRN-test to anyone who requests it, throttled to prevent abuse.

Minimal faucet:

```python
# faucet.py — minimalist Kern testnet faucet
from aiohttp import web
import json, urllib.request
from kern.crypto import KernKeypair
from kern.transaction import make_transfer

KEYPAIR = KernKeypair.from_seed(bytes.fromhex(open('/path/to/faucet-key.json').read()))
RPC = "http://127.0.0.1:8732"
DRIP_AMOUNT = 1000_000_000  # 1000 KRN per request
RATE_LIMIT = {}  # address -> last-request timestamp

async def request_handler(req):
    body = await req.json()
    target = body.get("address")
    amount = min(body.get("amount", 1000) * 1_000_000, DRIP_AMOUNT)

    if not target.startswith("kn1"):
        return web.json_response({"error": "invalid address"}, status=400)

    import time
    now = time.time()
    if RATE_LIMIT.get(target, 0) + 86400 > now:
        return web.json_response({"error": "wait 24h between requests"}, status=429)

    nonce = json.loads(urllib.request.urlopen(f"{RPC}/chain/nonce/{KEYPAIR.address}").read())["nonce"]
    tx = make_transfer(KEYPAIR, target, amount, nonce=nonce, fee=2000)
    inject = json.dumps(tx.to_dict()).encode()
    urllib.request.urlopen(urllib.request.Request(
        f"{RPC}/chain/inject_transaction", data=inject,
        headers={"Content-Type": "application/json"},
    ))

    RATE_LIMIT[target] = now
    return web.json_response({"ok": True, "amount_mukrn": amount})

app = web.Application()
app.router.add_post('/request', request_handler)
web.run_app(app, host="127.0.0.1", port=5000)
```

Run behind Caddy at `faucet.yggdrasil.kern.protocol`. Fund the faucet keypair with a chunk of testnet KRN at network setup.

For production: persist rate-limiting state (this in-memory dict is lost on restart). Use Redis or PostgreSQL.

---

## Step 8 — Operational hygiene

- **Backup the chain DB** weekly (or daily for high-traffic operators)
- **Monitor disk usage** — Kern chain DB grows ~100 MB/month at moderate use
- **Watch the upstream Kern release notes** — upgrade when v1.x.y patches drop
- **Coordinate with other public infra operators** in community channels for outage response
- **Subscribe to security disclosures** from the Foundation; apply patches within 48 hours

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| RPC returns 502 errors | Backend (Kern node) down | `sudo systemctl status kern-rpc`; restart if needed |
| Rate limit triggers normal users | Threshold too low | Raise the limit, or proxy through Cloudflare for better IP fingerprinting |
| Chain DB grows fast | Lots of contract storage; mempool buildup | Provision more disk; consider pruning old blocks (off-chain archival) |
| Faucet drains too fast | RATE_LIMIT logic too lenient | Tighten to per-IP + per-address combined |
| Public RPC blocked by region | Free hosting providers banning crypto-related traffic | Pay for a real VPS; Hetzner / OVH / DO all work |

---

## Funding

Operating public infrastructure has real costs. Three ways to recoup:

1. **Foundation grant**: file a [contributors-program.md](contributors-program.md) proposal for ongoing operating cost reimbursement.
2. **Treasury proposal**: once your infra is established, propose a treasury allocation for sustained operations.
3. **Premium tier**: offer an enhanced RPC with higher rate limits, longer history retention, or specialized indexing — paid by users.

---

## Next steps

- [setup-validator.md](setup-validator.md) — if you want to add baking
- [api.md](api.md) — full RPC reference
- [contributors-program.md](contributors-program.md) — funding via the Foundation or treasury
- [api-stability.md](api-stability.md) — what RPC surfaces are stable
