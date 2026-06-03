# Setup Guide — Validator (Baker)

**Audience**: Operators who want to run a Kern validator node on Yggdrasil testnet or Midgard mainnet, propose blocks, earn rewards, and accept delegations.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- A Linux server (Ubuntu 22.04+ or equivalent) — VPS or dedicated hardware
- 4 CPU cores, 8 GB RAM, 100 GB SSD minimum (16 GB RAM + NVMe recommended for Midgard)
- A static public IPv4 address, or IPv6
- Ports 9732 (P2P) and 8732 (RPC) controllable in your firewall
- 10 000 KRN minimum as own stake (Midgard) or KRN-test from faucet (Yggdrasil)
- Python 3.11+, git, systemd or equivalent process supervisor
- Familiarity with Linux system administration

**What this guide covers**: Provision a server, install Kern, generate validator keys, register as a validator on-chain, start the baking process, enable monitoring, run as a systemd service for production reliability.

**Estimated time**: 2-4 hours for initial setup; the running node is mostly hands-off.

**Cost**: server (~$20-100/month VPS depending on tier), 10 000 KRN stake (Midgard).

---

## Step 1 — Provision the server

This guide assumes Ubuntu 22.04 LTS. Adapt accordingly for other distributions.

```bash
# Update + base tooling
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3.11-venv python3-pip git \
                    build-essential libsodium-dev curl jq \
                    fail2ban ufw

# Disable password SSH (key-based only)
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Firewall
sudo ufw allow OpenSSH
sudo ufw allow 9732/tcp comment 'Kern P2P'
# RPC port 8732 should NOT be public on a production validator;
# bind it to 127.0.0.1 only and tunnel for ops.
sudo ufw enable
```

**Verification**:

```bash
sudo ufw status
python3.11 --version
# Expected: Python 3.11.x
```

---

## Step 2 — Create a dedicated system user

Never run Kern as root. Dedicate a `kern` user:

```bash
sudo useradd --create-home --shell /bin/bash --comment "Kern baker" kern
sudo mkdir -p /var/lib/kern
sudo chown -R kern:kern /var/lib/kern
```

Switch to the kern user for the rest of the setup:

```bash
sudo -iu kern
```

---

## Step 3 — Clone the repo and install Kern

```bash
# As the kern user
cd ~
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern

# Check out the specific tag for the network you're joining
# Yggdrasil testnet:
# git checkout v1.0.0rc1
# Midgard mainnet (after v1.0 release):
# git checkout v1.0.0

python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

**Verification**:

```bash
source ~/.bashrc; source ~/kern/.venv/bin/activate
python -c "import kern; print(kern.__file__)"
# Expected: /home/kern/kern/kern/__init__.py
```

---

## Step 4 — Generate validator keypair

**Critical**: this key is your validator identity. If it's compromised, your validator can be slashed by an attacker. Treat it with extreme care.

```bash
cd ~/kern
mkdir -p ~/.kern/keys
chmod 700 ~/.kern/keys

python scripts/generate_keys.py --out ~/.kern/keys/baker.json
chmod 600 ~/.kern/keys/baker.json
```

This produces a JSON file containing your address, public key, and seed. **Back this up immediately** to a secure location not on the server (encrypted USB, password manager, hardware security module).

**Verification**:

```bash
ls -la ~/.kern/keys/baker.json
# Expected: -rw------- (0600 permissions)

jq '.address' ~/.kern/keys/baker.json
# Expected: "kn1..." (your validator address)
```

**Save your address**:

```bash
export BAKER_ADDRESS=$(jq -r '.address' ~/.kern/keys/baker.json)
echo $BAKER_ADDRESS
```

---

## Step 5 — Fund the validator address

Your validator address needs at least **10 000 KRN** to register as a validator on Midgard. On Yggdrasil testnet, use the faucet:

```bash
curl -X POST https://faucet.yggdrasil.kern.protocol/request \
     -H "Content-Type: application/json" \
     -d "{\"address\": \"$BAKER_ADDRESS\", \"amount\": 20000}"
```

(Faucet URL is a placeholder — actual endpoint published at testnet launch.)

On Midgard mainnet, you'll need to acquire KRN from an exchange or the public sale, then transfer to your validator address from a separate keypair.

**Verification**:

```bash
curl -s http://localhost:8732/chain/balance/$BAKER_ADDRESS
# Expected after node is up: {"balance": 20000000000} (= 20 000 KRN in mukrn)
```

---

## Step 6 — Initialize the node from genesis

Download the canonical `genesis.json` for the network you're joining:

```bash
# For Yggdrasil testnet:
curl -sL https://docs.kern.protocol/networks/yggdrasil/genesis.json -o ~/.kern/genesis.json

# For Midgard mainnet (after launch):
curl -sL https://docs.kern.protocol/networks/midgard/genesis.json -o ~/.kern/genesis.json

# Verify checksum (published at network launch):
sha256sum ~/.kern/genesis.json
# Expected: matches the published checksum
```

Initialize the data directory:

```bash
python -m kern.node init \
    --genesis ~/.kern/genesis.json \
    --data-dir /var/lib/kern/data
```

**Verification**:

```bash
ls /var/lib/kern/data/
# Expected: chain.db (SQLite), genesis_state.json
```

---

## Step 7 — Configure peers

Edit `/var/lib/kern/data/peers.json` (or pass via CLI) to list bootstrap peers:

```bash
cat > /var/lib/kern/data/peers.json <<'JSON'
{
  "bootstrap_peers": [
    "node1.yggdrasil.kern.protocol:9732",
    "node2.yggdrasil.kern.protocol:9732",
    "node3.yggdrasil.kern.protocol:9732"
  ]
}
JSON
```

(Peer hostnames are placeholders — published at network launch.)

---

## Step 8 — Start the node manually first (verify before systemd)

```bash
cd ~/kern
source .venv/bin/activate

python -m kern.node start \
    --data-dir /var/lib/kern/data \
    --rpc-port 8732 --rpc-bind 127.0.0.1 \
    --p2p-port 9732 --p2p-bind 0.0.0.0 \
    --baker-key ~/.kern/keys/baker.json \
    --block-time 1.0
```

**Verification** (in a second terminal):

```bash
# Check the node is alive
curl -s http://127.0.0.1:8732/chain/health
# Expected: {"ok": true, "level": <N>, "peers": <K>, "mempool": <M>}

# Watch the head advance
watch -n 2 'curl -s http://127.0.0.1:8732/chain/head | jq ".level"'
# Expected: level increases steadily
```

If level doesn't advance:
- No peers? Check firewall, peer list.
- Peers connect but no blocks? Check that the time on your server is correct (`timedatectl status`); BFT consensus is sensitive to clock drift > 10 seconds.

Stop the foreground process with Ctrl+C once you've confirmed it works.

---

## Step 9 — Register as a validator on-chain

Once your node is fully synced and you have ≥ 10 000 KRN, submit a validator registration. The current reference implementation registers validators in the genesis file rather than via transaction — for v1.0, a `REGISTER_VALIDATOR` operation type will be added. Until then, your validator must be included in the network's canonical `genesis.json` for Yggdrasil/Midgard.

To request inclusion as a validator on Yggdrasil:

1. Open a pull request at `github.com/vaneeckhoutnicolas/kern` adding your validator entry to `networks/yggdrasil/validators.json`.
2. Include: your address, public key, declared stake amount, declared commission rate, contact info (Twitter handle or email for slashing-monitoring outreach).
3. Wait for Foundation approval (typically 1-2 weeks).

For Midgard mainnet, the validator onboarding will be more formal — managed by the Foundation per [setup-foundation.md](setup-foundation.md). See [contributors-program.md](contributors-program.md) for the validator bootstrap pool (2M KRN).

---

## Step 10 — Set your commission rate

The default validator commission is 10% (deducted from delegator rewards). To set a custom rate:

For now (v1.0-rc), commission is set in your validator's genesis entry. A future `SET_COMMISSION` transaction will allow on-chain updates. When that's available, the flow will be:

```bash
# Build and inject a SET_COMMISSION tx
python -c "
from kern.crypto import KernKeypair
from kern.transaction import make_set_commission   # available in v1.x
import json
kp = KernKeypair.from_seed(bytes.fromhex(open('/home/kern/.kern/keys/baker.json').read()))
tx = make_set_commission(sender_kp=kp, new_rate_pct=8, nonce=N)
# inject via RPC ...
"
```

---

## Step 11 — Run as a systemd service (production)

Once you've confirmed the manual run works, set up systemd for reliability:

```bash
sudo tee /etc/systemd/system/kern.service <<'EOF'
[Unit]
Description=Kern Blockchain Validator Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kern
Group=kern
WorkingDirectory=/home/kern/kern
Environment="PYTHONUNBUFFERED=1"
ExecStart=/home/kern/kern/.venv/bin/python -m kern.node start \
    --data-dir /var/lib/kern/data \
    --rpc-port 8732 --rpc-bind 127.0.0.1 \
    --p2p-port 9732 --p2p-bind 0.0.0.0 \
    --baker-key /home/kern/.kern/keys/baker.json \
    --block-time 1.0
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kern

# Resource limits (adjust for your hardware)
LimitNOFILE=65536
MemoryMax=8G

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/kern /home/kern/.kern

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kern
sudo systemctl start kern
```

**Verification**:

```bash
sudo systemctl status kern
# Expected: active (running)

sudo journalctl -u kern -f
# Watch live logs

curl -s http://127.0.0.1:8732/chain/head | jq ".level"
# Expected: number that increases over time
```

---

## Step 12 — Set up monitoring

The Kern node exposes Prometheus metrics at `/metrics`. Configure your monitoring stack to scrape it:

```yaml
# In your prometheus.yml
scrape_configs:
  - job_name: kern-validator
    static_configs:
      - targets: ['localhost:8732']
    metrics_path: /metrics
    scrape_interval: 15s
```

Key metrics to alert on:

| Metric | Alert when |
|---|---|
| `kern_chain_height` | Not increasing for > 60s |
| `kern_peers_connected` | < 3 peers for > 60s |
| `kern_blocks_produced_total{baker="<your-address>"}` | Suspiciously low vs expected rate |
| `kern_governance_equivocations_total` | Any increase (you're being slashed!) |
| `kern_block_apply_seconds` | p99 > 500ms |

A Grafana dashboard template will be published at `docs.kern.protocol/dashboards/validator.json` when available.

---

## Step 13 — Operational hygiene

**Weekly checks** (10 min):

```bash
# Confirm node is healthy
sudo systemctl status kern
curl -s http://127.0.0.1:8732/chain/health | jq

# Confirm balance unchanged or growing (rewards)
curl -s http://127.0.0.1:8732/chain/balance/$BAKER_ADDRESS | jq

# Check disk space (chain DB grows ~100 MB/month)
df -h /var/lib/kern

# Verify no equivocation incidents (a single one will slash you)
curl -s http://127.0.0.1:8732/metrics | grep kern_governance_equivocations
```

**Monthly checks** (30 min):

- Review the change log of any upgrade tags posted by the Foundation.
- Test your key backup by restoring to a clean machine in a dry-run.
- Rotate any SSH keys.
- Apply OS security patches: `sudo apt update && sudo apt upgrade`.

**Never run two Kern nodes with the same baker key simultaneously.** That causes double-signing → automatic slashing for 30% of your stake (and your delegators' balances).

---

## Step 14 — Upgrade procedure

When a new tagged release is announced:

```bash
sudo systemctl stop kern
cd ~/kern
git fetch origin
git checkout v1.x.y      # the new tag
.venv/bin/pip install -e .
sudo systemctl start kern

# Verify
sudo journalctl -u kern -n 50
curl -s http://127.0.0.1:8732/chain/head | jq
```

If the upgrade includes a database schema migration, the node will run it automatically at startup (see [api-stability.md](api-stability.md) §3.4).

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| `Address already in use` (port 9732) | Another process on that port | `sudo lsof -i :9732` → kill the conflicting process |
| No blocks produced after 30 minutes | Not in validator set | Confirm your address is in `chain/validators` |
| `Cannot connect to peer` errors only | Network ports closed | `ufw allow 9732/tcp` |
| Out of memory | Chain too large or insufficient RAM | Increase to 16 GB+, set `MemoryMax=16G` in systemd unit |
| Clock drift causes consensus issues | Server time wrong | `sudo apt install chrony` and ensure ntp sync |
| Slashed for double-signing | Two nodes using same key | NEVER do this; immediately stop the duplicate; check uptime monitoring |
| RPC accessible from public internet | Wrong bind address | Make sure `--rpc-bind 127.0.0.1` and the firewall blocks 8732 inbound |

---

## Slashing — what you risk

A single double-baking, double-endorsing, or governance equivocation event costs:

- **30% of your own stake** burned
- **30% of every delegator's delegated balance** burned (they will leave you, fast)
- **10% of your slashed amount** paid to the whistleblower

For a 10 000 KRN self-stake with 100 000 KRN of delegations, a single equivocation costs you 3 000 KRN out of your stake plus 30 000 KRN of delegator balances slashed (delegators move away). This is irreversible. Take operational hygiene seriously.

The most common causes of accidental slashing:
1. Two nodes running the same key (avoid: never run a "hot spare"; only one active node per key)
2. Restoring from backup while another node is running (avoid: confirm the original is stopped before starting any restore)
3. Container orchestration restarting the node faster than it can clean state (avoid: don't use orchestrators with aggressive restart policies for baker keys)

---

## Next steps

- [staking.md](staking.md) — detailed staking and reward mechanics
- [governance.md](governance.md) — how to participate in protocol votes as a validator
- [api-stability.md](api-stability.md) — what API surfaces you can rely on
- [setup-delegator.md](setup-delegator.md) — for understanding how your delegators see you
- [setup-heimdall-operator.md](setup-heimdall-operator.md) — run **Heimdall** (the official explorer + monitoring stack) against your validator node. The `kern_attestation_slashings_total` and `kern_chain_head_age_seconds` metrics it exports are what you should alert on; the `/validators` page shows you exactly what delegators see.
- Community channels (TBD) — for operational coordination with other validators
