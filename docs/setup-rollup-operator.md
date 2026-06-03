# Setup Guide — Rollup Operator (Sequencer)

**Audience**: Operators running an optimistic EVM rollup sequencer on top of Kern. You batch L2 transactions, post commitments to L1, and may face fraud-proof challenges.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- A working Kern node (see [setup-validator.md](setup-validator.md), or use a public RPC)
- Linux server, 16 GB RAM, 200 GB SSD minimum
- Bond capital: 100 000 KRN minimum (sequencer bond, slashable if fraud is proven)
- Familiarity with EVM, optimistic rollups, fraud-proof mechanics
- Reading: [rollups.md](rollups.md), [evm-fraud-proofs.md](evm-fraud-proofs.md), [forced-inclusion.md](forced-inclusion.md), [multi-frame-evm.md](multi-frame-evm.md)

**What this guide covers**: Set up the sequencer process, originate the rollup contract on L1, manage the batch posting cycle, handle challenges, respond to fraud proofs.

**Estimated time**: 4-8 hours for initial setup; the running sequencer is mostly automated.

**Cost**: ~$50-200/month server, 100 000 KRN bond posted on L1 (locked while sequencer is active).

---

## Step 1 — Understand the architecture

A rollup on Kern has three roles:

1. **Sequencer** (this guide): aggregates L2 transactions, executes them against the L2 state, commits batch results to L1.
2. **Challenger**: monitors sequencer commitments; if a commitment is wrong, submits a fraud proof.
3. **L1 settler** (a Skald contract): holds the rollup state root, the sequencer bond, and the challenge protocol.

The sequencer is the operator-side role. Anyone can be a challenger (and earn part of the slashed bond when a fraud is proven).

See [rollups.md](rollups.md) for the protocol-level architecture.

---

## Step 2 — Provision the sequencer host

```bash
sudo apt update && sudo apt install -y python3.11 python3.11-venv git \
    build-essential libsodium-dev curl jq

sudo useradd --create-home --shell /bin/bash rollup
sudo mkdir -p /var/lib/rollup
sudo chown -R rollup:rollup /var/lib/rollup
sudo -iu rollup
```

The sequencer reads from Kern L1 (to track inbox transactions and forced-inclusion mailbox), executes them on its local EVM, and writes back commitments. It is a busy machine.

---

## Step 3 — Install Kern (sequencer uses the same codebase)

```bash
cd ~
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern
git checkout v1.0.0rc1     # or the production tag

python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Verification**:

```bash
python -c "from kern.rollup import Rollup, Batch, FraudProof; print('Rollup module loaded')"
# Expected: Rollup module loaded
```

---

## Step 4 — Generate the sequencer keypair

This key signs batch commitments and challenge responses. **Critical to secure**.

```bash
mkdir -p ~/.rollup/keys
chmod 700 ~/.rollup/keys
python scripts/generate_keys.py --out ~/.rollup/keys/sequencer.json
chmod 600 ~/.rollup/keys/sequencer.json
```

Back up the seed offline immediately.

```bash
export SEQ_ADDRESS=$(jq -r '.address' ~/.rollup/keys/sequencer.json)
echo "Sequencer address: $SEQ_ADDRESS"
```

---

## Step 5 — Fund the sequencer address with bond

Your sequencer address needs at least **100 000 KRN** to be locked as the sequencer bond. This bond is what gets slashed if a fraud proof succeeds against your commitments.

```bash
# On Yggdrasil testnet:
curl -X POST https://faucet.yggdrasil.kern.protocol/request \
    -H "Content-Type: application/json" \
    -d "{\"address\": \"$SEQ_ADDRESS\", \"amount\": 110000}"
# (100k bond + 10k operational)

# Confirm balance:
curl -s $KERN_RPC/chain/balance/$SEQ_ADDRESS | jq
```

On Midgard, acquire from an exchange or a separate Kern address you control.

---

## Step 6 — Originate the rollup L1 contract

The rollup contract is a Skald contract that holds the state root, the bond, the inbox queue, and the challenge protocol.

The reference template lives in `kern/rollup.py` as `BRIDGE_SKALD`. Originate it:

```bash
python <<PYEOF
import json, os, urllib.request
from kern.crypto import KernKeypair
from kern.rollup import BRIDGE_SKALD
from kern.transaction import make_origination

with open(os.environ["HOME"] + "/.rollup/keys/sequencer.json") as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

# Initial rollup state
initial_storage = {
    "sequencer":     kp.address,
    "bond":          0,                    # will be deposited next
    "state_root":    "0" * 64,             # empty L2 state
    "last_commit":   0,                    # L1 block of last commitment
    "challenge_window_blocks": 1000,       # ~17 min at 1s blocks
    "inbox_queue":   [],
    "frozen":        False,
}

rpc = os.environ["KERN_RPC"]
nonce = json.loads(urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}").read())["nonce"]

tx = make_origination(
    sender_kp=kp, code=BRIDGE_SKALD,
    initial_storage=initial_storage, amount=0, nonce=nonce,
    fee=20_000, gas_limit=500_000,
)
body = json.dumps(tx.to_dict()).encode()
resp = urllib.request.urlopen(urllib.request.Request(
    f"{rpc}/chain/inject_transaction", data=body,
    headers={"Content-Type": "application/json"},
))
print(f"Rollup contract origination tx: {json.loads(resp.read())['hash']}")
PYEOF
```

After ~3 seconds, the rollup contract is on L1. Find its address from the block where the tx was included, then export it:

```bash
export ROLLUP_ADDR="kn1<your-rollup-contract-address>"
```

---

## Step 7 — Deposit the sequencer bond

Call the rollup contract's `deposit_bond` entry with the 100 000 KRN:

```bash
python <<PYEOF
import json, os, urllib.request
from kern.crypto import KernKeypair
from kern.transaction import make_call

with open(os.environ["HOME"] + "/.rollup/keys/sequencer.json") as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

rpc = os.environ["KERN_RPC"]
nonce = json.loads(urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}").read())["nonce"]

# Deposit 100 000 KRN = 100_000_000_000 mukrn as bond
tx = make_call(
    sender_kp=kp,
    contract=os.environ["ROLLUP_ADDR"],
    entry="deposit_bond",
    params={},
    amount=100_000_000_000,
    nonce=nonce,
    fee=10_000, gas_limit=100_000,
)
body = json.dumps(tx.to_dict()).encode()
resp = urllib.request.urlopen(urllib.request.Request(
    f"{rpc}/chain/inject_transaction", data=body,
    headers={"Content-Type": "application/json"},
))
print(f"Bond deposit tx: {json.loads(resp.read())['hash']}")
PYEOF
```

**Verification**:

```bash
curl -s $KERN_RPC/chain/contract/$ROLLUP_ADDR | jq '.storage.bond'
# Expected: 100000000000
```

---

## Step 8 — Configure the sequencer runtime

The sequencer process needs to:

1. Subscribe to L1 inbox events (forced-inclusion mailbox + direct deposits)
2. Maintain the L2 EVM state
3. Execute incoming transactions against L2 state
4. Periodically commit a new L2 state root to L1
5. Listen for challenge submissions and respond with fraud-proof bisection

Create the config file:

```bash
mkdir -p ~/.rollup/config
cat > ~/.rollup/config/sequencer.toml <<EOF
[l1]
rpc = "${KERN_RPC}"
rollup_contract = "${ROLLUP_ADDR}"
sequencer_key = "${HOME}/.rollup/keys/sequencer.json"

[l2]
chain_id = "kern-rollup-1"
data_dir = "/var/lib/rollup/data"

[batching]
# Commit a new batch every N L1 blocks (~1 minute at 1s block time)
commit_interval_blocks = 60
# Maximum txs per batch
max_txs_per_batch = 1000

[fraud_proofs]
# Time window for challengers to dispute (seconds)
challenge_window_seconds = 1020   # ~17 minutes
EOF
```

---

## Step 9 — Start the sequencer process

The v1.0-rc reference implementation includes the sequencer logic in `kern/rollup.py` but does not yet ship a standalone sequencer daemon. For now, write a small driver:

```bash
cat > ~/.rollup/run_sequencer.py <<'PYEOF'
#!/usr/bin/env python3
"""Minimal sequencer driver for Kern rollups.

Subscribes to the L1 inbox, batches L2 transactions, commits to L1
every N blocks. Production sequencer requires more robust error handling
and persistence — this is the skeleton.
"""
import json, os, time, urllib.request
from kern.crypto import KernKeypair
from kern.rollup import Rollup, Batch, RollupState
from kern.transaction import make_call

# Load config
config_path = os.path.expanduser("~/.rollup/config/sequencer.toml")
# Minimal TOML parsing (use tomllib in Python 3.11+):
import tomllib
with open(config_path, "rb") as f:
    config = tomllib.load(f)

# Load keypair
with open(os.path.expanduser(config["l1"]["sequencer_key"])) as f:
    keydata = json.load(f)
seq_kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

rpc = config["l1"]["rpc"]
rollup_addr = config["l1"]["rollup_contract"]

print(f"Sequencer starting. Address: {seq_kp.address}, Rollup contract: {rollup_addr}")

state = RollupState(initial_root=b"\x00" * 32)
last_commit_level = 0

while True:
    # Poll L1 for new blocks
    head = json.loads(urllib.request.urlopen(f"{rpc}/chain/head").read())
    current_level = head["level"]

    # Drain inbox for new L2 transactions (forced-inclusion mailbox queue)
    # ... (load from /chain/contract/<rollup_addr>, parse inbox_queue field) ...

    # Process pending L2 txs
    # ... (apply each to the local EVM, update L2 state root) ...

    # If commit interval elapsed, post a new batch commitment
    interval = config["batching"]["commit_interval_blocks"]
    if current_level - last_commit_level >= interval:
        # Build a Batch and post the new state root via a CALL to the rollup contract
        # ... (implementation per kern.rollup.Rollup.post_batch) ...
        last_commit_level = current_level
        print(f"L{current_level}: posted batch commitment")

    time.sleep(5)
PYEOF
chmod +x ~/.rollup/run_sequencer.py
```

This is a skeleton — the production implementation is part of the v1.x roadmap. For now, the v1.0-rc reference allows hand-driven testing of the rollup contract's batch acceptance and challenge-handling logic.

---

## Step 10 — Set up systemd for production

```bash
sudo tee /etc/systemd/system/rollup-sequencer.service <<'EOF'
[Unit]
Description=Kern Rollup Sequencer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rollup
Group=rollup
WorkingDirectory=/home/rollup
ExecStart=/home/rollup/kern/.venv/bin/python /home/rollup/.rollup/run_sequencer.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rollup-sequencer

MemoryMax=16G
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable rollup-sequencer
sudo systemctl start rollup-sequencer
sudo journalctl -u rollup-sequencer -f
```

---

## Step 11 — Handle a fraud-proof challenge

If a challenger submits a fraud proof against one of your commitments, you must respond within the challenge window or your bond is slashed.

The bisection protocol works like this:

1. Challenger asserts: "your commitment at step N is wrong"
2. Sequencer responds with the intermediate commitments at steps N/2 and 3N/4
3. Process bisects until they identify ONE specific EVM instruction where they disagree
4. The L1 contract re-executes that single instruction and decides the winner

Each round of bisection requires a transaction. The full protocol is in [evm-fraud-proofs.md](evm-fraud-proofs.md).

To respond automatically, your sequencer must:

- Watch the rollup contract for `ChallengeOpened` events
- Compute the bisection step responses from its own execution trace
- Sign and post the responses via `make_call` to the rollup contract

The reference Python implementation has the `run_full_bisection` helper that drives this in batch test mode; production wiring of this into a live daemon is v1.x roadmap.

**If you cannot respond before the challenge window closes**: your bond is slashed by the rollup contract's protocol. The slashed amount typically goes:
- 50% to the successful challenger (their reward for finding the fraud)
- 50% burned (reduces total KRN supply)

---

## Step 12 — Monitor

```bash
# Sequencer health
sudo systemctl status rollup-sequencer

# Bond intact?
curl -s $KERN_RPC/chain/contract/$ROLLUP_ADDR | jq '.storage.bond'

# Open challenges?
curl -s $KERN_RPC/chain/contract/$ROLLUP_ADDR | jq '.storage.open_challenges'

# Latest commit level
curl -s $KERN_RPC/chain/contract/$ROLLUP_ADDR | jq '.storage.last_commit'
```

Set up Prometheus alerts on:
- `bond` decreasing (you've been slashed)
- `open_challenges` non-zero (you need to respond)
- Time since `last_commit` exceeding interval (sequencer down)

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| Cannot post batch — "sequencer mismatch" | Rollup contract storage `sequencer` field doesn't match your address | Verify origination params; you may have used a different key |
| Bond field is 0 | Deposit transaction failed silently | Check the deposit tx; resubmit |
| Challenges keep coming | Sequencer is producing wrong commitments | Stop posting, debug your L2 execution trace vs honest re-execution |
| Bond drained to zero | Multiple successful challenges | Game over for this sequencer instance; the rollup may be permanently frozen until governance intervention |
| L2 transactions disappear | Inbox queue overflowing | Increase `commit_interval_blocks` to drain faster, or scale the L2 EVM compute |

---

## Economics

| Item | Cost / Income |
|---|---|
| Sequencer bond | 100 000 KRN locked, slashable |
| L1 batch posting fee | ~5 000 mukrn per commit, every minute = ~7.2M mukrn/day = 7.2 KRN/day |
| L2 transaction fees | You collect these from L2 users; ideally exceed L1 posting costs |
| Slashing risk | Up to full bond loss on any single proven fraud |

A profitable sequencer charges L2 users enough to exceed the daily L1 posting cost. The 100 KRN/day in fees at break-even assumes ~$0.01 average L2 tx fee at 10 KRN/USD.

---

## Next steps

- [rollups.md](rollups.md) — full rollup protocol spec
- [evm-fraud-proofs.md](evm-fraud-proofs.md) — bisection protocol detail
- [forced-inclusion.md](forced-inclusion.md) — the mailbox for censorship resistance
- [multi-frame-evm.md](multi-frame-evm.md) — the L2 execution semantics
- [setup-heimdall-operator.md](setup-heimdall-operator.md) — point Heimdall at the L1 RPC your sequencer settles to; the explorer surfaces every rollup state-commitment tx and lets you correlate them with bisection events
- Foundation grants for rollup development: [contributors-program.md](contributors-program.md)
