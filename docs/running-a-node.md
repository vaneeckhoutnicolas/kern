# Running a node

This guide covers running a single Kern node and setting up a small local network of two or three nodes.

## Prerequisites

- Python 3.11 or later
- A clone of this repository
- The Python dependencies installed: `pip install -r requirements.txt`

## Single-node setup

### 1. Generate a baker key

```bash
mkdir -p keys
python scripts/generate_keys.py --out keys/baker1.json
```

Output:

```
Wrote keyfile: keys/baker1.json
  Address:    kn1QzHmgDwWiCHQaVof4mHVK7qgSmGioGond
  Public key: 9XYenoNdH5oAsQ7r4wE74DpDMKpYLQDzMB95revzeR2ZXEU8UFo5f
```

The seed in this file is the private signing material. Keep it secret; anyone with it controls the account.

### 2. (Optional) Generate user keys and build a custom genesis

```bash
python scripts/generate_keys.py --out keys/alice.json
python scripts/generate_keys.py --out keys/bob.json

python scripts/build_genesis.py \
    --validator keys/baker1.json:1000000000 \
    --fund $(jq -r .address keys/alice.json):10000000000 \
    --fund $(jq -r .address keys/bob.json):5000000000 \
    --out genesis.json
```

Amounts are in **mukrn** (1 KRN = 1 000 000 mukrn). The validator's stake (`1000000000` mukrn = 1 000 KRN) is also added to its starting balance.

A pre-built `genesis.json` is included in the repository for quick testing.

### 3. Initialize the node data directory

```bash
python -m kern.node init --genesis genesis.json --data-dir ./data/node1
```

This creates `./data/node1/kern.sqlite` containing the genesis block and the initial state.

### 4. Start the node

```bash
python -m kern.node start \
    --data-dir ./data/node1 \
    --rpc-port 8732 \
    --p2p-port 9732 \
    --baker-key keys/baker1.json \
    --block-time 1.0
```

The node now produces a block every second. Block-time can be lowered (`--block-time 0.5`) for faster local testing.

### 5. Query the node

```bash
curl http://localhost:8732/chain/head
curl http://localhost:8732/chain/health
curl http://localhost:8732/chain/balance/$(jq -r .address keys/alice.json)
```

### 6. Send a transfer

```bash
python scripts/send_transfer.py \
    --rpc http://localhost:8732 \
    --key keys/alice.json \
    --to $(jq -r .address keys/bob.json) \
    --amount 1000000
```

Within one block (typically under a second) the transfer is included; balances update accordingly.

## Multi-node local network

A multi-node setup is useful for testing P2P gossip and validator-set scenarios. The simplest layout: three nodes, one of them a baker, the others peers.

### 1. Generate keys for each node

```bash
for i in 1 2 3; do
  python scripts/generate_keys.py --out keys/node$i.json
done
```

### 2. Build a shared genesis

Only one of the three is a baker in this setup (multi-validator BFT is not yet implemented; a multi-baker genesis is accepted but only the round-elected proposer will actually bake).

```bash
python scripts/build_genesis.py \
    --validator keys/node1.json:1000000000 \
    --out genesis.json
```

### 3. Initialize each data directory

```bash
for i in 1 2 3; do
  python -m kern.node init --genesis genesis.json --data-dir ./data/node$i
done
```

### 4. Start them on distinct ports

In three separate terminals:

```bash
# Terminal 1 — the baker
python -m kern.node start --data-dir ./data/node1 --rpc-port 8731 --p2p-port 9731 \
    --baker-key keys/node1.json --block-time 1.0

# Terminal 2 — a peer that listens to node1
python -m kern.node start --data-dir ./data/node2 --rpc-port 8732 --p2p-port 9732 \
    --peer 127.0.0.1:9731

# Terminal 3 — a peer that listens to node1
python -m kern.node start --data-dir ./data/node3 --rpc-port 8733 --p2p-port 9733 \
    --peer 127.0.0.1:9731
```

Within a second or two, all three nodes should have the same head:

```bash
for port in 8731 8732 8733; do
  echo "node on $port:"
  curl -s http://localhost:$port/chain/head | jq -r .level
done
```

### 5. Send a transaction to any node

The transaction will gossip to the others and be included by whichever node is the active baker. Submitting to node2 (a non-baker):

```bash
python scripts/send_transfer.py \
    --rpc http://localhost:8732 \
    --key keys/some-funded-account.json \
    --to <recipient address> \
    --amount 5000000
```

## Docker

A `docker-compose.yml` is provided in [`docker/`](../docker/) for spinning up the three-node setup with one command:

```bash
cd docker
docker-compose up
```

See [`docker/README.md`](../docker/README.md) for details.

## Common operations

**Restarting a node** — `start` is safe to re-run against an existing data directory. The node replays its persisted state and resumes from the head.

**Resetting** — to wipe and start from scratch:

```bash
rm -rf ./data/node1
python -m kern.node init --genesis genesis.json --data-dir ./data/node1
```

**Changing block-time** — pass `--block-time SECONDS` to `start`. Smaller values (e.g. `0.25`) are useful for testing high-throughput scenarios locally; in a real network this would be a protocol-level parameter under on-chain governance.

**Inspecting a block** — `curl http://localhost:8732/chain/block/{level}` returns the full block JSON (header, transactions, commits). See [`api.md`](api.md) for the full RPC surface.
