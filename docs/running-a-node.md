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

### 2. Generate user keys and build a genesis

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

The genesis file carries a `timestamp`, in seconds, which `build_genesis.py` writes: it is the time of the genesis block, hence part of its hash. A node reads it from the file and from nowhere else, and `init` refuses a genesis without it (`error: invalid genesis`). Every node of a network starts from the same file.

The `genesis.json` at the root of the repository describes the planned distribution of the mainnet. It is not a file a node starts from: build one as above.

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

**Listening addresses.** The RPC listens on `127.0.0.1` by default, so only this machine can query it; `--rpc-bind` changes that (`0.0.0.0` for every interface, which a node inside a container needs for a published port, or one specific address). The peer-to-peer layer listens on every interface by default, since other nodes must reach it; `--p2p-bind` restricts it. Both options take an IPv4 or IPv6 address, not a host name. A node whose RPC listens beyond loopback logs a warning at start: put a reverse proxy and a firewall in front of it ([setup-validator.md](setup-validator.md)).

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

For a multi-node devnet with the explorer and optional monitoring, in one command, see [devnet.md](devnet.md) (`python scripts/devnet.py up`).

A smaller `docker-compose.yml` is also provided in [`docker/`](https://github.com/vaneeckhoutnicolas/kern/tree/main/docker) for spinning up the three-node setup with one command:

```bash
cd docker
docker-compose up
```

See [`docker/README.md`](https://github.com/vaneeckhoutnicolas/kern/blob/main/docker/README.md) for details.

## Common operations

**Restarting a node** — `start` is safe to re-run against an existing data directory. The node replays its persisted state and resumes from the head.

**Resetting** — to wipe and start from scratch:

```bash
rm -rf ./data/node1
python -m kern.node init --genesis genesis.json --data-dir ./data/node1
```

**Changing block-time** — pass `--block-time SECONDS` to `start`. Smaller values (e.g. `0.25`) are useful for testing high-throughput scenarios locally; in a real network this would be a protocol-level parameter under on-chain governance.

**Inspecting a block** — `curl http://localhost:8732/chain/block/{level}` returns the full block JSON (header, transactions, commits). See [`api.md`](api.md) for the full RPC surface.
