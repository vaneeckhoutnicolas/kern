# Docker setup

This directory contains the artifacts for running a three-node Kern network in containers. The orchestration is `docker-compose`.

## Prerequisites

- Docker 20+
- docker-compose v2+

## First-time setup

The compose file expects the data directories and genesis file to already exist on the host (they are mounted into the containers). Run this once on the host:

```bash
# From the repository root:
mkdir -p keys data/node1 data/node2 data/node3

# Generate the baker key.
python scripts/generate_keys.py --out keys/baker1.json

# Build the genesis.
python scripts/build_genesis.py \
    --validator keys/baker1.json:1000000000 \
    --out genesis.json

# Initialize each node's data dir.
for i in 1 2 3; do
  python -m kern.node init --genesis genesis.json --data-dir ./data/node$i
done
```

## Bring up the network

```bash
cd docker
docker-compose up --build
```

This launches three nodes:

| Service | Role          | RPC port (host) | P2P port (host) |
|---------|---------------|-----------------|-----------------|
| node1   | Baker         | 8731            | 9731            |
| node2   | Peer (gossip) | 8732            | 9732            |
| node3   | Peer (gossip) | 8733            | 9733            |

## Verify the network is live

```bash
for port in 8731 8732 8733; do
  echo -n "node on $port: "
  curl -s http://localhost:$port/chain/head | jq -c '{level, hash}'
done
```

After a few seconds all three should report the same head level.

## Tear down

```bash
docker-compose down
```

To also wipe the on-disk node data:

```bash
docker-compose down -v
rm -rf ../data/node{1,2,3}
```
