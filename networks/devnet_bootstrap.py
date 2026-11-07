#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
devnet_bootstrap.py
===================

Bootstrap a local Kern devnet: N validators, each with their own
keypair, a shared genesis with all of them pre-funded and registered
as validators, and a docker-compose file to run them all.

Usage:
    python networks/devnet_bootstrap.py --validators 3 --out networks/devnet

This will produce:
    networks/devnet/
        genesis.json                     # shared genesis
        keys/baker0.json … bakerN-1.json # validator keypairs
        keys/faucet.json                 # extra funded account for distributing tokens
        docker-compose.yml               # one service per validator
        README.md                        # how to start, query, stop

Then:
    cd networks/devnet
    docker-compose up
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair


def write_keypair(path: Path, seed_hex: str) -> dict:
    kp = KernKeypair.from_seed(bytes.fromhex(seed_hex))
    data = {
        "address": kp.address,
        "public_key": kp.public_key_b58,
        "seed_hex": seed_hex,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return data


def build(out_dir: Path, n_validators: int, initial_stake: int,
          initial_balance: int, faucet_balance: int) -> None:
    keys_dir = out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    validators = []
    balances = {}
    # Validators
    for i in range(n_validators):
        seed = f"{i + 1:02x}" * 32
        data = write_keypair(keys_dir / f"baker{i}.json", seed)
        validators.append({
            "address": data["address"],
            "pubkey": data["public_key"],
            "stake": initial_stake,
        })
        balances[data["address"]] = initial_balance

    # Faucet
    faucet = write_keypair(keys_dir / "faucet.json", "fa" * 32)
    balances[faucet["address"]] = faucet_balance

    # Treasury
    treasury = write_keypair(keys_dir / "treasury.json", "7e" * 32)
    balances[treasury["address"]] = 0  # filled by issuance

    genesis = {
        "chain_id": "kern-devnet",
        "timestamp": int(time.time()),
        # Same placeholder convention as scripts/build_genesis.py: the
        # genesis block is accepted because it matches this file.
        "genesis_proposer": {"address": validators[0]["address"],
                             "pubkey": validators[0]["pubkey"]},
        "genesis_signature": "ksig" + "0" * 95,
        "balances": balances,
        "validators": validators,
        "treasury_address": treasury["address"],
        "issuance_params": None,
    }
    (out_dir / "genesis.json").write_text(json.dumps(genesis, indent=2))

    # Docker-compose. The image's entrypoint is `python -m kern.node`; each
    # service runs a shell instead, to initialize its data volume on first
    # start and then start the node (`init` refuses, harmlessly, a volume
    # that is already initialized). Inside the container the RPC listens on
    # every interface so that the published port reaches it; the host
    # publishes it on its own loopback only. The peer-to-peer port stays on
    # the compose network.
    services = {}
    base_rpc = 18732
    rpc_port, p2p_port = 8732, 9732
    repo_root = Path(__file__).resolve().parent.parent
    context = os.path.relpath(repo_root, out_dir.resolve())
    names = [f"baker{i}" for i in range(n_validators)]

    for i, name in enumerate(names):
        start = ["python", "-m", "kern.node", "start",
                 "--data-dir", "/data",
                 "--rpc-port", str(rpc_port), "--rpc-bind", "0.0.0.0",
                 "--p2p-port", str(p2p_port),
                 "--baker-key", f"/keys/{name}.json",
                 "--block-time", "1.0"]
        for other in names:
            if other != name:
                start += ["--peer", f"{other}:{p2p_port}"]
        init = ["python", "-m", "kern.node", "init",
                "--genesis", "/genesis.json", "--data-dir", "/data"]
        services[name] = {
            "build": {"context": context, "dockerfile": "docker/Dockerfile"},
            "entrypoint": ["sh", "-c"],
            "command": f"{shlex.join(init)}; exec {shlex.join(start)}",
            "volumes": [
                "./keys:/keys:ro",
                f"{name}-data:/data",
                "./genesis.json:/genesis.json:ro",
            ],
            "ports": [f"127.0.0.1:{base_rpc + i}:{rpc_port}"],
        }

    compose = {
        "services": services,
        "volumes": {f"baker{i}-data": {} for i in range(n_validators)},
    }
    (out_dir / "docker-compose.yml").write_text(
        json.dumps(compose, indent=2)
    )

    # README
    readme = f"""# Kern Devnet — {n_validators} validators

This is a local devnet bootstrap with {n_validators} validators that
will run in lock-step via BFT consensus, baking blocks every ~1 second.

## What's here

- `genesis.json`: chain genesis. {n_validators} validators, each with
  {initial_stake:,} mukrn stake and {initial_balance:,} starting balance.
  A faucet account with {faucet_balance:,} mukrn for distributing test
  tokens, and a treasury account that will fill from block rewards.
- `keys/baker0.json` … `baker{n_validators - 1}.json`: validator keypairs.
  **Devnet only — never use these for anything else.**
- `keys/faucet.json`: pre-funded account for sending test transfers.
- `keys/treasury.json`: the on-chain treasury (do not spend manually).
- `docker-compose.yml`: one container per validator.

## Bring it up

```bash
cd networks/devnet
docker-compose up --build
```

Each validator exposes its RPC on a different port of this machine
(published on 127.0.0.1 only):
- baker0 → http://localhost:{base_rpc + 0}
- baker1 → http://localhost:{base_rpc + 1}
{"".join(f"- baker{i} → http://localhost:{base_rpc + i}\n" for i in range(2, n_validators))}

## Query

```bash
# Chain head
curl http://localhost:{base_rpc}/chain/head | jq

# Metrics (Prometheus format)
curl http://localhost:{base_rpc}/metrics

# Governance state
curl http://localhost:{base_rpc}/chain/governance | jq

# All RPC endpoints
curl http://localhost:{base_rpc}/chain/health
```

## Send a test transfer

```bash
python -c "
from kern.crypto import KernKeypair
from kern.transaction import make_transfer
import json, urllib.request

with open('keys/faucet.json') as f: faucet = json.load(f)
with open('keys/baker0.json') as f: dest = json.load(f)

kp = KernKeypair.from_seed(bytes.fromhex(faucet['seed_hex']))
tx = make_transfer(kp, dest['address'], 1_000_000, nonce=0)

body = json.dumps(tx.to_dict()).encode()
req = urllib.request.Request('http://localhost:{base_rpc}/chain/inject_transaction',
                              data=body, headers={{'Content-Type': 'application/json'}})
print(urllib.request.urlopen(req).read().decode())
"
```

## Tear down

```bash
docker-compose down -v   # -v removes data volumes (reset chain)
```

## Status

Devnet is for contributor use only. Tokens have no value. Reset freely.
For the next step on the network track, see `docs/roadmap.md`
(Previewnet ← v0.9 ← here).
"""
    (out_dir / "README.md").write_text(readme)
    print(f"Devnet bootstrap written to {out_dir}/")
    print(f"  - {n_validators} validators + 1 faucet + 1 treasury account")
    print(f"  - docker-compose with RPC ports {base_rpc}..{base_rpc + n_validators - 1}")
    print(f"  - Run: cd {out_dir} && docker-compose up --build")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=3,
                    help="Number of validator nodes (default 3)")
    ap.add_argument("--out", type=Path, default=Path("networks/devnet"),
                    help="Output directory")
    ap.add_argument("--stake", type=int, default=1_000_000_000,
                    help="Initial stake per validator (mukrn)")
    ap.add_argument("--balance", type=int, default=5_000_000_000,
                    help="Initial balance per validator (mukrn)")
    ap.add_argument("--faucet", type=int, default=100_000_000_000,
                    help="Faucet balance (mukrn)")
    args = ap.parse_args()

    build(args.out, args.validators, args.stake, args.balance, args.faucet)


if __name__ == "__main__":
    main()
