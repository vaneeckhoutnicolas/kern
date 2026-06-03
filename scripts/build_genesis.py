#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Build a genesis.json from a set of validator keyfiles.

Usage:

    python scripts/build_genesis.py \\
        --validator keys/baker1.json:1000000000 \\
        --validator keys/baker2.json:1000000000 \\
        --fund kn1abc...:5000000000 \\
        --out genesis.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--validator", action="append", default=[],
                   help="path:stake (mukrn). Repeatable.")
    p.add_argument("--fund", action="append", default=[],
                   help="address:amount (mukrn). Repeatable.")
    p.add_argument("--chain-id", default="kern-mainnet-dev")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    validators = []
    balances = {}
    genesis_proposer = None
    for spec in args.validator:
        path, stake_s = spec.rsplit(":", 1)
        with open(path) as f:
            keyfile = json.load(f)
        v = {
            "address": keyfile["address"],
            "pubkey":  keyfile["public_key"],
            "stake":   int(stake_s),
        }
        validators.append(v)
        balances[v["address"]] = balances.get(v["address"], 0) + int(stake_s)
        if genesis_proposer is None:
            genesis_proposer = {"address": v["address"], "pubkey": v["pubkey"]}

    for spec in args.fund:
        addr, amt = spec.rsplit(":", 1)
        balances[addr] = balances.get(addr, 0) + int(amt)

    if not validators:
        print("at least one --validator is required", file=sys.stderr)
        return 1

    genesis = {
        "chain_id": args.chain_id,
        "timestamp": int(time.time()),
        "genesis_proposer": genesis_proposer,
        "genesis_signature": "ksig" + "0" * 95,
        "validators": validators,
        "balances": balances,
    }
    with open(args.out, "w") as f:
        json.dump(genesis, f, indent=2)
    print(f"Wrote {args.out}")
    print(f"  Validators: {len(validators)}")
    print(f"  Pre-funded accounts: {len(balances)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
