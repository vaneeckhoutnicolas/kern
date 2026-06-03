#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Send a transfer to a running Kern node.

Usage:

    python scripts/send_transfer.py \\
        --rpc http://localhost:8732 \\
        --key keys/baker1.json \\
        --to kn1xyz... \\
        --amount 1000000
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.transaction import make_transfer


def get_nonce(rpc: str, addr: str) -> int:
    req = urllib.request.Request(f"{rpc}/chain/nonce/{addr}")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())["nonce"]


def inject(rpc: str, tx_dict: dict) -> dict:
    data = json.dumps(tx_dict).encode("utf-8")
    req = urllib.request.Request(
        f"{rpc}/chain/inject_transaction",
        data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", default="http://localhost:8732")
    p.add_argument("--key", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--amount", type=int, required=True, help="In mukrn (1 KRN = 1_000_000 mukrn).")
    p.add_argument("--fee", type=int, default=1_000)
    args = p.parse_args()

    with open(args.key, encoding="utf-8") as f:
        keyfile = json.load(f)
    kp = KernKeypair.from_seed(bytes.fromhex(keyfile["seed_hex"]))

    nonce = get_nonce(args.rpc, kp.address)
    tx = make_transfer(kp, recipient=args.to, amount=args.amount, nonce=nonce, fee=args.fee)
    resp = inject(args.rpc, tx.to_dict())
    print(f"Injected transaction: {resp.get('hash')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
