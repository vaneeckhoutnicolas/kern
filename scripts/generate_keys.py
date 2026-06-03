#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Generate a Kern keypair and write it to disk.

Output JSON shape:

    {
        "seed_hex": "<64 hex chars>",
        "public_key": "kpk...",
        "address":    "kn1..."
    }

The seed is the *private* material. Store the resulting file securely;
anyone with the seed can sign transactions for this account.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, help="Path to write the keyfile.")
    p.add_argument("--from-seed", help="Hex-encoded 32-byte seed (otherwise random).")
    p.add_argument("--force", action="store_true", help="Overwrite if file exists.")
    args = p.parse_args()

    if os.path.exists(args.out) and not args.force:
        print(f"refusing to overwrite {args.out} (use --force)", file=sys.stderr)
        return 1

    if args.from_seed:
        seed = bytes.fromhex(args.from_seed)
        kp = KernKeypair.from_seed(seed)
    else:
        kp = KernKeypair.generate()

    keyfile = {
        "seed_hex":   kp.seed.hex(),
        "public_key": kp.public_key_b58,
        "address":    kp.address,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(keyfile, f, indent=2)
    os.chmod(args.out, 0o600)

    print(f"Wrote keyfile: {args.out}")
    print(f"  Address:    {kp.address}")
    print(f"  Public key: {kp.public_key_b58}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
