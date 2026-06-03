#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern-wallet: minimal Kern wallet CLI.
====================================

A reference CLI demonstrating how to build, sign, and inject Kern
transactions of every kind, plus how to query chain state. Intended
for developers, delegators, validators, and as a self-documenting
example of the full RPC surface.

Usage:
    kern-wallet keygen --out KEY.json
    kern-wallet inspect KEY.json
    kern-wallet balance KEY.json
    kern-wallet head
    kern-wallet validators
    kern-wallet transfer KEY.json --to ADDR --amount KRN [--fee MUKRN]
    kern-wallet delegate KEY.json --validator ADDR
    kern-wallet undelegate KEY.json
    kern-wallet vote KEY.json --proposal PID --track protocol|treasury --vote yes|no|pass
    kern-wallet slash KEY.json --proposal PID --equivocator ADDR

Environment:
    KERN_RPC      RPC endpoint URL (default: http://127.0.0.1:8732)

Key file format (JSON):
    {
        "address":    "kn1...",
        "public_key": "9X...",
        "seed_hex":   "<64 hex chars>"
    }

This CLI is intentionally minimal — no daemon, no key encryption at
rest, no multi-key wallet management. It's a learning tool and a
reproducible workflow demonstration. For production wallet use,
integrate with a hardware wallet and encrypt the seed at rest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Ensure kern package is importable when running from repo
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern.crypto import KernKeypair
from kern.transaction import (
    OpKind,
    Transaction,
    make_transfer,
    make_delegate_stake,
    make_undelegate_stake,
    make_governance_vote,
    make_slash_equivocation,
)


# Default RPC — overridable via environment
DEFAULT_RPC = "http://127.0.0.1:8732"

# Conversion
MUKRN_PER_KRN = 1_000_000


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def rpc_get(url: str) -> dict:
    """GET an RPC URL, return parsed JSON."""
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        die(f"RPC error {e.code} from {url}: {e.reason}")
    except (urllib.error.URLError, ConnectionResetError) as e:
        die(f"RPC unreachable at {url}: {e}")


def rpc_post(url: str, payload: dict) -> dict:
    """POST a JSON payload to RPC, return parsed JSON."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        die(f"RPC error {e.code} from {url}: {e.reason}\n  payload: {payload}")


def rpc_base() -> str:
    return os.environ.get("KERN_RPC", DEFAULT_RPC).rstrip("/")


# ---------------------------------------------------------------------------
# Key file I/O
# ---------------------------------------------------------------------------

def load_keypair(path: str) -> KernKeypair:
    """Load a keypair from a JSON file with seed_hex."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        die(f"Key file not found: {path}")
    except json.JSONDecodeError as e:
        die(f"Key file not valid JSON: {path}: {e}")

    seed_hex = data.get("seed_hex")
    if not seed_hex:
        die(f"Key file {path} missing 'seed_hex' field")
    return KernKeypair.from_seed(bytes.fromhex(seed_hex))


def save_keypair(kp: KernKeypair, path: str, seed_hex: str) -> None:
    """Save keypair to a JSON file with restrictive permissions."""
    data = {
        "address": kp.address,
        "public_key": kp.public_key_b58,
        "seed_hex": seed_hex,
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass   # Windows etc.


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_nonce(address: str) -> int:
    """Fetch current nonce from RPC."""
    data = rpc_get(f"{rpc_base()}/chain/nonce/{address}")
    return data.get("nonce", 0)


def krn_to_mukrn(krn_amount: float) -> int:
    """Convert a KRN amount (possibly fractional) to integer mukrn."""
    return int(round(krn_amount * MUKRN_PER_KRN))


def mukrn_to_krn_str(mukrn: int) -> str:
    """Format mukrn as a KRN string with 6 decimal places."""
    return f"{mukrn / MUKRN_PER_KRN:.6f}"


def inject(tx: Transaction) -> str:
    """POST a signed tx to /chain/inject_transaction. Return the tx hash."""
    result = rpc_post(f"{rpc_base()}/chain/inject_transaction", tx.to_dict())
    tx_hash = result.get("hash") or result.get("tx_hash")
    if not tx_hash:
        die(f"Inject responded without a tx hash: {result}")
    return tx_hash


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_keygen(args):
    """Generate a new keypair and save to file."""
    import secrets
    if Path(args.out).exists() and not args.force:
        die(f"Refusing to overwrite existing file {args.out} (use --force)")
    seed = secrets.token_bytes(32)
    kp = KernKeypair.from_seed(seed)
    save_keypair(kp, args.out, seed.hex())
    print(f"Generated new keypair:")
    print(f"  Address:    {kp.address}")
    print(f"  Public key: {kp.public_key_b58}")
    print(f"  Saved to:   {args.out}  (chmod 600)")
    print()
    print("IMPORTANT: back up this file securely. If you lose the seed,")
    print("the funds at this address are permanently lost.")


def cmd_inspect(args):
    """Print the address and public key from a keypair file."""
    kp = load_keypair(args.keyfile)
    print(f"Address:    {kp.address}")
    print(f"Public key: {kp.public_key_b58}")


def cmd_balance(args):
    """Print the balance and nonce of an address."""
    if Path(args.target).is_file():
        # Treat as keyfile
        kp = load_keypair(args.target)
        addr = kp.address
    else:
        # Treat as raw address
        addr = args.target

    bal_data = rpc_get(f"{rpc_base()}/chain/balance/{addr}")
    nonce_data = rpc_get(f"{rpc_base()}/chain/nonce/{addr}")
    balance = bal_data.get("balance", 0)
    nonce = nonce_data.get("nonce", 0)
    print(f"Address: {addr}")
    print(f"Balance: {mukrn_to_krn_str(balance)} KRN  ({balance} mukrn)")
    print(f"Nonce:   {nonce}")


def cmd_head(args):
    """Print the current chain head."""
    data = rpc_get(f"{rpc_base()}/chain/head")
    print(json.dumps(data, indent=2))


def cmd_validators(args):
    """List active validators."""
    data = rpc_get(f"{rpc_base()}/chain/validators")
    if isinstance(data, list):
        for v in data:
            stake = v.get("stake", 0)
            commission = v.get("commission_rate", "?")
            print(f"  {v['address']:<55}  stake: {mukrn_to_krn_str(stake)} KRN  commission: {commission}%")
    else:
        print(json.dumps(data, indent=2))


def cmd_transfer(args):
    """Build, sign, and inject a TRANSFER transaction."""
    kp = load_keypair(args.keyfile)
    amount_mukrn = krn_to_mukrn(args.amount)
    nonce = get_nonce(kp.address)

    tx = make_transfer(
        sender_kp=kp,
        recipient=args.to,
        amount=amount_mukrn,
        nonce=nonce,
        fee=args.fee,
        gas_limit=21_000,
    )

    print(f"Sending {args.amount} KRN ({amount_mukrn} mukrn)")
    print(f"  From: {kp.address}")
    print(f"  To:   {args.to}")
    print(f"  Fee:  {args.fee} mukrn")
    print(f"  Nonce: {nonce}")

    if not args.yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    tx_hash = inject(tx)
    print(f"Injected. Tx hash: {tx_hash}")


def cmd_delegate(args):
    """Build, sign, and inject a DELEGATE_STAKE transaction."""
    kp = load_keypair(args.keyfile)
    nonce = get_nonce(kp.address)

    tx = make_delegate_stake(
        sender_kp=kp,
        validator=args.validator,
        nonce=nonce,
        fee=args.fee,
    )

    print(f"Delegating to {args.validator}")
    print(f"  From: {kp.address}")
    print(f"  Fee:  {args.fee} mukrn")
    print(f"  Nonce: {nonce}")
    print()
    print("Your KRN remains in your custody. Only the delegation pointer changes.")

    if not args.yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    tx_hash = inject(tx)
    print(f"Injected. Tx hash: {tx_hash}")


def cmd_undelegate(args):
    """Build, sign, and inject an UNDELEGATE_STAKE transaction."""
    kp = load_keypair(args.keyfile)
    nonce = get_nonce(kp.address)

    tx = make_undelegate_stake(
        sender_kp=kp,
        nonce=nonce,
        fee=args.fee,
    )

    print(f"Removing delegation for {kp.address}")
    print(f"  Fee:  {args.fee} mukrn")
    print(f"  Nonce: {nonce}")

    if not args.yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    tx_hash = inject(tx)
    print(f"Injected. Tx hash: {tx_hash}")


def cmd_vote(args):
    """Build, sign, and inject a GOVERNANCE_VOTE transaction."""
    kp = load_keypair(args.keyfile)
    nonce = get_nonce(kp.address)

    if args.vote not in ("yes", "no", "pass"):
        die("--vote must be one of: yes / no / pass")
    if args.track not in ("protocol", "treasury"):
        die("--track must be one of: protocol / treasury")

    tx = make_governance_vote(
        sender_kp=kp,
        track=args.track,
        proposal_id=args.proposal,
        vote=args.vote,
        nonce=nonce,
        fee=args.fee,
    )

    print(f"Voting on proposal {args.proposal}")
    print(f"  Track: {args.track}")
    print(f"  Vote:  {args.vote}")
    print(f"  From:  {kp.address}")
    print(f"  Nonce: {nonce}")

    if not args.yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    tx_hash = inject(tx)
    print(f"Injected. Tx hash: {tx_hash}")


def cmd_slash(args):
    """Build, sign, and inject a SLASH_EQUIVOCATION transaction.

    Anyone can submit this — the chain validates the on-chain evidence.
    The submitter (whistleblower) earns 10% of the slashed amount."""
    kp = load_keypair(args.keyfile)
    nonce = get_nonce(kp.address)

    tx = make_slash_equivocation(
        sender_kp=kp,
        proposal_id=args.proposal,
        equivocator=args.equivocator,
        nonce=nonce,
        fee=args.fee,
    )

    print(f"Submitting slashing evidence:")
    print(f"  Proposal:    {args.proposal}")
    print(f"  Equivocator: {args.equivocator}")
    print(f"  Reporter:    {kp.address}")
    print(f"  Reward (if accepted): 10% of slashed amount → your address")

    if not args.yes:
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    tx_hash = inject(tx)
    print(f"Injected. Tx hash: {tx_hash}")


def cmd_governance(args):
    """Display current governance state."""
    data = rpc_get(f"{rpc_base()}/chain/governance")
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kern-wallet",
        description="Minimal Kern wallet CLI. Build, sign, and inject transactions.",
        epilog="Set KERN_RPC environment variable to override RPC endpoint (default: http://127.0.0.1:8732).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # keygen
    pk = sub.add_parser("keygen", help="Generate a new keypair")
    pk.add_argument("--out", required=True, help="Output JSON file path")
    pk.add_argument("--force", action="store_true", help="Overwrite existing file")
    pk.set_defaults(func=cmd_keygen)

    # inspect
    pi = sub.add_parser("inspect", help="Print address and public key from a keyfile")
    pi.add_argument("keyfile", help="Path to keypair JSON")
    pi.set_defaults(func=cmd_inspect)

    # balance
    pb = sub.add_parser("balance", help="Show balance and nonce for an address or keyfile")
    pb.add_argument("target", help="Either a keyfile path or a kn1... address")
    pb.set_defaults(func=cmd_balance)

    # head
    ph = sub.add_parser("head", help="Show current chain head")
    ph.set_defaults(func=cmd_head)

    # validators
    pv = sub.add_parser("validators", help="List active validators")
    pv.set_defaults(func=cmd_validators)

    # governance
    pg = sub.add_parser("governance", help="Show current governance state")
    pg.set_defaults(func=cmd_governance)

    # transfer
    pt = sub.add_parser("transfer", help="Send KRN to another address")
    pt.add_argument("keyfile", help="Sender keypair")
    pt.add_argument("--to", required=True, help="Recipient kn1... address")
    pt.add_argument("--amount", required=True, type=float, help="KRN amount (fractional allowed)")
    pt.add_argument("--fee", type=int, default=2_000, help="Fee in mukrn (default: 2000)")
    pt.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    pt.set_defaults(func=cmd_transfer)

    # delegate
    pd = sub.add_parser("delegate", help="Delegate baking to a validator")
    pd.add_argument("keyfile", help="Delegator keypair")
    pd.add_argument("--validator", required=True, help="Validator kn1... address")
    pd.add_argument("--fee", type=int, default=2_000, help="Fee in mukrn (default: 2000)")
    pd.add_argument("--yes", "-y", action="store_true")
    pd.set_defaults(func=cmd_delegate)

    # undelegate
    pu = sub.add_parser("undelegate", help="Stop delegating to any validator")
    pu.add_argument("keyfile", help="Delegator keypair")
    pu.add_argument("--fee", type=int, default=2_000, help="Fee in mukrn (default: 2000)")
    pu.add_argument("--yes", "-y", action="store_true")
    pu.set_defaults(func=cmd_undelegate)

    # vote
    pvg = sub.add_parser("vote", help="Cast a governance vote (validators only)")
    pvg.add_argument("keyfile", help="Voter keypair (must be a registered validator)")
    pvg.add_argument("--proposal", required=True, help="Proposal ID")
    pvg.add_argument("--track", required=True, choices=["protocol", "treasury"])
    pvg.add_argument("--vote", required=True, choices=["yes", "no", "pass"])
    pvg.add_argument("--fee", type=int, default=2_000)
    pvg.add_argument("--yes", "-y", action="store_true")
    pvg.set_defaults(func=cmd_vote)

    # slash
    psl = sub.add_parser("slash", help="Submit slashing evidence against an equivocating validator")
    psl.add_argument("keyfile", help="Whistleblower keypair (you will earn 10% of slashed amount)")
    psl.add_argument("--proposal", required=True, help="Proposal ID containing the equivocation record")
    psl.add_argument("--equivocator", required=True, help="The misbehaving validator's kn1... address")
    psl.add_argument("--fee", type=int, default=1_000)
    psl.add_argument("--yes", "-y", action="store_true")
    psl.set_defaults(func=cmd_slash)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
