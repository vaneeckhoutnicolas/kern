# Setup Guide — DApp Developer (Skald)

**Audience**: Developers writing smart contracts in Skald to deploy on Kern, and developers building user-facing applications that interact with Kern via RPC.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- Familiarity with smart contract concepts (state, entry points, gas)
- Python 3.11+ for the tooling
- A Kern RPC endpoint (your own node, or a public one)
- A Kern keypair with some KRN for contract origination fees
- Reading: [skald-language.md](skald-language.md) for the language reference

**What this guide covers**: Write a Skald contract, type-check it, test it locally, originate it on a Kern network, call it, and integrate it with a frontend.

**Estimated time**: 2-3 hours for the first contract end-to-end; subsequent contracts are faster.

**Cost**: ~10 000 mukrn (= 0.01 KRN) per contract origination on Yggdrasil; varies by storage size on Midgard.

---

## Step 1 — Set up the dev environment

If you've already done [setup-developer.md](setup-developer.md), you have what you need. If not:

```bash
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

pytest tests/test_skald.py tests/test_typecheck.py -v
# Expected: ~49 tests passing
```

**Verification**:

```bash
python -c "from kern.skald import interpret_origination; print('Skald loaded')"
# Expected: Skald loaded
```

---

## Step 2 — Write your first Skald contract

Create a file `mycontract.skald`:

```skald
// counter.skald — a minimal counter contract with bounded state.
//
// Demonstrates: typed storage, declared invariants, entry points,
// view functions.

contract Counter {
    storage {
        owner: address,
        value: int,
        max_value: int,
    }

    // Invariants are checked after every entry point.
    // If any invariant is violated, the call reverts atomically.
    invariant value_in_range {
        value >= 0
    }

    invariant value_bounded_by_max {
        value <= max_value
    }

    invariant owner_immutable {
        // owner is set at origination and never changes.
        // (This invariant has nothing to compare against at runtime —
        // the type system enforces immutability of fields you don't
        // reassign in any entry point. Documentation-as-invariant.)
        true
    }

    // Entry points are callable transactions.
    entry increment() {
        require value < max_value with "counter at maximum";
        value = value + 1;
    }

    entry decrement() {
        require value > 0 with "counter cannot go below zero";
        value = value - 1;
    }

    entry reset() {
        require sender == owner with "only owner can reset";
        value = 0;
    }

    // View functions are pure reads; they don't modify storage.
    view get() -> int {
        value
    }

    view percent_full() -> int {
        (value * 100) / max_value
    }
}
```

---

## Step 3 — Type-check the contract

Before you originate (deploying spends real KRN), confirm it compiles:

```bash
python <<PYEOF
from kern.skald.typecheck import type_check

with open("mycontract.skald") as f:
    source = f.read()

errors = type_check(source)
if errors:
    for e in errors:
        print(f"ERROR: {e}")
else:
    print("Type check passed.")
PYEOF
```

**Expected output**: `Type check passed.`

If there are errors, fix them. The type checker covers:
- Storage field types match assignments
- `require` conditions are boolean
- Entry-point parameters typed
- View return types match expressions

See [typecheck.md](typecheck.md) for the full type-system reference.

---

## Step 4 — Test the contract locally (without deploying)

Use the interpreter directly to simulate:

```bash
python <<PYEOF
from kern.skald import interpret_call, interpret_origination, SkaldError

with open("mycontract.skald") as f:
    src = f.read()

# Simulate origination — initialize storage
storage = interpret_origination(src, {
    "owner": "kn1ownerAddress",
    "value": 0,
    "max_value": 100,
})
print("Initial storage:", storage)

# Simulate calls
storage = interpret_call(src, storage, "increment", {},
                        sender="kn1someone", amount=0, self_addr="kn1counter")
print("After increment:", storage)

storage = interpret_call(src, storage, "increment", {},
                        sender="kn1someone", amount=0, self_addr="kn1counter")
print("After 2 increments:", storage)

# Test invariant enforcement
try:
    s = interpret_origination(src, {
        "owner": "kn1ownerAddress",
        "value": -5,           # violates value >= 0
        "max_value": 100,
    })
except SkaldError as e:
    print("Invariant violation caught:", e)

# Test access control
try:
    interpret_call(src, storage, "reset", {},
                  sender="kn1someone", amount=0, self_addr="kn1counter")
except SkaldError as e:
    print("Access control enforced:", e)
PYEOF
```

**Expected output**:
```
Initial storage: {'owner': 'kn1ownerAddress', 'value': 0, 'max_value': 100}
After increment: {..., 'value': 1, ...}
After 2 increments: {..., 'value': 2, ...}
Invariant violation caught: ...
Access control enforced: only owner can reset
```

---

## Step 5 — Set environment for the target network

```bash
# Yggdrasil testnet:
export KERN_RPC=https://rpc.yggdrasil.kern.protocol

# Or local node:
# export KERN_RPC=http://localhost:8732

# Your keypair:
export MY_KEY=/path/to/your-key.json
# (Same JSON format as setup-delegator.md: contains address, public_key, seed_hex)
```

---

## Step 6 — Originate the contract on-chain

```bash
python <<PYEOF
import json, os, urllib.request
from kern.crypto import KernKeypair
from kern.transaction import make_origination

with open(os.environ["MY_KEY"]) as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

with open("mycontract.skald") as f:
    source = f.read()

# Initial storage
initial_storage = {
    "owner": kp.address,         # you are the owner
    "value": 0,
    "max_value": 100,
}

# Get nonce
rpc = os.environ["KERN_RPC"]
nonce = json.loads(urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}").read())["nonce"]

# Build the origination tx
tx = make_origination(
    sender_kp=kp,
    code=source,
    initial_storage=initial_storage,
    amount=0,
    nonce=nonce,
    fee=10_000,
    gas_limit=200_000,
)

# Inject
body = json.dumps(tx.to_dict()).encode()
resp = urllib.request.urlopen(urllib.request.Request(
    f"{rpc}/chain/inject_transaction",
    data=body, headers={"Content-Type": "application/json"},
))
result = json.loads(resp.read())
print(f"Tx injected: {result['hash']}")
print(f"Contract address will be visible at next block (typically ~1-3 seconds)")
PYEOF
```

After ~3 seconds, the contract is on-chain. Its address is deterministically derived from your address and nonce (visible in the block where the transaction was included).

**Verification**:

```bash
# Query the latest block to find your contract address
curl -s $KERN_RPC/chain/head | jq

# Inspect the contract state
# (substitute the actual contract address — visible in the block's tx receipts)
curl -s $KERN_RPC/chain/contract/<contract-address> | python -m json.tool
# Expected: {"code": "...", "storage": {"owner": "...", "value": 0, "max_value": 100}}
```

---

## Step 7 — Call the contract

```bash
export CONTRACT_ADDR="kn1<your-contract-address>"

python <<PYEOF
import json, os, urllib.request
from kern.crypto import KernKeypair
from kern.transaction import make_call

with open(os.environ["MY_KEY"]) as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

rpc = os.environ["KERN_RPC"]
contract = os.environ["CONTRACT_ADDR"]
nonce = json.loads(urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}").read())["nonce"]

# Call increment()
tx = make_call(
    sender_kp=kp,
    contract=contract,
    entry="increment",
    params={},
    nonce=nonce,
    fee=5_000,
    gas_limit=50_000,
)

body = json.dumps(tx.to_dict()).encode()
resp = urllib.request.urlopen(urllib.request.Request(
    f"{rpc}/chain/inject_transaction",
    data=body, headers={"Content-Type": "application/json"},
))
print(f"Increment tx: {json.loads(resp.read())['hash']}")
PYEOF
```

**Verification**: query the contract state again — `value` should be 1 (then 2 after another call, etc.).

---

## Step 8 — Integrate with a frontend

For a web frontend, your application typically:

1. Has a wallet integration (browser extension or hardware) that signs transactions
2. Connects to a Kern RPC endpoint
3. Builds transactions client-side, signs them, injects them

Reference: until a JS SDK is published, you can call the Python builders server-side from a backend (Node.js can subprocess Python, or you can write a small JSON-RPC proxy). A full JS SDK is on the roadmap; until then, see the [api.md](api.md) reference for the canonical JSON wire format and implement the signing in your stack.

The key endpoints for a DApp frontend:

| Endpoint | Use |
|---|---|
| `GET /chain/head` | Current block level (for displaying "1 confirmation", "10 confirmations") |
| `GET /chain/contract/{addr}` | Read contract storage to display in UI |
| `GET /chain/balance/{addr}` | Display user's balance |
| `GET /chain/nonce/{addr}` | Required to build the next transaction |
| `POST /chain/inject_transaction` | Submit a signed transaction |

---

## Step 9 — Test on a local devnet (recommended for development)

Use the devnet bootstrap script to spin up a 3-validator local network:

```bash
cd /path/to/kern
python networks/devnet_bootstrap.py --validators 3 --out ./mydevnet
cd mydevnet
docker compose up -d
```

Each validator exposes an RPC port (18732, 18733, 18734). Set `KERN_RPC=http://localhost:18732` and develop against this local network. Block times are fast and there's no economic cost to mistakes.

When done:
```bash
docker compose down
```

---

## Step 10 — Skald best practices

| Practice | Why |
|---|---|
| Declare every invariant you can | Runtime-checked; catches bugs at execution time, not after |
| Use `require ... with "msg"` for all access control | Clear error messages on failure; user-friendly |
| Minimize state size | Storage costs scale with size; smaller = cheaper for users |
| Use view functions for reads | Free for callers (no transaction needed) |
| Type-check before originating | Origination is irreversible; type errors caught now save real KRN |
| Test invariant violations explicitly | Confirms your safety properties hold |
| Avoid loops over unbounded data | Skald doesn't have a gas budget for arbitrary computation; design for bounded work |
| One concern per contract | Composition via call (`call_contract`) is cheap; separate logic into multiple contracts when natural |

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| Type-check errors before origination | Code uses undeclared field or wrong type | Re-read [skald-language.md](skald-language.md) for grammar |
| `invariant ... violated` on origination | Initial storage doesn't satisfy invariants | Fix the initial values to satisfy all invariants |
| `entry point not found` on call | Wrong entry name (case sensitive) | Match the entry name exactly |
| Out-of-gas error | Default gas limit too low | Pass `gas_limit=...` parameter explicitly |
| Origination succeeded but contract not callable | Contract address mismatch; you stored the wrong one | Re-query the block where the origination tx was included |
| Storage shape doesn't match expectations | Caller passing wrong params type | Check the entry signature in your `.skald` file |

---

## Next steps

- [skald-language.md](skald-language.md) — full Skald reference: grammar, semantics, examples
- [typecheck.md](typecheck.md) — static type system details
- [governance.md](governance.md) — if your contract integrates with treasury governance
- [api.md](api.md) — RPC endpoint reference
- [setup-heimdall-operator.md](setup-heimdall-operator.md) — run Heimdall during development; the `/contract/<address>` page shows your live storage, the `/contracts?template=<your-template>` page classifies your contract automatically once the indexer detects its Skald template signature
- Example contracts in `kern/skald/examples/` (counter.skald, vault.skald, plus the 8 v1.1-rc templates: 3 STO, 2 PGF, 3 oracle/marketplace)
