# Setup Guide — Delegator

**Audience**: KRN holders who want to earn baking yield by delegating to a validator, without running their own node.

**Maintainer**: Nicolas Van Eeckhout (founder).

**Prerequisites**:
- KRN balance on Yggdrasil testnet or Midgard mainnet
- A Kern keypair (private key file or hardware wallet)
- Network access to a Kern RPC node (your own, or a public one)
- A terminal with Python 3.11+ for the CLI examples, OR a Kern-compatible wallet (when available)

**What this guide covers**: Pick a validator, build and sign a `DELEGATE_STAKE` transaction, inject it, verify the delegation, monitor rewards, switch validators, or undelegate.

**Estimated time**: 10 minutes for the delegation itself; ongoing monitoring of rewards is passive.

**Cost**: ~2 000 mukrn (= 0.002 KRN) per delegate/undelegate transaction.

---

## Concept refresher (one paragraph)

Kern uses **Liquid PoS baking delegation**: your KRN stays in your account, fully spendable, no LST derivative is minted, no lockup period. The validator you delegate to counts your balance toward their effective stake at reward-distribution time. You receive baking yield in proportion to your share of the validator's effective stake, minus the validator's commission (default 10%). For full mechanics see [staking.md](staking.md).

---

## Step 1 — Locate a Kern RPC endpoint

You need a node to query and to inject transactions through.

**Option A — Public RPC** (recommended for most users):

```bash
# Yggdrasil testnet (when launched):
export KERN_RPC=https://rpc.yggdrasil.kern.protocol

# Midgard mainnet (after launch):
export KERN_RPC=https://rpc.midgard.kern.protocol
```

(These URLs are placeholders — actual endpoints will be published with each network launch.)

**Option B — Your own local node**:

```bash
export KERN_RPC=http://localhost:8732
```

See [setup-validator.md](setup-validator.md) if you want to run your own node.

**Verification**:

```bash
curl -s $KERN_RPC/chain/head | python -m json.tool | head -10
# Expected: JSON with level, round, timestamp, etc.
```

If the curl fails, the endpoint is wrong or down — try another.

---

## Step 2 — Check your balance

```bash
export MY_ADDRESS="kn1..."   # your kn1 address

curl -s $KERN_RPC/chain/balance/$MY_ADDRESS | python -m json.tool
# Expected: {"balance": <integer in mukrn>}
```

If you don't have KRN yet:
- Yggdrasil testnet: use the faucet at `https://faucet.yggdrasil.kern.protocol` (URL when launched)
- Midgard mainnet: acquire from an exchange or from the public sale (see [tokenomics.md](tokenomics.md) §4)

---

## Step 3 — Choose a validator

List active validators:

```bash
curl -s $KERN_RPC/chain/validators | python -m json.tool
```

You'll get a list like:

```json
[
  {
    "address": "kn1baker1...",
    "pubkey": "9XYepk...",
    "stake": 1000000000,
    "commission_rate": 10
  },
  ...
]
```

**Selection criteria** (see [staking.md](staking.md) §5 for full guidance):

- **Commission**: lower is better, all else equal. 5-15% is the typical range.
- **Stake**: avoid the single largest — that concentrates the network.
- **Uptime**: not visible in this RPC; check the block explorer when available, or ask in community channels.
- **Identity**: a validator with a public website/Twitter is more reputable than an anonymous one.

For this guide, set:

```bash
export VALIDATOR="kn1baker_address_of_your_choice"
```

---

## Step 4 — Get your current nonce

Every transaction needs a strictly-increasing nonce per sender. Fetch yours:

```bash
curl -s $KERN_RPC/chain/nonce/$MY_ADDRESS | python -m json.tool
# Expected: {"nonce": N}
```

Note `N`. The next transaction you sign must use `nonce: N`.

---

## Step 5 — Build, sign, and inject the DELEGATE_STAKE transaction

Save your private key (or seed) to a file `mykey.json` in this format (only used locally — never share):

```json
{
  "address": "kn1...",
  "public_key": "9XYepk...",
  "seed_hex": "<64 hex characters>"
}
```

Then run:

```bash
python <<PYEOF
import json, urllib.request, os

from kern.crypto import KernKeypair
from kern.transaction import make_delegate_stake

with open("mykey.json") as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

# Get current nonce
rpc = os.environ["KERN_RPC"]
req = urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}")
nonce = json.loads(req.read())["nonce"]

# Build the transaction
tx = make_delegate_stake(
    sender_kp=kp,
    validator=os.environ["VALIDATOR"],
    nonce=nonce,
)

# Inject
body = json.dumps(tx.to_dict()).encode()
req = urllib.request.Request(
    f"{rpc}/chain/inject_transaction",
    data=body,
    headers={"Content-Type": "application/json"},
)
resp = urllib.request.urlopen(req)
result = json.loads(resp.read())
print("Injected. Tx hash:", result["hash"])
PYEOF
```

**Verification** (wait ~3 seconds for the next block, then):

```bash
curl -s $KERN_RPC/chain/balance/$MY_ADDRESS | python -m json.tool
# Note the balance — it dropped by ~2_000 mukrn (the delegation fee)

# Inspect the live state to confirm your delegation is on-chain.
# (Requires direct state inspection; the production /chain/governance
# endpoint exposes governance state. For delegations, query a future
# endpoint /chain/delegations/<address> or use a block explorer.)
```

For now, the canonical way to confirm a delegation is to query a block explorer that surfaces it, or run a local node and inspect `state["delegations"][MY_ADDRESS]`.

---

## Step 6 — Monitor your rewards

Once delegated, your share of block rewards is credited to your balance automatically at each block your validator proposes. To check growth:

```bash
# Snapshot now
B1=$(curl -s $KERN_RPC/chain/balance/$MY_ADDRESS | python -c "import json,sys; print(json.load(sys.stdin)['balance'])")
echo "Balance now: $B1 mukrn"

# Wait 1 hour, then re-check
sleep 3600
B2=$(curl -s $KERN_RPC/chain/balance/$MY_ADDRESS | python -c "import json,sys; print(json.load(sys.stdin)['balance'])")
echo "Balance after 1h: $B2 mukrn"
echo "Earned: $((B2 - B1)) mukrn over 1 hour"
```

Expected yield (at ~50% staking ratio and 10% validator commission):

| Annual yield | Approximate range |
|---|---|
| Gross (validator earns) | 0.25% to 3% |
| After 10% commission | 0.225% to 2.7% |
| On a 1 000 KRN balance | ~2.25 to 27 KRN per year |

These are protocol-level estimates. Actual yield depends on your validator's uptime and the network's staking ratio.

---

## Step 7 (optional) — Switch validators

You can re-delegate at any time. There is no waiting period.

```bash
export NEW_VALIDATOR="kn1different_baker_address"

# Same as Step 5, but with the new validator and nonce N+1
```

Use the same Python snippet from Step 5 with `make_delegate_stake(validator=NEW_VALIDATOR, nonce=current_nonce)`.

**Verification**: query the chain state to confirm the new delegation target.

---

## Step 8 (optional) — Stop delegating

If you want to stop delegating entirely (stop earning yield, also stop being exposed to validator slashing):

```bash
python <<PYEOF
import json, urllib.request, os

from kern.crypto import KernKeypair
from kern.transaction import make_undelegate_stake

with open("mykey.json") as f:
    keydata = json.load(f)
kp = KernKeypair.from_seed(bytes.fromhex(keydata["seed_hex"]))

rpc = os.environ["KERN_RPC"]
nonce = json.loads(urllib.request.urlopen(f"{rpc}/chain/nonce/{kp.address}").read())["nonce"]

tx = make_undelegate_stake(sender_kp=kp, nonce=nonce)
body = json.dumps(tx.to_dict()).encode()
req = urllib.request.Request(
    f"{rpc}/chain/inject_transaction", data=body,
    headers={"Content-Type": "application/json"},
)
print("Injected. Tx hash:", json.loads(urllib.request.urlopen(req).read())["hash"])
PYEOF
```

After the next block, you are no longer delegating.

---

## Slashing risk — what you're exposed to

If your chosen validator misbehaves (double-baking, double-endorsing, or equivocating in governance votes), they are slashed by **30% of their stake**. As a delegator, **you are slashed by the same percentage of your delegated balance**.

Concretely: if you delegate 1 000 KRN to a validator who gets slashed, you lose 300 KRN (burned, not paid to anyone).

This is the "skin in the game" property that makes validator selection a meaningful decision. See [staking.md](staking.md) §4 for full details.

To minimize slashing risk:
- Pick validators with publicly verifiable operations
- Diversify across multiple validators by splitting your KRN across multiple addresses
- Monitor news of slashing events on the chain explorer

---

## Common issues

| Symptom | Cause | Fix |
|---|---|---|
| `validator not in active set` error on injection | The validator address is wrong, or that validator was removed | Re-check `chain/validators` for current list |
| `cannot delegate to self` | You're delegating to your own address | Pick a different validator address |
| Balance unchanged after 1 hour | Your validator hasn't proposed a block yet | Check `chain/head` — has the level advanced? If not, the chain is paused. If yes, your validator may have very small stake; rewards are slow |
| Transaction signature fails | Your `seed_hex` is wrong | Verify with a fresh keygen; never edit it manually |
| `nonce too low` | You used a stale nonce | Re-fetch with `chain/nonce/<address>` and retry |
| `insufficient balance` | Your balance dropped below fee + gas | Top up the account |
| Cannot find an explorer to verify delegations | — | Use [Heimdall](setup-heimdall-operator.md), the official Kern block explorer; its `/account/<your-address>` and `/validators` pages show all the information you need |

---

## Next steps

- For a full understanding of the staking economy: [staking.md](staking.md)
- For the tokenomics broader context: [tokenomics.md](tokenomics.md)
- To run your own validator instead of delegating: [setup-validator.md](setup-validator.md)
- To participate in governance votes (validators only): [governance.md](governance.md)
- To inspect your delegation, your validator's recent activity, and the chain state: [Heimdall](setup-heimdall-operator.md). Run it locally against a public Kern RPC or use a community-hosted instance.
