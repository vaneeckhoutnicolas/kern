# Mempool bounds & RPC rate limiting (node-local DoS hardening)

The Kern node accepts unconfirmed transactions on two surfaces: the
write-facing RPC endpoint `POST /chain/inject_transaction`, and the P2P
gossip channel (`Node._on_tx_msg`). Both feed the same SQLite-backed
mempool. Before this change the mempool grew without bound and the RPC
endpoint applied no per-client throttling, so a single peer could exhaust
a node's memory with cheap, never-includable transactions — a purely
**local** denial-of-service vector (it degrades an individual node; it is
not a consensus-safety issue and so, unlike the
[fee floor](fee-floor.md), it is *not* a chain rule).

## What changed

### 1. Bounded mempool (`kern/storage.py`)

`Storage.add_to_mempool` now enforces two caps and returns a boolean
admission result:

- **Per-sender cap** (`max_mempool_per_sender`, default `256`): one
  sender cannot hold more than this many pending transactions. This is
  the cap that matters against a flood, because signing volume from a
  single key is the cheap-to-produce resource.
- **Global cap** (`max_mempool_size`, default `50_000`): a hard ceiling
  on total pending transactions regardless of sender, bounding worst-case
  memory across many senders.

A re-submission of a transaction already in the mempool (same hash) is an
`INSERT OR REPLACE` and **never** counts against either cap, so honest
resubmission and gossip duplication are always allowed.

Because both caps live in `add_to_mempool`, they protect **every** intake
route — the RPC path and the gossip path both go through this method, so
neither can bypass the bound.

The mempool table gains a `sender` column to make the per-sender count an
indexed `COUNT(*)` rather than a full scan + JSON parse. Databases created
before this change are migrated transparently on open (an idempotent
`ALTER TABLE ... ADD COLUMN`).

Both limits are constructor parameters, so a deployment can tune them
(for example, a permissioned validator may want a tighter per-sender cap).

### 2. RPC rate limiter (`kern/rpc.py`)

`POST /chain/inject_transaction` is now guarded by an in-process
sliding-window `RateLimiter` keyed by client identity (`req.remote`):
at most `rate_limit_max` injections (default `100`) per
`rate_limit_window_s` (default `10s`). Over-budget requests get
`429 Too Many Requests` with a `Retry-After` header. Read endpoints are
not limited.

When admission fails for a mempool-cap reason, the endpoint also returns
`429` with an explanatory body. A transaction is broadcast to peers only
*after* it is accepted locally, so a rejected transaction is not gossiped.

## Scope and limitations

This is a **first line of defence**, not a complete anti-DoS posture:

- The rate limiter is **per-process and per-node**. It is keyed by the
  immediate peer address, so it does not by itself defend against a
  distributed flood from many source addresses. Production deployments
  should still front the RPC with an edge proxy / WAF and, where
  applicable, authentication — see the operator runbook.
- The mempool caps bound *memory*, not *bandwidth*: gossip validation
  (signature checks) still costs CPU per received transaction. Peer
  scoring and gossip-layer throttling remain future work and are tracked
  alongside the broader network hardening in the security review.

## Tests

`tests/test_mempool_rpc_hardening.py` covers the per-sender cap, the
global cap, resubmission not consuming budget, the rate-limiter window
behaviour, and the legacy-database migration.

## Reference

External review surfacing these two surfaces as unbounded:
the v1.1-rc post-release vulnerability pass (mempool "no per-sender
limit" and RPC "verify rate-limiting" items). See also
[`security-review-v11rc.md`](security-review-v11rc.md) §4.6 (RPC) and the
deferred-audit areas.
