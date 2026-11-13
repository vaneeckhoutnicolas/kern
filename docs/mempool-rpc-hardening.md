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
`429 Too Many Requests` with a `Retry-After` header. When admission fails
for a mempool-cap reason, the endpoint also returns `429` with an
explanatory body. A transaction is broadcast to peers only *after* it is
accepted locally, so a rejected transaction is not gossiped.

### 3. Read throttling (`kern/rpc.py`)

Every `GET` endpoint is wrapped by a middleware (`make_read_throttle`) that
applies a **separate, more generous** per-client budget
(`read_rate_limit_max`, default `600` per window). Reads are far cheaper to
issue than the write path, so a GET flood — of `/metrics`, `/chain/head`,
`/chain/mempool` — was the larger residual exposure once injection was
throttled. The read budget is high enough that legitimate polling (block
explorers, Prometheus scrapes) is never affected, while a flood is shed
with `429 + Retry-After`. The liveness endpoint `/chain/health` is
**exempt**, so a `429` can never be misread as an unhealthy node by a load
balancer or monitor. Non-`GET` requests pass through untouched (the write
path does its own, stricter limiting).

`/chain/mempool` is additionally bounded: it now reports the true mempool
size but serialises only a capped slice of hashes (1,000), where it
previously drained up to 10,000 rows per call — removing a cheap
amplification vector.

### 4. What a node takes, and what a proposer takes from it (`kern/chain.py`)

A block charges a transaction as soon as its chain, its signature, its
nonce and its fee are right; from there the fee is paid, whatever the
operation does next. For the block that is built next, a transaction is
therefore in one of three cases, and four facts tell which: its sender, its
nonce, its fee and its size (`chain.mempool_verdict`).

| Verdict | When | At the door of the mempool | In front of a proposer |
|---|---|---|---|
| take | Its nonce is the nonce of its account, and the sender holds the fee | Taken | In the block, whether its operation then succeeds or fails |
| wait | Its nonce is ahead of its account, by 256 at most, and the sender holds the fee | Taken | Left in the mempool |
| drop | Its nonce is consumed, or more than 256 ahead; the sender does not hold the fee; the fee is under the [fee floor](fee-floor.md), when the floor is on; it is more than 131,072 bytes; it is signed for another chain | Refused | Removed from the mempool |

**At the door.** `Node.admit_transaction` is the one way in, for a
transaction that a peer sends and for one that a client posts. It applies
the table to the head of the chain (`chain.admission_error`), then verifies
the signature, then applies the two caps of section 1: the checks that cost
least come first. A transaction that is refused is neither stored nor
passed on to peers, and it is not remembered either: it is looked at again
when it comes again, since its account may have moved. A client is answered
`400` with the reason. A full mempool is the one refusal that says nothing
against the transaction, and is answered `429`.

**In front of a proposer.** `propose_block` reads the mempool in the order
of arrival and stops when its block is full: 5,000 transactions
(`BakerConfig.max_txs_per_block`), or the bytes that
`chain.proposed_block_bytes` gives, which are `max_block_bytes` when the
fee floor is on and 8,388,608 otherwise, so that a block always travels in
one frame. A transaction that does not fit in what is left ends the block:
what came after it waits for its turn. The table is applied to the state as
the block has made it so far, so a transaction paid for by an earlier one
of the same block is taken. What the block takes is applied once, on one
copy of the state. A transaction that pays its fee and then fails is in the
block, as every validator applies it (`apply_block`), and leaves the
mempool with it. What is dropped is removed from the mempool.

**The rows.** Each row of the mempool carries the nonce, the fee and the
size of its transaction next to its sender. A proposer reads these rows,
and decodes only the transactions its block takes: a transaction that waits
costs it one row. The three columns are added on open to a database written
by an older node, and filled from the transactions it holds; a row that is
not a transaction is removed.

**The reports of a validator.** The slashing reports a validator files
itself go through the same door. A report takes the first nonce that
neither the chain nor a waiting transaction of the validator has taken. A
validator that cannot pay for a report yet, after what it already has
waiting, keeps the evidence and files it when it can.

These are the choices of a node, not rules of consensus: a block that holds
a transaction of more than 131,072 bytes is a valid block today. Structure
version 1 makes these sizes rules of the chain
([`api-stability.md`](api-stability.md), section 9.3).

Before this rule a node took any transaction that was well formed and well
signed. A proposer tried the 5,000 oldest ones, each on a full copy of the
state, and left out every one whose operation failed, although the block
would have charged it. Transactions that could only fail stayed in the
mempool for ever, were tried again at every block, and hid those that came
after them. The proposer did not look at the fee floor either: with the
floor on, it built blocks that every validator refused.

## Scope and limitations

This is a **first line of defence**, not a complete anti-DoS posture:

- The rate limiters are **per-process and per-node**. They are keyed by the
  immediate peer address, so they do not by themselves defend against a
  distributed flood from many source addresses, nor against many clients
  sharing one NAT/proxy address. Production deployments should still front
  the RPC with an edge proxy / WAF and, where applicable, authentication —
  see the operator runbook.
- The mempool caps bound *memory*, not *bandwidth*: gossip validation
  still costs CPU per received transaction, a signature check for each
  one that a block could charge. Peer scoring and gossip-layer throttling
  remain future work and are tracked alongside the broader network
  hardening in the security review.
- The order of the mempool is the order of arrival. Ordering by fee is
  future work.

## Tests

`tests/test_mempool_rpc_hardening.py` covers the per-sender cap, the
global cap, resubmission not consuming budget, the rate-limiter window
behaviour, and the legacy-database migration.
`tests/test_mempool_admission.py` covers the door (each refusal, from a
peer and from a client), the rows and their migration, and the reports of
a validator. `tests/test_proposer_selection.py` covers what a proposer
takes, leaves and removes, the full block, and the validity of the block
whatever the mempool holds.

## Reference

External review surfacing these two surfaces as unbounded:
the v1.1-rc post-release vulnerability pass (mempool "no per-sender
limit" and RPC "verify rate-limiting" items). See also
[`security-review-v11rc.md`](security-review-v11rc.md) §4.6 (RPC) and the
deferred-audit areas.
