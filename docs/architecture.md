# Architecture

This document describes how the reference Kern node is organized. The code is in [`kern/`](../kern/) and each module is small enough to read in one sitting.

## Component map

```
                                      ┌─────────────────────┐
                                      │     CLI (node.py)   │
                                      └──────────┬──────────┘
                                                 │
            ┌────────────────┬───────────────────┼──────────────────┬─────────────┐
            │                │                   │                  │             │
            ▼                ▼                   ▼                  ▼             ▼
     ┌───────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────┐   ┌──────────┐
     │  rpc.py   │    │ consensus.py│    │  network.py  │    │ chain.py │   │storage.py│
     │ (aiohttp) │    │ (baker loop)│    │   (asyncio)  │    │  (state) │   │ (sqlite) │
     └─────┬─────┘    └──────┬──────┘    └──────┬───────┘    └────┬─────┘   └────┬─────┘
           │                 │                  │                 │              │
           └─────────────────┴──────────────────┴─────────────────┴──────────────┘
                                              │
                                              ▼
                                 ┌──────────────────────────┐
                                 │  block.py / transaction.py│
                                 │      (data model)         │
                                 └─────────────┬─────────────┘
                                               │
                                               ▼
                                       ┌───────────────┐
                                       │   crypto.py   │
                                       │ (Ed25519 etc) │
                                       └───────────────┘

                                       ┌───────────────┐
                                       │     skald/    │
                                       │ (contract VM) │
                                       └───────────────┘
```

## Modules

- **`crypto.py`** — Ed25519 keys, blake2b-256 hashing, base58check encoding, `kn1`/`kpk` address and key prefixes. All hashing in Kern is domain-separated via blake2b keys (`kern.block`, `kern.tx`, `kern.addr`, `kern.state`, `kern.merkle`).
- **`transaction.py`** — The `Transaction` dataclass, the three operation kinds (`TRANSFER`, `ORIGINATE`, `CALL`), signing and verification, and the helpers `make_transfer`, `make_origination`, `make_call`.
- **`block.py`** — `BlockHeader`, `Block`, and the merkle root over transaction hashes.
- **`chain.py`** — The state machine. Defines the canonical state layout (balances, nonces, contracts, validators), the per-transaction application rules, block validation, and the `Chain` in-memory wrapper.
- **`consensus.py`** — Stake-weighted proposer selection, block proposal (with mempool draining), and the `BakerConfig`.
- **`network.py`** — A small asyncio-based peer-to-peer layer with length-prefixed JSON messages.
- **`rpc.py`** — JSON-over-HTTP endpoints (see [`api.md`](api.md)).
- **`storage.py`** — SQLite-backed persistence for blocks, the head state snapshot, and the mempool.
- **`node.py`** — The `Node` class that wires everything together, plus the CLI entry point (`init` and `start`).
- **`skald/`** — The Skald contract language: lexer, parser, AST, interpreter, and invariant checker.

## Process lifecycle

1. **`kern.node init`** — Reads `genesis.json`, constructs the level-0 block, builds the initial state (balances + validators), and writes both to the SQLite store under the data directory.
2. **`kern.node start`** — Opens the SQLite store, reconstructs the chain from the persisted state snapshot, starts the P2P listener, starts the RPC server, and (if a baker key was supplied) starts the baker loop.
3. **Baker loop** — Every `block_time` seconds: check if we are the selected proposer for the next round. If yes, drain the mempool, trial-apply transactions, build a block, sign the header, append it to the chain, persist it, and broadcast to peers. If no, sleep and try again next round.
4. **Network handler** — On receiving a gossiped block, validate it against the parent and current state, append, persist, and drop included transactions from the mempool. On receiving a gossiped transaction, verify the signature and add it to the local mempool.

## State commitments

Every block header carries a `state_root` — the blake2b-256 hash of the canonical JSON serialization of the post-block state. This is sufficient for the reference implementation to detect any state divergence between honest nodes. A production implementation should replace this with a binary Merkle-Patricia trie keyed by account address, allowing light clients to verify individual account balances with O(log n)-sized proofs.

## What's not in scope here

- **Multi-validator BFT message exchange.** The reference baker self-commits; a multi-validator implementation would add pre-endorsement and endorsement aggregation in the consensus module, and signature verification of those messages in `chain.validate_block`.
- **Mempool prioritization.** Transactions are processed in mempool order; a production implementation would order by fee per gas unit and apply rate limiting per sender.
- **State proofs.** The current `state_root` is opaque; a production trie would expose merkle proofs through the RPC.
- **Rollup interop.** The optimistic rollup bridge described in the whitepaper is not part of this reference implementation.
