# RPC API

The Kern node exposes a JSON-over-HTTP API. All responses are JSON. All `kn1`/`kpk`/`ksig` strings are base58check-encoded.

The default RPC port is `8732`. Examples assume `localhost:8732`.

---

## `GET /chain/head`

Return the current head of the chain.

**Response**

```json
{
  "level": 142,
  "hash": "c219e2fa3789af66315056b32b939ab6e7955aaa08e6678db324a3fffc536fb7",
  "timestamp": 1779393610,
  "proposer": "kn1QzHmgDwWiCHQaVof4mHVK7qgSmGioGond",
  "txs": 0
}
```

---

## `GET /chain/block/{level}`

Return the block at the given level. Returns `404` if no such block exists.

**Response**

```json
{
  "header": {
    "level": 4,
    "round": 4,
    "timestamp": 1779393607,
    "parent_hash": "d9e9dfd05f02...",
    "state_root": "8c1f829c74df...",
    "txs_root": "edd6278a7c3a...",
    "proposer": "kn1QzHmgDwWiCHQaVof4mHVK7qgSmGioGond",
    "proposer_pubkey": "9XYenoNdH5oA...",
    "signature": "ksig..."
  },
  "transactions": [ ... ],
  "commits": [ "kn1QzHmgDwWi...:ksig..." ]
}
```

---

## `GET /chain/block/by_hash/{hash}`

Return the block with the given header hash (hex). Returns `404` if no such block exists.

---

## `GET /chain/balance/{address}`

Return the balance of the given account, in mukrn.

**Response**

```json
{ "address": "kn1ZnARRKAyRURf4Kr71zUxn5W9eUXnvUutT", "balance": 9998764433 }
```

A non-existent address returns `{ "address": "...", "balance": 0 }` rather than `404` — every address is implicitly an account.

---

## `GET /chain/nonce/{address}`

Return the next expected nonce for the given account. New addresses return `0`.

**Response**

```json
{ "address": "kn1ZnARRKAyRURf4Kr71zUxn5W9eUXnvUutT", "nonce": 1 }
```

This is what you should pass as the `nonce` field of a transaction signed by that address.

---

## `GET /chain/contract/{address}`

Return the originated contract at the given address (Skald source + current storage). Returns `404` if the address is not an originated contract.

**Response**

```json
{
  "address": "kn1XYZ...",
  "code": "contract Counter { ... }",
  "storage": { "count": 6, "owner": "kn1QzHmgDwWiCHQaVof4mHVK7qgSmGioGond" }
}
```

---

## `POST /chain/inject_transaction`

Inject a signed transaction into the node's mempool. The transaction will be gossiped to peers and (if valid) included in the next block by the active baker.

**Request body** — a `Transaction` dict (see [`transaction.py`](../kern/transaction.py)):

```json
{
  "kind": "transfer",
  "sender": "kn1Zn...",
  "sender_pubkey": "9XYe...",
  "nonce": 0,
  "fee": 1000,
  "gas_limit": 10000,
  "recipient": "kn1Sd...",
  "amount": 1234567,
  "signature": "ksig..."
}
```

**Response**

```json
{ "hash": "19c0716f22829050df78689abc49945ec7cc053f4c847b5fe938bc8a4e4529b9" }
```

The hash returned identifies the transaction; you can use it to track inclusion. Errors return `400` with a message.

---

## `GET /chain/mempool`

Return the current mempool size and the hashes of pending transactions.

**Response**

```json
{ "size": 3, "hashes": [ "19c0...", "8a31...", "c2bb..." ] }
```

---

## `GET /chain/validators`

Return the current active validator set.

**Response**

```json
[
  {
    "address": "kn1QzHmgDwWiCHQaVof4mHVK7qgSmGioGond",
    "pubkey":  "9XYenoNdH5oA...",
    "stake":   1000000000
  }
]
```

---

## `GET /chain/health`

A liveness probe. Returns the head level, peer count, and mempool size.

**Response**

```json
{ "ok": true, "level": 142, "peers": 2, "mempool": 0 }
```

---

## Error responses

All errors return JSON of the form:

```json
{ "error": "<reason>" }
```

with an HTTP status code in the 4xx (client errors) or 5xx (server errors) range.

| Status | Cause                                                  |
|-------:|--------------------------------------------------------|
| 400    | Malformed request body, invalid signature, bad nonce   |
| 404    | No such block / no such contract                       |
| 500    | Internal node error (consult the node log)             |
