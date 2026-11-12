# Cryptographic inventory and post-quantum plan

This page lists every cryptographic primitive Kern uses, where the code uses it, and what a large quantum computer would do to it. It then sets out the plan to give the first network beyond the devnet post-quantum signatures from its genesis, and what that plan would cost.

The inventory is checked against the code by [`tests/test_crypto_inventory.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_crypto_inventory.py): a hash domain, a library or a signature size that changes in the code without changing here fails the test suite.

> **Status.** No part of Kern is post-quantum today. Every signature is Ed25519 and the proof verifier uses the BN254 pairing curve; a large enough quantum computer would break both. Sections 3 and 4 describe a plan. None of it is implemented.

## 1. What Kern uses today

### 1.1 Signatures

One scheme signs everything: **Ed25519** ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)), through PyNaCl, which wraps libsodium. Public keys are 32 bytes and signatures are 64 bytes.

| What is signed | By whom | Checked in |
|---|---|---|
| Transactions of every kind (transfers, contracts, governance, staking, attestations, slashing evidence) | The sender | `Transaction.verify_signature`, `kern/transaction.py` |
| Block headers | The proposer | `BlockHeader.verify_signature`, `kern/block.py` |
| Consensus messages (proposal, pre-endorsement, endorsement) and the quorum certificates made of them | Validators | `ConsensusMessage.verify_signature` and `QuorumCertificate.verify`, `kern/bft.py` |
| Rollup batches | The sequencer of the rollup | `Batch.verify_signature`, `kern/rollup.py` |
| Any message a contract submits to precompile 0x01 | Whoever signed it | `_precompile_ecrecover`, `kern/evm/frames.py` |

All of them go through `kern.crypto.verify` in [`kern/crypto.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/crypto.py), except the precompile, which calls PyNaCl directly in [`kern/evm/frames.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/frames.py). These two files are the only places where a signature is verified.

**Keys.** A key pair is derived from a 32-byte seed (`KernKeypair.from_seed`), as RFC 8032 specifies. Seeds come from the generator of the operating system (`os.urandom` in `KernKeypair.generate`, `secrets.token_bytes` in the wallet). A key file is a JSON document that holds the seed in hexadecimal, unencrypted; the wallet restricts the file to its owner where the operating system allows it. There is no support for hardware security modules.

**Which keys are public.** Validator keys are in the chain state. Every transaction carries the public key of its sender, every block header that of its proposer, every consensus message that of its validator, and a rollup registers that of its sequencer. An account that has only received funds exposes the 160-bit hash of its key, not the key.

**No rotation.** The state holds a balance and a nonce per address, and no key. An address is bound to one key for as long as it exists.

### 1.2 Hash functions

In-protocol hashing is **BLAKE2b** ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)) from the `hashlib` module of Python, with a different key for each use, so that a hash computed for one purpose can never be taken for another. The table is complete: the test compares it with every keyed call in `kern/`.

| Key | Output | What it identifies | Computed by |
|---|---|---|---|
| `kern.block` | 256 bits | A block header: chain links, and the block a vote refers to | `block_hash`, `kern/crypto.py` |
| `kern.tx` | 256 bits | A transaction | `tx_hash`, `kern/crypto.py` |
| `kern.merkle` | 256 bits | The transactions of a block (Merkle root in the header) | `merkle_root`, `kern/block.py` |
| `kern.state` | 256 bits | The state, in `json` mode | `state_root_hex`, `kern/chain.py` |
| `kern.trie.leaf` | 256 bits | A leaf of the state trie | `kern/trie.py` |
| `kern.trie.branch` | 256 bits | A branch of the state trie | `kern/trie.py` |
| `kern.trie.key` | 256 bits | The position of an address in the state trie | `address_to_key`, `kern/trie.py` |
| `kern.storage` | 256 bits | The storage of a contract, inside its trie leaf | `trie_from_state`, `kern/trie.py` |
| `kern.code` | 256 bits | The code of a contract, inside its trie leaf | `trie_from_state`, `kern/trie.py` |
| `kern.addr` | 160 bits | An account (hash of its public key) or a contract (hash of the transaction that originated it) | `address_from_pubkey`, `kern/crypto.py`; `derive_contract_address`, `kern/chain.py` |
| `kern.batch` | 256 bits | A rollup batch | `Batch.hash`, `kern/rollup.py` |
| `kern.rollup.program` | 256 bits | The program a rollup batch executed | `program_hash`, `kern/rollup.py` |
| `kern.mailbox` | 256 bits | A forced inclusion request | `kern/forced_inclusion.py` |
| `kern.gov.id` | 128 bits | A governance proposal | `proposal_id`, `kern/governance.py` |
| `kern.attestation.id` | 128 bits | An attestation | `derive_attestation_id`, `kern/attestation.py` |
| `kern.zk_claims.vk` | 128 bits | A Groth16 verifier key; it ties a claim to the key that checks it | `derive_verifier_key_hash`, `kern/zk_claims.py` |
| `kern.evm` | 256 bits | A state of the Mini-EVM, for fraud proofs | `commitment`, `kern/evm/vm.py` |
| `kern.evm.create` | 160 bits | A contract created by `CREATE` in the Mini-EVM | `derive_create_address`, `kern/evm/frames.py` |
| `kern.evm.create2` | 160 bits | A contract created by `CREATE2` in the Mini-EVM | `derive_create2_address`, `kern/evm/frames.py` |
| `kern.evm.code` | 256 bits | The creation code hashed into a `CREATE2` address | `derive_create2_address`, `kern/evm/frames.py` |

BLAKE2b is used three more times without a key:

- the 4-byte checksum of base58check, which catches typing errors and protects nothing;
- the proposer draw, `select_proposer` in `kern/consensus.py`, which hashes the parent block hash and the round to 64 bits and picks a validator in proportion to its stake. The draw is public and deterministic by design. It is not a verifiable random function;
- the placeholder at precompile 0x09, described below.

The Mini-EVM of the rollup framework offers three other hash functions to contracts. The `SHA3` opcode computes SHA3-256 (FIPS 202). This is not the Keccak-256 of Ethereum, which pads its input differently and gives other digests. Precompile 0x02 is SHA-256. Precompile 0x03 is RIPEMD-160, taken from `hashlib` when OpenSSL provides it and from a portable implementation otherwise. Precompile 0x09 is a placeholder: it returns the 512-bit BLAKE2b hash of its input, not the F compression function of EIP-152.

### 1.3 Pairing curve

**BN254** (alt_bn128), through py_ecc, a library written in Python. It serves two purposes: precompiles 0x06 to 0x08 of the Mini-EVM (point addition, scalar multiplication, pairing check) in `kern/evm/bn254.py`, and the Groth16 verifier of zero-knowledge claims in `kern/zk_claims.py`. Kern verifies proofs. It ships no circuit, no trusted setup and no prover.

### 1.4 Transport and storage

Kern encrypts nothing. Peer to peer messages are length-prefixed JSON over TCP, without encryption and without authentication of the peer; what protects a message is the signature it carries. The RPC interface is plain HTTP and listens on 127.0.0.1 unless told otherwise. The chain database and the signing journal are plain files. All protocol data is public, so there is no traffic that someone could record today in order to decrypt it later.

### 1.5 Libraries

| Library | Used for | Imported by |
|---|---|---|
| PyNaCl (libsodium) | Ed25519 | `kern/crypto.py`, `kern/evm/frames.py` |
| py_ecc | BN254 | `kern/evm/bn254.py`, `kern/zk_claims.py` |
| `hashlib` (Python standard library) | BLAKE2b, SHA-256, SHA3-256, RIPEMD-160 | The modules listed in 1.2 |
| `random` (Python standard library) | Seeded generators of the fuzzing harness, never keys or consensus | `kern/fuzzing.py` |

No other cryptographic library is imported by `kern` or `kern_explorer`, and `pyproject.toml` declares no other.

### 1.6 Outside the protocol

Commits and release tags are signed with an SSH key of type Ed25519 ([release-tagging.md](release-tagging.md)). Git names its objects with SHA-1, and the Software Heritage identifiers of a release are those names. These protect the distribution of the code, not the chain, and they will follow what Git and its hosting offer.

## 2. What a quantum computer would change

Two algorithms matter. Shor's algorithm computes discrete logarithms: it recovers an elliptic curve private key from its public key. Grover's algorithm speeds up exhaustive search: finding a preimage of an n-bit hash takes about 2^(n/2) evaluations instead of 2^n.

| Primitive | Security today | Against a large quantum computer | What it means for Kern |
|---|---|---|---|
| Ed25519 | About 128 bits | Broken by Shor's algorithm | Whoever knows a public key can sign for it: spend from any account that has sent a transaction, vote and build quorum certificates as a validator, forge the two conflicting votes that get an honest validator slashed, and sign another history from genesis for a node that has no trusted checkpoint. |
| BN254 pairings (Groth16) | Commonly estimated near 100 bits | Broken by Shor's algorithm | Proofs of false statements can be made from a verifier key alone. Proofs already published still reveal nothing: the zero-knowledge property of Groth16 needs no hardness assumption. |
| BLAKE2b, 256 bits | 256 bits for a preimage, 128 bits for a collision | About 2^128 for a preimage; no practical gain for collisions | Holds. Block, transaction, state and trie hashes are not a concern. |
| BLAKE2b, 160 bits | 160 bits for a preimage, 80 bits for a collision | About 2^80 for a preimage | A thin margin for what identifies an account. To be widened. |
| BLAKE2b, 128 bits | 128 bits for a preimage, 64 bits for a collision | About 2^64 for a preimage | Identifiers of proposals and attestations, and the hash that ties a claim to its verifier key. To be widened. |
| Transport | No encryption, no authentication of peers | Nothing to decrypt | No confidentiality to lose. The missing authentication is a gap today, with or without quantum computers. |

The hash functions of the Mini-EVM follow the same rule: SHA3-256 and SHA-256 hold as BLAKE2b does at 256 bits, and RIPEMD-160 has the margin of a 160-bit hash. They concern contracts, not the protocol.

A running node never replaces a block it has finalized, so a forged history cannot undo what honest nodes already hold. It can deceive a node that starts from genesis with nothing to compare against.

**When.** No machine can do this today, and nobody knows when one will. The published estimates of what it takes have fallen. In March 2026 a team led by Google Quantum AI estimated that the discrete logarithm on a 256-bit elliptic curve could be computed in minutes with fewer than half a million physical qubits ([arXiv:2603.28846](https://arxiv.org/abs/2603.28846)). Their figure is for the curve secp256k1; Ed25519 is a curve of the same size and falls to the same algorithm. Standards and policy have moved: NIST published its first post-quantum standards in August 2024 (FIPS 203, 204 and 205), and the European roadmap of June 2025 asks Member States to start the transition by the end of 2026 and to protect critical infrastructures no later than the end of 2030.

## 3. Target: post-quantum from genesis

Kern has no open network and no assets at stake. Its formats can still change without migrating anyone, which chains already in service can no longer do. The target is therefore a starting point, not a migration: **from the first network that outside validators join, no account and no validator ever exists with a classical key alone.** In the [roadmap](roadmap.md) that network is the Previewnet.

The work is scheduled as a dedicated release, ahead of any new feature: the formats are cheapest to change now, and what comes next (conformance vectors, the Go client, the authenticated handshake) is built on them.

What is planned:

1. **Scheme identifiers.** Every public key, signature and address states its scheme, and `kern.crypto.verify` dispatches on it. Today the scheme is implicit and Ed25519 is the only code path. This is what makes any later change possible, including a change to schemes that do not exist yet.
2. **Hybrid signatures.** A signature is an Ed25519 signature and an ML-DSA signature (FIPS 204), and it is valid only if both are. ML-DSA is the lattice signature that NIST standardized in 2024. It is younger than Ed25519, which is why both are required: forging takes breaking both, so Kern keeps the security it has today if a flaw is found in ML-DSA or in an implementation of it. ML-DSA is available to both client languages without a research library: the `cryptography` package from version 48 in Python, and `crypto/mldsa` from Go 1.27.
3. **Accounts and addresses.** An address becomes the 256-bit hash of the scheme and the public keys. The public key is recorded in the account at first use, so that later transactions carry a signature and no key, and so that an account can replace its key.
4. **Validators.** Validator sets hold hybrid keys. Proposals, votes and quorum certificates carry hybrid signatures.
5. **Size accounting.** The fee floor and the block size cap count signatures (section 4).
6. **Peer connections.** The authenticated handshake planned with the hardening of the network layer uses a hybrid key agreement (X25519 with ML-KEM, FIPS 203).
7. **Proofs and identifiers.** The field `proof_system` of a claim already names its proof system. `groth16-bn254` stays available and is documented as classical. The three 128-bit identifiers move to 256 bits.

Kern keys are already derived from a seed. Research on EdDSA chains shows that the seed lets an owner prove ownership even after the curve is broken ([ePrint 2025/1368](https://eprint.iacr.org/2025/1368)). Hybrid keys from genesis make that recovery path unnecessary; it remains a fallback.

What the plan does not solve:

- **Aggregation.** No standardized post-quantum scheme aggregates signatures, so a quorum certificate grows with the number of validators (section 4).
- **Zero-knowledge claims.** Groth16 on BN254 stays classical until a proof system built on hash functions is added.
- **Certainty.** ML-DSA is a standard believed to resist quantum computers. It is not proven to, and no scheme is.

Decisions still open:

- ML-DSA-44 or ML-DSA-65.
- The exact hybrid construction (what each signature covers, domain separation) and the encodings, in a design note to be reviewed before any code is written.
- A binary encoding for keys and signatures in place of base58 text.
- Whether precompile 0x01 offers the hybrid check to contracts.
- Signatures built on hash functions alone (SLH-DSA, FIPS 205) for the rare signatures that must hold for decades, such as those of a genesis.

## 4. What hybrid signatures would cost

The sizes below are computed by the test with the encoder of this repository, for a transfer of 1 KRN bound to a chain identifier. ML-DSA sizes are the fixed sizes of FIPS 204. A hybrid key or signature is taken to be the Ed25519 one followed by the ML-DSA one, encoded as today (base58check text in JSON). A binary encoding would save about a quarter.

| | Today (Ed25519) | Hybrid with ML-DSA-44 | Hybrid with ML-DSA-65 |
|---|---:|---:|---:|
| Public key, bytes | 32 | 1,344 | 1,984 |
| Signature, bytes | 64 | 2,484 | 3,373 |
| Public key, encoded characters | 53 | 1,845 | 2,719 |
| Signature, encoded characters | 98 | 3,403 | 4,617 |
| Transfer, signed payload | 345 | 2,137 | 3,011 |
| Transfer, complete | 458 | 5,555 | 7,643 |
| Transfer, complete, key kept in the account | n/a | 3,710 | 4,924 |
| Certificate of 4 signatures | 392 | 13,612 | 18,468 |
| Certificate of 30 signatures | 2,940 | 102,090 | 138,510 |
| Certificate of 100 signatures | 9,800 | 340,300 | 461,700 |

Transfers are in bytes of JSON without whitespace; a certificate is counted as the encoded characters of its signatures.

How to read it:

- A transfer becomes about twelve times larger with ML-DSA-44, and about eight times when the public key is kept in the account.
- The Previewnet is planned with about 30 validators. Their certificate goes from 3 kilobytes to about 100 per block. With 100 validators it is a third of a megabyte.
- The text encoding has to change for large values. The base58 conversion of this repository is quadratic in the length: a few microseconds for a 64-byte signature, several milliseconds for a hybrid one, which is more than the time needed to verify it. Hybrid keys and signatures need an encoding that is linear, such as base64; addresses stay short and can keep base58check.
- Signature bytes are not counted today. `encoded_size()`, which the optional fee floor and the block size cap use, is the length of the signed payload: it includes the public key and leaves the signature out. With 64-byte signatures the difference is small. With hybrid signatures the signature is the largest part of a transaction, so the accounting has to include it before the formats are frozen.

## 5. What Kern does not claim

- Kern is not post-quantum today, and no document of this repository says it is. A test keeps it so: any line of the README, the documentation or the website that mentions quantum computers must link to this page.
- Kern will never be called quantum proof. No signature scheme is proven secure against quantum computers. The hybrid construction is there for the case where the belief in ML-DSA turns out wrong.
- The words become available one step at a time. With this page: the inventory and the plan are public. Once hybrid signatures are implemented, pass the test vectors of NIST in both clients, reject every message whose classical half is valid and whose post-quantum half is not, and have been reviewed by a cryptographer: hybrid post-quantum signatures from the first block, with the limits of section 3 stated next to them.

## 6. References

- NIST, [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA), August 2024.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), Edwards-Curve Digital Signature Algorithm, and [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693), BLAKE2.
- R. Babbush and others, [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations](https://arxiv.org/abs/2603.28846), 2026.
- F. Baldimtsi, K. Chalkias, A. Roy and M. Sedaghat, [Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368), 2025.
- European Commission and Member States, [A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography), June 2025.
- ML-DSA in the client languages: [changelog of the `cryptography` package](https://cryptography.io/en/latest/changelog/) (version 48.0.0) and [Go 1.27 release notes](https://go.dev/doc/go1.27).
