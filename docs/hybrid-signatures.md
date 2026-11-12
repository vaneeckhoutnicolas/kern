# Hybrid signatures (design)

> **Status.** Draft for review. Nothing in this note is implemented. The [cryptographic inventory](cryptographic-inventory.md) describes what the code does today: every signature is Ed25519, and no part of Kern is post-quantum.

Kern is not in production, so its formats can still change without migrating anyone. The decision is to make the protocol post-quantum by construction, in a dedicated release (1.2), before any network beyond the devnet exists. This note says how. It is written to be challenged: each choice gives its reason and what it costs, and section 9 lists the points on which a reviewer is asked to rule.

## 1. The proposal in one table

| Subject | Proposal |
|---|---|
| Scheme | Composite ML-DSA as standardized by the IETF (RFC 10073), in one combination: ML-DSA-65 with Ed25519 |
| Rule | A signature is valid only if both components are |
| Keys | Both component keys derived from the 32-byte seed Kern already uses |
| Text form | `kpk1.` and `ksig1.` followed by base64url; addresses keep `kn1` and base58check |
| Addresses | 256-bit hash of the scheme and the public key |
| Where keys live | Stored once in the state (validator set, account key registry, rollup descriptor), never repeated in messages |
| Sizes | The fee floor and the block size cap count the signature |
| Classical leftovers | Precompile 0x01 (Ed25519) and the Groth16 verifier (BN254) stay, documented as classical |
| Release | 1.2.0rc1; a devnet started with an earlier version has to be reset |

## 2. The scheme

### 2.1 A standard construction, not one of our own

Combining two signature schemes looks trivial and has traps: which bytes each one signs, how the two are tied together, how a signature made for one purpose is kept from serving another. The IETF has specified this as **Composite ML-DSA**. The IETF datatracker records its publication as RFC 10073, a Proposed Standard, from [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/). Kern uses it as written instead of defining its own.

Kern uses a single combination of that standard:

| | |
|---|---|
| Name | `id-MLDSA65-Ed25519-SHA512` (OID 1.3.6.1.5.5.7.6.48) |
| Post-quantum component | ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) |
| Classical component | Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) |
| Public key | ML-DSA public key followed by the Ed25519 public key: 1,952 + 32 = 1,984 bytes |
| Signature | ML-DSA signature followed by the Ed25519 signature: 3,309 + 64 = 3,373 bytes |
| Private key | ML-DSA seed followed by the Ed25519 seed: 64 bytes |

To sign a message `M` in a context `ctx`:

```
M'       = "CompositeAlgorithmSignatures2025" || "COMPSIG-MLDSA65-Ed25519-SHA512" || len(ctx) || ctx || SHA-512(M)
mldsaSig = ML-DSA-65.Sign(mldsaKey, M', context = "COMPSIG-MLDSA65-Ed25519-SHA512")
edSig    = Ed25519.Sign(edKey, M')
signature = mldsaSig || edSig
```

To verify, rebuild `M'` and verify both components. If either fails, the signature is invalid.

Both components sign the same `M'`, which names the combination. A component signature therefore cannot be taken out and presented as an ordinary ML-DSA or Ed25519 signature of `M`: it is a signature of `M'`.

### 2.2 Why these parameters

- **Hybrid.** ML-DSA was standardized in 2024 and is younger than Ed25519. With both required, forging a signature takes breaking both: Kern keeps the security it has today if a flaw is found in ML-DSA or in a library, and resists a quantum computer if Ed25519 falls. The German federal office for information security (BSI) asks for ML-DSA to be used in hybrid, and the French agency (ANSSI) states that the concatenation of a classical and a post-quantum signature meets its requirement.
- **ML-DSA-65, not ML-DSA-44.** The BSI recommends ML-DSA-65 or ML-DSA-87 only (TR-02102-1, version of January 2026). For a protocol that addresses European institutions, the smaller parameter set would be a weakness in every due diligence. The price is about a third more bytes than ML-DSA-44 (section 5).
- **Libraries.** ML-DSA comes from the `cryptography` package (version 48 or later, built on OpenSSL 3.5 or later), which is licensed under Apache 2.0 or BSD. It installs without compiling on Linux (checked under Python 3.11 and 3.13), and a Windows build is published. Ed25519 stays on PyNaCl, so the classical component is verified by the same code as today. The Go client has both in its standard library (`crypto/mldsa` from Go 1.27, `crypto/ed25519`).

### 2.3 What it does not give

- **Certainty.** ML-DSA is believed to resist quantum computers. It is not proven to, and no scheme is.
- **Aggregation.** A quorum certificate carries one composite signature per validator. Nothing standardized shrinks it.
- **Proofs.** The Groth16 verifier on BN254 and precompile 0x01 are untouched and stay classical.

## 3. Keys

A Kern key is a 32-byte seed today, and stays one. The two component seeds are derived from it with the keyed hash the protocol already uses, BLAKE2b with a 32-byte output, under two new domains:

| Component seed | Hash domain |
|---|---|
| ML-DSA-65 | `kern.key.mldsa65` |
| Ed25519 | `kern.key.ed25519` |

The private key is the first seed followed by the second, 64 bytes, which is the serialization of RFC 10073.

Key files keep their `seed_hex` field. An existing seed gives a new key pair and a new address.

RFC 10073 generates the two component keys independently and forbids using a component key outside the composite. The derivation above keeps both properties: the two seeds are outputs of a keyed hash under different keys, and no function of Kern signs with one component alone. Precompile 0x01 verifies Ed25519 signatures of 32-byte messages; `M'` is always longer, so a component signature can never be replayed through it.

## 4. Identifiers and text forms

**Scheme identifier.** Scheme 1 is the combination of section 2. The identifier is visible in the text form of every key and signature, and it is hashed into every address. Adding a scheme later is a new number, not a new format.

**Public keys and signatures.** `kpk1.` followed by the base64url encoding, without padding, of the 1,984 bytes (2,651 characters), and `ksig1.` followed by that of the 3,373 bytes (4,504 characters). They need no checksum: a damaged signature fails verification and a damaged key fails the address check.

Base58 is not used for them because the conversion in this repository is quadratic in the length. Measured on one machine: 16 milliseconds to encode a signature of this size and 4 to decode it, against less than 20 microseconds for base64, and against 0.3 millisecond to verify the signature itself.

**Addresses.** An address is the base58check form of a 256-bit hash:

```
address = base58check_encode(prefix || blake2b(0x01 || public_key, digest_size=32, key="kern.addr"))
```

`0x01` is the scheme identifier, and the prefix is chosen so that addresses still begin with `kn1` (three-byte prefixes from `0x430bbb` to `0x430bd7` do, whatever the hash). Addresses are short and typed by people, so they keep base58check and its checksum. They grow from 36 to 53 characters.

**Other identifiers.** The three 128-bit identifiers (governance proposals, attestations, verifier keys) and the 160-bit addresses of the Mini-EVM move to 256 bits with the same change of formats.

## 5. Where keys live, and what a signature covers

**A public key is stored once and never repeated.** A composite public key is 2.6 kilobytes of text; today a 53-character key travels in every transaction, block header and vote.

- **Validators.** Their keys are in the validator set already. Consensus messages, quorum certificates and block headers carry the address of the validator and its signature; the fields `validator_pubkey` and `proposer_pubkey` go.
- **Accounts.** The state gains a key registry, address to public key. The first transaction of an account carries `sender_pubkey`, which must hash to the address and is recorded. Later transactions leave it empty. A new operation, `rotate_key`, signed by the current key, replaces it; the address does not change.
- **Rollups.** The sequencer key is in the rollup descriptor already; batches drop `sequencer_pubkey`.

**Contexts.** Every signature is made in a context, the `ctx` of section 2.1, which states its purpose and its network:

```
ctx = purpose || 0x00 || chain_id        purpose in { "kern.tx", "kern.header", "kern.vote", "kern.batch" }
```

A signature made for one purpose or one network is invalid for any other. Today only transactions are bound to a chain identifier, through their payload.

**Sizes.** `Transaction.encoded_size()` becomes the size of the whole transaction, signature and key included, so that the fee floor and the block size cap see what a transaction really weighs. Estimates with the text forms above:

| | Today | Composite |
|---|---:|---:|
| Transfer, first of an account | 458 bytes | about 7.5 kilobytes |
| Transfer, later ones | 458 bytes | about 4.8 kilobytes |
| Certificate of 30 validators | 2,940 characters | about 135 kilobytes |
| Certificate of 100 validators | 9,800 characters | about 450 kilobytes |
| Verifying one signature | 0.06 millisecond | about 0.3 millisecond |
| Signing | 0.03 millisecond | about 1.1 milliseconds |

The composite figures were measured with the construction of section 2 written out with the real libraries, outside the repository: sizes as stated, and every altered case refused (either component damaged, another message, another purpose, another chain, another key).

With the default cap of one mebibyte per block, a block holds about 210 later transfers. The cap is a governance parameter and its default is one of the questions of section 9.

## 6. Consequences in the code

- **Signatures are randomized.** Ed25519 gives one signature per key and message; ML-DSA, as provided by the library, gives a different one each time. Nothing may depend on the bytes of a signature. Checked so far: a transaction identifier is the hash of the signed payload, without the signature; the vote deduplication key is (kind, level, round, validator, block hash); the signing journal records what was signed, not the signature. The comment of `kern/signing_journal.py` which says that signing a message again reproduces the same signature has to change, and the equivocation evidence has to be read with this in mind.
- **Two clients, one verdict.** Implementations of Ed25519 disagree on edge cases: keys and signature points of small order, encodings that are not canonical ([Taming the many EdDSAs](https://eprint.iacr.org/2020/1244)). An account owner can craft such a signature for his own key, and if the Python client rejects what the Go client accepts, a block splits the network. The conformance vectors must include these cases, and both clients must give the answer of libsodium. [go-port-breakpoints.md](go-port-breakpoints.md) lists Ed25519 as interoperable without this caveat today.
- **Everything is regenerated.** Every address changes. The genesis of the repository, the devnet generator, the wallet, the explorer and the examples of the documentation are regenerated; a devnet has to be reset.
- **One more dependency.** The `cryptography` package joins PyNaCl and py_ecc in the inventory.

## 7. Tests that come before the words

The [inventory](cryptographic-inventory.md) refuses any claim of resistance until the following exist and pass, in both clients where the client is concerned:

1. The test vectors of RFC 10073 for this combination: the published signatures verify, and the published seeds give the published public keys.
2. The test vectors of NIST for ML-DSA-65 (key generation and signature verification, with the invalid cases).
3. **Ed25519 assumed broken.** At every place a signature is checked (transaction, block header, vote, quorum certificate, rollup batch, slashing evidence), a message whose Ed25519 component is valid and whose ML-DSA component is not must be refused. And the reverse.
4. **Contexts.** A signature made for one purpose or one chain identifier is refused for another.
5. The Ed25519 edge cases of section 6.
6. The existing consensus simulator and the tests with real processes, unchanged in what they assert.

## 8. Order of work

1. Inventory and guard tests (merged).
2. This note, reviewed.
3. `kern/crypto.py`: composite keys, signatures and addresses, with tests 1 to 5.
4. Formats and state: transactions, headers, votes, certificates, batches, genesis, devnet, wallet, explorer.
5. Account key registry, `rotate_key`, size accounting.
6. Conformance vectors for the Go client, documentation, release 1.2.0rc1.

## 9. Questions for the reviewer

1. Is deriving both component seeds from one seed (section 3) acceptable, or should a key file hold two independent seeds as RFC 10073 generates them?
2. Should the account key registry and `rotate_key` be part of this release, or should every transaction carry its key until a later one?
3. Is the context of section 5 the right one, and should the chain identifier also stay inside the signed payload of transactions?
4. What should the default block size cap be once transactions weigh five kilobytes?
5. Should a precompile verify composite signatures for contracts in this release, or later?
6. Should the signatures of a genesis use a scheme built on hash functions alone (SLH-DSA, FIPS 205)?

## References

- IETF, Composite ML-DSA, [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/), recorded by the datatracker as published in RFC 10073.
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard, August 2024.
- BSI TR-02102-1, version 2026-01, as summarized by [Fraunhofer AISEC](https://www.aisec.fraunhofer.de/en/spotlights/Competence-Center-PQC/developments-in-pqc.html).
- ANSSI, [questions and answers on post-quantum cryptography](https://cyber.gouv.fr/cryptographie-post-quantique-faq).
- K. Chalkias, F. Garillot and V. Nikolaenko, [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244), 2020.
