# Hybrid signatures (design)

> **Status.** Draft for review. Nothing in this note is implemented. The [cryptographic inventory](cryptographic-inventory.md) describes what the code does today: every signature is Ed25519, and no part of Kern is post-quantum.

Kern is not in production, so its formats can still change without migrating anyone. The decision is to make the protocol post-quantum by construction, in a dedicated release (1.2), before any network beyond the devnet exists. This note is the cryptographic profile of that release: what is signed and how, how keys are derived, how large each hash is and why.

This is its second version. A first review, on 12 November 2026, is recorded in section 12; the choices it led to are marked **decided**. The profile is frozen, and code written, only after a second review of this version. Section 13 lists what that review is asked to rule on.

## 1. The profile in one table

| Subject | Choice |
|---|---|
| Signature scheme | Composite ML-DSA as standardized by the IETF (RFC 10073), in one combination: ML-DSA-65 with Ed25519 |
| Rule | A signature is valid only if both components are. No other scheme is accepted anywhere, and there is no fallback |
| Keys | Both component keys derived from the 32-byte seed Kern already uses, and bound to one network (**decided**) |
| Commitments | 384-bit hashes for everything that commits to content: blocks, transactions, state, Merkle trees (**decided**) |
| Addresses | 256-bit hash of the scheme and the public key, with a rule that makes collisions harmless |
| Text forms | `kpk1.` and `ksig1.` followed by base64url; addresses keep `kn1` and base58check |
| Where keys live | Stored once in the state (validator set, account key registry, rollup descriptor), never repeated in messages; key registry and rotation in this release (**decided**) |
| Signing contexts | Every signature states its purpose and its network |
| Sizes | The fee floor and the block size cap count the signature |
| Classical leftovers | Precompile 0x01 (Ed25519) and the Groth16 verifier (BN254) stay, documented as classical |
| Release | 1.2.0rc1; a devnet started with an earlier version has to be reset |

## 2. The signature scheme

### 2.1 A standard mechanism, a Kern profile

Combining two signature schemes looks trivial and has traps: which bytes each one signs, how the two are tied together, how a signature made for one purpose is kept from serving another. The IETF has specified this as **Composite ML-DSA**, published as RFC 10073 in November 2026 (from [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/)). Kern uses it instead of defining its own.

RFC 10073 is written for certificates. Kern takes its mechanism and nothing else: how the keys are generated, what the two components sign, how keys and signatures are serialized. It takes none of the X.509 structures. Around that mechanism Kern defines its own profile, which is the rest of this note: contexts, key derivation, text forms, addresses.

Kern uses a single combination of the standard:

| | |
|---|---|
| Name | `id-MLDSA65-Ed25519-SHA512` (OID 1.3.6.1.5.5.7.6.48, quoted for reference; Kern formats carry a scheme number) |
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

### 2.2 Why these parameters

- **Hybrid.** ML-DSA was standardized in 2024 and is younger than Ed25519. With both required, forging a signature takes breaking both: Kern keeps the security it has today if a flaw is found in ML-DSA or in a library, and resists a quantum computer if Ed25519 falls. The German federal office for information security (BSI) asks for ML-DSA to be used in hybrid, and the French agency (ANSSI) states that the concatenation of a classical and a post-quantum signature meets its requirement.
- **ML-DSA-65, not ML-DSA-44.** The BSI recommends ML-DSA-65 or ML-DSA-87 only (TR-02102-1, version of January 2026). For a protocol that addresses European institutions, the smaller parameter set would be a weakness in every due diligence. The price is about a third more bytes than ML-DSA-44. ANSSI states a preference for the highest level; the standard pairs ML-DSA-87 with other classical algorithms than Ed25519, and the scheme number of section 5 leaves room for such a combination later.
- **Libraries.** ML-DSA comes from the `cryptography` package (version 48 or later, built on OpenSSL 3.5 or later), which is licensed under Apache 2.0 or BSD. It installs without compiling on Linux (checked under Python 3.11 and 3.13), and a Windows build is published. Ed25519 stays on PyNaCl, so the classical component is verified by the same code as today. The Go client has both in its standard library (`crypto/mldsa` from Go 1.27, `crypto/ed25519`).

### 2.3 What it guarantees, and what it does not

- **Unforgeable if either component is.** RFC 10073 (section 9.2.1) states that the composite resists forgery as long as one of its components does and the pre-hash is collision resistant. SHA-512 is sized well above the rest of the profile (section 4).
- **Not strongly unforgeable.** The RFC is explicit (section 9.2.2): another valid signature of a message that was already signed can exist. The signer can produce as many as he wants, because ML-DSA signing is randomized. And whoever breaks Ed25519 can replace the Ed25519 component of any signature he sees. The RFC advises against the scheme wherever that would matter. **So in Kern nothing may depend on the bytes of a signature**: no identifier, no deduplication key, no evidence, no stored commitment. Section 9 lists what was checked in the code and section 10 the tests that hold the rule.
- **A component is not a signature.** Both components sign `M'`, which names the combination. A component cannot be taken out and presented as an ordinary ML-DSA or Ed25519 signature of `M`.
- **No certainty.** ML-DSA is believed to resist quantum computers. It is not proven to, and no scheme is.
- **No aggregation.** A quorum certificate carries one composite signature per validator. Nothing standardized shrinks it, and Kern does not invent an aggregation of its own.

### 2.4 No fallback

A network has one signature scheme, named in its genesis. On a network of scheme 1, an Ed25519 signature alone is invalid everywhere a signature is checked, however valid it is as Ed25519. There is no flag, no transition period and no mixed validator set. A later scheme is a new number, introduced by a protocol amendment.

## 3. Keys

A Kern key is a 32-byte seed drawn from the generator of the operating system, and stays one. The two component seeds are derived from it **and from the identifier of the network** (**decided**), with the keyed hash the protocol already uses, BLAKE2b with a 32-byte output:

| Component seed | Hash domain | Hashed input |
|---|---|---|
| ML-DSA-65 | `kern.key.mldsa65` | One byte giving the length of the chain identifier, the chain identifier, the seed |
| Ed25519 | `kern.key.ed25519` | The same |

The private key is the first seed followed by the second, 64 bytes, which is the serialization of RFC 10073.

- **Bound to one network.** The same seed gives another key pair and another address on every network. A key exposed on a test network says nothing about the key of the main one, and component keys cannot be shared between networks by accident. A key file keeps its `seed_hex` field and names no network: the wallet already asks the node for the chain identifier before it signs, and the tools that write a genesis take the chain identifier first.
- **Independent components.** RFC 10073 generates the two component keys independently and forbids using a component key outside the composite. The two seeds are outputs of a keyed hash under different domains, and no function of Kern signs with one component alone. Precompile 0x01 verifies Ed25519 signatures of 32-byte messages; `M'` is always longer, so a component can never be replayed through it.
- **Rotation, and its limit.** The operation `rotate_key` (section 6) lets an account replace its key. It does not save an account whose seed is stolen if the thief acts first. A second key, kept offline and able to take the account back, is a possible later addition.
- **Storage.** A seed is a file in clear text today. A hybrid scheme does nothing for a stolen seed; encrypted key files and hardware modules are listed in section 8.

## 4. Hash sizes

Signatures are not the only primitive. A hash is sized against two generic attacks, and a quantum computer lowers both: finding a preimage of an n-bit hash goes from 2^n evaluations to about 2^(n/2), and finding a collision from 2^(n/2) to about 2^(n/3). The second figure assumes a quantum memory as large as the search and is not the estimate of a practical attack. It is the figure a conservative design is sized against, and ANSSI asks for hash functions at the level of SHA2-384 in this transition.

Each size below follows from what an attacker would need.

| Object | What an attacker would need | Size | Generic cost today | Generic quantum bound |
|---|---|---|---|---|
| Commitments: block headers, transactions, Merkle roots, the state root and trie nodes, rollup batches and programs, forced inclusion requests, Mini-EVM states | A collision. Whoever builds the object chooses its content | **384 bits** (**decided**) | 2^192 | 2^128 |
| Pre-hash of a signature (SHA-512, fixed by RFC 10073) | A collision | 512 bits | 2^256 | About 2^171 |
| Addresses of accounts and contracts | A second preimage. Collisions are made harmless by the rule below | 256 bits | 2^256 | 2^128 |
| Identifiers of proposals, attestations and verifier keys | A second preimage. The chain stores the content under the identifier and refuses a duplicate | 256 bits | 2^256 | 2^128 |
| Checksum of an address | Nothing. It catches typing errors | 32 bits | | |

BLAKE2b gives any output size up to 512 bits at the same cost, in both client languages. A commitment grows by 16 bytes, which is nothing next to a signature of 3,373.

**The address rule.** An address that holds a contract can never sign a transaction or receive a key, and a contract cannot be originated at an address that has a registered key. A collision between the address of a key and the address of a contract is the one case where two colliding addresses would matter, and under this rule it gives nothing. Addresses can therefore stay at 256 bits, short enough to be read and typed.

## 5. Identifiers and text forms

**Scheme number.** Scheme 1 is the combination of section 2. The number is visible in the text form of every key and signature, it is hashed into every address, and it is named in the genesis.

**Public keys and signatures.** `kpk1.` followed by the base64url encoding, without padding, of the 1,984 bytes (2,651 characters), and `ksig1.` followed by that of the 3,373 bytes (4,504 characters). They need no checksum: a damaged signature fails verification and a damaged key fails the address check.

Base58 is not used for them because the conversion in this repository is quadratic in the length. Measured on one machine: 16 milliseconds to encode a signature of this size and 4 to decode it, against less than 20 microseconds for base64, and against 0.3 millisecond to verify the signature itself.

**Addresses.** An address is the base58check form of a 256-bit hash:

```
address = base58check_encode(prefix || blake2b(0x01 || public_key, digest_size=32, key="kern.addr"))
```

`0x01` is the scheme number, and the prefix is chosen so that addresses still begin with `kn1` (three-byte prefixes from `0x430bbb` to `0x430bd7` do, whatever the hash). Since the public key depends on the network, so does the address. Addresses grow from 36 to 53 characters.

**Hashes.** A commitment is written as 96 hexadecimal characters, where it is 64 today.

## 6. Where keys live, and what a signature covers

**A public key is stored once and never repeated.** A composite public key is 2.6 kilobytes of text; today a 53-character key travels in every transaction, block header and vote.

- **Validators.** Their keys are in the validator set already. Consensus messages, quorum certificates and block headers carry the address of the validator and its signature; the fields `validator_pubkey` and `proposer_pubkey` go.
- **Accounts** (**decided**: in this release). The state gains a key registry, address to public key. The first transaction of an account carries `sender_pubkey`, which must hash to the address and is recorded. Later transactions leave it empty. The operation `rotate_key`, signed by the current key, replaces it; the address does not change.
- **Rollups.** The sequencer key is in the rollup descriptor already; batches drop `sequencer_pubkey`.

**Contexts.** Every signature is made in a context, the `ctx` of section 2.1. It is specified to the character, because two clients must build the same bytes:

- **Purpose.** One of four ASCII strings, exactly: `kern.tx` for transactions, `kern.header` for block headers, `kern.consensus` for proposals, pre-endorsements and endorsements (and so for quorum certificates and slashing evidence), `kern.batch` for rollup batches.
- **Chain identifier.** From 1 to 64 characters, each a lowercase letter from a to z, a digit or a hyphen, the first one a letter. It becomes mandatory: a genesis without one, or with one of another form, is refused. Being ASCII, it needs no normalization.
- **Context.** The purpose, one zero byte, the chain identifier. At most 79 bytes, under the limit of 255 that RFC 10073 sets.
- **Errors.** Signing in a context that is not well formed raises an error. Verifying in such a context answers no, like any invalid signature.

A signature made for one purpose or one network is invalid for any other. The chain identifier also stays in the signed payload of a transaction, where tools read it.

## 7. Sizes and measurements

`Transaction.encoded_size()` becomes the size of the whole transaction, signature and key included, so that the fee floor and the block size cap see what a transaction really weighs. Estimates with the text forms above:

| | Today | Composite |
|---|---:|---:|
| Transfer, first of an account | 458 bytes | about 7.5 kilobytes |
| Transfer, later ones | 458 bytes | about 4.8 kilobytes |
| Certificate of 30 validators | 2,940 characters | about 135 kilobytes |
| Certificate of 100 validators | 9,800 characters | about 450 kilobytes |
| Verifying one signature | 0.06 millisecond | about 0.3 millisecond |
| Signing | 0.03 millisecond | about 1.1 milliseconds |

The composite figures were measured with the construction of section 2 written out with the real libraries, outside the repository: sizes as stated, and every altered case refused (either component damaged, another message, another purpose, another chain, another key).

With the present default cap of one mebibyte per block, a block holds about 210 later transfers. That default is not chosen here. It is chosen from measurements made with the implementation, on a devnet of 4, 30 and 100 validators and by projection beyond: signatures per second on one core, verification in parallel, time for a certificate to reach every validator, block size, bandwidth per validator.

## 8. What stays classical, and what comes later

Replacing signatures does not make a chain post-quantum everywhere. What this release leaves as it is, and says so:

- **Zero-knowledge claims.** The Groth16 verifier on BN254 stays, documented as classical. A proof system built on hash functions is the later answer; it does not block this release.
- **Precompile 0x01.** It keeps its Ed25519 interface for contracts, documented as classical. No rule of the protocol itself may rely on it. A precompile that verifies composite signatures is planned for contracts, after this release.
- **Peer connections.** They are neither encrypted nor authenticated today. The plan, with the hardening of the network layer, is TLS 1.3 with a standard hybrid key exchange and peers authenticated by a composite signature. ML-KEM establishes a secret and authenticates nobody, and Kern does not design a handshake of its own.
- **Root signatures.** The genesis, release tags and integrity manifests are signed rarely and must hold for decades. SLH-DSA (FIPS 205), built on hash functions alone, is the planned scheme for them: another family than ML-DSA, large and slow signatures that these uses can afford.
- **Key storage.** Encrypted key files and hardware security modules for validators.

## 9. Consequences in the code

- **Nothing depends on the bytes of a signature.** Checked so far: a transaction identifier is the hash of the signed payload, without the signature (`Transaction.hash`); a block hash is the hash of the header without its signature, and the certificate is outside it; the vote deduplication key in `kern/node.py` is (kind, level, round, validator, block hash); a slashing offence is identified in `kern/chain.py` by (validator, kind, level, round), so the same offence proved with other signature bytes is not punished twice; the signing journal records what was signed. To change: the comment of `kern/signing_journal.py` which says that signing a message again reproduces the same signature.
- **Two clients, one verdict.** Implementations of Ed25519 disagree on edge cases: keys and signature points of small order, encodings that are not canonical ([Taming the many EdDSAs](https://eprint.iacr.org/2020/1244)). An account owner can craft such a signature for his own key, and if the Python client rejects what the Go client accepts, a block splits the network. The conformance vectors must include these cases, and both clients must give the answer of libsodium. [go-port-breakpoints.md](go-port-breakpoints.md) lists Ed25519 as interoperable without this caveat today.
- **Hashes grow.** Every commitment field goes from 64 to 96 hexadecimal characters; strict decoding and its tests follow.
- **The chain identifier is mandatory.** Chains built by the tests get one.
- **Everything is regenerated.** Every address changes. The genesis of the repository, the devnet generator, the wallet, the explorer and the examples of the documentation are regenerated; a devnet has to be reset.
- **One more dependency.** The `cryptography` package joins PyNaCl and py_ecc in the inventory.

## 10. Tests that come before the words

The [inventory](cryptographic-inventory.md) refuses any claim of resistance until the following exist and pass. The Go client runs the same vectors, from the same files, and must give the same answers.

1. **The standard.** The test vectors of RFC 10073 for this combination: the published signatures verify, and the published seeds give the published public keys.
2. **NIST.** The test vectors for ML-DSA-65 (key generation and signature verification, with the invalid cases). The list of errata kept on the page of FIPS 204 is read again at each release.
3. **Ed25519 assumed broken.** At every place a signature is checked (transaction, block header, vote, quorum certificate, rollup batch, slashing evidence), a message whose Ed25519 component is valid and whose ML-DSA component is not must be refused. And the reverse.
4. **No fallback.** An Ed25519 signature alone is refused at each of those places.
5. **Contexts.** A signature made for one purpose or one chain identifier is refused for another. The context bytes of a fixed list of cases are part of the vectors.
6. **Signature bytes.** The same transaction or vote signed twice, or with its Ed25519 component replaced by another valid one, keeps its identifier, is counted once and is evidence of nothing.
7. **Keys.** A fixed seed and chain identifier give a fixed public key and address; another chain identifier gives another one.
8. **Ed25519 edge cases** of section 9.
9. **Addresses.** The rule of section 4: no transaction from an address that holds a contract, no contract at an address that has a key.
10. The existing consensus simulator and the tests with real processes, unchanged in what they assert.

## 11. Order of work

1. **Freeze the profile.** This note, after a second review.
2. **Implement**, behind the tests of section 10: `kern/crypto.py` (composite keys, signatures, addresses); then formats and state (384-bit commitments, contexts, mandatory chain identifier, no fallback, genesis, devnet, wallet, explorer); then the key registry, `rotate_key` and size accounting.
3. **Measure**, and choose the default block size cap.
4. **Second client.** Conformance vectors and differential tests with the Go client. Release 1.2.0rc1.
5. **Later.** Peer connections, root signatures, a composite precompile, proofs built on hash functions.

## 12. Review of 12 November 2026

A first review read the inventory and the first version of this note. It endorsed the direction (hybrid from genesis, ML-DSA-65 with Ed25519, the standard construction, no aggregation of our own) and asked for the following.

| Point raised | Outcome |
|---|---|
| RFC 10073 is written for X.509; Kern must define its own profile around the mechanism | Section 2.1 |
| The inventory dismissed quantum collision search; hash sizes must be justified one by one, with 384 bits considered for commitments | Accepted. The inventory now gives the generic bound, and section 4 justifies each size. Commitments move to 384 bits (decided). The bound is theoretical; it is taken as the sizing figure all the same |
| Key derivation needs a dedicated review; the same seed must not give the same keys on independent networks | Keys are bound to the network (decided, section 3). Entropy, component reuse, rotation and storage are stated there. The derivation is question 1 of section 13 |
| The composite is not strongly unforgeable; the protocol must never depend on signature bytes | Sections 2.3 and 9, test 6 |
| The context must be specified to the character, within 255 bytes | Section 6, test 5 |
| Groth16, precompile 0x01, peer connections, genesis and release signatures, key management remain classical or open | Section 8 |
| Costs must be measured up to hundreds of validators | Section 7 |
| The same vectors in Python and Go; follow the errata of NIST | Section 10. The errata known to us, announced on the NIST forum in 2024 and 2025, correct text and change no algorithm; the list on the page of FIPS 204 is read when the vectors are taken |
| No silent fallback to Ed25519 alone | Section 2.4, test 4 |

Also decided on that day: the account key registry and `rotate_key` are part of this release.

## 13. Questions for the next review

1. Is the derivation of section 3 sound: two domains, and as input a length byte, the chain identifier and the seed? Should it carry a version?
2. Is the address rule of section 4 enough for addresses to stay at 256 bits, or should they be 384 bits like commitments?
3. Are four purposes the right granularity, with one for all consensus messages?
4. Is there anything left in the code or in the formats that depends on the bytes of a signature?
5. Is anything missing from the tests of section 10 before the profile is frozen?

## References

- IETF, Composite ML-DSA, RFC 10073, read in [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/); the published text is to be checked line by line when the code is written.
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard, August 2024, and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
- BSI TR-02102-1, version 2026-01, as summarized by [Fraunhofer AISEC](https://www.aisec.fraunhofer.de/en/spotlights/Competence-Center-PQC/developments-in-pqc.html).
- ANSSI, [views on the post-quantum cryptography transition](https://cyber.gouv.fr/publications/anssi-views-post-quantum-cryptography-transition), 2022, and [questions and answers](https://cyber.gouv.fr/cryptographie-post-quantique-faq).
- G. Brassard, P. Høyer and A. Tapp, [Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002), 1997.
- K. Chalkias, F. Garillot and V. Nikolaenko, [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244), 2020.
