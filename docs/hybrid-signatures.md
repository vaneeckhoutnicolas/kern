# Hybrid signatures (design)

> **Status.** Draft for review. Nothing in this note is implemented. The [cryptographic inventory](cryptographic-inventory.md) describes what the code does today: every signature is Ed25519, and no part of Kern is post-quantum.

Kern is not in production, so its formats can still change without migrating anyone. The decision is to make the protocol post-quantum by construction, in a dedicated release (1.2), before any network beyond the devnet exists. This note is the cryptographic profile of that release: what is signed and how, how keys are derived, which hash function is used and at what size.

This is its third version. Two reviews, both on 12 November 2026, are recorded in sections 12 and 13; the choices they led to are marked **decided**. The second one checked the construction against the published text of RFC 10073, found it conforming, and asked for five changes before the profile is frozen. They are made here. The profile is frozen, and code written, after a last review limited to what changed. Section 14 lists what that review is asked to rule on.

## 1. The profile in one table

| Subject | Choice |
|---|---|
| Signature scheme | Composite ML-DSA as standardized by the IETF (RFC 10073), in one combination: ML-DSA-65 with Ed25519 |
| Rule | A signature is valid only if both components are. No other scheme is accepted anywhere, and there is no fallback |
| Network identity | A 32-byte identifier drawn at random when the genesis is built (**decided**). The chain name is a label |
| Keys | Both component keys derived from one 32-byte seed with HKDF-SHA-512, for one network and one version of the derivation |
| Hash function | SHA3-384 with a domain name, for everything the protocol hashes (**decided**) |
| Hash size | 384 bits for every commitment, identifier and address (**decided**) |
| Addresses | `kn1` and base58check as today, 75 characters |
| Text forms | `kpk1.` and `ksig1.` followed by base64url, one text per value |
| Where keys live | Stored once in the state (validator set, account key registry, rollup descriptor), never repeated in messages; key registry and rotation in this release (**decided**) |
| Signing contexts | Six purposes. Every signature states its purpose and its network |
| Ed25519 verification | One written rule, the same in every client |
| Blocks | The header commits to the signatures of its transactions (proposed) |
| Sizes | The fee floor and the block size cap count the signature |
| Classical leftovers | Precompile 0x01 (Ed25519) and the Groth16 verifier (BN254) stay, documented as classical |
| Release | 1.2.0rc1; a devnet started with an earlier version has to be reset |

## 2. The signature scheme

### 2.1 A standard mechanism, a Kern profile

Combining two signature schemes looks trivial and has traps: which bytes each one signs, how the two are tied together, how a signature made for one purpose is kept from serving another. The IETF has specified this as **Composite ML-DSA**, published as RFC 10073 in October 2026 (from [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/)). Kern uses it instead of defining its own.

RFC 10073 is written for certificates. Kern takes its mechanism and nothing else: how the keys are generated, what the two components sign, how keys and signatures are serialized. It takes none of the X.509 structures, and a Kern signature is not meant to be read by software that handles certificates. Around that mechanism Kern defines its own profile, which is the rest of this note: network identity, key derivation, contexts, text forms, addresses.

Kern uses a single combination of the standard:

| | |
|---|---|
| Name | `id-MLDSA65-Ed25519-SHA512` (OID 1.3.6.1.5.5.7.6.48, quoted for reference; Kern formats carry a scheme number) |
| Post-quantum component | ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) |
| Classical component | Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) |
| Public key | ML-DSA public key followed by the Ed25519 public key: 1,952 + 32 = 1,984 bytes |
| Signature | ML-DSA signature followed by the Ed25519 signature: 3,309 + 64 = 3,373 bytes |
| Private key | ML-DSA seed followed by the Ed25519 seed: 64 bytes |

To sign a message `M` in a context `ctx` (RFC 10073, sections 2.2 and 3.2):

```
Prefix    = "CompositeAlgorithmSignatures2025"
Label     = "COMPSIG-MLDSA65-Ed25519-SHA512"
M'        = Prefix || Label || len(ctx) || ctx || SHA-512(M)
mldsaSig  = ML-DSA-65.Sign(mldsaKey, M', mldsa_ctx = Label)
edSig     = Ed25519.Sign(edKey, M')
signature = mldsaSig || edSig
```

Two contexts appear, and they are not the same thing. `ctx` is the context of the application, which Kern supplies (section 6.2): one byte gives its length, then come its bytes. `mldsa_ctx` is the context parameter of ML-DSA itself: it is always the Label, and never anything chosen by Kern.

To verify, rebuild `M'` and verify both components. If either fails, the signature is invalid.

This construction has been run against the test vectors published with the RFC for this combination: the published private key gives the published public key, the two published signatures verify (without a context and with one), and every altered case is refused.

### 2.2 Why these parameters

- **Hybrid.** ML-DSA was standardized in 2024 and is younger than Ed25519. With both required, forging a signature takes breaking both: Kern keeps the security it has today if a flaw is found in ML-DSA or in a library, and resists a quantum computer if Ed25519 falls. The German federal office for information security (BSI) asks for ML-DSA to be used in hybrid, and the French agency (ANSSI) states that the concatenation of a classical and a post-quantum signature meets its requirement.
- **ML-DSA-65, not ML-DSA-44.** The BSI recommends ML-DSA-65 or ML-DSA-87 only (TR-02102-1, version of January 2026). For a protocol that addresses European institutions, the smaller parameter set would be a weakness in every due diligence. The price is about a third more bytes than ML-DSA-44. ANSSI states a preference for the highest level; the standard pairs ML-DSA-87 with other classical algorithms than Ed25519, and the scheme number of section 5 leaves room for such a combination later.
- **Libraries.** ML-DSA comes from the `cryptography` package, version 48 or later (version 47 does not provide it), which is licensed under Apache 2.0 or BSD. It installs without compiling on Linux (checked under Python 3.11 and 3.13), a Windows build is published, and it passes the test vectors of NIST for ML-DSA-65, invalid cases included. Ed25519 stays on PyNaCl, so the classical component is verified by the same code as today. The Go client has both in its standard library (`crypto/mldsa` from Go 1.27, `crypto/ed25519`).

### 2.3 What it guarantees, and what it does not

- **Unforgeable if either component is.** In the terms of RFC 10073 (section 9.2.1): the composite is existentially unforgeable under chosen message attack (EUF-CMA) as long as one of its two components is, and as long as the pre-hash is collision resistant. SHA-512 is sized well above the rest of the profile.
- **Not strongly unforgeable against a quantum adversary.** The RFC is explicit (section 9.2.2): whoever breaks Ed25519 can replace the Ed25519 component of a signature he has seen, and so obtains another valid signature of a message that was already signed, without holding the key. The RFC advises against the scheme wherever that would matter.
- **Not unique either.** ML-DSA signing is randomized: the key holder produces other bytes every time he signs the same message. Even with Ed25519 a signer can do so, by choosing another nonce.
- **So nothing may identify a statement by the bytes of its signature**: no identifier, no deduplication key, no comparison, no evidence. A transaction, a vote or a proposal is what was signed. Signature bytes are committed to in one place only: a block, whose proposer commits to the transactions it carries together with their signatures (section 6.3). Section 9 lists what was checked in the code and section 10 the tests that hold the rule.
- **A component is not a signature.** Both components sign `M'`, which names the combination. A component cannot be taken out and presented as an ordinary ML-DSA or Ed25519 signature of `M` (RFC 10073, section 9.2.3).
- **No certainty.** ML-DSA is believed to resist quantum computers. It is not proven to, and no scheme is.
- **No aggregation.** A quorum certificate carries one composite signature per validator. Nothing standardized shrinks it, and Kern does not invent an aggregation of its own.

### 2.4 No fallback

A network has one signature scheme, named in its genesis. On a network of scheme 1, an Ed25519 signature alone is invalid everywhere a signature is checked, however valid it is as Ed25519. There is no flag, no transition period and no mixed validator set. A later scheme is a new number, introduced by a protocol amendment.

### 2.5 One verdict for Ed25519

Implementations of Ed25519 do not all accept the same signatures. RFC 8032 leaves a choice in the verification equation and says nothing about points of small order, and libraries differ ([Taming the many EdDSAs](https://eprint.iacr.org/2020/1244)). Measured for this note on 31 cases built for the purpose: the standard library of Go (1.24) and OpenSSL (4.0) accept 14 of them that libsodium, the library behind PyNaCl, refuses. All 14 have a public key of small order, or a nonce point that is the identity. The holder of an account can craft such a signature for a key of his own, and whoever owns the ML-DSA key makes that component valid. If one client accepted the result and another refused it, one transaction would split the network.

Kern therefore fixes one rule. It gives the verdict of libsodium on every case that could be built, and it is written out so that it depends on no library:

1. The public key `A` is 32 bytes and the signature 64 bytes: `R` then `S`.
2. `A` and `R` are canonical encodings: the 255-bit integer they carry is lower than p = 2^255 - 19.
3. Neither `A` nor `R` is one of the eight points of small order. Their y coordinates are 0, 1, p - 1 and the two values shared by the four points of order 8.
4. `S` is lower than the order of the group.
5. `[S]B = R + [k]A` holds exactly, not after multiplication by the cofactor, with `k` the SHA-512 of `R`, `A` and the message reduced modulo the order of the group.

A signature accepted under this rule is valid under RFC 8032. The rule applies to the Ed25519 component of every composite signature and to precompile 0x01. A client whose library is more lenient makes checks 2, 3 and 4 itself before calling it: with them, the standard library of Go and OpenSSL give the verdict of libsodium on all 31 cases. These cases and their verdicts are part of the conformance vectors.

## 3. Network identity and keys

### 3.1 The network identifier

A network is identified by `network_id` (**decided**): 32 bytes drawn from the generator of the operating system when its genesis is built, written in the genesis as 64 hexadecimal characters, and never changed afterwards. Keys are derived for one network identifier, and every signature is made for one.

A name is not an identity. Two operators can pick the same chain name, and the devnet generator of this repository writes the same one every time. With a random identifier, every genesis that is built is another network: the keys, addresses and signatures of one mean nothing on another.

- **The chain name stays, as a label.** `chain_id` is 1 to 64 characters, each a lowercase letter from a to z, a digit or a hyphen, the first one a letter. It becomes mandatory in the genesis and stays in the signed payload of a transaction, where tools and people read it. A node still refuses a transaction that names another chain. That check is a courtesy; the protection is the context of section 6.2.
- **A wallet does not learn its network from a node.** Today the wallet asks the node for the chain name and signs for it. With this profile, a key file records the network identifier next to the seed, or the wallet is given the genesis. It asks the node for its identifier and refuses to sign when the two differ. It never derives a key from a value a node supplied.
- **The limit.** Two networks started from the same genesis file are the same network at that point, with the same identifier. A fork that wants to be distinct changes its identifier by a protocol amendment, from a given level.

### 3.2 Derivation

A Kern key is a 32-byte seed drawn from the generator of the operating system, and stays one. The two component seeds are derived from it with HKDF ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) over SHA-512:

| Parameter of HKDF | Value |
|---|---|
| Input keying material | The seed, 32 bytes |
| Salt | None. RFC 5869 then uses 64 zero bytes |
| Info | Four fields, in this order: the 22 ASCII characters `KERN-KEY-DERIVATION-V1`; one byte for the scheme number, 0x01; the 32 bytes of the network identifier; the ASCII name of the component, `mldsa65` or `ed25519` |
| Output length | 32 bytes |

The private key is the output for `mldsa65` followed by the output for `ed25519`: 64 bytes, which is the serialization of RFC 10073. Every field of the info before the component name has a fixed length, so two different inputs never give the same info.

- **Allowed by the standard.** RFC 10073 (section 3.1) allows a deterministic generation in which one seed is expanded into the seeds of both components. It leaves the expansion to the application, and requires that both component keys be fresh and never used outside the composite.
- **A standard construction.** HKDF is among the key derivation mechanisms that the selection guide of ANSSI recommends. It is in the standard library of Go, and Python builds it from HMAC in a few lines. The derivation has been computed for fixed inputs by three independent implementations (the Python standard library, the `cryptography` package, the Go standard library), which agree. The vectors are delivered with the code.
- **Versioned.** The first field of the info is the version of the derivation. Another derivation is another label, and a key file records the version it was made with. The scheme number is a separate thing: the chain never sees how a key was derived.
- **Bound to one network.** The same seed gives another key pair and another address for every network identifier. A key exposed on a test network says nothing about the key of another network, and component keys cannot be shared between networks by accident.

### 3.3 What a key is never used for

- **Never a component alone.** RFC 10073 forbids using a component key outside the composite (sections 3.1 and 9.3): a key that also signs alone weakens the composite it belongs to. No function of Kern signs with one component, and none returns a component key.
- **Precompile 0x01.** It verifies Ed25519 signatures of 32-byte messages. `M'` is always longer, so the Ed25519 component of a composite signature cannot be replayed through it. That says nothing about the key itself: the holder of a seed could, by his own means, sign a 32-byte message with the Ed25519 component key. The rule of Kern is that no tool of Kern does. A key meant for a contract that verifies Ed25519 signatures is another key, derived from the seed under a component name of its own, `ed25519-standalone`, and never part of an account key.
- **Rotation, and its limit.** The operation `rotate_key` (section 6.1) lets an account replace its key. It does not save an account whose seed is stolen if the thief acts first. A second key, kept offline and able to take the account back, is a possible later addition.
- **Storage.** A seed is a file in clear text today. A hybrid scheme does nothing for a stolen seed; encrypted key files and hardware modules are listed in section 8.

## 4. Hashes

### 4.1 One function

Everything the protocol hashes goes through one function (**decided**):

```
H(domain, data) = SHA3-384( len(domain) || domain || data )
```

`domain` is the ASCII name of the use, from 1 to 255 bytes, preceded by its length on one byte. The names are those the code uses today (`kern.block`, `kern.tx`, `kern.state` and the others listed in the [inventory](cryptographic-inventory.md)). The output is 48 bytes.

Today the code hashes with BLAKE2b, keyed with the same names. BLAKE2b has no known weakness. But it is not a standard of NIST, and it is not among the hash functions that the selection guide of ANSSI recommends, which are those of the SHA-2 and SHA-3 families. A protocol that addresses institutions is asked about both. Every hash changes size in this release, so changing the function at the same time costs nothing more. SHA3-384 ([FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)) is in the standard library of both client languages. The length and the name in front of the data replace the key of BLAKE2b: two uses never hash the same bytes.

What does not move: SHA-512 inside the signatures (RFC 10073 and Ed25519) and in the key derivation; the hash functions inside ML-DSA; and the hash functions that contracts call (the `SHA3` opcode, precompiles 0x02 and 0x03, the placeholder at 0x09), which are interfaces for contracts and not commitments of the protocol.

### 4.2 One size

Every hash of the protocol is 384 bits (**decided**): commitments (block headers, transactions, Merkle roots, the state root and trie nodes, rollup batches and programs, forced inclusion requests, Mini-EVM states), identifiers (governance proposals, attestations, verifier keys) and addresses (accounts and contracts).

A hash is sized against two generic attacks, and a quantum computer lowers both: finding a preimage of an n-bit hash goes from 2^n evaluations to about 2^(n/2), and finding a collision from 2^(n/2) to about 2^(n/3). The second figure assumes a quantum memory as large as the search and is not the estimate of a practical attack. It is the figure a conservative design is sized against. The rules of ANSSI published in March 2026 require at least 256 bits, and recommend at least 384 bits when post-quantum security is sought; they add that 256 bits should be enough in the long run, and that the recommendation may become a rule.

| What an attacker would need | Generic cost today | Generic quantum bound |
|---|---|---|
| A collision: two contents of his choice with the same hash | 2^192 | 2^128 |
| A second preimage: another content for a hash that already exists | 2^384 | 2^192 |

The second version of this profile kept addresses and identifiers at 256 bits, on the argument that only second preimages matter for them. The second review showed that this argument has to be made object by object, and that it fails for some. The identifier of a governance proposal covers a payload and a salt that its author chooses, so the author can look for two proposals with one identifier. The address of a contract computed in advance covers code that its author chooses. With one size, no such argument is needed.

Three values are not commitments and keep their own size: the checksum of an address (32 bits, it catches typing errors), the pre-hash of a signature (SHA-512, fixed by RFC 10073), and the public draw of the proposer (64 bits taken from a hash).

### 4.3 What an address designates

The size makes collisions between addresses out of reach. The rules below hold in addition, so that what an address designates never changes silently.

1. **One kind.** An address designates an account or a contract, and never the other afterwards. An address that holds a contract can never sign a transaction or receive a key, and a contract cannot be originated at an address that has a recorded key. The genesis lists accounts and contracts separately, and no address may appear in both.
2. **One key at a time.** The registry maps an address to one public key. The first key recorded for an address is the one whose hash is the address. No other key is ever recorded for that address because it was presented: the only change is `rotate_key`, signed by the key currently recorded.
3. **No second presentation.** Once a key is recorded for an address, a transaction for that address that carries a public key is refused, whatever the key.
4. **Genesis.** An account funded in the genesis without a key follows rule 2 at its first transaction. The key of a validator is recorded by the genesis in the registry and in the validator set, and the two must agree.

## 5. Identifiers and text forms

**Scheme number.** Scheme 1 is the combination of section 2. The number is visible in the text form of every key and signature, it is hashed into every address and into every key derivation, and it is named in the genesis.

**Public keys and signatures.** `kpk1.` followed by the base64url encoding, without padding, of the 1,984 bytes (2,651 characters), and `ksig1.` followed by that of the 3,373 bytes (4,504 characters). They need no checksum: a damaged signature fails verification and a damaged key fails the address check.

**One text per value.** Decoding accepts the exact prefix, the exact length, the 64 characters of base64url and unused bits at zero, and refuses everything else: padding, another alphabet, spaces, a last character whose unused bits are set. Without this, two nodes could store two spellings of the same key.

Base58 is not used for keys and signatures because the conversion in this repository is quadratic in the length. Measured on one machine: 16 milliseconds to encode a signature of this size and 4 to decode it, against less than 20 microseconds for base64, and against 0.3 millisecond to verify the signature itself.

**Addresses.** An address is the base58check form of a 384-bit hash:

```
address = base58check( prefix || H("kern.addr", 0x01 || public_key) )
```

`0x01` is the scheme number. The prefix is the three bytes `0x7b0339`: with any prefix from `0x7b031f` to `0x7b0353`, an address has 75 characters and begins with `kn1`, whatever the hash. The checksum that base58check appends is the first four bytes of `H("kern.checksum", prefix || hash)`. Since the public key depends on the network, so does the address. The address of a contract has the same form, with the hash of its own domain. Addresses grow from 36 to 75 characters.

**Hashes.** A hash is written as 96 hexadecimal characters, where it is 64 today, or 32 for three identifiers.

## 6. Where keys live, and what a signature covers

### 6.1 A public key is stored once

A composite public key is 2.6 kilobytes of text; today a 53-character key travels in every transaction, block header and vote.

- **Validators.** Their keys are in the validator set already. Consensus messages, quorum certificates and block headers carry the address of the validator and its signature; the fields `validator_pubkey` and `proposer_pubkey` go.
- **Accounts** (**decided**: in this release). The state gains a key registry, address to public key, under the rules of section 4.3. The first transaction of an account carries its public key, which must hash to the address and is recorded. Later transactions carry none. The operation `rotate_key`, signed by the current key, replaces it; the address does not change.
- **Rollups.** The sequencer key is in the rollup descriptor already; batches drop `sequencer_pubkey`.

### 6.2 Contexts

Every signature is made in a context, the `ctx` of section 2.1. It is specified to the byte, because two clients must build the same bytes.

| Purpose | Signed object |
|---|---|
| `kern.tx` | A transaction |
| `kern.header` | A block header |
| `kern.propose` | A PROPOSE message |
| `kern.preendorse` | A PREENDORSE message |
| `kern.endorse` | An ENDORSE message, the self-commit of a proposer included |
| `kern.batch` | A rollup batch |

- **Context.** The purpose in ASCII, one zero byte, the 32 bytes of the network identifier. At most 48 bytes, under the limit of 255 that RFC 10073 sets.
- **Six purposes, not four.** The kind of a consensus message is part of what is signed, so one purpose for the three kinds would not confuse them today. Separate purposes keep that true if the serialization ever changes, at no cost before a genesis exists.
- **Certificates and evidence.** A quorum certificate and a piece of slashing evidence carry signatures made earlier. Each is verified in the context of the message it was made for; they have no purpose of their own.
- **Errors.** Signing with a purpose outside this list, or with a network identifier that is not 32 bytes, raises an error. Verifying in such a context answers no, like any invalid signature.

A signature made for one purpose or one network is invalid for any other.

### 6.3 What a block commits to (proposed)

Today a header commits to its transactions through the root of their identifiers, and an identifier leaves the signature out. That is right for a transaction and not enough for a block: two copies of one block can carry different signature bytes under the same header.

Proposed: the header carries a second root, over what each transaction carries besides what it signs, that is, its signature and its public key when it has one. Each transaction contributes `H("kern.witness", ...)` of those bytes, and the values are combined like those of the first root.

- A copy of a block is that block only if both roots match, which is checked by hashing alone, before any signature is verified.
- Every node holds the same bytes for a block.
- The rule of section 2.3 is unchanged for statements: the identifier of a transaction, a vote or a proposal never includes its own signature. A header is a statement of its proposer about transactions and their signatures.
- A block that contains a transaction whose signature does not verify is invalid. Today such a transaction is skipped and the block stands.

## 7. Sizes and measurements

`Transaction.encoded_size()` becomes the size of the whole transaction, signature and key included, so that the fee floor and the block size cap see what a transaction really weighs. Estimates with the text forms above:

| | Today | Composite |
|---|---:|---:|
| Transfer, first of an account | 458 bytes | about 7.5 kilobytes |
| Transfer, later ones | 458 bytes | about 4.9 kilobytes |
| Certificate of 30 validators | 2,940 characters | about 135 kilobytes |
| Certificate of 100 validators | 9,800 characters | about 450 kilobytes |
| Verifying one signature | 0.06 millisecond | about 0.3 millisecond |
| Signing | 0.03 millisecond | about 1.1 milliseconds |

The composite figures were measured with the construction of section 2 written out with the real libraries, outside the repository. Expanding a key from its seed takes about 0.2 millisecond more, once per key.

With the present default cap of one mebibyte per block, a block holds about 210 later transfers. That default is not chosen here. It is chosen from measurements made with the implementation, on a devnet of 4, 30 and 100 validators and by projection beyond: signatures per second on one core, verification in parallel, time for a certificate to reach every validator, block size, bandwidth per validator.

## 8. What stays classical, and what comes later

Replacing signatures does not make a chain post-quantum everywhere. What this release leaves as it is, and says so:

- **Zero-knowledge claims.** The Groth16 verifier on BN254 stays, documented as classical. A proof system built on hash functions is the later answer; it does not block this release.
- **Precompile 0x01.** It keeps its Ed25519 interface for contracts, documented as classical, under the verification rule of section 2.5. No rule of the protocol itself may rely on it, and no account key is ever used through it (section 3.3). A precompile that verifies composite signatures is planned for contracts, after this release.
- **Peer connections.** They are neither encrypted nor authenticated today. The plan, with the hardening of the network layer, is TLS 1.3 with a standard hybrid key exchange and peers authenticated by a composite signature. ML-KEM establishes a secret and authenticates nobody, and Kern does not design a handshake of its own.
- **Root signatures.** The genesis, release tags and integrity manifests are signed rarely and must hold for decades. SLH-DSA (FIPS 205), built on hash functions alone, is the planned scheme for them: another family than ML-DSA, large and slow signatures that these uses can afford.
- **Key storage.** Encrypted key files and hardware security modules for validators.

## 9. Consequences in the code

- **Nothing identifies a statement by its signature.** Checked: a transaction identifier is the hash of the signed payload, without the signature (`Transaction.hash`); a block hash is the hash of the header without its signature, and the certificate is outside it; the vote deduplication key in `kern/node.py` is (kind, level, round, validator, block hash); a slashing offence is identified in `kern/chain.py` by (validator, kind, level, round); proposal evidence compares what is signed; the signing journal records what was signed. The second review found one exception, since corrected: the node compared two proposals of a round with their signatures ([consensus-locking.md](consensus-locking.md), section 10.11). To change: the comment of `kern/signing_journal.py` which says that signing a message again reproduces the same signature.
- **Two clients, one verdict.** The rule of section 2.5 is applied by both clients. The Go client makes the checks on encodings and on points of small order itself, since its standard library does not. [go-port-breakpoints.md](go-port-breakpoints.md) lists Ed25519 as interoperable without this caveat today.
- **One hash function.** Every protocol hash becomes a call of `H`. The table of domains in the inventory changes with the code, and a test holds the two together.
- **The network identifier is mandatory.** A genesis without one is refused. Chains built by the tests get one, and the devnet generator draws one each time it builds a genesis.
- **Hashes and addresses grow.** Every hash field goes to 96 hexadecimal characters and every address to 75; strict decoding and its tests follow.
- **Everything is regenerated.** Every address changes. The genesis of the repository, the devnet generator, the wallet, the explorer and the examples of the documentation are regenerated; a devnet has to be reset.
- **One more dependency.** The `cryptography` package joins PyNaCl and py_ecc in the inventory.

## 10. Tests that come before the words

The [inventory](cryptographic-inventory.md) refuses any claim of resistance until the following exist and pass. The Go client runs the same vectors, from the same files, and must give the same answers.

1. **The standard.** The test vectors of RFC 10073 for this combination: the published signatures verify, the published seeds give the published public keys, and keys and signatures have the published serialization.
2. **NIST.** The test vectors for ML-DSA-65 (key generation and signature verification, with the invalid cases). The list of errata kept on the page of FIPS 204 is read again at each release.
3. **Either component broken.** At every place a signature is checked (transaction, block header, proposal, vote, quorum certificate, rollup batch, slashing evidence), a message whose Ed25519 component is valid and whose ML-DSA component is not must be refused. And the reverse.
4. **No fallback.** An Ed25519 signature alone is refused at each of those places.
5. **Contexts.** A signature made for one of the six purposes is refused for each of the five others, and a signature made for one network identifier is refused for another. The context bytes of a fixed list of cases are part of the vectors.
6. **Key derivation.** Fixed seeds and network identifiers give fixed component seeds, public keys and addresses, the same in Python and in Go. The same seed and the same chain name with another network identifier give other keys and another address, and nothing signed for one network is accepted on the other.
7. **Signature bytes.** The same transaction, vote or proposal signed twice, or with its Ed25519 component replaced by another valid one, keeps its identifier, is counted once, leads to no second vote and is evidence of nothing. For proposals this already holds on the present code: the same proposal sent without its proof, then signed again with a valid proof, is voted on (`tests/test_signature_bytes.py`).
8. **Ed25519.** The cases of section 2.5 get the stated verdict, in the composite and through precompile 0x01.
9. **Component keys.** The key derived for a contract is not the Ed25519 component of the account key, and no function of the repository signs with a component alone or returns one.
10. **Key registry.** First recording, rotation, a second key presented for an address that has one, a transaction that carries a key after one is recorded, an account of the genesis without a key, and agreement between the registry and the validator set.
11. **Addresses.** The rules of section 4.3: no transaction from an address that holds a contract, no contract at an address that has a key, no address listed twice in a genesis.
12. **Hashes and text forms.** Every hash is 96 hexadecimal characters; a shorter, longer or truncated value is refused wherever a hash is decoded. Every spelling of a key or a signature other than the canonical one is refused.
13. **Blocks.** A copy of a block in which a signature was changed does not match its header, and a block that contains a transaction with an invalid signature is invalid.
14. **Two clients.** The same keys, addresses, verdicts on signatures and certificates, and results of execution in Python and in Go.
15. The existing consensus simulator and the tests with real processes, unchanged in what they assert.

## 11. Order of work

1. **Freeze the profile.** This note, after a last review limited to what changed since the second version.
2. **Implement**, behind the tests of section 10: the signature mechanism and the functions of the profile (derivation, contexts, hash, text forms, addresses); then formats and state (SHA3-384 everywhere, network identifier, no fallback, the second root of a block, genesis, devnet, wallet, explorer); then the key registry, `rotate_key` and size accounting.
3. **Measure**, and choose the default block size cap.
4. **Second client.** Conformance vectors and differential tests with the Go client. Release 1.2.0rc1.
5. **Later.** Peer connections, root signatures, a composite precompile, proofs built on hash functions.

## 12. First review, 12 November 2026

A first review read the inventory and the first version of this note. It endorsed the direction (hybrid from genesis, ML-DSA-65 with Ed25519, the standard construction, no aggregation of our own) and asked for the following.

| Point raised | Outcome |
|---|---|
| RFC 10073 is written for X.509; Kern must define its own profile around the mechanism | Section 2.1 |
| The inventory dismissed quantum collision search; hash sizes must be justified one by one, with 384 bits considered for commitments | Accepted. The inventory gives the generic bound. Commitments moved to 384 bits; after the second review, so did everything else (section 4.2) |
| Key derivation needs a dedicated review; the same seed must not give the same keys on independent networks | Keys are bound to the network (section 3) |
| The composite is not strongly unforgeable; the protocol must never depend on signature bytes | Sections 2.3 and 9, test 7 |
| The context must be specified to the character, within 255 bytes | Section 6.2, test 5 |
| Groth16, precompile 0x01, peer connections, genesis and release signatures, key management remain classical or open | Section 8 |
| Costs must be measured up to hundreds of validators | Section 7 |
| The same vectors in Python and Go; follow the errata of NIST | Section 10. The errata known to us, announced on the NIST forum in 2024 and 2025, correct text and change no algorithm |
| No silent fallback to Ed25519 alone | Section 2.4, test 4 |

Also decided on that day: the account key registry and `rotate_key` are part of this release.

## 13. Second review, 12 November 2026

A second review read the second version against the published text of RFC 10073 and against the code. It found the construction of section 2 conforming and would not change it. It considered settled: ML-DSA-65 with Ed25519, the construction of the RFC, SHA-512 as pre-hash, composite signatures everywhere, no fallback, 384-bit commitments, the key registry and rotation. It asked for the following before the profile is frozen.

| Point raised | Outcome |
|---|---|
| Name the two contexts apart; say that the format is not an X.509 implementation; state the guarantee in the terms of the RFC | Sections 2.1 and 2.3 |
| The derivation must carry a version and be specified exactly; HKDF-SHA-512 preferred | Section 3.2 |
| A chain name is not the identity of a network: use an independent 32-byte identifier, recorded in the genesis, in the derivation and in the contexts; a wallet must not trust the name a node returns | Accepted (decided). Section 3.1 |
| Addresses at 256 bits only if every relevant attack is shown to be a second preimage; identifiers examined one by one | Everything moves to 384 bits (decided), and the registry rules are stated. Sections 4.2 and 4.3 |
| Six purposes instead of four, with one per kind of consensus message | Accepted. Section 6.2 |
| The node compared two proposals of a round with their signatures: the same proposal signed again was taken for a conflict | Confirmed by a failing test and corrected ([consensus-locking.md](consensus-locking.md), section 10.11) |
| The component key Ed25519 must not be usable alone through precompile 0x01; the argument on message lengths covers the signature bytes, not the key | Accepted. Section 3.3, test 9 |
| More tests: derivation vectors, network binding, a proposal signed twice, the component key, the registry, hash lengths, identifiers, both clients | Section 10 |

Raised by the author while preparing the implementation, and added to this version:

| Point | Outcome |
|---|---|
| The standard library of Go and OpenSSL accept Ed25519 signatures that libsodium refuses | One written rule and its vectors. Section 2.5, test 8 |
| The text form of a key or a signature must be unique | Section 5, test 12 |
| BLAKE2b is neither a standard of NIST nor among the hash functions recommended by ANSSI | SHA3-384 (decided). Section 4.1 |
| A header does not commit to the signatures of its transactions | A second root is proposed. Section 6.3, test 13 |
| The official vectors of RFC 10073 and of NIST have been run, and the lowest version of the library that provides ML-DSA established | Sections 2.1 and 2.2 |

## 14. Questions for the last review

1. Is the derivation of section 3.2 now specified exactly enough for two independent implementations, and is anything missing from its info?
2. Is a random identifier recorded in the genesis the right identity for a network (section 3.1)? Is what the note says of wallets and of forks enough?
3. Is the framing of `H` right for SHA3-384: one byte of length, the ASCII domain, then the data (section 4.1)?
4. Should the header commit to the signatures of its transactions, and should a block that contains an invalid signature be invalid (section 6.3)?
5. Is the rule of section 2.5 the right one for Ed25519, or should Kern take the rule that multiplies by the cofactor?
6. May a validator rotate its key, and from which level does the consensus use the new one?
7. Is anything else missing before the profile is frozen?

## References

- IETF, Composite ML-DSA, RFC 10073, October 2026, from [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/). The section numbers quoted here are those of the published text.
- IETF, HKDF, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), and Ed25519, [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard, August 2024; [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), SHA-3 Standard; [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
- BSI TR-02102-1, version 2026-01, as summarized by [Fraunhofer AISEC](https://www.aisec.fraunhofer.de/en/spotlights/Competence-Center-PQC/developments-in-pqc.html).
- ANSSI, [rules and recommendations on the choice and sizing of cryptographic mechanisms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf), version 3.00, March 2026 (section 2.1.4 on hash functions); [selection guide for cryptographic algorithms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-selection_crypto-1.0.pdf), 2021; [views on the post-quantum cryptography transition](https://cyber.gouv.fr/publications/anssi-views-post-quantum-cryptography-transition), 2022, and [questions and answers](https://cyber.gouv.fr/cryptographie-post-quantique-faq).
- G. Brassard, P. Høyer and A. Tapp, [Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002), 1997.
- K. Chalkias, F. Garillot and V. Nikolaenko, [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244), 2020.
