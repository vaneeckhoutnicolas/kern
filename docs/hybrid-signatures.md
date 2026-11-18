# Hybrid signatures (design)

> **Status.** Profile frozen on 12 November 2026, after five reviews. Nothing in this note is implemented. The [cryptographic inventory](cryptographic-inventory.md) describes what the code does today: every signature is Ed25519, and no part of Kern is post-quantum.

Kern is not in production, so its formats can still change without migrating anyone. The decision is to make the protocol post-quantum by construction, in a dedicated release (1.2), before any network beyond the devnet exists. This note is the cryptographic profile of that release: what is signed and how, how keys are derived, how objects are encoded and hashed.

This is its sixth version, and the profile is frozen with it. Five reviews, all on 12 November 2026, are recorded in sections 12 to 16; the choices they led to are marked **decided**. The third one approved the architecture and asked that everything two implementations must agree on be specified to the byte and held by vectors. The fourth recomputed those vectors on its own and asked for four closures: the exact bytes hashed under every domain, the addresses of the Mini-EVM, the reuse of keys, several rotations in one block. The fifth found them made and approved the freeze, with three precisions that this version writes down. Section 17 describes the vectors, which two independent implementations reproduce, and section 18 says what the freeze is and what it is not. Code is written behind those vectors.

## 1. The profile in one table

| Subject | Choice |
|---|---|
| Signature scheme | Composite ML-DSA as standardized by the IETF (RFC 10073), in one combination: ML-DSA-65 with Ed25519 |
| Rule | A signature is valid only if both components are. No other scheme is accepted anywhere, and there is no fallback |
| Network identity | A 32-byte identifier drawn at random when the genesis is built, immutable (**decided**). The chain name is a label |
| Keys | Both component keys derived from one 32-byte seed with HKDF-SHA-512, for one network and one version of the derivation |
| Hash function | SHA3-384 over a domain name, the network identifier and the data, for everything the protocol hashes (**decided**) |
| Hash size | 384 bits for every commitment, identifier and address (**decided**) |
| Encoding | Canonical JSON, with one encoding per object (**decided**) |
| Merkle trees | The structure of RFC 6962, with separate domains for the empty tree, leaves and nodes |
| State root | Every field of the state, whichever function computes it (**decided**) |
| Addresses | `kn1` and base 58 as today, 75 characters, valid on one network |
| Text forms | `kpk1.` and `ksig1.` followed by base64url, one text per value |
| Where keys live | Stored once in the state (the account key registry), never repeated in messages; registry and rotation in this release (**decided**) |
| Key reuse | A public key is recorded once on a network, for one address; a rotation takes no part of an earlier key of the address; one rotation per address and per block (**decided**). Between addresses, never reusing a component is an obligation of wallets, which the chain does not check |
| Signing contexts | Seven purposes. Every signature states its purpose and its network |
| Ed25519 verification | One rule, written as mathematics, the same in every client |
| Blocks | The header has a structure version and commits to the signatures of its transactions; a block that contains an invalid signature is invalid |
| Sizes | The fee floor and the block size cap count the signature |
| Classical leftovers | Precompile 0x01 (Ed25519) and the Groth16 verifier (BN254) stay, documented as classical |
| Mini-EVM | Its own derivation of contract addresses, on 160 bits, stated as not the one of Ethereum (**decided**) |
| Release | 1.2.0rc1; a devnet started with an earlier version has to be reset |

## 2. The signature scheme

### 2.1 A standard mechanism, a Kern profile

Combining two signature schemes looks trivial and has traps: which bytes each one signs, how the two are tied together, how a signature made for one purpose is kept from serving another. The IETF has specified this as **Composite ML-DSA**, published as [RFC 10073](https://www.rfc-editor.org/rfc/rfc10073.html) in November 2026 (until then draft-ietf-lamps-pq-composite-sigs). Kern uses it instead of defining its own.

RFC 10073 is written for certificates. Kern takes its mechanism and nothing else: how the keys are generated, what the two components sign, how keys and signatures are serialized. It takes none of the X.509 structures, and a Kern signature is not meant to be read by software that handles certificates. Around that mechanism Kern defines its own profile, which is the rest of this note: network identity, key derivation, hashing and encoding, contexts, text forms, addresses.

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

This construction has been run against the test vectors published with the RFC for this combination: the published private key gives the published public key, the two published signatures verify (without a context and with one), and every altered case is refused. Two programs written independently, one in Python and one in Go, also verify each other's signatures in the seven contexts of section 6.2 and refuse the same invalid ones (section 17).

### 2.2 Why these parameters

- **Hybrid.** ML-DSA was standardized in 2024 and is younger than Ed25519. With both required, forging a signature takes breaking both: Kern keeps the security it has today if a flaw is found in ML-DSA or in a library, and resists a quantum computer if Ed25519 falls. The German federal office for information security (BSI) asks for ML-DSA to be used in hybrid, and the French agency (ANSSI) states that the concatenation of a classical and a post-quantum signature meets its requirement.
- **ML-DSA-65, not ML-DSA-44.** The BSI recommends ML-DSA-65 or ML-DSA-87 only (TR-02102-1, version of January 2026). For a protocol that addresses European institutions, the smaller parameter set would be a weakness in every due diligence. The price is about a third more bytes than ML-DSA-44. ANSSI states a preference for the highest level; the standard pairs ML-DSA-87 with other classical algorithms than Ed25519, and the scheme number of section 5 leaves room for such a combination later.
- **Libraries.** ML-DSA comes from the `cryptography` package, version 48 or later (version 47 does not provide it), which is licensed under Apache 2.0 or BSD. It installs without compiling on Linux (checked under Python 3.11 and 3.13), a Windows build is published, and it passes the test vectors of NIST for ML-DSA-65, invalid cases included. Ed25519 stays on PyNaCl, so the classical component is verified by the same code as today. The Go client has both in its standard library (`crypto/mldsa` from Go 1.27, `crypto/ed25519`).

### 2.3 What it guarantees, and what it does not

What Kern claims is what RFC 10073 establishes, and nothing more.

- **Unforgeable if either component is.** In the terms of the RFC (section 9.2.1): the composite is existentially unforgeable under chosen message attack (EUF-CMA) as long as one of its two components is, and as long as the pre-hash is collision resistant. SHA-512 is sized well above the rest of the profile.
- **Both components, always.** A signature with one valid component is invalid, and no rule of Kern accepts a component alone (section 2.4). This is the protection against downgrade.
- **Weak non-separability, and a limited form of the strong one.** In the terms of the RFC (section 9.2.3, which takes its definitions from RFC 9955): a component cannot be removed from a composite signature without leaving evidence, for both components; and the ML-DSA component, signed under the Label as its own context, is refused by an ML-DSA verifier that does not expect that context. Kern adds nothing to these properties. It only keeps the conditions under which they hold: no verifier of Kern accepts a component alone (precompile 0x01 takes messages of 32 bytes, and `M'` is always longer), and no key is ever used outside its composite (section 3.3).
- **Not strongly unforgeable against a quantum adversary.** The RFC is explicit (section 9.2.2): whoever breaks Ed25519 can replace the Ed25519 component of a signature he has seen, and so obtains another valid signature of a message that was already signed, without holding the key. The RFC advises against the scheme wherever that would matter.
- **Not unique either.** ML-DSA signing is randomized: the key holder produces other bytes every time he signs the same message. Even with Ed25519 a signer can do so, by choosing another nonce.
- **So nothing may identify a statement by the bytes of its signature**: no identifier, no deduplication key, no comparison, no evidence. A transaction, a vote or a proposal is what was signed. Signature bytes are committed to in one place only: a block, whose proposer commits to the transactions it carries together with their signatures (section 6.3).
- **Not claimed.** Strong non-separability in general, simultaneous verification in the sense of RFC 9955, strong unforgeability, or any certainty: ML-DSA is believed to resist quantum computers, it is not proven to, and no scheme is.
- **No aggregation.** A quorum certificate carries one composite signature per validator. Nothing standardized shrinks it, and Kern does not invent an aggregation of its own.

### 2.4 No fallback

A network has one signature scheme, named in its genesis. On a network of scheme 1, an Ed25519 signature alone is invalid everywhere a signature is checked, however valid it is as Ed25519. There is no flag, no transition period and no mixed validator set. A later scheme is a new number, introduced by a protocol amendment.

### 2.5 One verdict for Ed25519

Implementations of Ed25519 do not all accept the same signatures. RFC 8032 leaves a choice in the verification equation and says nothing of points of small order, and libraries differ ([Taming the many EdDSAs](https://eprint.iacr.org/2020/1244)). The holder of an account can craft a signature on which they disagree, for a key of his own, and whoever owns the ML-DSA key makes that component valid. If one client accepted the result and another refused it, one transaction would split the network.

Kern therefore fixes one rule. It is a definition of Kern, written as mathematics: what a library answers is a test of conformance, never the specification. `B` is the base point, `L` the order of the subgroup it generates, p = 2^255 - 19.

1. The public key `A` is 32 bytes and the signature 64 bytes: `R`, then `S`.
2. `A` is the canonical encoding of a point of the curve (RFC 8032, section 5.1.3: the 255-bit integer is below p, a point has this y, and the sign bit is not set when x is 0). That point is in the subgroup of prime order, `[L]A = O`, and is not the identity `O`. This refuses the eight points of small order and every point of mixed order.
3. `R` is the canonical encoding of a point of the curve, and is not the identity.
4. `S` is below `L`.
5. `[S]B = R + [k]A` holds exactly, not after multiplication by the cofactor, with `k` the SHA-512 of `R`, `A` and the message, reduced modulo `L`.

With 2 and 5, `R` is in the subgroup of prime order as well: no separate check is needed. A signature accepted under this rule is valid under RFC 8032.

**Byte order.** Every number here is read as RFC 8032 writes it, least significant byte first (little-endian). `A` and `R` are 32 bytes each: the y coordinate on 255 bits, and the sign of x in the top bit of the last byte (section 5.1.2 of the RFC). `S` is the last 32 bytes of the signature, read as a number in that order. `k` is the 64 bytes of SHA-512(`R` || `A` || message), read as a number in that order and then reduced modulo `L`.

- **Where it applies.** To the Ed25519 component of every composite signature, and to precompile 0x01. Rule 2 is also checked when a key is recorded: in the genesis, at the first transaction of an account, in `rotate_key` (section 6.4). A key that fails it is never recorded.
- **The identity as `R`.** It is in the subgroup, and a deterministic signer produces it with a probability of about 2^-252. Refusing it is a restriction that Kern takes on purpose: such a signature gives the secret away, since `S` divided by `k` is the secret scalar.
- **Measured.** On 31 cases built for this note from RFC 8032, one is valid under the rule: an ordinary signature. The standard library of Go (1.24 and 1.27) and OpenSSL (4.0), left alone, accept 17: 16 of them are refused by the rule. libsodium, the library behind PyNaCl, accepts 3: it takes a public key of mixed order, which the rule refuses. The 210 Ed25519 vectors of Project Wycheproof leave 29 cases to the implementation, all of them with a public key of small or mixed order; the rule refuses the 29.
- **Implemented three times.** The rule gives the same verdict on the 31 cases when it is computed as plain arithmetic with no library, with libsodium doing the arithmetic, and with the standard library of Go after the checks 2 to 4 (section 17).

## 3. Network identity and keys

### 3.1 The network identifier

A network is identified by `network_id` (**decided**): 32 bytes drawn from the generator of the operating system when its genesis is built, written in the genesis as 64 hexadecimal characters. Keys are derived for one network identifier, every signature is made for one, and every hash of the protocol includes one (section 4.1).

A name is not an identity. Two operators can pick the same chain name, and the devnet generator of this repository writes the same one every time. With a random identifier, every genesis that is built is another network: the keys, addresses, hashes and signatures of one mean nothing on another.

- **Immutable.** The identifier of a network never changes during the life of a chain: it is in its keys, its addresses and all its hashes. A fork that wants to be distinct is a new network, with a new identifier, started from a new genesis or from an explicit transition checkpoint. How accounts, contracts, keys and state would be carried over to it is a migration, to be defined by whoever makes that fork; this profile defines none.
- **The genesis is the reference.** A wallet takes the network identifier from a genesis it trusts, or from a key file made for that network, which records the identifier next to the seed. It asks the node for its identifier and refuses to sign when the two differ. A node is never the authority on which network this is, and no key is ever derived from a value a node supplied. Today the wallet asks the node for the chain name and signs for it.
- **The chain name stays, as a label.** `chain_id` is 1 to 64 characters, each a lowercase letter from a to z, a digit or a hyphen, the first one a letter. It becomes mandatory in the genesis and stays in the signed payload of a transaction, where tools and people read it. A node still refuses a transaction that names another chain. That check is a courtesy; the protection is the network identifier.
- **The limit.** Two networks started from the same genesis file are the same network at that point, with the same identifier.

### 3.2 Derivation

A Kern key is a 32-byte seed drawn from the generator of the operating system, and stays one. The seeds of the components are derived from it with HKDF ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) over SHA-512, written out here in full:

```
Hash     = SHA-512, HashLen = 64
IKM      = the seed, 32 bytes
salt     = 64 zero bytes (RFC 5869 when no salt is given)
PRK      = HMAC-SHA-512(salt, IKM)                              64 bytes
info     = "KERN-KEY-DERIVATION-V1" || 0x01 || network_id || component
T(1)     = HMAC-SHA-512(PRK, info || 0x01)
output   = the first 32 bytes of T(1)
```

The four fields of `info`, in this order: the 22 ASCII characters `KERN-KEY-DERIVATION-V1`; one byte for the scheme number, 0x01; the 32 bytes of the network identifier; the ASCII name of the component. Every field before the name has a fixed length and the name is last, so two different inputs never give the same info.

| Component | Output, 32 bytes | Used as |
|---|---|---|
| `mldsa65` | The ML-DSA seed | The seed ξ of ML-DSA.KeyGen_internal (FIPS 204, algorithm 6), which gives the key pair without any other randomness |
| `ed25519` | The Ed25519 seed | The 32-byte private key of RFC 8032, section 5.1.5 |
| `ed25519-standalone` | The seed of another Ed25519 key | A key for contracts that verify Ed25519 signatures (section 3.3). Never part of an account key |

The composite private key is the output for `mldsa65` followed by the output for `ed25519`: 64 bytes, which is the serialization of RFC 10073. The three outputs come from three independent expansions of the same PRK.

- **Allowed by the standard.** RFC 10073 (section 3.1.1) allows a deterministic generation in which one seed is expanded into the seeds of both components. It leaves the expansion to the application, and section 3.1 requires that both component keys be fresh and never used anywhere else.
- **A standard construction.** HKDF is among the key derivation mechanisms that the selection guide of ANSSI recommends. It is in the standard library of Go, and Python builds it from HMAC in a few lines.
- **Versioned.** The first field of the info is the version of the derivation. Another derivation is another label, and a key file records the version it was made with. The scheme number is a separate thing: the chain never sees how a key was derived.
- **One seed, one identity.** A seed gives one account key per network. Several accounts are several seeds, drawn independently; this version of the derivation has no account index.
- **Bound to one network.** The same seed gives another key pair and another address for every network identifier. A key exposed on a test network says nothing about the key of another network.

Section 17 gives a complete vector: seed, PRK, the three infos, the three outputs and the public keys they give.

### 3.3 What a key is never used for

- **Never a component alone.** RFC 10073 forbids using a component key outside the composite (sections 3.1 and 9.3): a key that also signs alone weakens the composite it belongs to. No function of Kern signs with one component, and none returns a component key.
- **Never in two keys.** Section 3.1 of the RFC also forbids a component key that is used in another combination. The derivation gives every seed, on every network, two component keys of its own, and no tool of Kern builds a public key from parts taken elsewhere: a wallet that did would break this rule. It is an obligation of whoever generates keys, and the chain does not check it between addresses: what the chain itself refuses is in section 6.4, with the reason it does not refuse more.
- **Precompile 0x01.** It verifies Ed25519 signatures of 32-byte messages. `M'` is always longer, so the Ed25519 component of a composite signature cannot be replayed through it. That says nothing about the key itself: the holder of a seed could, by his own means, sign a 32-byte message with the Ed25519 component key. The rule of Kern is that no tool of Kern does. A key meant for a contract is the one derived under `ed25519-standalone`: the same mechanism, another secret.
- **Rotation, and its limit.** The operation `rotate_key` (section 6.4) lets an account replace its key. It does not save an account whose seed is stolen if the thief acts first. A second key, kept offline and able to take the account back, is a possible later addition.
- **Storage.** A seed is a file in clear text today, and this release does not change that: whoever reads the file holds the account. A hybrid scheme does nothing for a stolen seed. Encrypted key files and hardware modules are listed in section 8.

## 4. Hashes and encoding

### 4.1 One function

Everything the protocol hashes goes through one function (**decided**):

```
H(domain, data) = SHA3-384( len(domain) || domain || network_id || data )
```

`domain` is the ASCII name of the use, from 1 to 255 bytes, preceded by its length on one byte. `network_id` is the 32 bytes of section 3.1. The output is 48 bytes. This is SHA3-384 of [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), not the Keccak function with the earlier padding, which gives other digests.

With the network identifier in every preimage, two networks never share a hash because they hold the same data: a transaction identifier, a block hash, a state root or an address of one network means nothing on another.

Today the code hashes with BLAKE2b, keyed with the same names. BLAKE2b has no known weakness. But it is not a standard of NIST, and it is not among the hash functions that the selection guide of ANSSI recommends, which are those of the SHA-2 and SHA-3 families. A protocol that addresses institutions is asked about both. Every hash changes size in this release, so changing the function at the same time costs nothing more. SHA3-384 is in the standard library of both client languages.

The domains are the following, and there is no other. A hash under a name that is not in these tables is not a hash of the protocol.

**What is hashed, to the byte.** For every domain, `data` is one of two things, and the tables say which:

- **an object**: its canonical JSON, the one of section 4.3. Its fields are those of its schema;
- **a string of bytes**, made of the fields the table lists, in that order, with nothing between them. The number of bytes of a field is given in brackets when it is fixed. A number is unsigned and written with its most significant byte first (big-endian). A hash is its 48 bytes, never its hexadecimal text. An address is its 75 characters, in ASCII. A text is its UTF-8 bytes.

Domains whose data is a string of bytes:

| Domain | Data | What the hash is |
|---|---|---|
| `kern.merkle.empty` | Nothing: no byte | The root of a tree with no item (section 4.4) |
| `kern.merkle.leaf` | The item | A leaf of a tree |
| `kern.merkle.node` | The root of the left subtree (48), the root of the right subtree (48) | A node of a tree |
| `kern.witness` | The transaction identifier (48), the flags (1), the public key if the flags say so (1,984), the signature (3,373), the second signature if the flags say so (3,373) | A leaf of the witness tree of a block (section 6.3) |
| `kern.addr` | The scheme number, `0x01` (1), the public key (1,984) | The hash inside the address of an account (section 5) |
| `kern.addr.contract` | The identifier of the transaction that originates the contract (48) | The hash inside the address of a contract |
| `kern.checksum` | The prefix of an address (3), the hash inside it (48) | Its first 4 bytes are the checksum of the address |
| `kern.proposer` | The hash of the parent block (48), the round (4) | Its first 8 bytes, read as a number, are the public draw of the proposer of that round |
| `kern.trie.key` | The address (75) | The position of an account in the state trie (section 4.6) |
| `kern.trie.leaf` | The number of bits (2), the bits, the length of the value (4), the value | A leaf of the state trie (section 4.6) |
| `kern.trie.branch` | The left child (48), the right child (48) | A branch of the state trie |
| `kern.code` | The code of a contract, as text | `code_hash` in the account of the contract (section 4.6) |
| `kern.rollup.program` | The program a rollup batch executed, as the bytes that are run | `tx_data_hash` in the batch |
| `kern.evm.code` | The creation code of a contract of the Mini-EVM | The code hash inside a `CREATE2` address |
| `kern.evm.create` | The creator (20), its nonce (8) | Its first 20 bytes are an address inside the Mini-EVM (section 8) |
| `kern.evm.create2` | The creator (20), the salt (32), the hash of the creation code under `kern.evm.code` (48) | Its first 20 bytes are an address inside the Mini-EVM |
| `kern.evm.signer` | The Ed25519 public key whose signature precompile 0x01 has verified (32) | Its first 20 bytes are what the precompile returns: the address of that key inside the Mini-EVM (section 8) |

Domains whose data is an object:

| Domain | Object | Fields |
|---|---|---|
| `kern.tx` | A transaction without its witness: what its sender signs. The hash is the identifier of the transaction | The schema of transactions. The public key of its sender and the signatures a transaction carries are not part of it (section 6.3) |
| `kern.block` | A block header without its signature. The hash is the hash of the block | The nine fields of section 6.3 |
| `kern.state` | The state. The hash is the state root (section 4.6) | Every field of the state |
| `kern.storage` | The storage of a contract. The hash is `storage_root` in the account of the contract | The fields the contract declares |
| `kern.batch` | A rollup batch without its signature | `rollup_id`, `batch_index`, `parent_state_root`, `state_root`, `tx_hashes`, `tx_data_hash`, `timestamp`, `sequencer` |
| `kern.mailbox` | A forced inclusion request | `rollup_id`, `sender`, `l2_tx_payload`, `posted_at_l1_level`, `posted_at_l1_timestamp`, `deadline_blocks` |
| `kern.gov.id` | A governance proposal. The hash is its identifier | `submitter`, `payload`, `salt` |
| `kern.attestation.id` | An attestation. The hash is its identifier | `issuer`, `schema_id`, `subject`, `claim`, `attest_nonce` |
| `kern.zk_claims.vk` | A Groth16 verifier key. The hash is its identifier | `alpha1`, `beta2`, `gamma2`, `delta2`, `ic`. Every coordinate is a string of decimal digits |
| `kern.evm` | A state of the Mini-EVM, for fraud proofs | `pc`, `stack`, `memory`, `gas`, `halted`, `output`, `reverted`, `storage`, `context`. A word of the machine is a string of decimal digits, bytes are hexadecimal text, and `storage` is an object that maps a word to a word |

The draw of `kern.proposer` picks the proposer as today: the number is taken modulo the total stake, and the proposer is the first validator, in the order of the epoch snapshot, at which the running total of the stakes exceeds it.

What is not `H`, and stays as it is: SHA-512 inside the signatures (the pre-hash of RFC 10073, and Ed25519) and in the key derivation; the hash functions inside ML-DSA; and the hash functions that contracts call (the `SHA3` opcode, precompiles 0x02 and 0x03, the placeholder at 0x09), which are interfaces for contracts and not commitments of the protocol.

### 4.2 One size

Every hash of the protocol is 384 bits (**decided**): commitments (block headers, transactions, Merkle roots, the state root and trie nodes, rollup batches and programs, forced inclusion requests, Mini-EVM states), identifiers (governance proposals, attestations, verifier keys) and addresses (accounts and contracts).

A hash is sized against two generic attacks, and a quantum computer lowers both: finding a preimage of an n-bit hash goes from 2^n evaluations to about 2^(n/2), and finding a collision from 2^(n/2) to about 2^(n/3). The second figure assumes a quantum memory as large as the search and is not the estimate of a practical attack. It is the figure a conservative design is sized against. The rules of ANSSI published in March 2026 require at least 256 bits, and recommend at least 384 bits when post-quantum security is sought; they add that 256 bits should be enough in the long run, and that the recommendation may become a rule.

| What an attacker would need | Generic cost today | Generic quantum bound |
|---|---|---|
| A collision: two contents of his choice with the same hash | 2^192 | 2^128 |
| A second preimage: another content for a hash that already exists | 2^384 | 2^192 |

The second version of this profile kept addresses and identifiers at 256 bits, on the argument that only second preimages matter for them. The second review showed that this argument has to be made object by object, and that it fails for some. The identifier of a governance proposal covers a payload and a salt that its author chooses, so the author can look for two proposals with one identifier. With one size, no such argument is needed.

Four values keep a size of their own, and say so:

- the checksum of an address, 32 bits: it catches typing errors;
- the pre-hash of a signature, SHA-512, fixed by RFC 10073;
- the public draw of the proposer, 64 bits taken from a hash;
- the addresses inside the Mini-EVM of the rollup framework, 160 bits. They are values of that virtual machine, whose words are 256 bits and whose instructions assume this size. This is not the margin of the rest of the profile, and it is not a post-quantum margin: finding two contracts with one address costs about 2^80 evaluations today and about 2^53 under the bound of the table above, where 384 bits give 2^192 and 2^128. Widening these addresses is a decision for the rollup framework, outside this profile (section 8).

### 4.3 One encoding

What is hashed or signed is the canonical JSON of an object: one sequence of bytes per object, the same in every implementation (**decided**: JSON is kept, a binary encoding is not needed for this release).

| Subject | Rule |
|---|---|
| Encoding | UTF-8, no byte order mark |
| Values | Objects, arrays, strings, integers, `true` and `false`. No `null`, no number with a fraction or an exponent |
| White space | None outside strings |
| Objects | Members sorted by the UTF-8 bytes of their keys, at every depth. A key appears once |
| Arrays | The order is kept |
| Integers | Decimal digits, with a minus sign for a negative value. No leading zero, no `-0`, no plus sign |
| Range of integers | From -2^63 to 2^63 - 1; the schema of each field narrows it. A value that can be larger, such as a 256-bit word of the Mini-EVM, is a string of decimal digits |
| Strings | Between double quotes, with the escapes of the next paragraph and no other |
| Absence | An optional field that has no value is absent. It is never `null`, and never an empty placeholder |
| Unknown fields | Refused. An object has exactly the fields its schema allows for its structure version |
| Reception | A node refuses an object whose bytes, as received, are not the canonical encoding of what it decodes |

**Strings.** The quotation mark and the reverse solidus are written `\"` and `\\`. The five control characters U+0008, U+0009, U+000A, U+000C and U+000D are written `\b`, `\t`, `\n`, `\f` and `\r`. The other characters below U+0020 are written `\u00xx`, with lowercase hexadecimal digits. Every other character is written as its UTF-8 bytes and never as an escape: the solidus, U+007F, U+2028 and characters outside the Basic Multilingual Plane included. Nothing is normalized. A string that is not valid Unicode, such as a lone surrogate, has no encoding and is refused.

**Keys.** The keys of protocol objects are ASCII field names. A map whose keys are data, such as the storage of a contract, is sorted by the same rule.

**Integers.** A parser reads them as integers, never through a floating point number: beyond 2^53 a floating point number no longer holds every integer. Amounts, levels, rounds, nonces and timestamps all fit in the range above.

**Reception.** A peer message, or an object submitted through the RPC, is decoded and encoded again: if the bytes differ, it is refused. White space, another key order, a repeated key, `1.0` for `1`, another spelling of a string: none of them reaches the state or the mempool, and one object has one form on the network.

For objects whose keys are ASCII and whose integers stay within 2^53, this is the output of the JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)). Kern does not follow that RFC for numbers: it has no floating point, and its integers go up to 64 bits.

The fields of each object, their types and their bounds are the schema of that object. Schemas are written in [api-stability.md](api-stability.md) before the formats are implemented, each with its vectors, and reviewed as this note was; this note fixes the encoding they all share, and section 4.1 names the fields of the objects that are hashed.

**One version for all schemas.** A schema belongs to a structure version, the `version` of the block header (section 6.3). Everything a block of version 1 holds or refers to has the schema of version 1: its header, its transactions, the consensus messages of its level, the state it commits to, and the byte layouts of section 4.1. Changing any of them is another version, introduced by a protocol amendment.

### 4.4 Merkle trees

A list of items has one root, defined as in RFC 6962 (section 2.1), with `H` and three domains. For a list `D` of `n` items, each a string of bytes:

```
root({})        = H("kern.merkle.empty", "")
root({d})       = H("kern.merkle.leaf", d)
root(D[0:n])    = H("kern.merkle.node", root(D[0:k]) || root(D[k:n]))      for n > 1
```

`k` is the largest power of two strictly below `n`: 1 for two items, 2 for three or four, 4 for five to eight. The left subtree is always a complete tree, and the right one takes the rest.

- The order of the items is part of the root.
- Nothing is repeated to fill a level. The tree used today repeats the last hash when a level is odd, which gives one root to a list and to the same list with its last item twice.
- A leaf is never taken for a node: they are hashed under two domains, so an item that happens to be the concatenation of two hashes is still an item.

The transactions of a block have two such trees (section 6.3). The state trie has its own structure and its own domains (section 4.6).

### 4.5 What an address designates

The size makes collisions between addresses out of reach. The rules below hold in addition, so that what an address designates never changes silently.

1. **One kind.** An address designates an account or a contract, and never the other afterwards. The two are hashed under two domains. An address that holds a contract can never sign a transaction or receive a key, and a contract cannot be originated at an address that has a recorded key. The genesis lists accounts and contracts separately, and no address may appear in both.
2. **One key at a time.** The registry maps an address to one public key. The first key recorded for an address is the one whose hash is the address. No other key is ever recorded for that address because it was presented: the only change is `rotate_key` (section 6.4).
3. **No second presentation.** Once a key is recorded for an address, a transaction for that address that carries a public key is refused, whatever the key.
4. **A key is checked before it is recorded.** It has the right length, and its Ed25519 part passes rule 2 of section 2.5. Any 1,952 bytes are an ML-DSA-65 public key, so that part has nothing more to check.
5. **Genesis.** An account funded in the genesis without a key follows rule 2 at its first transaction. The key of a validator is recorded by the genesis, in the registry.
6. **A key is recorded once.** A public key is the key of one address, once in the life of a network. It is recorded by the first transaction of the account whose address is its hash, or by one `rotate_key`, and never again after that, for that address or for another (section 6.4). A genesis records no key twice.

### 4.6 The state root

A block header commits to the state through one hash, and that hash covers every field of the state (**decided**). The state names the function that computes it, in its field `state_root_function`; a protocol amendment can change it.

```
json:  state_root = H("kern.state", the state)
trie:  state_root = H("kern.state", the state, in which the fields balances, nonces and contracts
                                    are replaced by one field: accounts_root)
```

In both cases the data is the canonical JSON of an object, and every field of the state is in it, `state_root_function` included. With `trie`, the three maps keyed by address leave the object, and what they hold is committed through the state trie, whose root is written in `accounts_root` as 96 hexadecimal characters. The name `accounts_root` is reserved: the state itself has no such field.

The key registry, the validator set and every other field are hashed as they are, with both functions. A rotation, or a change in the level from which a key is current, therefore changes the state root whichever function computes it. The registry is not in the trie in this version: a proof of an account by the trie proves a balance, a nonce and a contract, not a key. Moving it there is left to a later structure version.

**The state trie.** A binary trie. The account of an address is reached by following the bits of a key, from the most significant bit of its first byte.

```
key(address)  = H("kern.trie.key", address)                                 384 bits
value         = the canonical JSON of the account
node(S, d)    = 48 zero bytes                                               if S is empty
              = H("kern.trie.leaf", count || bits || length || value)       if S holds one account
              = H("kern.trie.branch", node(S0, d + 1) || node(S1, d + 1))   otherwise
accounts_root = node(every account, 0)
```

`S` is a set of accounts whose keys share their first `d` bits. `S0` holds the accounts of `S` whose next bit is 0, and `S1` those whose next bit is 1. In a leaf, `count` is the number of bits of the key that the path has not used, 384 - d, on 2 bytes; `bits` are those bits, the first one in the top of the first byte, completed with zero bits to a whole number of bytes; `length` is the number of bytes of the value, on 4 bytes.

- **Accounts.** An account is an address that is a key of `balances`, `nonces` or `contracts`. Its object has a `balance` and a `nonce`, zero when the address is not in that map. For a contract it also has `code_hash` and `storage_root`, the hashes of its code and of its storage under `kern.code` and `kern.storage`, each as 96 hexadecimal characters.
- **One shape.** The trie depends on the set of accounts alone, not on the order in which they appeared. A leaf sits at the first depth where no other key shares its path. Where several keys share a run of bits, the branches of that run have one child; the other one is empty, 48 zero bytes.
- **A leaf states its number of bits.** Today it states a number of bytes, so the paths `1` and `10`, which fill the same byte, are hashed alike.
- **One position per address.** Two addresses at the same position would take a collision of `H`.

## 5. Identifiers and text forms

**Scheme number.** Scheme 1 is the combination of section 2. The number is visible in the text form of every key and signature, it is hashed into every address and into every key derivation, and it is named in the genesis.

**Public keys and signatures.** `kpk1.` followed by the base64url encoding, without padding, of the 1,984 bytes (2,651 characters), and `ksig1.` followed by that of the 3,373 bytes (4,504 characters). They need no checksum: a damaged signature fails verification and a damaged key fails the address check.

**One text per value.** Decoding accepts the exact prefix, the exact length, the 64 characters of base64url and unused bits at zero, and refuses everything else: padding, another alphabet, spaces, a last character whose unused bits are set. Without this, two nodes could store two spellings of the same key.

Base 58 is not used for keys and signatures because the conversion in this repository is quadratic in the length. Measured on one machine: 16 milliseconds to encode a signature of this size and 4 to decode it, against less than 20 microseconds for base64, and against 0.4 millisecond to verify the signature itself.

**Addresses.** An address is 55 bytes written in base 58, with the alphabet Kern uses today: a prefix, a 384-bit hash and a checksum.

```
hash     = H("kern.addr", 0x01 || public_key)            for an account
hash     = H("kern.addr.contract", transaction_id)        for a contract
checksum = the first 4 bytes of H("kern.checksum", prefix || hash)
address  = base58( prefix || hash || checksum )
```

`0x01` is the scheme number. The prefix is the three bytes `0x7b0339`: with any prefix from `0x7b031f` to `0x7b0353`, an address has 75 characters and begins with `kn1`, whatever the hash. Addresses grow from 36 to 75 characters.

- **Not Base58Check.** The alphabet is the one of Bitcoin, but the checksum is Kern's own: SHA3-384 under a domain, not a double SHA-256. A tool written for Base58Check will not validate a Kern address.
- **One network.** The public key depends on the network, and so do the hash and the checksum. An address typed into a wallet of another network fails its checksum.

**Hashes.** A hash is written as 96 hexadecimal characters, in lowercase, where it is 64 today, or 32 for three identifiers.

## 6. Keys in the state, contexts, blocks, rotation

### 6.1 A public key is stored once

A composite public key is 2.6 kilobytes of text; today a 53-character key travels in every transaction, block header and vote.

- **The registry** (**decided**: in this release). The state gains a key registry, under the rules of section 4.5. For each address it holds the key that is current, and the keys the address had before, each with the level from which it was current. Nothing is ever removed from it, and a key is recorded in it once (section 6.4).
- **Accounts.** The first transaction of an account carries its public key, which must hash to the address and is recorded. Later transactions carry none.
- **Validators.** The validator set and its epoch snapshot hold addresses and stakes, never keys. The key of a validator is read from the registry, like any other. Consensus messages, quorum certificates and block headers carry the address of the validator and its signature; the fields `validator_pubkey` and `proposer_pubkey` go.
- **Rollups.** The sequencer of a rollup is an address, and its key is read from the registry; batches drop `sequencer_pubkey`.
- **The key of a level.** A signature made for level `n` is verified with the key that was current at level `n`. For what a block contains this is the current key; for a vote or a proposal quoted later as evidence, it is the key the registry kept for that level.

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
| `kern.rotate` | The same payload as a `rotate_key` transaction, signed by the new key (section 6.4) |

- **Context.** The purpose in ASCII, one zero byte, the 32 bytes of the network identifier. At most 48 bytes, under the limit of 255 that RFC 10073 sets.
- **One purpose per kind of statement.** The kind of a consensus message is part of what is signed, so one purpose for the three kinds would not confuse them today. Separate purposes keep that true if the serialization ever changes, at no cost before a genesis exists.
- **Certificates and evidence.** A quorum certificate and a piece of slashing evidence carry signatures made earlier. Each is verified in the context of the message it was made for; they have no purpose of their own.
- **Errors.** Signing with a purpose outside this list, or with a network identifier that is not 32 bytes, raises an error. Verifying in such a context answers no, like any invalid signature.

A signature made for one purpose or one network is invalid for any other.

### 6.3 What a block commits to

Today a header commits to its transactions through the root of their identifiers, and an identifier leaves the signature out. That is right for a transaction and not enough for a block: two copies of one block can carry different signature bytes under the same header.

The header of a block becomes:

| Field | Content |
|---|---|
| `version` | The structure version of the block, 1. Another structure is another number, never guessed from the fields present |
| `level`, `payload_round`, `timestamp` | As today |
| `parent_hash` | The hash of the parent block |
| `state_root` | The root of the state after the block |
| `txs_root` | The root of the transaction identifiers, in block order |
| `witness_root` | The root of the witness leaves, in the same order |
| `proposer` | The address of the proposer |

The hash of the block is `H("kern.block", ...)` of the canonical JSON of these fields. It therefore covers both roots, and so do the header signature, the proposals and the votes, which all name the block by that hash. The quorum certificate stays outside the header, as today.

Both roots are trees of section 4.4. The items of the first are the transaction identifiers, 48 bytes each. The items of the second are the witness leaves, one per transaction:

```
leaf = H("kern.witness", transaction_id || flags || [public key] || signature || [second signature])
```

`flags` is one byte: bit 0 is set when the transaction carries the public key of its sender (the first transaction of an account), bit 1 when it carries a second signature (`rotate_key`); the other bits are zero. The public key is its 1,984 bytes, each signature its 3,373 bytes, in that order, present or absent as the flags say. The lengths follow from the flags, so the leaf has one reading. The identifier ties the witness to what it signs.

- A copy of a block is that block only if both roots match, which is checked by hashing alone, before any signature is verified.
- Every node holds the same bytes for a block. Two blocks with the same transactions and other signature bytes are two blocks, with two hashes. That is the intended consequence.
- The rule of section 2.3 is unchanged for statements: the identifier of a transaction, a vote or a proposal never includes its own signature. A header is a statement of its proposer about transactions and their signatures.
- **A block that contains a transaction whose signature does not verify is invalid.** Today such a transaction is skipped and the block stands.

### 6.4 Replacing a key

`rotate_key` replaces the key of an address, account or validator alike. The address does not change.

| | |
|---|---|
| Payload | The address, its nonce, the new public key |
| First signature | By the key that is current, in the context `kern.tx`: it authorizes the change |
| Second signature | By the new key, over the same payload, in the context `kern.rotate`: it proves that whoever asks for the change holds the new key |
| New key | Checked like any key before it is recorded (section 4.5, rule 4) |

If the transaction is in the block of level `H`:

| Level of what is signed | Key |
|---|---|
| Up to `H`, the other transactions of block `H` included | The old key |
| From `H` + 1 | The new key |

- **One transition.** The registry is the only place where a key is held, and the consensus reads it. There is no moment at which the registry and the consensus disagree, and no copy of a key to update at an epoch boundary.
- **No overlap.** For a given level, one key is valid for an address. The old key signs nothing from `H` + 1 on, and the new key nothing before.
- **History.** The registry keeps the old key with the levels at which it was current, so that a vote or a proposal of level `H` - 10 is still verified, in evidence, with the key of that level.
- **The second signature covers** the network (through its context), the address, the new key and the nonce, which fixes the place of the rotation in the history of the account. The level of activation follows from the block that includes it.
- **One rotation per block** (**decided**). At most one `rotate_key` of an address takes effect in a block. A `rotate_key` that fails records nothing and does not count. The first one that succeeds is applied, and after it any other `rotate_key` of that address in the same block fails, as a transaction that breaks a rule of the state does. As a rule of the state: an address that already has a key due at `H` + 1 cannot rotate again in block `H`. The key that is current from `H` + 1 is never in doubt.
- **A key is recorded once** (**decided**). `rotate_key` is refused if its new key is, or has ever been, the key of an address: this one or another, by a first transaction or by a rotation. And a key that a rotation gave to an address cannot open the account it hashes to: the first transaction of that account is refused. One public key, one address, for the life of the network (section 4.5, rule 6).
- **No part of an earlier key** (**decided**). `rotate_key` is refused if the ML-DSA part of the new key is the ML-DSA part of a key this address has had, or if its Ed25519 part is the Ed25519 part of one. A rotation replaces both components.
- **What the chain does not refuse, and why.** RFC 10073 (section 3.1) forbids a component key that is used in another combination. That rule binds whoever generates keys: it is mandatory for wallets and for every tool that makes a key, and the tools of Kern follow it (section 3.3). The consensus does not check it between addresses, so a key the chain accepts is not thereby a key generated as the RFC requires. What the consensus enforces is narrower: a whole public key is recorded once, and an address never takes a part of one of its earlier keys, where only the holder acts. It deliberately does not refuse a key because one of its two parts is a part of the key of another address. A public key is seen before it is recorded: in the first transaction of its account, or in a `rotate_key`, while they wait to be included. If it did, whoever can forge one of the two schemes could record first a key of his own built on a part of the key he has just seen, with a forged signature for that part, and the honest key would be refused for ever. Breaking one component must give nothing, the power to lock an account out included. To get ahead of a whole key, the same attacker has to forge both.
- **Why reuse would yield little here.** Every signed object names the address of its signer: `sender` in a transaction, `proposer` in a header, `validator` in a consensus message, `sequencer` in a batch. A signature is never the statement of another address, whatever two keys have in common.

## 7. Sizes and measurements

`Transaction.encoded_size()` becomes the size of the whole transaction, signature and key included, so that the fee floor and the block size cap see what a transaction really weighs. Estimates with the text forms above:

| | Today | Composite |
|---|---:|---:|
| Transfer, first of an account | 458 bytes | about 7.5 kilobytes |
| Transfer, later ones | 458 bytes | about 4.9 kilobytes |
| `rotate_key` | | about 12 kilobytes |
| Certificate of 30 validators | 2,940 characters | about 135 kilobytes |
| Certificate of 100 validators | 9,800 characters | about 450 kilobytes |
| Verifying one signature | 0.06 millisecond | about 0.4 millisecond |
| Signing | 0.03 millisecond | about 1.1 milliseconds |

The composite figures were measured with the construction of section 2 written out with the real libraries, outside the repository. Expanding a key from its seed takes about 0.2 millisecond more, once per key. The subgroup check of section 2.5 is one more scalar multiplication at each verification.

With the present default cap of one mebibyte per block, a block holds about 210 later transfers. That default is not chosen here. It is chosen from measurements made with the implementation, on a devnet of 4, 30 and 100 validators and by projection beyond: signatures per second on one core, verification in parallel, time for a certificate to reach every validator, block size, bandwidth per validator.

## 8. What stays classical, and what comes later

Replacing signatures does not make a chain post-quantum everywhere. What this release leaves as it is, and says so:

- **Zero-knowledge claims.** The Groth16 verifier on BN254 stays, documented as classical. A proof system built on hash functions is the later answer; it does not block this release.
- **Precompile 0x01.** It keeps its Ed25519 interface for contracts, documented as classical, under the verification rule of section 2.5. For a valid signature it returns 12 zero bytes and the address of the key inside the Mini-EVM, which is the first 20 bytes of `H("kern.evm.signer", public key)`; that is not the address of an account, whose key is composite. No rule of the protocol itself may rely on it, and no account key is ever used through it (section 3.3). A precompile that verifies composite signatures is planned for contracts, after this release.
- **The Mini-EVM** (**decided**). It is the machine of the fraud proofs of the rollup framework. It is not the virtual machine of Ethereum, and does not claim to be: its `SHA3` opcode computes SHA3-256 and not Keccak-256, its precompile 0x01 verifies Ed25519, and it derives the address of a contract in its own way. `CREATE` gives the first 20 bytes of `H("kern.evm.create", creator || nonce)`, and `CREATE2` the first 20 bytes of `H("kern.evm.create2", creator || salt || code_hash)`, where `code_hash` is `H("kern.evm.code", creation code)`. The creator is written on 20 bytes, its nonce on 8 and the salt on 32. Ethereum takes the last 20 bytes of a Keccak-256, computed for `CREATE` over an encoding of its own (RLP): a contract does not get there the address it gets here, and nothing in Kern assumes that it does. A rollup that needs the semantics of Ethereum runs an execution layer of Ethereum ([rollups.md](rollups.md)). The two derivations belong to structure version 1 and are held by vectors. The addresses stay at 160 bits and the `SHA3` opcode stays what it is (section 4.2). The states and the code of the machine are committed with `H` like everything else.
- **Peer connections.** They are neither encrypted nor authenticated today. The plan, with the hardening of the network layer, is TLS 1.3 with a standard hybrid key exchange and peers authenticated by a composite signature. ML-KEM establishes a secret and authenticates nobody, and Kern does not design a handshake of its own.
- **Root signatures.** The genesis, release tags and integrity manifests are signed rarely and must hold for decades. SLH-DSA (FIPS 205), built on hash functions alone, is the planned scheme for them: another family than ML-DSA, large and slow signatures that these uses can afford.
- **Key storage.** A seed in a file in clear text is the weakest point of an account, before and after this release. Encrypted key files and hardware security modules for validators come later.
- **Forks.** A fork is a new network (section 3.1). Carrying a state over to it is a migration this profile does not define.

## 9. Consequences in the code

- **Nothing identifies a statement by its signature.** Checked: a transaction identifier is the hash of the signed payload, without the signature (`Transaction.hash`); a block hash is the hash of the header without its signature, and the certificate is outside it; the vote deduplication key in `kern/node.py` is (kind, level, round, validator, block hash); a slashing offence is identified in `kern/chain.py` by (validator, kind, level, round); proposal evidence compares what is signed; the signing journal records what was signed. The second review found one exception, since corrected: the node compared two proposals of a round with their signatures ([consensus-locking.md](consensus-locking.md), section 10.11). To change: the comment of `kern/signing_journal.py` which says that signing a message again reproduces the same signature.
- **Two clients, one verdict.** The rule of section 2.5 is applied by both clients. The Python client asks libsodium whether the key is a valid point of the subgroup; the Go client makes the checks itself, since its standard library does not. [go-port-breakpoints.md](go-port-breakpoints.md) lists Ed25519 as interoperable without this caveat today.
- **One hash function.** Every protocol hash becomes a call of `H`, with the network identifier. The table of domains in the inventory changes with the code, and a test holds the two together.
- **One encoding.** The encoder writes characters outside ASCII as UTF-8, where it writes escapes today; for ASCII content the bytes do not change. Decoding gains the check of section 4.3: what is not canonical is refused.
- **Another tree.** The transactions of a block are hashed into the tree of section 4.4, and a second root is added to the header, with a structure version.
- **Invalid signatures invalidate blocks.** The node stops skipping a transaction whose signature does not verify.
- **The network identifier is mandatory.** A genesis without one is refused. Chains built by the tests get one, and the devnet generator draws one each time it builds a genesis.
- **Hashes and addresses grow.** Every hash field goes to 96 hexadecimal characters and every address to 75; strict decoding and its tests follow.
- **Keys leave the validator set.** The snapshot of an epoch holds addresses and stakes; keys are read from the registry.
- **Everything is regenerated.** Every address changes. The genesis of the repository, the devnet generator, the wallet, the explorer and the examples of the documentation are regenerated; a devnet has to be reset.
- **One more dependency.** The `cryptography` package joins PyNaCl and py_ecc in the inventory.
- **The state root.** With the function `trie`, what is hashed is the state with its accounts replaced by the root of the trie (section 4.6). The leaf of the trie states a number of bits, and the name of the function is hashed with the rest of the state.
- **A registry that remembers.** It refuses a key it has ever recorded, a second rotation of an address in a block, and a rotation that takes a part of an earlier key of the address (section 6.4).
- **The proposer draw.** It hashes the 48 bytes of the parent hash under `kern.proposer`, where it hashes their hexadecimal text without a domain today.
- **The Mini-EVM.** `CREATE` and `CREATE2` hash with `H`, the code hash of `CREATE2` is 48 bytes, and the state of the machine writes its storage as an object. Precompile 0x01 hashes the key it verified under `kern.evm.signer`, where it uses the domain of account addresses today.

## 10. Tests that come before the words

The [inventory](cryptographic-inventory.md) refuses any claim of resistance until the following exist and pass. The Go client runs the same vectors, from the same files, and must give the same answers.

1. **The standard.** The test vectors of RFC 10073 for this combination: the published signatures verify, the published seeds give the published public keys, and keys and signatures have the published serialization.
2. **NIST and Wycheproof.** The vectors of NIST for ML-DSA-65 (key generation and signature verification, with the invalid cases) and those of Project Wycheproof for ML-DSA-65 and Ed25519. The files are kept whole in the repository, each with its origin and its hash. The list of errata on the page of FIPS 204 is read again at each release.
3. **Either component broken.** At every place a signature is checked (transaction, block header, proposal, vote, quorum certificate, rollup batch, slashing evidence, key rotation), a message whose Ed25519 component is valid and whose ML-DSA component is not must be refused. And the reverse.
4. **No fallback.** An Ed25519 signature alone is refused at each of those places.
5. **Contexts.** A signature made for one of the seven purposes is refused for each of the six others, and a signature made for one network identifier is refused for another. The context bytes are part of the vectors.
6. **Key derivation.** The vectors of section 17: PRK, infos, the three outputs, the public keys and the address. The same seed and the same chain name with another network identifier give other keys and another address, and nothing signed for one network is accepted on the other.
7. **Signature bytes.** The same transaction, vote or proposal signed twice, or with its Ed25519 component replaced by another valid one, keeps its identifier, is counted once, leads to no second vote and is evidence of nothing. For proposals this already holds on the present code (`tests/test_signature_bytes.py`).
8. **Ed25519.** The 31 cases of section 17 and the Wycheproof vectors get the verdict of section 2.5, in the composite, through precompile 0x01 and when a key is recorded.
9. **Component keys.** The key derived for a contract is not the Ed25519 component of the account key, and no function of the repository signs with a component alone or returns one.
10. **Encoding.** The canonical encodings of section 17, and every non-canonical form refused, at decoding and at reception.
11. **Hashes and trees.** The digests and roots of section 17: empty tree, one item, odd numbers of items; and, for every domain, the data that section 4.1 lays out. Every hash is 96 hexadecimal characters; a shorter, longer or truncated value is refused wherever a hash is decoded.
12. **Text forms.** Every spelling of a key or a signature other than the canonical one is refused.
13. **Key registry.** First recording, a key that fails its check, a second key presented for an address that has one, a transaction that carries a key after one is recorded, an account of the genesis without a key, a key recorded twice: for two addresses, or by a rotation and then by the account it hashes to.
14. **Addresses.** The rules of section 4.5: no transaction from an address that holds a contract, no contract at an address that has a key, no address listed twice in a genesis; an address of another network fails its checksum.
15. **Blocks.** A copy of a block in which a signature was changed, or its last transaction repeated, does not match its header; a block that contains a transaction with an invalid signature is invalid.
16. **Rotation.** The old key up to `H`, the new one from `H` + 1 and never both; a rotation without a valid second signature is refused; a vote of an earlier level is still verified, in evidence, with the key of that level. Two rotations of one address in one block: the first is applied and the second fails. A rotation that fails, then a valid one of the same address in the same block: the second is applied. A rotation to a key that was ever recorded, or that takes a part of an earlier key of the address, is refused.
17. **Two clients.** The same keys, addresses, encodings, roots, verdicts on signatures and certificates, and results of execution in Python and in Go. Each client verifies the signatures of the other, in the seven contexts, and both refuse the same invalid ones; they need not produce the same bytes, since signing is randomized. The two programs of section 17 already do this, outside the node.
18. The existing consensus simulator and the tests with real processes, unchanged in what they assert.
19. **State root.** A change in any field of the state changes the root, with both functions, the key registry and its history included; the trie has one shape for one set of accounts, whatever the order in which they appeared.

## 11. Order of work

1. **Freeze the profile.** Done with this version (section 18).
2. **Implement**, behind the tests of section 10. First the signature mechanism and the functions of the profile (derivation, contexts, hash, encoding, trees, text forms, addresses), with the official vectors and the whole verification, in Python, of the signatures of section 17. Then the schemas of version 1, written in [api-stability.md](api-stability.md) and reviewed before any format is implemented. Then formats and state (the new hash everywhere, network identifier, no fallback, the two roots of a block, the state root of section 4.6, genesis, devnet, wallet, explorer). Then the key registry, `rotate_key` and size accounting: the registry never enters a state whose root does not cover it.
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
| The same vectors in Python and Go; follow the errata of NIST | Sections 10 and 17. The errata known to us, announced on the NIST forum in 2024 and 2025, correct text and change no algorithm |
| No silent fallback to Ed25519 alone | Section 2.4, test 4 |

Also decided on that day: the account key registry and `rotate_key` are part of this release.

## 13. Second review, 12 November 2026

A second review read the second version against the published text of RFC 10073 and against the code. It found the construction of section 2 conforming and would not change it. It asked for the following.

| Point raised | Outcome |
|---|---|
| Name the two contexts apart; say that the format is not an X.509 implementation; state the guarantee in the terms of the RFC | Sections 2.1 and 2.3 |
| The derivation must carry a version and be specified exactly; HKDF-SHA-512 preferred | Section 3.2 |
| A chain name is not the identity of a network: use an independent 32-byte identifier, recorded in the genesis | Accepted (decided). Section 3.1 |
| Addresses at 256 bits only if every relevant attack is shown to be a second preimage; identifiers examined one by one | Everything moves to 384 bits (decided), and the registry rules are stated. Sections 4.2 and 4.5 |
| One purpose per kind of consensus message | Accepted. Section 6.2 |
| The node compared two proposals of a round with their signatures: the same proposal signed again was taken for a conflict | Confirmed by a failing test and corrected ([consensus-locking.md](consensus-locking.md), section 10.11) |
| The component key Ed25519 must not be usable alone through precompile 0x01 | Accepted. Section 3.3, test 9 |

Raised by the author while preparing the implementation, and kept:

| Point | Outcome |
|---|---|
| The standard library of Go and OpenSSL accept Ed25519 signatures that libsodium refuses | One rule and its vectors. Section 2.5, test 8 |
| The text form of a key or a signature must be unique | Section 5, test 12 |
| BLAKE2b is neither a standard of NIST nor among the hash functions recommended by ANSSI | SHA3-384 (decided). Section 4.1 |
| A header does not commit to the signatures of its transactions | A second root. Section 6.3, test 15 |

## 14. Third review, 12 November 2026

A third review read the third version in full. It approved the architecture, answered the seven questions that version asked, confirmed that JSON is kept, and listed what had to be made exact before the profile is frozen.

| Point raised | Outcome |
|---|---|
| The derivation written out step by step, the ML-DSA seed stated as the input of KeyGen_internal, a vector of its own for the key of contracts, one seed for one identity | Section 3.2, vectors of section 17 |
| The genesis is the reference of trust for a wallet. A network identity is immutable: a fork is a new network, and its migration is defined apart | Accepted. Section 3.1 replaces the sentence that let a fork change its identifier at a given level |
| The network identifier in every protocol hash; an exhaustive, normative table of domains; the exceptions stated | Section 4.1 |
| Canonical JSON specified in full: integers and their limits, escapes, absent fields, and refusal at reception of bytes that are not canonical. No binary encoding needed | Accepted (decided). Section 4.3 |
| Merkle trees defined in full on the model of RFC 6962, with three domains | Section 4.4 |
| The witness leaf should include the transaction identifier and an explicit sign of the presence of a key; both roots in the block hash; a block with an invalid signature is invalid | Accepted. Section 6.3 |
| Ed25519: the exact equation is right; the public key must be in the subgroup of prime order, mixed orders refused; the case of the identity as `R` stated and tested; keys checked when recorded, at each use, in the genesis and in the precompile; libsodium is not the definition | Accepted. Section 2.5, rewritten as mathematics. It is stricter than the third version and than libsodium |
| A validator may rotate its key: old key up to the block that includes the rotation, new key from the next level, proof of possession by the new key, one state transition, old keys kept for evidence, no period where both are accepted | Accepted. Section 6.4, and a seventh purpose for the proof of possession |
| The checksum of an address is Kern's own, not the one of Base58Check | Section 5 |
| The protection of key files is a limitation to state | Sections 3.3 and 8 |
| Claim for the composition exactly what RFC 10073 establishes | Section 2.3 |

Found while writing this version:

| Point | Outcome |
|---|---|
| "384 bits everywhere" cannot include the addresses inside the Mini-EVM, which are values of a 256-bit virtual machine built around 160-bit addresses | Stated as an exception. Sections 4.2 and 8 |
| The keys of a map of data, such as the storage of a contract, are not ASCII field names | The same order applies to them. Section 4.3 |
| The address of an account and the address of a contract were hashed under one domain | Two domains. Sections 4.1 and 4.5 |

## 15. Fourth review, 12 November 2026

A fourth review read the fourth version and its vectors, and recomputed part of them on its own: the PRK, the three outputs of the derivation on both networks, the Ed25519 public keys, digests of `H`, the Merkle roots for zero to eight items, the four witness leaves and the address. All of them matched. It approved the three points the fourth version had added, declared the architecture frozen (the scheme, the derivation, the hash function, the network identifier, the encoding, the trees, the registry and its rotation, the witness root), and listed what remained before the profile itself is.

| Point raised | Outcome |
|---|---|
| The bytes hashed under every domain are not all stated: which data is canonical JSON, which is a string of bytes, and how each is laid out | Section 4.1, in two tables, with vectors for every domain |
| `CREATE` and `CREATE2` in the Mini-EVM are not the formulas of Ethereum. Keep its semantics, or state a derivation of Kern, versioned and tested; say how the code is hashed | A derivation of Kern (**decided**). Section 8. It is what the code does today, with another hash function |
| The 160 bits of the addresses of the Mini-EVM are not the margin of the rest, and not a post-quantum margin | Said in those words. Section 4.2 |
| Two `rotate_key` of one address in one block: nothing says which key becomes current | One rotation per address and per block, the first in the order of the block (**decided**). Section 6.4 |
| RFC 10073 forbids the reuse of component keys, and a key could be given to several addresses by rotations. Refuse a key that was already used, and any component already used in another key | A key is recorded once on a network, and a rotation takes no part of an earlier key of the address (**decided**). The chain does not refuse a key for one part shared with another address: section 6.4 says why |
| Three values of each derivation come from one implementation of ML-DSA, and Go has one since version 1.27 | The Go program computes them. Section 17 |
| Composite signatures are to be verified in both directions, in the seven contexts, with invalid cases. The two implementations need not give the same bytes | Done between the two programs, with a file of signatures. Section 17. Between the two clients: section 10, test 17 |
| Say that `S` and `k` are read least significant byte first | Section 2.5 |
| RFC 10073 was published in November 2026, not in October. Link the published text | Corrected. Section 2.1 and the references |
| The schemas of the objects are to be normative, each tied to a version that can be named | One structure version for all of them. Section 4.3 |
| A migration stays explicitly outside the profile | Unchanged. Section 3.1 |

Found while writing this version:

| Point | Outcome |
|---|---|
| The key registry has to be committed by the state root whichever function computes it | The root covers every field of the state with both functions (**decided**). Section 4.6 |
| The leaf of the state trie hashes the number of bytes of its path: the paths `1` and `10` are hashed alike | The leaf states its number of bits. Section 4.6 |
| The generation of both component seeds from one seed is allowed by section 3.1.1 of the RFC, not 3.1 | Section 3.2 |
| The proposer draw hashes the hexadecimal text of the parent hash, without a domain | Its 48 bytes, under `kern.proposer`. Section 4.1 |
| Precompile 0x01 returns 20 bytes of a hash of the Ed25519 key it verified, computed under the domain of account addresses | A domain of its own, `kern.evm.signer`. Sections 4.1 and 8 |

## 16. Fifth review, 12 November 2026

A fifth review read the fifth version, its vectors and the Go program. It found the four points and the four complements of the fourth review closed, and approved the rule of the state root, the leaf of the state trie and the domain of precompile 0x01. It agreed that refusing a key for one component shared with another address would let whoever forges one scheme lock a key out. It approved the freeze of the profile, and asked for precisions and vectors, not for changes of design.

| Point raised | Outcome |
|---|---|
| The rule against reuse between different keys is an obligation of key generation and of wallets. The consensus does not check it between addresses, and the note must not read as if it did | Said in those words. Sections 3.3 and 6.4 |
| The vectors of the state root hold no key registry, which is what the rule was written for | Six more vectors: a current key, an earlier one, the level from which each is current, and a change in each, with both functions. Section 17 |
| What happens when the first rotation of an address in a block fails and a valid one follows | A rotation that fails does not count, and the first that succeeds is applied (**decided**). Section 6.4, and test 16 |
| The whole verification of the signatures, in Python, belongs in the continuous integration | With the implementation, which brings the dependency. Sections 11 and 17 |
| The schemas of version 1 are to be normative in api-stability.md before they are implemented | Written and reviewed before the formats. Sections 4.3 and 11 |
| The freeze of the profile is not its implementation, its integration in the consensus, or an audit | Section 18 |

## 17. Reference vectors

The byte rules of this note are held by vectors kept in the repository:

- `tests/vectors/kern/profile.json`: canonical encodings and the forms that must be refused; digests of `H`; Merkle roots for zero to eight items; two complete key derivations (seed, PRK, the three infos, the three outputs, the composite private key, the public keys and the address); the seven contexts; an address on two networks; the four shapes of a witness leaf. And the data of every domain of section 4.1: the proposer draw of four rounds, the address of a contract, the three addresses of the Mini-EVM (`CREATE`, `CREATE2`, and the one precompile 0x01 returns), nine objects with their canonical JSON, a leaf of the state trie at ten depths, the root of the trie for zero to four accounts, and the state root with both functions: without a key registry, then with one, where a change in the level from which a key is current, or in the key itself, changes the root with both.
- `tests/vectors/kern/ed25519_edge_cases.json`: the 31 cases of section 2.5, each with the verdict of the rule and the verdict of a verifier that makes only the checks RFC 8032 requires. 16 of them are accepted by such a verifier and refused by the rule.
- `tests/vectors/kern/composite_signatures.json`: composite signatures of one message by one key in the seven contexts, seven made by each of the two programs below, and seventeen cases that must be refused: a wrong component on either side, an ML-DSA component signed outside its Label, a signature that is too short or too long, a component alone, another purpose, another network, another message, and public keys that are not keys.

Two implementations written independently reproduce them:

- `tests/profile_reference.py` and `tests/ed25519_reference.py`, with the Python standard library: the profile as executable text, and Ed25519 written out from RFC 8032 with no library. `tests/test_profile_vectors.py` runs them in the test suite.
- `tests/vectors/kern/profile_check.go`, with the Go standard library, from version 1.27. The continuous integration runs it on every pull request: `go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json`.

libsodium is a third opinion on the Ed25519 public keys and on the rule.

**The values that need ML-DSA.** Three values of each derivation need the ML-DSA key pair: the digest of the ML-DSA public key, the digest of the composite public key, and the address they give. Two libraries compute them and agree: the `cryptography` package, over OpenSSL, when the vectors are built, and `crypto/mldsa` in the Go program.

**Signatures, in both directions.** The Go program verifies the seven signatures made in Python and the seven it made itself, each in its context and refused in the six others, and refuses the seventeen invalid cases. It rebuilds its own signatures byte for byte: for that it signs in the deterministic mode of ML-DSA, where the Python program signs in the randomized mode. The two programs therefore do not produce the same bytes, and do not have to. In the other direction, the Python test suite checks what needs no ML-DSA: the message both components sign, and the Ed25519 half of the fourteen signatures under the rule of section 2.5. The whole verification in Python, both halves, was run outside the repository on the fourteen signatures and the seventeen cases, with the same results. It enters the test suite with the implementation, which brings the `cryptography` package as a dependency.

The tests delivered with the implementation also run the official vectors of RFC 10073, NIST and Wycheproof, on which the construction of section 2 and the library have already been run outside the repository.

Neither reference is the node, which still hashes with BLAKE2b and signs with Ed25519.

## 18. The freeze

The third review made the freeze depend on ten conditions. The fourth found six of them satisfied and four in part. The fifth found the four closed and approved the freeze. The profile is frozen in this sixth version, on 12 November 2026.

| Condition | Where it is met |
|---|---|
| Derivation: complete vectors from two implementations, and the derivation of the key for contracts | Sections 3.2 and 17. The public keys that need ML-DSA come from two implementations |
| Hash: SHA3-384, exhaustive domains, network identifier in every protocol preimage | Section 4.1: the data of every domain to the byte, with vectors; the addresses of the Mini-EVM decided (section 8) |
| Merkle: recursive construction, empty tree, one item, odd numbers, vectors | Section 4.4, vectors |
| JSON: the canonical profile in full, large integers, encoding tests | Section 4.3, vectors. Every schema belongs to the structure version of the block |
| Ed25519: subgroup, `A` and `R`, exact equation, adversarial cases | Section 2.5, with the byte order stated; 31 cases computed three ways |
| Witness root: encoding of the leaves, link to the transaction identifier, place in the header | Section 6.3, vectors |
| Rotation: proof of possession, level of activation, old keys kept | Section 6.4: one rotation per address and per block, a key recorded once, no part of an earlier key |
| Forks: rules for the network identifier and for the migration of state | Section 3.1: no change of identifier, a fork is a new network, its migration is not defined here |
| Composition: claims limited to what RFC 10073 establishes | Section 2.3 |
| Interoperability: Python and Go run the same positive and negative vectors | Section 17: the profile, the keys that need ML-DSA, and composite signatures in both directions between the two programs. Between the two clients, with the node: section 10, test 17 |

**What frozen means.** The rules of this note and the values of its vectors no longer change. Vectors can be added for a rule that exists. An error found while implementing is corrected as an erratum, dated and listed in this section. A change of rule is a new version of the profile, reviewed as this one was.

**What the freeze is not.** It is not the implementation of the profile in the node, nor the proof that the consensus and the state follow it, nor an audit. The status at the top of this note stays true until the code exists, passes the tests of section 10 in both clients and has been reviewed: no part of Kern is post-quantum today. An external cryptographic audit comes with the implementation, and before any open network.

**What comes first.** The schemas of version 1 are written and reviewed before the formats are implemented, and the whole verification of signatures in Python enters the continuous integration with the implementation (section 11).

## References

- IETF, Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for Use in X.509 Public Key Infrastructure, [RFC 10073](https://www.rfc-editor.org/rfc/rfc10073.html), November 2026 (until then draft-ietf-lamps-pq-composite-sigs). The section numbers quoted here are those of the published text. RFC 9955, which it cites for the notions of non-separability.
- IETF, HKDF, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869); Ed25519, [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032); Certificate Transparency, [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), for the Merkle tree; JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard, August 2024; [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), SHA-3 Standard; [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
- BSI TR-02102-1, version 2026-01, as summarized by [Fraunhofer AISEC](https://www.aisec.fraunhofer.de/en/spotlights/Competence-Center-PQC/developments-in-pqc.html).
- ANSSI, [rules and recommendations on the choice and sizing of cryptographic mechanisms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf), version 3.00, March 2026 (section 2.1.4 on hash functions); [selection guide for cryptographic algorithms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-selection_crypto-1.0.pdf), 2021; [views on the post-quantum cryptography transition](https://cyber.gouv.fr/publications/anssi-views-post-quantum-cryptography-transition), 2022, and [questions and answers](https://cyber.gouv.fr/cryptographie-post-quantique-faq).
- Project Wycheproof, [test vectors](https://github.com/C2SP/wycheproof).
- Go, package [crypto/mldsa](https://pkg.go.dev/crypto/mldsa), in the standard library from version 1.27.
- G. Brassard, P. Høyer and A. Tapp, [Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002), 1997.
- K. Chalkias, F. Garillot and V. Nikolaenko, [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244), 2020.
