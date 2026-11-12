# Hybrid signatures (design)

> **Status.** Draft for review. Nothing in this note is implemented. The [cryptographic inventory](cryptographic-inventory.md) describes what the code does today: every signature is Ed25519, and no part of Kern is post-quantum.

Kern is not in production, so its formats can still change without migrating anyone. The decision is to make the protocol post-quantum by construction, in a dedicated release (1.2), before any network beyond the devnet exists. This note is the cryptographic profile of that release: what is signed and how, how keys are derived, how objects are encoded and hashed.

This is its fourth version. Three reviews, all on 12 November 2026, are recorded in sections 12 to 14; the choices they led to are marked **decided**. The third one approved the architecture and asked that everything two implementations must agree on be specified to the byte and held by vectors. This version does that: section 15 describes the vectors, which two independent implementations reproduce, and section 16 is the list of conditions for freezing the profile. Code is written once that list is accepted.

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
| Addresses | `kn1` and base 58 as today, 75 characters, valid on one network |
| Text forms | `kpk1.` and `ksig1.` followed by base64url, one text per value |
| Where keys live | Stored once in the state (the account key registry), never repeated in messages; registry and rotation in this release (**decided**) |
| Signing contexts | Seven purposes. Every signature states its purpose and its network |
| Ed25519 verification | One rule, written as mathematics, the same in every client |
| Blocks | The header has a structure version and commits to the signatures of its transactions; a block that contains an invalid signature is invalid |
| Sizes | The fee floor and the block size cap count the signature |
| Classical leftovers | Precompile 0x01 (Ed25519) and the Groth16 verifier (BN254) stay, documented as classical |
| Release | 1.2.0rc1; a devnet started with an earlier version has to be reset |

## 2. The signature scheme

### 2.1 A standard mechanism, a Kern profile

Combining two signature schemes looks trivial and has traps: which bytes each one signs, how the two are tied together, how a signature made for one purpose is kept from serving another. The IETF has specified this as **Composite ML-DSA**, published as RFC 10073 in October 2026 (from [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/)). Kern uses it instead of defining its own.

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

This construction has been run against the test vectors published with the RFC for this combination: the published private key gives the published public key, the two published signatures verify (without a context and with one), and every altered case is refused.

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

- **Where it applies.** To the Ed25519 component of every composite signature, and to precompile 0x01. Rule 2 is also checked when a key is recorded: in the genesis, at the first transaction of an account, in `rotate_key` (section 6.4). A key that fails it is never recorded.
- **The identity as `R`.** It is in the subgroup, and a deterministic signer produces it with a probability of about 2^-252. Refusing it is a restriction that Kern takes on purpose: such a signature gives the secret away, since `S` divided by `k` is the secret scalar.
- **Measured.** On 31 cases built for this note from RFC 8032, one is valid under the rule: an ordinary signature. The standard library of Go (1.24) and OpenSSL (4.0), left alone, accept 17: 16 of them are refused by the rule. libsodium, the library behind PyNaCl, accepts 3: it takes a public key of mixed order, which the rule refuses. The 210 Ed25519 vectors of Project Wycheproof leave 29 cases to the implementation, all of them with a public key of small or mixed order; the rule refuses the 29.
- **Implemented three times.** The rule gives the same verdict on the 31 cases when it is computed as plain arithmetic with no library, with libsodium doing the arithmetic, and with the standard library of Go after the checks 2 to 4 (section 15).

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

- **Allowed by the standard.** RFC 10073 (section 3.1) allows a deterministic generation in which one seed is expanded into the seeds of both components. It leaves the expansion to the application, and requires that both component keys be fresh and never used outside the composite.
- **A standard construction.** HKDF is among the key derivation mechanisms that the selection guide of ANSSI recommends. It is in the standard library of Go, and Python builds it from HMAC in a few lines.
- **Versioned.** The first field of the info is the version of the derivation. Another derivation is another label, and a key file records the version it was made with. The scheme number is a separate thing: the chain never sees how a key was derived.
- **One seed, one identity.** A seed gives one account key per network. Several accounts are several seeds, drawn independently; this version of the derivation has no account index.
- **Bound to one network.** The same seed gives another key pair and another address for every network identifier. A key exposed on a test network says nothing about the key of another network.

Section 15 gives a complete vector: seed, PRK, the three infos, the three outputs and the public keys they give.

### 3.3 What a key is never used for

- **Never a component alone.** RFC 10073 forbids using a component key outside the composite (sections 3.1 and 9.3): a key that also signs alone weakens the composite it belongs to. No function of Kern signs with one component, and none returns a component key.
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

The domains are the following, and there is no other. A hash under a name that is not in this table is not a hash of the protocol.

| Domain | What is hashed |
|---|---|
| `kern.tx` | A transaction, without what it carries besides what it signs: its identifier |
| `kern.block` | A block header without its signature: the hash of the block |
| `kern.merkle.empty` | Nothing: the root of a tree with no item (section 4.4) |
| `kern.merkle.leaf` | One item of a tree |
| `kern.merkle.node` | The two subtrees of a node |
| `kern.witness` | What a transaction carries besides what it signs (section 6.3) |
| `kern.state` | The state, in `json` mode |
| `kern.trie.leaf` | A leaf of the state trie |
| `kern.trie.branch` | A branch of the state trie |
| `kern.trie.key` | The position of an address in the state trie |
| `kern.storage` | The storage of a contract, inside its trie leaf |
| `kern.code` | The code of a contract, inside its trie leaf |
| `kern.addr` | The scheme number and the public key of an account: its address |
| `kern.addr.contract` | The identifier of the transaction that originates a contract: its address |
| `kern.checksum` | The prefix and the hash of an address: its checksum, the first 4 bytes |
| `kern.proposer` | The hash of the parent block and the round: the public draw of the proposer, the first 8 bytes |
| `kern.batch` | A rollup batch without its signature |
| `kern.rollup.program` | The program a rollup batch executed |
| `kern.mailbox` | A forced inclusion request |
| `kern.gov.id` | A governance proposal: its identifier |
| `kern.attestation.id` | An attestation: its identifier |
| `kern.zk_claims.vk` | A Groth16 verifier key: its identifier |
| `kern.evm` | A state of the Mini-EVM, for fraud proofs |
| `kern.evm.code` | The creation code hashed into a `CREATE2` address |
| `kern.evm.create` | The creator and its nonce: an address inside the Mini-EVM, the first 20 bytes |
| `kern.evm.create2` | The creator, a salt and the hash of the code: an address inside the Mini-EVM, the first 20 bytes |

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
- the addresses inside the Mini-EVM of the rollup framework, 160 bits. They are values of that virtual machine, whose words are 256 bits and whose instructions assume this size. A contract address computed in advance there has the collision margin of a 160-bit hash, as on the chains that share this model. Widening it is a decision for the rollup framework, outside this profile (section 8).

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

The fields of each object, their types and their bounds are the schema of that object. Schemas are written in [api-stability.md](api-stability.md) when the formats are implemented, each with its vectors; this note fixes the encoding they all share.

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

The transactions of a block have two such trees (section 6.3). The state trie has its own structure and its own domains; it is unchanged except for `H`.

### 4.5 What an address designates

The size makes collisions between addresses out of reach. The rules below hold in addition, so that what an address designates never changes silently.

1. **One kind.** An address designates an account or a contract, and never the other afterwards. The two are hashed under two domains. An address that holds a contract can never sign a transaction or receive a key, and a contract cannot be originated at an address that has a recorded key. The genesis lists accounts and contracts separately, and no address may appear in both.
2. **One key at a time.** The registry maps an address to one public key. The first key recorded for an address is the one whose hash is the address. No other key is ever recorded for that address because it was presented: the only change is `rotate_key` (section 6.4).
3. **No second presentation.** Once a key is recorded for an address, a transaction for that address that carries a public key is refused, whatever the key.
4. **A key is checked before it is recorded.** It has the right length, and its Ed25519 part passes rule 2 of section 2.5. Any 1,952 bytes are an ML-DSA-65 public key, so that part has nothing more to check.
5. **Genesis.** An account funded in the genesis without a key follows rule 2 at its first transaction. The key of a validator is recorded by the genesis, in the registry.

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

- **The registry** (**decided**: in this release). The state gains a key registry, under the rules of section 4.5. For each address it holds the key that is current, and the keys the address had before, each with the level from which it was current. Nothing is ever removed from it.
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
- **Precompile 0x01.** It keeps its Ed25519 interface for contracts, documented as classical, under the verification rule of section 2.5. No rule of the protocol itself may rely on it, and no account key is ever used through it (section 3.3). A precompile that verifies composite signatures is planned for contracts, after this release.
- **The Mini-EVM.** Its addresses stay at 160 bits and its `SHA3` opcode stays what it is (section 4.2). Its states and its code are committed with `H` like everything else.
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

## 10. Tests that come before the words

The [inventory](cryptographic-inventory.md) refuses any claim of resistance until the following exist and pass. The Go client runs the same vectors, from the same files, and must give the same answers.

1. **The standard.** The test vectors of RFC 10073 for this combination: the published signatures verify, the published seeds give the published public keys, and keys and signatures have the published serialization.
2. **NIST and Wycheproof.** The vectors of NIST for ML-DSA-65 (key generation and signature verification, with the invalid cases) and those of Project Wycheproof for ML-DSA-65 and Ed25519. The files are kept whole in the repository, each with its origin and its hash. The list of errata on the page of FIPS 204 is read again at each release.
3. **Either component broken.** At every place a signature is checked (transaction, block header, proposal, vote, quorum certificate, rollup batch, slashing evidence, key rotation), a message whose Ed25519 component is valid and whose ML-DSA component is not must be refused. And the reverse.
4. **No fallback.** An Ed25519 signature alone is refused at each of those places.
5. **Contexts.** A signature made for one of the seven purposes is refused for each of the six others, and a signature made for one network identifier is refused for another. The context bytes are part of the vectors.
6. **Key derivation.** The vectors of section 15: PRK, infos, the three outputs, the public keys and the address. The same seed and the same chain name with another network identifier give other keys and another address, and nothing signed for one network is accepted on the other.
7. **Signature bytes.** The same transaction, vote or proposal signed twice, or with its Ed25519 component replaced by another valid one, keeps its identifier, is counted once, leads to no second vote and is evidence of nothing. For proposals this already holds on the present code (`tests/test_signature_bytes.py`).
8. **Ed25519.** The 31 cases of section 15 and the Wycheproof vectors get the verdict of section 2.5, in the composite, through precompile 0x01 and when a key is recorded.
9. **Component keys.** The key derived for a contract is not the Ed25519 component of the account key, and no function of the repository signs with a component alone or returns one.
10. **Encoding.** The canonical encodings of section 15, and every non-canonical form refused, at decoding and at reception.
11. **Hashes and trees.** The digests and roots of section 15: empty tree, one item, odd numbers of items. Every hash is 96 hexadecimal characters; a shorter, longer or truncated value is refused wherever a hash is decoded.
12. **Text forms.** Every spelling of a key or a signature other than the canonical one is refused.
13. **Key registry.** First recording, a key that fails its check, a second key presented for an address that has one, a transaction that carries a key after one is recorded, an account of the genesis without a key.
14. **Addresses.** The rules of section 4.5: no transaction from an address that holds a contract, no contract at an address that has a key, no address listed twice in a genesis; an address of another network fails its checksum.
15. **Blocks.** A copy of a block in which a signature was changed, or its last transaction repeated, does not match its header; a block that contains a transaction with an invalid signature is invalid.
16. **Rotation.** The old key up to `H`, the new one from `H` + 1 and never both; a rotation without a valid second signature is refused; a vote of an earlier level is still verified, in evidence, with the key of that level.
17. **Two clients.** The same keys, addresses, encodings, roots, verdicts on signatures and certificates, and results of execution in Python and in Go.
18. The existing consensus simulator and the tests with real processes, unchanged in what they assert.

## 11. Order of work

1. **Freeze the profile.** This note and its vectors, once the conditions of section 16 are accepted.
2. **Implement**, behind the tests of section 10: the signature mechanism and the functions of the profile (derivation, contexts, hash, encoding, trees, text forms, addresses), with the official vectors; then formats and state (the new hash everywhere, network identifier, no fallback, the two roots of a block, genesis, devnet, wallet, explorer); then the key registry, `rotate_key` and size accounting.
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
| The same vectors in Python and Go; follow the errata of NIST | Sections 10 and 15. The errata known to us, announced on the NIST forum in 2024 and 2025, correct text and change no algorithm |
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
| The derivation written out step by step, the ML-DSA seed stated as the input of KeyGen_internal, a vector of its own for the key of contracts, one seed for one identity | Section 3.2, vectors of section 15 |
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

## 15. Reference vectors

The byte rules of this note are held by vectors kept in the repository:

- `tests/vectors/kern/profile.json`: canonical encodings and the forms that must be refused; digests of `H`; Merkle roots for zero to eight items; two complete key derivations (seed, PRK, the three infos, the three outputs, the composite private key, the Ed25519 public keys); the seven contexts; an address on two networks; the four shapes of a witness leaf.
- `tests/vectors/kern/ed25519_edge_cases.json`: the 31 cases of section 2.5, each with the verdict of the rule and the verdict of a verifier that makes only the checks RFC 8032 requires. 16 of them are accepted by such a verifier and refused by the rule.

Two implementations written independently reproduce them:

- `tests/profile_reference.py` and `tests/ed25519_reference.py`, with the Python standard library: the profile as executable text, and Ed25519 written out from RFC 8032 with no library. `tests/test_profile_vectors.py` runs them in the test suite.
- `tests/vectors/kern/profile_check.go`, with the Go standard library, run by hand: `go run profile_check.go profile.json ed25519_edge_cases.json`.

libsodium is a third opinion on the Ed25519 public keys and on the rule.

Three values of each derivation need ML-DSA and come from one implementation only, the `cryptography` package: the digest of the ML-DSA public key, the digest of the composite public key, and the address they give. The Go standard library has ML-DSA from version 1.27. The tests delivered with the implementation check them, together with the official vectors of RFC 10073, NIST and Wycheproof, on which the construction of section 2 and the library have already been run outside the repository.

Neither reference is the node, which still hashes with BLAKE2b and signs with Ed25519.

## 16. Conditions for freezing the profile

The third review made the freeze depend on ten conditions. Where each stands:

| Condition | In this version |
|---|---|
| Derivation: complete vectors from two implementations, and the derivation of the key for contracts | Sections 3.2 and 15. The public keys that need ML-DSA come from one implementation |
| Hash: SHA3-384, exhaustive domains, network identifier in every protocol preimage | Section 4.1, vectors |
| Merkle: recursive construction, empty tree, one item, odd numbers, vectors | Section 4.4, vectors |
| JSON: the canonical profile in full, large integers, encoding tests | Section 4.3, vectors. The schema of each object comes with the formats |
| Ed25519: subgroup, `A` and `R`, exact equation, adversarial cases | Section 2.5, 31 cases computed three ways |
| Witness root: encoding of the leaves, link to the transaction identifier, place in the header | Section 6.3, vectors |
| Rotation: proof of possession, level of activation, old keys kept | Section 6.4 |
| Forks: rules for the network identifier and for the migration of state | Section 3.1: no change of identifier, a fork is a new network, its migration is not defined here |
| Composition: claims limited to what RFC 10073 establishes | Section 2.3 |
| Interoperability: Python and Go run the same positive and negative vectors | Section 15 for the profile. For the signatures themselves, with the two clients (section 10, test 17) |

What the freeze does not wait for: an external cryptographic audit, which comes with the implementation and before any open network.

## References

- IETF, Composite ML-DSA, RFC 10073, October 2026, from [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/). The section numbers quoted here are those of the published text. RFC 9955, which it cites for the notions of non-separability.
- IETF, HKDF, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869); Ed25519, [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032); Certificate Transparency, [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), for the Merkle tree; JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard, August 2024; [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), SHA-3 Standard; [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
- BSI TR-02102-1, version 2026-01, as summarized by [Fraunhofer AISEC](https://www.aisec.fraunhofer.de/en/spotlights/Competence-Center-PQC/developments-in-pqc.html).
- ANSSI, [rules and recommendations on the choice and sizing of cryptographic mechanisms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf), version 3.00, March 2026 (section 2.1.4 on hash functions); [selection guide for cryptographic algorithms](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-selection_crypto-1.0.pdf), 2021; [views on the post-quantum cryptography transition](https://cyber.gouv.fr/publications/anssi-views-post-quantum-cryptography-transition), 2022, and [questions and answers](https://cyber.gouv.fr/cryptographie-post-quantique-faq).
- Project Wycheproof, [test vectors](https://github.com/C2SP/wycheproof).
- G. Brassard, P. Høyer and A. Tapp, [Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002), 1997.
- K. Chalkias, F. Garillot and V. Nikolaenko, [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244), 2020.
