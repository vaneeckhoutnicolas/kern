# Kern Protocol

**Kern** is a Layer-1 blockchain protocol that combines the developer ecosystem and EVM tooling of Ethereum with the on-chain governance, formal verifiability, and Liquid Proof-of-Stake of Tezos.

Smart contracts are written in **Skald**, a resource-typed language with declared invariants compiled to verifiable bytecode and executed deterministically.

This site is the canonical documentation for the Kern protocol — its design, its economy, its governance, and the reference implementation.

---

## Where to start

If you have **5 minutes** → read the [Executive summary](executive-summary.md).

If you have **30 minutes** and want the full design → read the [Whitepaper](whitepaper.md) and the [Tokenomics](tokenomics.md).

If you want to **delegate KRN** without running a node → [Staking & delegation](staking.md).

If you want to **contribute** to the protocol → [Contributors program](contributors-program.md).

If you want to **run a node** → [Running a node](running-a-node.md).

If you want to **explore the chain** (blocks, transactions, attestations, oracle health, STO compliance state) → set up [Heimdall](setup-heimdall-operator.md), the official block explorer and monitoring stack.

If you're building **alternative client software** → [API stability spec](api-stability.md).

---

## What's distinctive about Kern

| Feature | Ethereum | Tezos | **Kern** |
|---|---|---|---|
| EVM compatibility | Native L1 | None at L1 | Via optimistic rollups |
| Smart contract language safety | Solidity (no native invariants) | Michelson + LIGO | **Skald with declared, runtime-enforced invariants** |
| Staking model | 32 ETH locked or LST | Liquid PoS, custody preserved | **Liquid PoS: Liquid PoS, no LST needed** |
| Governance | Off-chain, hard forks | On-chain, self-amending | **On-chain, transactional, dual-track (protocol + treasury)** |
| zkSNARK precompiles | BN254 + KZG | None | **BN254 (via py_ecc)** |
| Light-client proofs | Merkle-Patricia trie | Patricia tree | **Binary Merkle trie with O(log n) proofs** |

The design philosophy: take the things Ethereum proved at scale (EVM ecosystem, smart contract tooling, account model) and the things Tezos proved at scale (on-chain governance, formal verifiability, no-lockup delegation), and put them in one protocol without forcing a choice.

---

## Genesis economy

| Pool | KRN | % | Vesting |
|---|---:|---:|---|
| Public sale | 70 000 000 | 70% | Liquid at genesis |
| Founder | 10 000 000 | 10% | 1-year cliff + 4-year linear |
| Foundation | 15 000 000 | 15% | Foundation legal entity multisig |
| Early contributors pool | 3 000 000 | 3% | 6-month cliff + 3-year linear |
| Validator bootstrap | 2 000 000 | 2% | Released over 1 year |
| **Total** | **100 000 000** | **100%** | |

Modeled on the Ethereum 2014 ICO template with modern vesting practices. See [Tokenomics §4](tokenomics.md#4-distribution-at-genesis).

---

## Current status

This documentation reflects **v1.0-rc** (release candidate). The reference implementation is feature-complete:

- ✅ Multi-validator BFT consensus with Liquid PoS
- ✅ Skald language + static type checker + invariant runtime enforcement
- ✅ Multi-frame EVM with fraud-proof bisection
- ✅ Real BN254 pairing for zkSNARK verification
- ✅ EVM Yellow Paper-compliant gas pricing
- ✅ Two-track on-chain governance with quadratic + delegated voting + slashing
- ✅ Liquid PoS baking delegation (no LST, no lockup)
- ✅ Adaptive issuance + treasury
- ✅ 368 tests passing

What remains before mainnet (Midgard):

- 🟡 Audit cycle 1 (Trail of Bits, OtterSec, Hashlock, or Runtime Verification — pending Foundation setup)
- 🟡 Foundation legal entity (recommended: Estonian Sihtasutus; alternatives: AISBL or Stiftung)
- 🟡 Yggdrasil public testnet launch
- 🟡 Wallet integration (custom or via Ledger + Metamask Snap)
- 🟡 Block explorer (fork Blockscout or build minimal)
- 🟡 Public sale design (ICO / Dutch auction / LBP / staged)
- 🟡 Audit cycle 2 (post-fixes)
- 🟡 Genesis ceremony

See the [Roadmap](roadmap.md) for the full three-track plan (code / networks / operations).

---

## Source code

The reference implementation is hosted at <https://github.com/vaneeckhoutnicolas/kern>.

License: **Apache-2.0** (permissive). Use in proprietary, closed-source software is permitted, with no obligation to open-source your changes; Apache-2.0 also includes an express patent grant.

```bash
git clone https://github.com/vaneeckhoutnicolas/kern.git
cd kern
pip install -r requirements.txt
pytest tests/
# 368 passed, 2 skipped in ~10s
```

For a multi-node devnet:

```bash
python networks/devnet_bootstrap.py --validators 3 --out ./devnet
cd devnet && docker compose up
```
