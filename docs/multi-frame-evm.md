# Calls, creations and precompiles of the Mini-EVM

This page says what [`kern/evm/frames.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/frames.py) does around the Mini-EVM of [`evm-fraud-proofs.md`](evm-fraud-proofs.md): it runs one program for a call or for a creation, on a world of accounts, and it serves nine precompiles. It is a library of the rollup framework. Nothing in the node calls it.

The page keeps the file name it had when it described a design with several frames. What that design promised and this library does not do is listed [at the end](#what-this-library-does-not-do).

---

## One program at a time

The machine of [`kern/evm/vm.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/vm.py) executes one program. Its instructions are listed in [section 2.8 of the API stability page](api-stability.md#28-kvm-evm-rollup-opcode-set). CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE and CREATE2 are not among them: a program that reaches one of them halts, reverted, as on an unknown instruction. A contract cannot call another contract, and there is no stack of frames.

A call comes from outside the machine, through `call_contract`. It runs the code of one account once and gives back a `CallResult`: whether the call succeeded, what it returned and the gas that is left.

## World state

```python
@dataclass
class Account:
    balance: int = 0
    code: bytes = b""
    storage: Dict[int, int] = field(default_factory=dict)
    nonce: int = 0

@dataclass
class WorldState:
    accounts: Dict[int, Account]
```

`WorldState` holds the accounts by address. `get` gives the account at an address and makes an empty one when there is none. `transfer` moves a balance and returns `False` when the sender does not hold it. `snapshot` copies every account and `revert_to` puts a copy back: that is how a call that fails leaves the world as it was.

## The three kinds of call

```python
result = call_contract(
    world, kind=FrameKind.CALL, caller=0xabc, address=0x100,
    value=0, calldata=b"", gas=100_000,
)
```

| Kind | Storage the program runs on | Value |
|---|---|---|
| `CALL` | The storage of the contract | Moved from the caller to the contract before the program runs |
| `DELEGATECALL` | The storage of the caller | Not moved; the program reads it as the value of its call |
| `STATICCALL` | The storage of the contract | Refused: a static call that carries a value fails |

- A call that succeeds keeps the storage its program leaves. A static call writes nothing to the world.
- A call whose program reverts, or is still running when the step limit of the machine cuts it, fails: the world is as it was before the call, the value included.
- A call to an account without code moves the value and succeeds.
- A call whose value the caller does not hold fails.
- A call does not start when its gas, value, addresses, block or calldata do not make the context of a state of the machine, or when the code or the storage it would run on does not make one. It raises `ValueError`, and the world is as it was ([section 2.9](api-stability.md#29-gas-pricing)).

## Creations

```python
address, result = create_contract(
    world, creator=0xabc, init_code=init_bytecode,
    value=0, gas=100_000,
)
```

`create_contract` runs an init program and stores the bytes it returns as the code of a new account, with the storage the program leaves. It returns the new address, or `None` when the creation fails: the init program reverts, the step limit cuts it, or the creator does not hold the value. The nonce of the creator goes up whether the creation succeeds or fails. A creation whose program or context is refused with `ValueError` does not start, and changes nothing.

| Creation | Address |
|---|---|
| Without a salt | 20 bytes of keyed BLAKE2b over the creator and its nonce |
| With a salt | 20 bytes of keyed BLAKE2b over the creator, the salt and the hash of the init program |

The same creator, salt and init program give the same address. These are not the addresses of Ethereum, which derives them with Keccak-256.

## Precompiles

A call to one of the addresses 0x01 to 0x09 runs a built-in function instead of a program:

| Address | Function | Note |
|---|---|---|
| 0x01 | Signature check | Ed25519, not the secp256k1 recovery of Ethereum: see below |
| 0x02 | SHA-256 | |
| 0x03 | RIPEMD-160 | The digest, left-padded to 32 bytes |
| 0x04 | Identity | Returns its input |
| 0x05 | Modular exponentiation | |
| 0x06 | BN254 point addition | Through py_ecc |
| 0x07 | BN254 scalar multiplication | Through py_ecc |
| 0x08 | BN254 pairing check | Through py_ecc |
| 0x09 | BLAKE2F | A placeholder: see the [cryptographic inventory](cryptographic-inventory.md) |

Address 0x01 does not recover a key. It takes 128 bytes, a 32-byte message, a 32-byte Ed25519 public key and a 64-byte signature, and returns the address of that key, 20 bytes left-padded to 32. It returns 32 zero bytes when the input is short or the signature does not verify.

The addresses and their roles are those of [section 2.10 of the API stability page](api-stability.md#210-precompile-addresses).

## What this library does not do

- No call from inside a program. There are no nested frames, no gas handed from a caller to a callee and no return data copied back into the memory of a caller.
- No event. LOG0 to LOG4 halt a program, and the `logs` of a `CallResult` stay empty.
- No stack of frames in the commitment of a state. A state of the machine has the nine fields of [section 9.22](api-stability.md#922-states-of-the-mini-evm), and a fraud proof is about one program.
- Not the addresses of Ethereum, and not its signature precompile.

The design this page used to describe, where a CALL instruction opens a frame and the stack of frames is hashed into the state, is not implemented.

## Reference

[`kern/evm/frames.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/kern/evm/frames.py) provides:

- `Account`, `WorldState`: the accounts and their snapshots
- `FrameKind`, `CallResult`: the kind of a call and its result
- `call_contract(...)`: one call, of one of the three kinds
- `create_contract(...)`: one creation, with or without a salt
- `derive_create_address`, `derive_create2_address`: the address of a creation
- `PRECOMPILES`, `is_precompile`, `execute_precompile`: the nine built-in functions
- `Frame`: a dataclass of the earlier design, which nothing builds

It is tested in [`tests/test_evm_frames.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_evm_frames.py), in [`tests/test_evm_referee.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_evm_referee.py) for what a call refuses and what it leaves when it fails, and in [`tests/test_evm_pages.py`](https://github.com/vaneeckhoutnicolas/kern/blob/main/tests/test_evm_pages.py), which compares this page with the library.
