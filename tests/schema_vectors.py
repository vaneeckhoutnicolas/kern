# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Builds tests/vectors/kern/schemas.json, the vectors of the schemas.

Not a test file and not the node. tests/schema_reference.py is section 9
of docs/api-stability.md as executable text; this file writes the objects
that reference accepts and the ones it refuses, each with the rule that
refuses it, and checks every one against the reference while it builds.
tests/test_schema_vectors.py reads the file back, and the Go program kept
next to it does the same with tables of its own.

Keys and signatures weigh kilobytes, and a bound is only tested by an
object that reaches it. The file therefore writes objects with
directives, which both programs carry out in the same way, and pins every
object by the length of its canonical encoding and the start of its
SHA3-384. The fillers are not keys, and no signature in these vectors
verifies: verifying signatures is not what a schema does.

    python tests/schema_vectors.py            rebuilds schemas.json
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))      # the references stand next to this file

import profile_reference as ref                               # noqa: E402
import schema_reference as sch                                # noqa: E402
from schema_reference import INT_MAX, INT_MIN, LIMITS, ROUND_MAX  # noqa: E402

FILE = ref.VECTORS.with_name("schemas.json")

DIRECTIVES = {
    "$ref": "the object of the accepted vector of that name, which stands earlier in the file",
    "$index": "inside the item of a $list or of a $map, the number of the item, from 0, plus the argument; "
              "elsewhere, the argument",
    "$key": "the text form of the 1,984 bytes SHAKE256('kern schema vectors, key N'), N being the argument in decimal",
    "$sig": "the text form of the 3,373 bytes SHAKE256('kern schema vectors, signature N')",
    "$address": "the address of this network whose hash is the 48 bytes SHAKE256('kern schema vectors, address N')",
    "$account": "the address of the account whose public key is the key N of $key: the hash of that key (note, "
                "section 5)",
    "$key_of_parts": "[n, m]: the text form of the first 1,952 bytes of the key n of $key, its ML-DSA part, followed "
                     "by the last 32 bytes of the key m, its Ed25519 part",
    "$text": "[count, piece]: the piece written count times",
    "$concat": "[parts]: the parts one after the other, an integer in decimal",
    "$canonical": "the canonical JSON of the argument, once its directives are carried out, as a text",
    "$list": "[count, item]: a list of count items",
    "$map": "[count, name, value]: an object of count members",
}


def filler(what: str, n: int, length: int) -> bytes:
    return hashlib.shake_256(f"kern schema vectors, {what} {n}".encode("ascii")).digest(length)


def copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


class Vectors:
    """What both programs do with the file: carry out directives, apply
    the changes of a refused vector, derive the mutations of an accepted
    one."""

    def __init__(self, network_id: bytes) -> None:
        self.network_id = network_id
        self.objects: dict[str, Any] = {}                    # accepted vectors, by name, directives carried out

    def expand(self, value: Any, index: int = 0) -> Any:
        """A value of the file with its directives carried out. A directive
        is an object whose only member has a name that starts with `$`."""
        if isinstance(value, list):
            return [self.expand(item, index) for item in value]
        if not isinstance(value, dict):
            return value
        if len(value) != 1 or not next(iter(value)).startswith("$"):
            return {name: self.expand(item, index) for name, item in value.items()}
        (name, argument), = value.items()
        if name == "$ref":
            return copy(self.objects[argument])
        if name == "$index":
            return index + argument
        if name == "$key":
            return ref.key_text(filler("key", self.expand(argument, index), ref.PUBLIC_KEY_BYTES))
        if name == "$sig":
            return ref.signature_text(filler("signature", self.expand(argument, index), ref.SIGNATURE_BYTES))
        if name == "$address":
            return ref.address_from_hash(self.network_id, filler("address", self.expand(argument, index), 48))
        if name == "$account":
            public_key = filler("key", self.expand(argument, index), ref.PUBLIC_KEY_BYTES)
            return ref.account_address(self.network_id, public_key)
        if name == "$key_of_parts":
            first, second = (filler("key", self.expand(part, index), ref.PUBLIC_KEY_BYTES) for part in argument)
            return ref.key_text(sch.key_parts(first)[0] + sch.key_parts(second)[1])
        if name == "$text":
            count, piece = argument
            return piece * count
        if name == "$concat":
            return "".join(str(self.expand(part, index)) for part in argument)
        if name == "$canonical":
            return ref.canonical_json(self.expand(argument, index)).decode("utf-8")
        if name == "$list":
            count, item = argument
            return [self.expand(item, i) for i in range(count)]
        if name == "$map":
            count, member, item = argument
            return {self.expand(member, i): self.expand(item, i) for i in range(count)}
        raise ValueError(f"unknown directive {name}")

    def edited(self, value: Any, remove: list[str] | None = None, set_: dict[str, Any] | None = None) -> Any:
        """A copy of an object with members removed, then values put in
        place. A value put one position past the end of a list is added."""
        out = copy(value)
        for path in remove or []:
            holder, step = locate(out, path)
            del holder[step]
        for path, new in (set_ or {}).items():
            holder, step = locate(out, path)
            if isinstance(holder, list) and step == len(holder):
                holder.append(self.expand(new))
            else:
                holder[step] = self.expand(new)
        return out


def locate(value: Any, path: str) -> tuple[Any, Any]:
    """The array or object that holds the last step of a path, and that
    step: the name of a member, or a position in a list."""
    steps = path.split(".")
    for step in steps[:-1]:
        value = value[int(step)] if isinstance(value, list) else value[step]
    return value, (int(steps[-1]) if isinstance(value, list) else steps[-1])


def join(path: str, step: object) -> str:
    return f"{path}.{step}" if path else str(step)


def mutations(value: Any, maps: list[str], free: list[str]) -> Iterator[tuple[str, str, Any]]:
    """The objects one change away from an accepted one: (change, path,
    object). Every array and every object is replaced by the string "x";
    nothing more is changed in the ones listed as `free`. Elsewhere, every
    member of an object is removed in turn, and a member "zz": 0 is added,
    except in the objects listed as `maps`; every string is replaced by 0,
    every boolean by 1, every integer by its digits as a string, then by
    true."""
    def put(path: str, new: Any) -> Any:
        if not path:
            return new
        out = copy(value)
        holder, step = locate(out, path)
        holder[step] = new
        return out

    def walk(node: Any, path: str) -> Iterator[tuple[str, str, Any]]:
        if isinstance(node, (dict, list)):
            yield "x", path, put(path, "x")
            if path in free:
                return
            if isinstance(node, dict) and path not in maps:
                for member in node:
                    out = copy(value)
                    holder, step = locate(out, join(path, member))
                    del holder[step]
                    yield "remove", join(path, member), out
                yield "add", path, put(path, {**node, "zz": 0})
            for step, child in (node.items() if isinstance(node, dict) else enumerate(node)):
                yield from walk(child, join(path, step))
        elif isinstance(node, bool):
            yield "1", path, put(path, 1)
        elif isinstance(node, int):
            yield "digits", path, put(path, str(node))
            yield "true", path, put(path, True)
        else:
            yield "0", path, put(path, 0)

    yield from walk(value, "")


def pin(encoding: bytes) -> dict:
    return {"bytes": len(encoding), "pin": hashlib.sha3_384(encoding).hexdigest()[:16]}


def derived(name: str, schema: str, value: Any, network_id: bytes) -> dict:
    """What the profile computes from an accepted object, kept with its
    vector: identifiers, hashes, and the text that is signed."""
    out: dict[str, Any] = {}
    if schema == "transaction":
        if name == "transfer":
            out["signed"] = sch.signed_transaction(value).decode("utf-8")
        out["id"] = sch.transaction_id(network_id, value).hex()
        out["witness_leaf"] = sch.witness_leaf(network_id, value).hex()
        if value["kind"] == "governance_propose":
            out["proposal_id"] = sch.proposal_id(network_id, value).hex()
        if value["kind"] == "attest":
            out["attestation_id"] = sch.attestation_id(network_id, value).hex()
    elif schema == "header":
        out["signed"] = sch.signed_header(value).decode("utf-8")
        out["hash"] = sch.block_hash(network_id, value).hex()
    elif schema in ("vote", "propose message"):
        out["context"] = sch.PURPOSES[value["kind"]]
        out["signed"] = sch.signed_message(value).decode("utf-8")
    elif schema == "state":
        out["state_root"] = sch.state_root(network_id, value).hex()
        out["accounts_root"] = ref.accounts_root(network_id, value).hex()
        if name == "state_full":
            out["accounts"] = sch.accounts(network_id, value)
    elif schema == "genesis":
        out["hashed"] = ref.canonical_json(sch.first_header(value)).decode("utf-8")
        out["block_hash"] = sch.first_block_hash(value).hex()
    return out


# What the node of today takes when a genesis says nothing, written out: a state has no default.
PARAMETERS_OF_TODAY = {
    "i_min_ppm": 2_500, "i_max_ppm": 60_000, "target_staking_ratio_ppm": 500_000, "target_block_time_ms": 1_000,
    "treasury_share_ppm": 50_000, "proposer_bonus_ppm": 100_000, "fee_floor_enabled": False, "fee_floor_base": 100,
    "fee_floor_per_byte": 2, "max_block_bytes": 1_048_576,
}
# Short periods, so that the vectors can hold what is due and what is not.
CONSTANTS_OF_THE_VECTORS = {
    "epoch_blocks": 120, "delegation_unbonding_blocks": 300, "attestation_unbonding_blocks": 150,
    "protocol_proposal_blocks": 100, "protocol_exploration_blocks": 100, "protocol_cooldown_blocks": 100,
    "protocol_adoption_blocks": 100, "treasury_proposal_blocks": 200, "treasury_vote_blocks": 100,
    "guardian_delay_blocks": 50, "treasury_release_blocks": 150,
    "protocol_bond": 100_000_000, "treasury_bond": 10_000_000,
}


def the_rule(words: str) -> str:
    """The one sentence of chapter 2 that holds these words."""
    found = {sentence for obj in sch.CHAPTER_2 for sentence, _ in obj.rules if words in sentence}
    assert len(found) == 1, (words, found)
    return found.pop()


@contextlib.contextmanager
def without(sentence: str) -> Iterator[None]:
    """The reference without one rule of chapter 2, for as long as the block lasts."""
    saved = [(obj, obj.rules) for obj in sch.CHAPTER_2]
    for obj in sch.CHAPTER_2:
        obj.rules = [rule for rule in obj.rules if rule[0] != sentence]
    try:
        yield
    finally:
        for obj, rules in saved:
            obj.rules = rules


DESCRIPTION = (
    "Vectors of the schemas of structure version 1 (docs/api-stability.md, section 9), chapters 1 and 2: what is "
    "signed and what travels, and what is kept. Built by tests/schema_vectors.py with tests/schema_reference.py; "
    "tests/vectors/kern/profile_check.go checks them with tables of its own (-schemas). "
    "`accepted` holds objects that are of their schema on the network `network_id`. `refused` holds objects that are "
    "not: an accepted object (`from`) with members removed (`remove`), then values put in place (`set`), or an "
    "object of its own; `rule` names the rule that refuses it, by a key of `rules`. A path is names of members and "
    "positions in lists joined by full stops; a value put one position past the end of a list is added to it, and "
    "a position that is removed takes its item out of the list. "
    "Objects are written with the `directives`. `bytes` is the length of the canonical encoding of the object once "
    "its directives are carried out, and `pin` the first 8 bytes of the SHA3-384 of that encoding: they only show "
    "that two programs built the same object. The fillers are not keys, and no signature here verifies: a schema "
    "does not verify signatures. `mutations`, where present, asks for more: every object one change away from this "
    "one is refused, except this one without a member listed in `optional`. The changes: every array and every "
    "object replaced by the string x, and nothing more in the ones listed in `free`; elsewhere, every member of an "
    "object removed in turn, and a member zz of value 0 added, except in the objects listed in `maps`; every string "
    "replaced by 0, every boolean by 1, every integer by its digits as a string, then by true. `accepted_texts` and "
    "`refused_texts` are texts as a node receives them: the size of a frame and the nesting are checked on the "
    "bytes, then the canonical encoding, then the schema; the schema `json` is any value of canonical JSON, and "
    "`prefix` is the four bytes that precede the text in a frame. An accepted object of the schema `frame` has its "
    "`prefix` too: the length of its canonical encoding, most significant byte first, and nothing else. `prefixes` "
    "holds four bytes as a node reads them before a frame: `announces` is the number of bytes that follow, and "
    "`rule` refuses those that announce more than `frame_bytes`, which bounds what follows and does not count the "
    "four bytes. `answers` holds what a node sends in answer to a `get_blocks` from `from` to `to`: `held` lists the "
    "blocks it holds, each as a level and the bytes of its final block in the frame, and `levels` the levels of the "
    "blocks of its answer; a frame without a block is 29 bytes, and each block after the first adds a comma. "
    "`replies` holds answers as the node that asked sees them, by the levels of their blocks: accepted, or refused "
    "by `rule`. "
    "Chapter 2. A state is checked on itself, and a genesis on the network it names. `breaks`, on a refused state, "
    "account or genesis, is the sentence of the document that the object breaks, and it breaks no other: without "
    "that sentence the object is accepted. A state comes with its `state_root`, computed by the function it names, "
    "and with the root of its accounts, `accounts_root`; `state_full` comes with its `accounts` too, as the state "
    "trie holds them. A genesis comes with the nine fields of its block of level 0 in canonical JSON (`hashed`) and "
    "with the hash of that block (`block_hash`); a text of the schema `genesis` is read like any text, without a "
    "bound on its length. `charges` holds blocks of transfers: `state` gives the `chain_id`, the `parameters`, the "
    "`balances` and the `nonces` before the block, and `then` what the block leaves, with the positions of the "
    "transfers that failed and paid (`failed`); or `rule` names, by a key of `block_rules`, the rule that makes the "
    "block invalid, and `at` the position of the transaction that breaks it. `decisions` holds proposals that are "
    "decided at one level: `before` gives the parameters, the function of the state root, what the treasury holds "
    "(`treasury`) and the two bonds; a protocol proposal is its `payload` and whether its vote passes, and a "
    "treasury proposal the phase that ends, `voting` or `passed`, and when its vote ends whether it passes; `then` "
    "gives the phase each one is in afterwards and what the rest has become, with what was burned. `payments` "
    "holds transactions of guardians in one block: `before` gives the level of the block, the guardians, what the "
    "treasury holds, the bond of the treasury track, the delay of the guardians other than the first, and the "
    "treasury proposals by identifier, each one its `phase` as the block finds it, the level at which its vote "
    "ended (`voted`), the sum of its amounts (`total`), the part of that sum whose recipient is the treasury itself "
    "(`to_itself`) and `released_by` where a guardian has released it; an operation is its `sender`, its `kind` and "
    "the `proposal_id` it names; `then` gives what each operation did (`did`: `paid`, `recorded` or `cancelled`, or "
    "the rule that makes it fail, by a key of `guardian_rules`: the first one broken, in the order of that table), "
    "what the treasury holds, what was burned and each payment afterwards. Guardians, senders and identifiers are "
    "short names there: the rules only compare them. "
    "`exchanges` holds what happens on a connection as the node that asks for blocks "
    "sees it: a step is a request it would send (`ask`: the first and the last level), a `blocks` frame it receives "
    "(`blocks`: the levels of its blocks) or four bytes it reads before a frame (`prefix`); `verdicts` gives "
    "`accepted`, `refused` or `closed` for each step. `served` holds what a node sends when several requests reach "
    "it on one connection: `held` as in `answers`, and the levels of one answer for each request."
)


class Builder(Vectors):
    def __init__(self) -> None:
        profile = json.loads(ref.VECTORS.read_text(encoding="utf-8"))
        super().__init__(bytes.fromhex(profile["network_id"]))
        self.frozen = {entry["domain"]: entry for entry in profile["objects"]}
        self.schemas: dict[str, str] = {}                    # accepted vectors: name -> schema
        self.accepted: list[dict] = []
        self.refused: list[dict] = []
        self.accepted_texts: list[dict] = []
        self.refused_texts: list[dict] = []
        self.prefixes: list[dict] = []
        self.answers: list[dict] = []
        self.replies: list[dict] = []
        self.charged: list[dict] = []
        self.decided: list[dict] = []
        self.guarded: list[dict] = []
        self.exchanged: list[dict] = []
        self.served: list[dict] = []

    # -- recording --------------------------------------------------------

    def yes(self, name: str, schema: str, what: str, obj: Any, *, mutate: bool = False,
            maps: tuple[str, ...] = (), free: tuple[str, ...] = ()) -> Any:
        value = self.expand(obj)
        sch.check(schema, value, self.network_id)
        record = {"name": name, "schema": schema, "what": what, "object": obj, **pin(ref.canonical_json(value)),
                  **derived(name, schema, value, self.network_id)}
        if schema == "frame":
            record["prefix"] = sch.frame_prefix(record["bytes"]).hex()
        if mutate:
            optional = []
            for change, path, changed in mutations(value, list(maps), list(free)):
                answer = sch.verdict(schema, changed, self.network_id)
                if change == "remove" and answer == "accepted":
                    optional.append(path)
                elif answer == "accepted":
                    raise AssertionError(f"{name}: the change {change!r} at {path!r} is accepted")
            record["mutations"] = {"optional": optional, "maps": list(maps), "free": list(free)}
        assert name not in self.objects, name
        self.objects[name], self.schemas[name] = value, schema
        self.accepted.append(record)
        return value

    def no(self, base: str, rule: str, why: str, *, remove: list[str] | None = None,
           set: dict[str, Any] | None = None, breaks: str | None = None) -> None:
        """A refused object: an accepted one with members removed, then
        values put in place. `breaks` names, by a few of its words, the one
        sentence of chapter 2 that refuses it: without that sentence the
        reference accepts the object, so it breaks no other rule."""
        changed = self.edited(self.objects[base], remove, set)
        answer = sch.verdict(self.schemas[base], changed, self.network_id)
        assert answer == rule, f"{base}, {why}: {answer}, not {rule}"
        record: dict[str, Any] = {"from": base}
        if remove:
            record["remove"] = remove
        if set:
            record["set"] = set
        record.update({"rule": rule, "why": why})
        if breaks is not None:
            record["breaks"] = the_rule(breaks)
            with without(record["breaks"]):
                alone = sch.verdict(self.schemas[base], changed, self.network_id)
            assert alone == "accepted", f"{base}, {why}: without its rule, still {alone}"
        elif self.schemas[base] in ("state", "account", "genesis"):
            assert rule != "inconsistent", f"{base}, {why}: which sentence does it break?"
        self.refused.append({**record, **pin(ref.canonical_json(changed))})

    def no_object(self, schema: str, rule: str, why: str, obj: Any) -> None:
        value = self.expand(obj)
        answer = sch.verdict(schema, value, self.network_id)
        assert answer == rule, f"{why}: {answer}, not {rule}"
        self.refused.append({"schema": schema, "object": obj, "rule": rule, "why": why,
                             **pin(ref.canonical_json(value))})

    def text(self, schema: str, rule: str, why: str, text: Any) -> None:
        raw = self.expand(text).encode("utf-8")
        try:
            sch.receive(schema, raw, self.network_id)
            answer = "accepted"
        except sch.Refused as refusal:
            answer = refusal.rule
        assert answer == rule, f"{why}: {answer}, not {rule}"
        record = {"schema": schema, "text": text, "rule": rule, "why": why, **pin(raw)}
        if rule != "accepted":
            self.refused_texts.append(record)
            return
        del record["rule"]
        if schema == "frame":
            record["prefix"] = len(raw).to_bytes(4, "big").hex()
        self.accepted_texts.append(record)

    # -- pieces -----------------------------------------------------------

    def tx(self, kind: str, *, nonce: Any = 1, sig: Any = 1, sender: Any = None, **fields: Any) -> dict:
        more = {name: fields.pop(name) for name in sch.KIND_FIELDS if name in fields}
        return {"kind": kind, "sender": sender or {"$address": 1}, "nonce": nonce, "fee": 1000, "gas_limit": 10000,
                **more, "chain_id": "kern-devnet", "signature": {"$sig": sig}, **fields}

    def origination(self, size: int, nonce: Any, sig: Any) -> dict:
        """An origination of the size asked, to the byte: fields of the
        longest text, fifteen of them if they fit, and a code as long as
        it takes."""
        def build(fields: int, code_bytes: int) -> dict:
            return self.tx("originate", nonce=nonce, sig=sig, code={"$text": [code_bytes, "x"]},
                           initial_storage={"$map": [fields, {"$concat": ["field_", {"$index": 10}]},
                                                     {"$text": [LIMITS["value_bytes"], "x"]}]})
        for fields in range(15, -1, -1):
            code_bytes = 1 + size - sch.transaction_size(self.expand(build(fields, 1)))
            if 1 <= code_bytes <= LIMITS["code_bytes"]:
                return build(fields, code_bytes)
        raise AssertionError(f"no origination of {size} bytes")

    def largest(self, nonce: Any, sig: Any) -> dict:
        """An origination whose size is the bound, to the byte."""
        return self.origination(LIMITS["transaction_bytes"], nonce, sig)

    def roots(self, transactions: list) -> dict:
        ids = [sch.transaction_id(self.network_id, t) for t in transactions]
        leaves = [sch.witness_leaf(self.network_id, t) for t in transactions]
        return {"txs_root": ref.merkle_root(self.network_id, ids).hex(),
                "witness_root": ref.merkle_root(self.network_id, leaves).hex()}

    def block(self, level: int, payload_round: int, parent: str, txs: Any, sig: int) -> dict:
        header = {"version": 1, "level": level, "payload_round": payload_round, "timestamp": 1794000000 + level,
                  "parent_hash": parent, "state_root": {"$text": [48, "5a"]}, **self.roots(self.expand(txs)),
                  "proposer": {"$address": 1}, "signature": {"$sig": sig}}
        return {"header": header, "transactions": txs}

    def hash_of(self, name: str) -> str:
        return sch.block_hash(self.network_id, self.objects[name]["header"]).hex()

    def certificate(self, kind: str, level: int, round_: int, hash_: str, count: int = 3) -> dict:
        return {"kind": kind, "level": level, "round": round_, "block_hash": hash_,
                "signatures": {"$map": [count, {"$address": {"$index": 30}}, {"$sig": {"$index": 30}}]}}

    def message(self, kind: str, level: int, round_: int, hash_: str, sig: int, **more: Any) -> dict:
        return {"kind": kind, "level": level, "round": round_, "block_hash": hash_, "validator": {"$address": 1},
                **more, "signature": {"$sig": sig}}

    # -- chapter 2: what is kept -----------------------------------------------

    def account(self, key: int) -> str:
        return self.expand({"$account": key})

    def address(self, n: int) -> str:
        return self.expand({"$address": n})

    def guardians(self) -> list[str]:
        """The three guardians of the states of these vectors: the first
        one, and the two others."""
        return [self.account(n) for n in (160, 161, 162)]

    def with_supply(self, state: dict) -> dict:
        """The state with its `total_supply` set to the sum of what it holds."""
        state["total_supply"] = sch.held(self.expand(state))
        return state

    def first_state(self, validators: int = 3) -> dict:
        """A first state: balances, validators with their keys, parameters
        and constants, and nothing else yet."""
        listed = [{"address": self.account(100 + i), "stake": 1_000_000_000_000 - i} for i in range(validators)]
        return self.with_supply({
            "level": 0, "chain_id": "kern-devnet", "state_root_function": "json", "total_supply": 0,
            "treasury_address": self.address(9), "guardians": self.guardians(),
            "balances": {self.account(100): 5_000_000, self.address(1): 70_000_000_000_000, self.address(2): 1,
                         self.address(9): 14_000_000_000_000},
            "nonces": {}, "contracts": {},
            "keys": {self.account(100 + i): [{"from": 0, "public_key": {"$key": 100 + i}}] for i in range(validators)},
            "validators": listed, "consensus_set": copy(listed),
            "delegations": {}, "delegation_unbonding": [], "attestations": {}, "consensus_slashes": [],
            "governance": {"protocol": [], "treasury": []},
            "parameters": dict(PARAMETERS_OF_TODAY), "constants": dict(CONSTANTS_OF_THE_VECTORS),
        })

    def full_state(self) -> dict:
        """A state of level 1,000 in which every table holds something. Four
        validators: A and B vote, C has sent a transaction and is named
        nowhere else, Q has done nothing since the genesis."""
        a, b, c, q = (self.account(100 + i) for i in range(4))
        d, e, f, g = (self.account(n) for n in (110, 120, 130, 135))
        one, two, treasury, contract = (self.address(n) for n in (1, 2, 9, 20))
        hex_of = lambda pair: pair * 48                                                      # noqa: E731
        listed = [{"address": a, "stake": 400_000_000}, {"address": b, "stake": 300_000_000},
                  {"address": c, "stake": 200_000_000}, {"address": q, "stake": 1}]
        snapshot = [{"address": a, "stake": 400_000_300}, {"address": b, "stake": 299_999_999},
                    {"address": c, "stake": 200_000_000}, {"address": q, "stake": 1}]
        bond = CONSTANTS_OF_THE_VECTORS
        return self.with_supply({
            "level": 1000, "chain_id": "kern-devnet", "state_root_function": "trie", "total_supply": 0,
            "treasury_address": treasury, "guardians": self.guardians(),
            "balances": {a: 12_345, b: 1, d: 900_000, e: 77, f: 5_000, one: 70_000_000_000_000, two: 1,
                         treasury: 14_000_000_000_000, contract: 5},
            "nonces": {a: 6, b: 3, c: 1, d: 3, e: 5, f: 2, g: 2},
            "contracts": {contract: {"code": "contract Counter { storage { count: int } }", "storage": {"count": 7}}},
            "keys": {
                a: [{"from": 0, "public_key": {"$key": 100}}],
                b: [{"from": 0, "public_key": {"$key": 101}}],
                c: [{"from": 0, "public_key": {"$key": 102}}],
                q: [{"from": 0, "public_key": {"$key": 103}}],
                d: [{"from": 12, "public_key": {"$key": 110}}, {"from": 400, "public_key": {"$key": 111}}],
                e: [{"from": 50, "public_key": {"$key": 120}}, {"from": 1001, "public_key": {"$key": 121}}],
                f: [{"from": 90, "public_key": {"$key": 130}}],
                g: [{"from": 95, "public_key": {"$key": 135}}],
            },
            "validators": listed, "consensus_set": snapshot,
            "delegations": {e: {"validator": a, "amount": 700,
                                "tranches": [{"level": 60, "amount": 300}, {"level": 90, "amount": 400}]}},
            "delegation_unbonding": [
                {"delegator": f, "validator": b, "amount": 500, "tranches": [{"level": 100, "amount": 500}],
                 "unbonding_from": 950, "release_at": 1250},
                {"delegator": g, "validator": a, "amount": 40, "tranches": [{"level": 96, "amount": 40}],
                 "unbonding_from": 960, "release_at": 1260},
            ],
            "attestations": {
                hex_of("a1"): {"issuer": d, "schema_id": "kyc.basic", "subject": "subject-1",
                               "claim": {"country": "BE", "level": 2}, "bond": 1000, "issued_at": 500,
                               "slashed": False},
                hex_of("a2"): {"issuer": d, "schema_id": "kyc.basic", "subject": "subject-2", "claim": {},
                               "bond": 250, "issued_at": 500, "revoked_at": 900, "slashed": False},
                hex_of("a3"): {"issuer": d, "schema_id": "kyc.basic", "subject": "subject-1",
                               "claim": {"country": "FR", "level": 2}, "bond": 0, "issued_at": 600, "slashed": True},
                hex_of("a4"): {"issuer": e, "schema_id": "s", "subject": " ", "claim": {}, "bond": 0,
                               "issued_at": 100, "revoked_at": 200, "slashed": False},
            },
            "consensus_slashes": [{"validator": b, "kind": "endorse", "level": 990, "round": 0},
                                  {"validator": b, "kind": "preendorse", "level": 990, "round": 0}],
            "governance": {
                "protocol": [
                    {"proposal_id": hex_of("b1"), "submitter": a, "payload": {"params": {"treasury_share_ppm": 40_000}},
                     "submitted_at": 400, "phase": "activated", "ended_at": 800,
                     "exploration_votes": {a: "yes", b: "yes"}, "adoption_votes": {a: "yes", b: "yes"},
                     "double_votes": []},
                    {"proposal_id": hex_of("b0"), "submitter": b, "payload": {"params": {"proposer_bonus_ppm": 0}},
                     "submitted_at": 550, "phase": "rejected", "ended_at": 750,
                     "exploration_votes": {a: "no", b: "abstain"}, "adoption_votes": {}, "double_votes": []},
                    {"proposal_id": hex_of("b2"), "submitter": b,
                     "payload": {"swap": "state_root_function", "to": "json"},
                     "submitted_at": 850, "phase": "exploration",
                     "exploration_votes": {a: "yes", b: "no"}, "adoption_votes": {},
                     "double_votes": [{"voter": b, "phase": "exploration", "level": 960, "punished": False}],
                     "bond": bond["protocol_bond"]},
                    {"proposal_id": hex_of("b3"), "submitter": a,
                     "payload": {"params": {"i_max_ppm": 70_000, "fee_floor_enabled": True}},
                     "submitted_at": 950, "phase": "submitted", "exploration_votes": {}, "adoption_votes": {},
                     "double_votes": [], "bond": bond["protocol_bond"]},
                ],
                "treasury": [
                    {"proposal_id": hex_of("c0"), "submitter": d,
                     "payload": {"recipients": [{"address": d, "amount": 1}]},
                     "submitted_at": 690, "phase": "rejected", "ended_at": 990, "votes": {b: "no"}},
                    {"proposal_id": hex_of("c1"), "submitter": d,
                     "payload": {"recipients": [{"address": one, "amount": 1000}], "memo": "a grant"},
                     "submitted_at": 780, "phase": "voting", "votes": {a: "yes"}, "bond": bond["treasury_bond"]},
                    {"proposal_id": hex_of("c2"), "submitter": e,
                     "payload": {"recipients": [{"address": two, "amount": 5}]},
                     "submitted_at": 900, "phase": "submitted", "votes": {}, "bond": bond["treasury_bond"]},
                    {"proposal_id": hex_of("c3"), "submitter": e,
                     "payload": {"recipients": [{"address": two, "amount": 6}, {"address": contract, "amount": 7}]},
                     "submitted_at": 950, "phase": "submitted", "votes": {}, "bond": bond["treasury_bond"]},
                ],
            },
            "parameters": {**PARAMETERS_OF_TODAY, "treasury_share_ppm": 40_000},
            "constants": dict(CONSTANTS_OF_THE_VECTORS),
        })

    def states(self) -> None:
        top = INT_MAX
        a, b, c, q = (self.account(100 + i) for i in range(4))
        d, e, f, g = (self.account(n) for n in (110, 120, 130, 135))
        one, two, contract, stranger = (self.address(n) for n in (1, 2, 20, 77))
        h = lambda pair: pair * 48                                                           # noqa: E731
        maps = ("balances", "nonces", "contracts", "keys", "delegations", "attestations")

        first = self.first_state()
        self.yes("state_first", "state", "a first state: balances, three validators with their keys, the parameters "
                 "and the constants; two validators have everything staked and are not in `balances`",
                 first, mutate=True, maps=maps)
        self.yes("state_first_trie", "state", "the same state under the function trie: another object is hashed",
                 {**first, "state_root_function": "trie"})

        full = self.full_state()
        votes = [f"governance.protocol.{i}.{name}" for i in range(4)
                 for name in ("exploration_votes", "adoption_votes")]
        votes += [f"governance.treasury.{i}.votes" for i in range(4)]
        claims = tuple(f"attestations.{h(pair)}.claim" for pair in ("a1", "a2", "a3", "a4"))
        self.yes("state_full", "state", "a state of level 1,000 in which every table holds something: a key rotated, "
                 "a key due at the next level, a contract, a delegation in two tranches, two delegations that unbond, "
                 "four attestations, two slashed votes, proposals in flight and proposals that are over, a double vote",
                 full, mutate=True, maps=maps + tuple(votes), free=claims + (f"contracts.{contract}.storage",))
        self.yes("state_full_json", "state", "the same state under the function json",
                 {**full, "state_root_function": "json"})

        def variant(name: str, what: str, **changes: Any) -> None:
            changed = copy(full)
            for path, new in changes.items():
                holder, step = locate(changed, path)
                holder[step] = new
            self.yes(name, "state", what, changed)

        # What the chain does not refuse: a part of the key of another address (note, section 6.4).
        variant("state_part_of_another_key", "the key due for one address has the ML-DSA part of a key of another "
                "address: only a part of an earlier key of the same address is refused",
                **{f"keys.{e}.1.public_key": {"$key_of_parts": [110, 121]}})
        variant("state_treasury_contract", "the treasury at the address of a contract: a contract has no key either",
                treasury_address=contract)
        variant("state_about_to_change", "what the block of the next level does is not done yet: a delegation that "
                "ended 299 levels ago is still held, an attestation revoked 149 levels ago still holds its bond, a "
                "proposal that ended 299 levels ago is still there, and so is a slashed vote 299 levels old",
                **{"delegation_unbonding.0.unbonding_from": 701, "delegation_unbonding.0.release_at": 1001,
                   f"attestations.{h('a2')}.revoked_at": 851, "governance.protocol.0.submitted_at": 301,
                   "governance.protocol.0.ended_at": 701, "consensus_slashes.0.level": 701})

        variant("state_just_changed", "what the block of this level did is done, and is not ahead of the state: a "
                "tranche bonded, two delegations ended, an attestation issued and revoked, a vote slashed and a "
                "double vote recorded at this level, a proposal submitted, one activated and one rejected at the end "
                "of their second vote, two votes that started at it on proposals submitted at one level; a validator "
                "that voted two ways in both phases of a proposal; and slashed votes that differ by one thing only",
                **{f"delegations.{e}.tranches.1.level": 1000,
                   "delegation_unbonding.0.unbonding_from": 1000, "delegation_unbonding.0.release_at": 1300,
                   "delegation_unbonding.1.unbonding_from": 1000, "delegation_unbonding.1.release_at": 1300,
                   f"attestations.{h('a4')}.issued_at": 1000, f"attestations.{h('a4')}.revoked_at": 1000,
                   "consensus_slashes": [{"validator": b, "kind": "endorse", "level": 1000, "round": 0},
                                         {"validator": b, "kind": "preendorse", "level": 1000, "round": 0},
                                         {"validator": a, "kind": "endorse", "level": 1000, "round": 0},
                                         {"validator": b, "kind": "endorse", "level": 1000, "round": 1},
                                         {"validator": b, "kind": "endorse", "level": 999, "round": 0}],
                   "governance.protocol.0.submitted_at": 600, "governance.protocol.0.ended_at": 1000,
                   "governance.protocol.0.double_votes": [
                       {"voter": b, "phase": "exploration", "level": 750, "punished": True},
                       {"voter": b, "phase": "adoption", "level": 950, "punished": False}],
                   "governance.protocol.1.submitted_at": 600, "governance.protocol.1.ended_at": 1000,
                   "governance.protocol.2.double_votes.0.level": 1000,
                   "governance.protocol.3.submitted_at": 1000,
                   "governance.treasury.1.submitted_at": 800,
                   "governance.treasury.2.submitted_at": 800, "governance.treasury.2.phase": "voting"})

        # Payments: what a vote passed, and what guardians did with it. With the constants of these vectors a
        # proposal submitted at S ends its vote at S + 300; the other guardians release from S + 350 on, and
        # the wait ends at S + 450.
        first, second, third = self.guardians()
        waiting = self.full_state()

        def payment(pair: str, submitted_at: int, phase: str, ended_at: int | None = None, **more: Any) -> dict:
            out = {"proposal_id": h(pair), "submitter": d,
                   "payload": {"recipients": [{"address": one, "amount": 1000}]}, "submitted_at": submitted_at,
                   "phase": phase, "votes": {a: "yes", b: "yes"}, **more}
            if ended_at is None:
                return {**out, "bond": CONSTANTS_OF_THE_VECTORS["treasury_bond"]}
            return {**out, "ended_at": ended_at}

        waiting["governance"]["treasury"] = [
            payment("d0", 420, "executed", 721),
            payment("d1", 430, "executed", 880),
            payment("d2", 440, "rejected", 890),
            payment("d3", 450, "rejected", 751),
            payment("d4", 460, "rejected", 760, votes={a: "abstain", b: "no"}),
            payment("d5", 551, "passed"),
            payment("d6", 600, "passed", released_by=second),
            payment("d7", 650, "passed", released_by=third),
            payment("d8", 651, "passed"),
            payment("d9", 700, "passed"),
            payment("da", 701, "voting", votes={a: "yes"}),
        ]
        waiting["keys"].update({first: [{"from": 721, "public_key": {"$key": 160}}],
                                second: [{"from": 950, "public_key": {"$key": 161}}],
                                third: [{"from": 1000, "public_key": {"$key": 162}}]})
        waiting["nonces"].update({first: 3, second: 1, third: 1})
        self.yes("state_payments", "state", "payments, at level 1,000: one the first guardian released in the block "
                 "that followed its vote, one released in the last block of its wait, one that nobody released, one "
                 "that the first guardian cancelled, one that its vote rejected; then five that wait: one whose wait "
                 "ends at the next level, one that another guardian released, one released at the very level at "
                 "which the delay of the other guardians had passed, one that only the first guardian can release "
                 "yet, one whose vote passed at this level; and a proposal still in its vote",
                 self.with_supply(waiting))
        many = self.first_state()
        many["guardians"] = {"$list": [LIMITS["guardians"], {"$account": {"$index": 160}}]}
        self.yes("state_8_guardians", "state", "as many guardians as a treasury can have", self.with_supply(many))

        bound = self.first_state()
        bound["balances"] = {self.address(1): 1}
        bound["validators"] = {"$list": [LIMITS["validators"], {"address": {"$account": {"$index": 1000}},
                                                                "stake": 1_000_000}]}
        bound["consensus_set"] = copy(bound["validators"])
        bound["keys"] = {"$map": [LIMITS["validators"], {"$account": {"$index": 1000}},
                                  [{"from": 0, "public_key": {"$key": {"$index": 1000}}}]]}
        self.yes("state_1024_validators", "state", "as many validators as a network can have, each with its key",
                 self.with_supply(bound))

        lowest = self.first_state(validators=1)
        lowest.update({"chain_id": "k", "balances": {}})
        lowest["validators"] = lowest["consensus_set"] = [{"address": self.account(100), "stake": 1}]
        lowest["parameters"] = {name: (type_.low if isinstance(type_, sch.Int) else False)
                                for name, type_, _ in sch.STATE_PARAMETERS.fields}
        lowest["constants"] = {name: (type_.inner.low if isinstance(type_, sch.Named) else type_.low)
                               for name, type_, _ in sch.CONSTANTS.fields}
        self.yes("state_lowest", "state", "the lowest value of every range: one validator with a stake of 1 and no "
                 "balance at all, periods of one block, no bond, both rates of issuance at 0",
                 self.with_supply(lowest))

        x = self.account(140)
        highest = self.first_state(validators=1)
        highest.update({
            "level": top, "chain_id": "k" + "0-9" * 21, "state_root_function": "trie",
            "balances": {x: top - 1 - 5 - 7},
            "nonces": {x: top},
            "keys": {self.account(100): [{"from": 0, "public_key": {"$key": 100}}],
                     x: [{"from": top, "public_key": {"$key": 140}}]},
            "validators": [{"address": self.account(100), "stake": 1}],
            "consensus_set": [{"address": self.account(100), "stake": 6}],
            "delegations": {x: {"validator": self.account(100), "amount": 5,
                                "tranches": [{"level": top, "amount": 5}]}},
            "attestations": {h("ff"): {"issuer": x, "schema_id": "s", "subject": "~", "claim": {}, "bond": 7,
                                       "issued_at": top, "revoked_at": top, "slashed": False}},
            "consensus_slashes": [{"validator": self.account(100), "kind": "endorse", "level": top,
                                   "round": ROUND_MAX}],
        })
        highest["parameters"] = {name: (type_.high if isinstance(type_, sch.Int) else True)
                                 for name, type_, _ in sch.STATE_PARAMETERS.fields}
        highest["constants"] = {name: (type_.inner.high if isinstance(type_, sch.Named) else type_.high)
                                for name, type_, _ in sch.CONSTANTS.fields}
        assert self.with_supply(highest)["total_supply"] == top
        self.yes("state_highest", "state", "the highest values a state can hold together: the last level there is, a "
                 "supply of 2^63 - 1 held almost whole by one account, whose nonce is the last one, a weight that is "
                 "the stake and the delegation of its validator, the longest periods, the largest bonds, both rates "
                 "of issuance at 1,000,000", highest)
        staked = self.first_state(validators=1)
        staked["balances"] = {}
        staked["validators"] = staked["consensus_set"] = [{"address": self.account(100), "stake": top}]
        assert self.with_supply(staked)["total_supply"] == top
        self.yes("state_highest_stake", "state", "everything that exists is the stake of one validator: the largest "
                 "stake and the largest weight there are", staked)

        # -- refused: a form ------------------------------------------------
        no = lambda rule, why, **how: self.no("state_full", rule, why, **how)               # noqa: E731
        no("out_of_range", "a balance of 0 written out: an address that holds nothing is not in `balances`",
           set={f"balances.{two}": 0})
        no("out_of_range", "a nonce of 0 written out", set={f"nonces.{c}": 0})
        no("out_of_range", "a validator with a stake of 0", set={"validators.3.stake": 0})
        no("out_of_range", "no validator", set={"validators": [], "consensus_set": []})
        no("out_of_range", "a tranche of 0", set={f"delegations.{e}.tranches.0.amount": 0})
        no("out_of_range", "1,025 votes on a proposal",
           set={"governance.treasury.1.votes": {"$map": [1025, {"$address": {"$index": 3000}}, "yes"]}})
        no("out_of_range", "2,049 double votes on a proposal",
           set={"governance.protocol.2.double_votes": {"$list": [2049, {"voter": b, "phase": "exploration",
                                                                        "level": 960, "punished": False}]}})
        no("out_of_range", "an epoch of 0 blocks", set={"constants.epoch_blocks": 0})
        no("out_of_range", "a period of 2^32 blocks", set={"constants.treasury_vote_blocks": ROUND_MAX + 1})
        no("out_of_range", "a parameter beyond its range, as in a proposal", set={"parameters.i_max_ppm": 1_000_001})
        no("out_of_range", "a block size under the largest transaction", set={"parameters.max_block_bytes": 131_071})
        no("bad_text", "a function that is neither json nor trie", set={"state_root_function": "merkle"})
        no("bad_text", "a phase of the devnet that structure version 1 does not have: no transaction withdraws a "
           "proposal", set={"governance.treasury.2.phase": "withdrawn"})
        no("bad_text", "a contract without code", set={f"contracts.{contract}.code": ""})
        no("bad_text", "an attestation under a name that is not a hash", remove=[f"attestations.{h('a4')}"],
           set={"attestations.a4": {"issuer": e, "schema_id": "s", "subject": " ", "claim": {}, "bond": 0,
                                    "issued_at": 100, "revoked_at": 200, "slashed": False}})
        no("wrong_type", "a contract that holds an object in a field", set={f"contracts.{contract}.storage.count": {}})
        no("bad_address", "a treasury that is not an address", set={"treasury_address": "kn1treasury"})
        no("bad_address", "a balance under an address of another network",
           set={"balances." + ref.address_from_hash(bytes(32), filler("address", 1, 48)): 1})
        no("bad_key", "a key of another scheme in the registry",
           set={f"keys.{f}.0.public_key": {"$concat": ["kpk2.", {"$text": [2646, "A"]}]}})
        no("missing_field", "no treasury", remove=["treasury_address"])
        no("missing_field", "no guardians", remove=["guardians"])
        no("out_of_range", "two guardians: the two that release without the first would be all there is",
           set={"guardians": [first, second]})
        no("out_of_range", "nine guardians", set={"guardians": {"$list": [9, {"$account": {"$index": 160}}]}})
        no("bad_address", "a guardian that is not an address", set={"guardians.1": "kn1guardian"})
        self.no("state_payments", "bad_address", "a release by something that is not an address",
                set={"governance.treasury.6.released_by": "kn1guardian"})
        self.no("state_payments", "bad_text", "a phase that is not one of the five a treasury proposal has",
                set={"governance.treasury.5.phase": "approved"})
        no("missing_field", "no key registry", remove=["keys"])
        no("missing_field", "a parameter without a value: the state has no default",
           remove=["parameters.fee_floor_enabled"])
        no("missing_field", "a constant without a value", remove=["constants.protocol_bond"])
        no("unknown_field", "the level under its name of today, beside the level", set={"_current_level": 1000})
        no("unknown_field", "the parameters of the issuance under their name of today",
           set={"issuance_params": {"i_min_ppm": 2500}})
        no("unknown_field", "an index that can be computed again", set={"attestations_by_subject": {}})
        no("unknown_field", "a validator with its key: keys are in the registry",
           set={"validators.0.pubkey": {"$key": 100}})
        no("unknown_field", "a proposal with its history", set={"governance.protocol.0.phase_transitions": []})

        # -- refused: a rule of the state, and that rule alone -----------------
        supply = full["total_supply"]
        rule = lambda breaks, why, **how: self.no("state_full", "inconsistent", why, breaks=breaks, **how)  # noqa: E731
        rule("`validators` holds an address once", "a validator listed twice",
             set={"validators.2.address": a, "consensus_set.2.address": a})
        rule("`validators` holds an address once", "the snapshot in another order",
             set={"consensus_set.0": {"address": b, "stake": 299_999_999},
                  "consensus_set.1": {"address": a, "stake": 400_000_300}})
        rule("`validators` holds an address once", "a snapshot that leaves a validator out", remove=["consensus_set.3"])
        rule("is not above its stake", "a weight one above the stake of a validator and what is delegated to it",
             set={"consensus_set.0.stake": 400_000_701})
        rule("is not above its stake", "a weight that counts a delegation that is unbonding",
             set={"consensus_set.1.stake": 300_000_001})
        rule("Every validator has a key", "a validator without a key", remove=[f"keys.{q}"])
        rule("An address of `contracts` is not in `keys`", "a contract at an address that has a key and has signed",
             set={f"contracts.{d}": {"code": "x", "storage": {}}})
        rule("An address of `contracts` is not in `keys`", "a contract at the address of a validator that has sent "
             "nothing", set={f"contracts.{q}": {"code": "x", "storage": {}}})
        rule("`treasury_address` is not in `keys`", "the treasury at the address of an account that has a key",
             set={"treasury_address": d})
        rule("`treasury_address` is not in `keys`", "the treasury at the address of a validator",
             set={"treasury_address": q})
        rule("`guardians` holds an address once", "a guardian listed twice", set={"guardians.2": second})
        rule("A guardian is not `treasury_address`", "the treasury among its own guardians: it has no key, and "
             "could release nothing", set={"guardians.1": self.address(9)})
        rule("A guardian is not `treasury_address`", "a contract among the guardians", set={"guardians.2": contract})
        rule("A guardian is not `treasury_address`", "a validator as the first guardian", set={"guardians.0": a})
        rule("A guardian is not `treasury_address`", "a validator that has done nothing since the genesis, among "
             "the guardians", set={"guardians.2": q})
        rule("Every address of `nonces`", "an account that has sent a transaction and has no key",
             set={f"nonces.{one}": 1})
        rule("Every address of `nonces`", "a key for an address that has sent nothing and is not a validator",
             set={f"keys.{self.account(150)}": [{"from": 10, "public_key": {"$key": 150}}]})
        rule("the levels `from`", "two keys of an address current from the same level", set={f"keys.{d}.1.from": 12})
        rule("the levels `from`", "a key due two levels ahead", set={f"keys.{e}.1.from": 1002})
        rule("The first key of an address", "a first key whose hash is not the address",
             set={f"keys.{f}.0.public_key": {"$key": 199}})
        rule("A key stands once", "the key of one address given to another by a rotation",
             set={f"keys.{e}.1.public_key": {"$key": 111}})
        rule("A key stands once", "a rotation that keeps the ML-DSA part of the key it replaces",
             set={f"keys.{d}.1.public_key": {"$key_of_parts": [110, 111]}})
        rule("A key stands once", "a rotation that keeps the Ed25519 part of the key it replaces",
             set={f"keys.{d}.1.public_key": {"$key_of_parts": [111, 110]}})
        rule("`total_supply` is the sum", "a supply one above what exists", set={"total_supply": supply + 1})
        rule("`total_supply` is the sum", "a supply one below what exists", set={"total_supply": supply - 1})
        rule("A delegation names a validator", "a delegation to an address that is not a validator, which no "
             "weight counts", set={f"delegations.{e}.validator": stranger, "consensus_set.0.stake": 400_000_000})
        rule("A delegation names a validator", "a validator that delegates to itself",
             set={f"delegations.{a}": {"validator": a, "amount": 1, "tranches": [{"level": 1, "amount": 1}]},
                  "total_supply": supply + 1})
        rule("A delegation names a validator", "an unbonding from an address that is not a validator",
             set={"delegation_unbonding.1.validator": stranger})
        rule("A delegation names a validator", "a validator whose delegation to itself unbonds",
             set={"delegation_unbonding.1.delegator": a})
        rule("Nothing happened after `level`", "a tranche bonded after the level of the state",
             set={f"delegations.{e}.tranches.1.level": 1001})
        rule("Nothing happened after `level`", "an attestation issued after the level of the state",
             set={f"attestations.{h('a1')}.issued_at": 1001})
        rule("Nothing happened after `level`", "a proposal that ends after the level of the state",
             set={"governance.protocol.1.submitted_at": 801, "governance.protocol.1.ended_at": 1001})
        rule("Nothing happened after `level`", "a double vote after the level of the state",
             set={"governance.protocol.2.double_votes.0.level": 1001})
        rule("Nothing happened after `level`", "a delegation that ended after the level of the state",
             set={"delegation_unbonding.1.unbonding_from": 1001, "delegation_unbonding.1.release_at": 1301})
        rule("Nothing happened after `level`", "a tranche of a delegation that unbonds, bonded after the level of "
             "the state", set={"delegation_unbonding.0.tranches.0.level": 1001})
        rule("Nothing happened after `level`", "an attestation revoked after the level of the state",
             set={f"attestations.{h('a4')}.revoked_at": 1001})
        rule("Nothing happened after `level`", "a slashed vote of a level after the level of the state",
             set={"consensus_slashes.0.level": 1001})
        rule("A delegation that is unbonding is released", "a release one level late",
             set={"delegation_unbonding.0.release_at": 1251})
        rule("A delegation that is unbonding is released", "a delegation that should have been released by the "
             "block of this level", set={"delegation_unbonding.0.unbonding_from": 700,
                                         "delegation_unbonding.0.release_at": 1000})
        rule("A delegation that is unbonding is released", "two delegations that unbond, the later one first",
             set={"delegation_unbonding.0.unbonding_from": 961, "delegation_unbonding.0.release_at": 1261})
        rule("or earlier, holds no bond", "a bond that should have returned at this level",
             set={f"attestations.{h('a2')}.revoked_at": 850})
        rule("No two slashed votes", "the same vote slashed twice",
             set={"consensus_slashes.1.kind": "endorse"})
        rule("No two slashed votes", "a slashed vote 300 levels old", set={"consensus_slashes.0.level": 700})
        rule("in the order of their submission", "two proposals of a track under one identifier",
             set={"governance.treasury.2.proposal_id": h("c1")})
        rule("in the order of their submission", "a proposal listed before one submitted earlier",
             set={"governance.treasury.2.submitted_at": 960})
        rule("The bond of a proposal", "a proposal with another bond than the one of its track",
             set={"governance.treasury.2.bond": 1, "total_supply": supply - 10_000_000 + 1})
        rule("in the phase of its level", "a proposal still submitted at the level at which its vote starts",
             set={"governance.treasury.2.submitted_at": 800})
        rule("in the phase of its level", "a proposal in its vote before its vote starts",
             set={"governance.treasury.3.phase": "voting"})
        rule("in the phase of its level", "a proposal submitted after the level of the state",
             set={"governance.treasury.3.submitted_at": 1001})
        rule("ended when a vote did", "a proposal activated one level before its adoption ends",
             set={"governance.protocol.0.ended_at": 799})
        rule("ended when a vote did", "a proposal activated at the end of its exploration",
             set={"governance.protocol.1.phase": "activated"})
        rule("ended when a vote did", "a treasury proposal rejected before its vote started",
             set={"governance.treasury.0.ended_at": 890})
        waits = lambda breaks, why, **how: self.no("state_payments", "inconsistent", why,   # noqa: E731
                                                   breaks=breaks, **how)
        waits("in the phase of its level", "a payment that still waits at the level at which its wait ends",
              set={"governance.treasury.5.submitted_at": 550})
        waits("in the phase of its level", "a proposal still in its vote at the level at which its vote ends",
              set={"governance.treasury.10.submitted_at": 700})
        waits("in the phase of its level", "a payment that waits before its vote has ended",
              set={"governance.treasury.9.submitted_at": 701})
        waits("`released_by` is a guardian other than the first", "a release recorded for the first guardian, who "
              "releases alone", set={"governance.treasury.6.released_by": first})
        waits("`released_by` is a guardian other than the first", "a release by an address that is not a guardian",
              set={"governance.treasury.6.released_by": stranger})
        waits("When `released_by` is present", "a release by another guardian one level before its delay had passed",
              set={"governance.treasury.7.submitted_at": 651})
        waits("ended when a vote did", "a payment made at the level at which its vote ended: no guardian could "
              "release it before the next block", set={"governance.treasury.0.ended_at": 720})
        waits("ended when a vote did", "a payment made one level after its wait ended",
              set={"governance.treasury.1.ended_at": 881})
        waits("ended when a vote did", "a payment rejected one level after its wait ended",
              set={"governance.treasury.2.ended_at": 891})
        waits("ended when a vote did", "a proposal rejected one level before its vote ended",
              set={"governance.treasury.4.ended_at": 759})
        rule("ended less than", "a proposal that ended 300 levels ago",
             set={"governance.protocol.0.submitted_at": 300, "governance.protocol.0.ended_at": 700})
        rule("are those of a validator", "the vote of an address that is not a validator",
             set={f"governance.treasury.1.votes.{stranger}": "no"})
        rule("are those of a validator", "a first vote on a protocol proposal by an address that is not a validator",
             set={f"governance.protocol.2.exploration_votes.{stranger}": "yes"})
        rule("are those of a validator", "a second vote on a protocol proposal by an address that is not a validator",
             set={f"governance.protocol.0.adoption_votes.{stranger}": "abstain"})
        rule("are those of a validator", "the slashed vote of an address that is not a validator",
             set={"consensus_slashes.0.validator": stranger})

        # -- refused: a rule of one table -------------------------------------
        rule("whose levels grow", "a delegation that is not the sum of its tranches",
             set={f"delegations.{e}.amount": 701, "total_supply": supply + 1})
        rule("whose levels grow", "a delegation of less than its tranches",
             set={f"delegations.{e}.amount": 699, "total_supply": supply - 1})
        rule("whose levels grow", "two tranches of one level", set={f"delegations.{e}.tranches.1.level": 60})
        rule("whose levels grow", "a delegation that unbonds and is not the sum of its tranches",
             set={"delegation_unbonding.0.amount": 501, "total_supply": supply + 1})
        rule("`revoked_at` is not lower", "an attestation revoked before it was issued",
             set={f"attestations.{h('a4')}.revoked_at": 99})
        rule("slashed holds no bond", "a slashed attestation that still holds a bond",
             set={f"attestations.{h('a3')}.bond": 5, "total_supply": supply + 5})
        rule("`activated` or `rejected`", "a proposal that is over and still holds its bond",
             set={"governance.protocol.0.bond": 100_000_000, "total_supply": supply + 100_000_000})
        rule("`activated` or `rejected`", "a proposal that is over and does not say since when",
             remove=["governance.protocol.0.ended_at"])
        rule("`executed` or `rejected`", "a proposal in its vote that holds no bond",
             remove=["governance.treasury.1.bond"], set={"total_supply": supply - 10_000_000})
        rule("`executed` or `rejected`", "a proposal that has ended and is still submitted",
             set={"governance.treasury.3.ended_at": 990})
        waits("`released_by` is present only", "a payment already made that still names who released it",
              set={"governance.treasury.0.released_by": second})
        waits("`released_by` is present only", "a proposal that its vote rejected and that names a guardian",
              set={"governance.treasury.4.released_by": third})
        waits("`executed` or `rejected`", "a payment that waits and holds no bond",
              remove=["governance.treasury.5.bond"],
              set={"total_supply": self.objects["state_payments"]["total_supply"] - 10_000_000})
        waits("`executed` or `rejected`", "a payment that waits and says when it ended",
              set={"governance.treasury.5.ended_at": 900})
        rule("one double vote in a phase", "two double votes of a voter in one phase",
             set={"governance.protocol.2.double_votes.1": {"voter": b, "phase": "exploration", "level": 970,
                                                           "punished": True}})
        rule("one double vote in a phase", "a double vote in a phase in which the voter has no vote",
             set={"governance.protocol.2.double_votes.0.phase": "adoption"})
        rule("`i_min_ppm` is not above", "the lowest rate of issuance above the highest",
             set={"parameters.i_min_ppm": 60_001})
        rule("is not lower than `epoch_blocks`", "an unbonding shorter than an epoch",
             set={"constants.epoch_blocks": 301})
        rule("is not above `treasury_release_blocks`", "a delay for the other guardians that ends after the wait "
             "does: they could release nothing", set={"constants.guardian_delay_blocks": 151})
        self.no("state_1024_validators", "out_of_range", "1,025 validators",
                set={"validators.1024": {"address": {"$account": 99}, "stake": 1},
                     "consensus_set.1024": {"address": {"$account": 99}, "stake": 1}})

    def accounts_and_genesis(self) -> None:
        top = INT_MAX
        self.yes("account", "account", "the account of an address that holds a balance and has sent three "
                 "transactions: what the state trie keeps under that address", {"balance": 1000, "nonce": 3},
                 mutate=True)
        self.yes("account_contract", "account", "the account of a contract: the hash of its code and the root of "
                 "its storage", {"balance": 5, "nonce": 0, "code_hash": {"$text": [48, "c0"]},
                                 "storage_root": {"$text": [48, "5a"]}}, mutate=True)
        self.yes("account_highest", "account", "the highest balance and the highest nonce",
                 {"balance": top, "nonce": top})
        self.no("account_contract", "inconsistent", "the hash of a code without the root of a storage",
                remove=["storage_root"], breaks="present together")
        self.no("account_contract", "inconsistent", "the root of a storage without the hash of a code",
                remove=["code_hash"], breaks="present together")
        self.no("account", "unknown_field", "an account that holds its code and not its hash",
                set={"code": "contract Counter { storage { count: int } }"})
        self.no("account_contract", "bad_text", "a hash of 64 characters, as today",
                set={"code_hash": {"$text": [32, "c0"]}})
        self.no("account", "out_of_range", "a nonce below 0", set={"nonce": -1})

        first = {"version": 1, "scheme": 1, "network_id": self.network_id.hex(), "timestamp": 1794000000,
                 "state": {"$ref": "state_first"}}
        maps = tuple("state." + name
                     for name in ("balances", "nonces", "contracts", "keys", "delegations", "attestations"))
        self.yes("genesis", "genesis", "a genesis: the structure version, the signature scheme, the network, the "
                 "moment, and the first state", first, mutate=True, maps=maps)
        self.yes("genesis_trie", "genesis", "the same genesis with a first state under the function trie: another "
                 "state root, another block of level 0", {**first, "state": {"$ref": "state_first_trie"}})
        self.yes("genesis_earliest", "genesis", "the lowest value of every range, at the first second there is",
                 {**first, "timestamp": 0, "state": {"$ref": "state_lowest"}})
        self.yes("genesis_1024_validators", "genesis", "a genesis with as many validators as a network can have",
                 {**first, "timestamp": top, "state": {"$ref": "state_1024_validators"}})

        a = self.account(100)
        no = lambda rule, why, **how: self.no("genesis", rule, why, **how)                  # noqa: E731
        rule = lambda breaks, why, **how: self.no("genesis", "inconsistent", why, breaks=breaks, **how)  # noqa: E731
        no("missing_field", "a genesis without its moment: nothing takes the time of the machine in its place",
           remove=["timestamp"])
        no("missing_field", "a genesis without a network identifier", remove=["network_id"])
        no("out_of_range", "another structure version", set={"version": 2})
        no("out_of_range", "another signature scheme", set={"scheme": 2})
        no("bad_text", "a network identifier of 62 characters", set={"network_id": {"$text": [31, "a0"]}})
        no("bad_address", "the same genesis under the identifier of another network: no address of it is an "
           "address of that network", set={"network_id": {"$text": [32, "00"]}})
        no("unknown_field", "a genesis with the name of its chain beside its state", set={"chain_id": "kern-devnet"})
        no("unknown_field", "a note for the reader", set={"_notice": "DEVNET GENESIS"})
        no("unknown_field", "a mark of the tools of today", set={"placeholder_keys": True})
        rule("The `level` of `state` is 0", "a first state of level 1", set={"state.level": 1})
        rule("are empty", "a first state in which a validator has already sent a transaction",
             set={f"state.nonces.{a}": 1})
        rule("are empty", "a first state that holds a contract",
             set={f"state.contracts.{self.address(20)}": {"code": "x", "storage": {}}})
        holder, supply = self.address(1), self.objects["state_first"]["total_supply"]
        tranches = [{"level": 0, "amount": 1}]
        rule("are empty", "a first state that holds a delegation",
             set={f"state.delegations.{holder}": {"validator": a, "amount": 1, "tranches": tranches},
                  "state.total_supply": supply + 1})
        rule("are empty", "a first state in which a delegation unbonds",
             set={"state.delegation_unbonding.0": {"delegator": holder, "validator": a, "amount": 1,
                                                   "tranches": tranches, "unbonding_from": 0, "release_at": 300},
                  "state.total_supply": supply + 1})
        rule("are empty", "a first state that holds an attestation",
             set={"state.attestations." + "a1" * 48: {"issuer": holder, "schema_id": "s", "subject": " ", "claim": {},
                                                      "bond": 0, "issued_at": 0, "slashed": False}})
        rule("are empty", "a first state that holds a slashed vote",
             set={"state.consensus_slashes.0": {"validator": a, "kind": "endorse", "level": 0, "round": 0}})
        rule("are empty", "a first state that holds a protocol proposal",
             set={"state.governance.protocol.0": {
                 "proposal_id": "b1" * 48, "submitter": a, "payload": {"params": {"treasury_share_ppm": 1}},
                 "submitted_at": 0, "phase": "submitted", "exploration_votes": {}, "adoption_votes": {},
                 "double_votes": [], "bond": 100_000_000}, "state.total_supply": supply + 100_000_000})
        rule("are empty", "a first state that holds a proposal",
             set={"state.governance.treasury.0": {
                 "proposal_id": "c1" * 48, "submitter": a, "payload": {"recipients": [{"address": a, "amount": 1}]},
                 "submitted_at": 0, "phase": "submitted", "votes": {}, "bond": 10_000_000},
                 "state.total_supply": self.objects["state_first"]["total_supply"] + 10_000_000})
        rule("one key, current from level 0", "a validator whose key is current from level 1",
             set={f"state.keys.{a}.0.from": 1})
        rule("one key, current from level 0", "a validator with a second key, due at level 1",
             set={f"state.keys.{a}.1": {"from": 1, "public_key": {"$key": 190}}})
        rule("`consensus_set` is `validators`", "a snapshot that gives a validator another weight",
             set={"state.consensus_set.0.stake": 2})
        # The rules of a state are rules of a genesis.
        rule("`i_min_ppm` is not above", "a genesis whose rates of issuance are crossed",
             set={"state.parameters.i_min_ppm": 60_001})
        rule("`total_supply` is the sum", "a genesis whose supply is not the sum of what it gives",
             set={"state.total_supply": self.objects["state_first"]["total_supply"] + 1})
        rule("Every validator has a key", "a genesis with a validator that has no key",
             remove=[f"state.keys.{self.account(102)}"])
        rule("`treasury_address` is not in `keys`", "a genesis whose treasury is the address of one of its validators",
             set={"state.treasury_address": a})
        self.no("genesis_1024_validators", "out_of_range", "a genesis with 1,025 validators",
                set={"state.validators.1024": {"address": {"$account": 99}, "stake": 1},
                     "state.consensus_set.1024": {"address": {"$account": 99}, "stake": 1}})

        # A genesis is read as a text is received, without a bound on its length.
        written, depth = {"$canonical": {"$ref": "genesis"}}, LIMITS["json_nesting"]
        self.text("genesis", "accepted", "a genesis as a node reads it: the canonical encoding of the object", written)
        self.text("genesis", "not_canonical", "the same text with a line feed at its end, as an editor leaves one",
                  {"$concat": [written, "\n"]})
        self.text("genesis", "wrong_type", "a genesis inside a list", {"$concat": ["[", written, "]"]})
        self.text("genesis", "too_deep", "65 arrays, one inside the other: the nesting of a genesis is measured "
                  "first, like that of any text",
                  {"$concat": [{"$text": [depth + 1, "["]}, {"$text": [depth + 1, "]"]}]})
        self.text("genesis", "not_canonical", f"{LIMITS['frame_bytes'] + 1:,} spaces: a frame of that length is too "
                  "long, and a genesis has no bound on its length, so its encoding answers",
                  {"$text": [LIMITS["frame_bytes"] + 1, " "]})

    def charges(self) -> None:
        """What a block charges: blocks of transfers on a state, valid or
        invalid, and what they leave."""
        proposer, treasury = self.address(40), self.address(49)
        s1, s2, s3, r1 = (self.address(n) for n in (41, 42, 43, 44))
        chain = "kern-devnet"

        def transfer(sender: int, nonce: Any, amount: int, recipient: int = 44, fee: int = 1000, sig: Any = 1,
                     chain_id: str = chain) -> dict:
            tx = self.tx("transfer", nonce=nonce, sig=sig, sender={"$address": sender},
                         recipient={"$address": recipient}, amount=amount)
            return {**tx, "fee": fee, "chain_id": chain_id}

        def block(why: str, balances: dict, nonces: dict, transactions: Any, rule: str = "", at: int | None = None,
                  **parameters: Any) -> dict:
            state = {"chain_id": chain, "treasury_address": treasury,
                     "parameters": {**PARAMETERS_OF_TODAY, **parameters}, "balances": balances, "nonces": nonces}
            result = sch.charge(state, proposer, self.expand(transactions))
            record: dict[str, Any] = {"why": why, "state": state, "proposer": proposer, "transactions": transactions}
            if rule:
                assert result == ({"valid": False, "rule": rule} if at is None else
                                  {"valid": False, "rule": rule, "at": at}), (why, result)
                record["rule"] = rule
                if at is not None:
                    record["at"] = at
            else:
                assert result["valid"], (why, result)
                record["then"] = {name: result[name] for name in ("balances", "nonces", "failed")}
            self.charged.append(record)
            return result

        size = sch.transaction_size(self.expand(transfer(41, 0, 0, fee=9999)))
        left = block("three transfers of three senders: each pays its fee to the proposer and takes its next nonce; "
                     "the first sender has spent everything and leaves `balances`, and the recipient enters it",
                     {s1: 1025, s2: 5000, s3: 9000}, {s2: 7},
                     [transfer(41, 0, 25), transfer(42, 7, 100, sig=2), transfer(43, 0, 1, sig=3)])
        assert left["balances"] == {s2: 3900, s3: 7999, r1: 126, proposer: 3000}
        assert left["nonces"] == {s1: 1, s2: 8, s3: 1}
        block("a transfer whose sender holds the fee and not the amount: it fails, stays in the block and has paid",
              {s1: 1024}, {}, [transfer(41, 0, 25)])
        assert self.charged[-1]["then"] == {"balances": {s1: 24, proposer: 1000}, "nonces": {s1: 1}, "failed": [0]}
        block("a sender that holds exactly its fee, and moves nothing", {s1: 1000}, {}, [transfer(41, 0, 0)])
        block("two transactions of one sender, one after the other", {s1: 5000}, {s1: 3},
              [transfer(41, 3, 10), transfer(41, 4, 10, sig=2)])
        block("the proposer pays a fee with a fee it received earlier in the block",
              {s1: 1000}, {}, [transfer(41, 0, 0), transfer(40, 0, 0, sig=2)])
        block("no transaction: a block can be empty", {s1: 5}, {s1: 2}, [])
        block("a nonce that is not the next one: the block is invalid", {s1: 5000}, {s1: 3}, [transfer(41, 4, 10)],
              "wrong_nonce", 0)
        block("a nonce that is consumed", {s1: 5000}, {s1: 3}, [transfer(41, 2, 10)], "wrong_nonce", 0)
        block("one nonce twice in a block", {s1: 5000}, {}, [transfer(41, 0, 10), transfer(41, 0, 20, sig=2)],
              "wrong_nonce", 1)
        block("the last transaction an account can send: its nonce becomes 2^63 - 1, the highest a state holds",
              {s1: 5000}, {s1: INT_MAX - 1}, [transfer(41, INT_MAX - 1, 10)])
        assert self.charged[-1]["then"]["nonces"] == {s1: INT_MAX}
        block("a sender whose nonce is 2^63 - 1 sends nothing more: its nonce could not go up",
              {s1: 5000}, {s1: INT_MAX}, [transfer(41, INT_MAX, 10)], "wrong_nonce", 0)
        block("a sender one mukrn short of its fee", {s1: 999}, {}, [transfer(41, 0, 0)], "unpaid_fee", 0)
        block("a sender that holds nothing", {}, {}, [transfer(41, 0, 0)], "unpaid_fee", 0)
        block("a sender that could pay when the block started, and cannot when its turn comes: its first transaction "
              "moved what it held", {s1: 2000}, {}, [transfer(41, 0, 1000), transfer(41, 1, 0, sig=2)], "unpaid_fee", 1)
        block("a transaction that names another chain", {s1: 5000}, {}, [transfer(41, 0, 1, chain_id="kern-testnet")],
              "wrong_chain", 0)
        block("a transfer to the treasury: anyone can give to it", {s1: 5000, treasury: 70}, {},
              [transfer(41, 0, 30, recipient=49)])
        assert self.charged[-1]["then"]["balances"] == {s1: 3970, treasury: 100, proposer: 1000}
        block("a transfer sent by the treasury address, which holds the amount and the fee: only a vote moves what "
              "the treasury holds", {treasury: 5000}, {}, [transfer(49, 0, 10)], "sent_by_treasury", 0)
        block("the second transaction of a block is sent by the treasury address", {s1: 5000, treasury: 5000}, {},
              [transfer(41, 0, 10), transfer(49, 0, 10, sig=2)], "sent_by_treasury", 1)
        floor = PARAMETERS_OF_TODAY["fee_floor_base"] + PARAMETERS_OF_TODAY["fee_floor_per_byte"] * size
        assert (size, floor) == (4790, 9680), (size, floor)
        block(f"the fee floor on: a transfer of {size:,} bytes pays {floor:,} at least, and this one does",
              {s1: floor}, {}, [transfer(41, 0, 0, fee=floor)], fee_floor_enabled=True)
        block("the fee floor on: a fee one mukrn under the floor", {s1: floor}, {}, [transfer(41, 0, 0, fee=floor - 1)],
              "fee_under_floor", 0, fee_floor_enabled=True)
        block("the fee floor off: a fee of 0", {s1: 7}, {}, [transfer(41, 0, 7, fee=0)])
        many = lambda count: {"$list": [count, transfer(41, {"$index": 0}, 0, fee=0,       # noqa: E731
                                                        sig={"$index": 600})]}
        smallest = LIMITS["transaction_bytes"]
        fits = max(n for n in range(1, 40) if sum(sch.transaction_size(t) for t in self.expand(many(n))) <= smallest)
        assert fits == 27
        block(f"the smallest `max_block_bytes`: {fits} transfers fit", {}, {}, many(fits), max_block_bytes=smallest)
        block("one transfer more: the block is too large", {}, {}, many(fits + 1), "block_too_large",
              max_block_bytes=smallest)
        filled = sum(sch.transaction_size(tx) for tx in self.expand(many(fits + 1)))
        assert filled == 134_054, filled
        block(f"{fits + 1} transfers that fill a block of {filled:,} bytes to the byte", {}, {}, many(fits + 1),
              max_block_bytes=filled)
        block("the same block when `max_block_bytes` is one byte less", {}, {}, many(fits + 1), "block_too_large",
              max_block_bytes=filled - 1)

    def decisions(self) -> None:
        """Proposals that are decided at one level: what they do, taken
        in one order and in the other."""
        today = PARAMETERS_OF_TODAY

        def decide(why: str, protocol: list, treasury: list, then: dict, **before: Any) -> None:
            start = {"parameters": {**today, **before.pop("parameters", {})}, "state_root_function": "json",
                     "treasury": 1000, "protocol_bond": 100, "treasury_bond": 10, **before}
            result = sch.decide(start, protocol, treasury)
            expected = {"protocol": [], "treasury": [], "state_root_function": start["state_root_function"],
                        "treasury_holds": start["treasury"], "burned": 0, **then,
                        "parameters": {**start["parameters"], **then.get("parameters", {})}}
            assert result == expected, (why, result)
            self.decided.append({"why": why, "before": start, "protocol": protocol, "treasury": treasury,
                                    "then": result})

        passes = lambda **payload: {"payload": payload, "passes": True}                    # noqa: E731
        voted = lambda passed=True: {"phase": "voting", "passes": passed}                  # noqa: E731
        waited = {"phase": "passed"}
        share = lambda value: passes(params={"treasury_share_ppm": value})                 # noqa: E731
        low, high = passes(params={"i_min_ppm": 50_000}), passes(params={"i_max_ppm": 40_000})
        wider, higher = passes(params={"i_max_ppm": 90_000}), passes(params={"i_min_ppm": 70_000})

        decide("nothing ends at this level", [], [], {})
        decide("a protocol proposal whose vote passes: its parameters replace those of the state, and its bond returns",
               [share(10_000)], [], {"protocol": ["activated"], "parameters": {"treasury_share_ppm": 10_000}})
        decide("a protocol proposal whose vote fails: half its bond is burned, the rest goes to the treasury",
               [{"payload": {"params": {"treasury_share_ppm": 10_000}}, "passes": False}], [],
               {"protocol": ["rejected"], "treasury_holds": 1050, "burned": 50})
        decide("a bond of an odd amount: the half that is burned is rounded down",
               [{"payload": {"params": {"treasury_share_ppm": 10_000}}, "passes": False}], [],
               {"protocol": ["rejected"], "treasury_holds": 1051, "burned": 50}, protocol_bond=101)
        decide("two proposals set one parameter: the later one of the list has the last word",
               [share(10_000), share(20_000)], [],
               {"protocol": ["activated", "activated"], "parameters": {"treasury_share_ppm": 20_000}})
        decide("the same two in the other order: another value",
               [share(20_000), share(10_000)], [],
               {"protocol": ["activated", "activated"], "parameters": {"treasury_share_ppm": 10_000}})
        decide("two proposals move one bound each and cross together: the second is rejected",
               [low, high], [], {"protocol": ["activated", "rejected"], "parameters": {"i_min_ppm": 50_000},
                                 "treasury_holds": 1050, "burned": 50})
        decide("the same two in the other order: the other one is rejected",
               [high, low], [], {"protocol": ["activated", "rejected"], "parameters": {"i_max_ppm": 40_000},
                                 "treasury_holds": 1050, "burned": 50})
        decide("a proposal that only fits after another one: the highest rate goes up first, then the lowest",
               [wider, higher], [],
               {"protocol": ["activated", "activated"], "parameters": {"i_min_ppm": 70_000, "i_max_ppm": 90_000}},
               parameters={"i_min_ppm": 50_000, "i_max_ppm": 60_000})
        decide("the same two in the other order: the lowest rate cannot go above the highest yet",
               [higher, wider], [],
               {"protocol": ["rejected", "activated"], "parameters": {"i_max_ppm": 90_000},
                "treasury_holds": 1050, "burned": 50},
               parameters={"i_min_ppm": 50_000, "i_max_ppm": 60_000})
        decide("the two rates set equal", [passes(params={"i_min_ppm": 60_000})], [],
               {"protocol": ["activated"], "parameters": {"i_min_ppm": 60_000}})
        decide("two proposals change the function of the state root: the later one has the last word",
               [passes(swap="state_root_function", to="trie"), passes(swap="state_root_function", to="json")], [],
               {"protocol": ["activated", "activated"], "state_root_function": "json"}, state_root_function="trie")
        decide("a proposal that is rejected changes nothing: neither its parameters nor its function",
               [passes(params={"i_min_ppm": 70_000}, swap="state_root_function", to="trie")], [],
               {"protocol": ["rejected"], "treasury_holds": 1050, "burned": 50})
        decide("a treasury proposal whose vote passes: nothing is paid, its bond stays held, and it waits for a "
               "guardian", [], [voted()], {"treasury": ["passed"]})
        decide("a treasury proposal whose vote fails: half its bond is burned, the rest goes to the treasury",
               [], [voted(False)], {"treasury": ["rejected"], "treasury_holds": 1005, "burned": 5})
        decide("a payment that nobody released by the end of its wait: it is rejected, and its bond is lost the "
               "same way", [], [waited], {"treasury": ["rejected"], "treasury_holds": 1005, "burned": 5})
        decide("a bond of an odd amount on the treasury track", [], [waited],
               {"treasury": ["rejected"], "treasury_holds": 1006, "burned": 5}, treasury_bond=11)
        decide("a vote that passes, a vote that fails and a wait that ends, at one level: each in its turn",
               [], [voted(), voted(False), waited],
               {"treasury": ["passed", "rejected", "rejected"], "treasury_holds": 1010, "burned": 10})
        decide("both tracks lose a bond at one level: the protocol track first, then the treasury track",
               [{"payload": {"params": {"treasury_share_ppm": 1}}, "passes": False}], [voted(False), voted()],
               {"protocol": ["rejected"], "treasury": ["rejected", "passed"], "treasury_holds": 1055, "burned": 55})

    def payments(self) -> None:
        """Payments that wait, and what the transactions of guardians do
        to them in one block. Guardians, senders and identifiers are short
        names here: the rules only compare them."""
        first, second, third, stranger = "first", "second", "third", "stranger"

        def guard(why: str, payments: dict, operations: list, did: list, then: dict | None = None,
                  **before: Any) -> None:
            start = {"level": 1000, "guardians": [first, second, third], "treasury": 1000, "treasury_bond": 10,
                     "guardian_delay_blocks": 50, **before, "payments": payments}
            result = sch.guard(start, operations)
            after = {identifier: {name: value for name, value in entry.items() if name in ("phase", "released_by")}
                     for identifier, entry in payments.items()}
            then = dict(then or {})
            for identifier, entry in then.pop("payments", {}).items():
                after[identifier] = entry
            expected = {"did": did, "treasury_holds": start["treasury"], "burned": 0, "payments": after, **then}
            assert result == expected, (why, result)
            self.guarded.append({"why": why, "before": start, "operations": operations, "then": result})

        def waiting(total: int = 600, voted: int = 900, phase: str = "passed", **more: Any) -> dict:
            return {"phase": phase, "voted": voted, "total": total, "to_itself": 0, **more}

        release = lambda sender, name="p": {"sender": sender, "kind": "release_payment",   # noqa: E731
                                            "proposal_id": name}
        cancel = lambda sender, name="p": {"sender": sender, "kind": "cancel_payment",     # noqa: E731
                                           "proposal_id": name}
        paid, dropped = {"phase": "executed"}, {"phase": "rejected"}

        guard("the first guardian releases a payment that waits: it is paid in that transaction",
              {"p": waiting()}, [release(first)], ["paid"], {"treasury_holds": 400, "payments": {"p": paid}})
        guard("the first guardian releases in the block that follows the end of the vote, long before the others can",
              {"p": waiting()}, [release(first)], ["paid"], {"treasury_holds": 400, "payments": {"p": paid}},
              level=901)
        guard("in the block of the level at which its vote ends, a proposal is still in its vote when the "
              "transactions are applied: nobody releases it yet",
              {"p": waiting(voted=1000, phase="voting")}, [release(first), cancel(first)],
              ["not_waiting", "not_waiting"])
        guard("the first guardian cancels: the payment is rejected, half its bond is burned and the rest goes to "
              "the treasury", {"p": waiting()}, [cancel(first)], ["cancelled"],
              {"treasury_holds": 1005, "burned": 5, "payments": {"p": dropped}})
        guard("a bond of an odd amount: the half that is burned is rounded down",
              {"p": waiting()}, [cancel(first)], ["cancelled"],
              {"treasury_holds": 1006, "burned": 5, "payments": {"p": dropped}}, treasury_bond=11)
        guard("another guardian releases one level before its delay has passed",
              {"p": waiting()}, [release(second)], ["too_early"], level=949)
        guard("another guardian releases at the level at which its delay has passed: its release is recorded, and "
              "nothing is paid", {"p": waiting()}, [release(second)], ["recorded"],
              {"payments": {"p": {"phase": "passed", "released_by": second}}}, level=950)
        guard("a second guardian releases a payment that another one released: it is paid",
              {"p": waiting(released_by=second)}, [release(third)], ["paid"],
              {"treasury_holds": 400, "payments": {"p": paid}})
        guard("the two releases in one block", {"p": waiting()}, [release(third), release(second)],
              ["recorded", "paid"], {"treasury_holds": 400, "payments": {"p": paid}})
        guard("the same guardian releases twice in one block: its second release fails, and the payment still waits "
              "for another guardian", {"p": waiting()}, [release(second), release(second)],
              ["recorded", "released_twice"], {"payments": {"p": {"phase": "passed", "released_by": second}}})
        guard("a guardian that released comes back in a later block: it releases once",
              {"p": waiting(released_by=third)}, [release(third)], ["released_twice"])
        guard("the first guardian releases a payment that another guardian released: it is paid",
              {"p": waiting(released_by=third)}, [release(first)], ["paid"],
              {"treasury_holds": 400, "payments": {"p": paid}})
        guard("the first guardian cancels a payment that another guardian released",
              {"p": waiting(released_by=second)}, [cancel(first)], ["cancelled"],
              {"treasury_holds": 1005, "burned": 5, "payments": {"p": dropped}})
        guard("another guardian cannot cancel, even a payment it released",
              {"p": waiting(released_by=second)}, [cancel(second), cancel(third)],
              ["not_the_first", "not_the_first"])
        guard("an address that is not a guardian releases, then cancels",
              {"p": waiting()}, [release(stranger), cancel(stranger)], ["not_a_guardian", "not_a_guardian"])
        guard("who is first is the order of the list: with another list, the same address waits like the others",
              {"p": waiting()}, [release(first), cancel(first), release(second)],
              ["too_early", "not_the_first", "paid"], {"treasury_holds": 400, "payments": {"p": paid}},
              guardians=[second, first, third], level=949)
        guard("a proposal that does not wait is neither released nor cancelled: one already paid, one rejected, "
              "one that is not voted yet, and one that the state does not hold",
              {"p": waiting(phase="executed"), "q": waiting(phase="rejected"), "r": waiting(phase="submitted")},
              [release(first, "p"), cancel(first, "q"), release(second, "r"), release(first, "s")],
              ["not_waiting"] * 4)
        guard("the sender is looked at first: an address that is not a guardian and names nothing that waits",
              {"p": waiting(phase="executed")}, [release(stranger)], ["not_a_guardian"])
        guard("then the payment: another guardian cancels a proposal that does not wait",
              {"p": waiting(phase="rejected")}, [cancel(second)], ["not_waiting"])
        guard("then the delay: before it has passed, a release fails for that reason, whoever is recorded",
              {"p": waiting(released_by=second)}, [release(second), release(third)], ["too_early", "too_early"],
              level=949)
        guard("a payment of everything the treasury holds", {"p": waiting(1000)}, [release(first)], ["paid"],
              {"treasury_holds": 0, "payments": {"p": paid}})
        guard("one mukrn more than the treasury holds: the release fails, and the payment goes on waiting",
              {"p": waiting(1001)}, [release(first)], ["unfunded"])
        guard("the release of a second guardian that cannot be paid: the release of the first one stays recorded",
              {"p": waiting(1001, released_by=second)}, [release(third)], ["unfunded"])
        guard("a release that is only recorded does not look at what the treasury holds",
              {"p": waiting(1001)}, [release(second)], ["recorded"],
              {"payments": {"p": {"phase": "passed", "released_by": second}}})
        guard("two payments the treasury cannot make both: the one released first is paid",
              {"p": waiting(), "q": waiting()}, [release(first, "p"), release(first, "q")], ["paid", "unfunded"],
              {"treasury_holds": 400, "payments": {"p": paid}})
        guard("the same two released in the other order: the other one is paid",
              {"p": waiting(), "q": waiting()}, [release(first, "q"), release(first, "p")], ["paid", "unfunded"],
              {"treasury_holds": 400, "payments": {"q": paid}})
        guard("a payment that names the treasury among its recipients: what the treasury pays itself is still "
              "there for the payment that follows",
              {"p": waiting(1000, to_itself=400), "q": waiting(400)}, [release(first, "p"), release(first, "q")],
              ["paid", "paid"], {"treasury_holds": 0, "payments": {"p": paid, "q": paid}})
        guard("the same payment is judged on its whole sum: one mukrn more than the treasury holds, and its "
              "release fails, whoever it pays", {"p": waiting(1001, to_itself=400)}, [release(first)], ["unfunded"])
        guard("a cancellation pays for a release: the half of the bond that the treasury keeps is there for the "
              "payment that follows", {"p": waiting(), "q": waiting(1005)}, [cancel(first, "p"), release(first, "q")],
              ["cancelled", "paid"], {"treasury_holds": 0, "burned": 5, "payments": {"p": dropped, "q": paid}})
        guard("the same two in the other order: the release comes too soon",
              {"p": waiting(), "q": waiting(1005)}, [release(first, "q"), cancel(first, "p")],
              ["unfunded", "cancelled"], {"treasury_holds": 1005, "burned": 5, "payments": {"p": dropped}})
        guard("a release, then a cancellation of the same payment in one block: it is already made",
              {"p": waiting()}, [release(first), cancel(first)], ["paid", "not_waiting"],
              {"treasury_holds": 400, "payments": {"p": paid}})
        guard("a cancellation, then a release: nothing waits any more",
              {"p": waiting()}, [cancel(first), release(first), release(second)],
              ["cancelled", "not_waiting", "not_waiting"],
              {"treasury_holds": 1005, "burned": 5, "payments": {"p": dropped}})

    def exchanges(self) -> None:
        """A connection, as the node that asks for blocks sees it."""
        def exchange(why: str, steps: list[dict], verdicts: list[str]) -> None:
            assert sch.exchange(steps) == verdicts, (why, sch.exchange(steps))
            self.exchanged.append({"why": why, "steps": steps, "verdicts": verdicts})

        ask = lambda first, last: {"ask": [first, last]}                                    # noqa: E731
        got = lambda *levels: {"blocks": list(levels)}                                     # noqa: E731
        exchange("a request, then its answer", [ask(2, 4), got(2, 3, 4)], ["accepted", "accepted"])
        exchange("a second request while the first one waits: a node does not send it, and the first one still "
                 "waits for its answer", [ask(2, 4), ask(5, 9), got(2, 3, 4)], ["accepted", "refused", "accepted"])
        exchange("blocks that nobody asked for", [got(2, 3)], ["refused"])
        exchange("an answer in two frames: the second one answers nothing, since nothing waits any more",
                 [ask(5, 9), got(5, 6), got(7), ask(7, 9), got(7, 8, 9)],
                 ["accepted", "accepted", "refused", "accepted", "accepted"])
        exchange("an answer that does not start at the level asked for is refused, and the request still waits",
                 [ask(5, 9), got(6, 7), got(5)], ["accepted", "refused", "accepted"])
        exchange("an empty answer is an answer: the peer does not hold the first level asked for",
                 [ask(5, 9), got(), ask(5, 9)], ["accepted", "accepted", "accepted"])
        exchange("four bytes that announce the largest frame, then a request and its answer",
                 [{"prefix": "01000000"}, ask(1, 1), got(1)], ["accepted", "accepted", "accepted"])
        exchange("four bytes that announce one byte too many: the node closes the connection, and reads nothing "
                 "that follows", [ask(1, 3), {"prefix": "01000001"}, got(1, 2, 3), ask(1, 3)],
                 ["accepted", "refused", "closed", "closed"])

        def served(why: str, held: list[list[int]], requests: list[list[int]], answers: list[list[int]]) -> None:
            assert sch.serve(dict(map(tuple, held)), [tuple(r) for r in requests]) == answers, why
            self.served.append({"why": why, "held": held, "requests": requests, "answers": answers})

        run = [[level, 5_000] for level in range(1, 6)]
        served("two requests received on a connection: two answers, in the order of the requests",
               run, [[4, 5], [1, 2]], [[4, 5], [1, 2]])
        served("the same request twice: the same answer twice", run, [[2, 3], [2, 3]], [[2, 3], [2, 3]])
        served("a request the node cannot serve, then one it can: an empty answer first",
               run, [[7, 9], [5, 9]], [[], [5]])

    # -- the vectors ------------------------------------------------------

    def build(self) -> dict:
        self.transactions()
        self.messages_and_certificates()
        self.blocks()
        self.frames()
        self.texts()
        self.four_bytes()
        self.requests_and_answers()
        self.states()
        self.accounts_and_genesis()
        self.charges()
        self.decisions()
        self.payments()
        self.exchanges()
        return {"description": DESCRIPTION, "network_id": self.network_id.hex(), "limits": LIMITS,
                "rules": sch.RULES, "block_rules": sch.BLOCK_RULES, "guardian_rules": sch.GUARDIAN_RULES,
                "directives": DIRECTIVES,
                "accepted": self.accepted, "refused": self.refused,
                "accepted_texts": self.accepted_texts, "refused_texts": self.refused_texts,
                "prefixes": self.prefixes, "answers": self.answers, "replies": self.replies,
                "charges": self.charged, "decisions": self.decided, "payments": self.guarded,
                "exchanges": self.exchanged, "served": self.served}

    def transactions(self) -> None:
        yes, no, tx, limit = self.yes, self.no, self.tx, LIMITS
        frozen_tx = self.frozen["kern.tx"]["object"]
        other = frozen_tx["recipient"]

        yes("transfer_first", "transaction", "the first transaction of an account: its nonce is 0, and it carries "
            "the public key", {**frozen_tx, "nonce": 0, "signature": {"$sig": 0}, "public_key": {"$key": 1}},
            mutate=True)
        value = yes("transfer", "transaction", "the next transaction of that account: no key. What it signs is the "
                    "transfer of the profile vectors, so its identifier is theirs",
                    {**frozen_tx, "signature": {"$sig": 1}}, mutate=True)
        assert sch.transaction_id(self.network_id, value).hex() == self.frozen["kern.tx"]["digest"]
        yes("transfer_lowest", "transaction", "every number at the bottom of its range, and a chain name of one letter",
            {**frozen_tx, "nonce": 0, "fee": 0, "gas_limit": 0, "amount": 0, "chain_id": "k", "signature": {"$sig": 5}})
        yes("transfer_highest", "transaction", "every number at the top of its range, and a chain name of 64 "
            "characters with digits and hyphens",
            {**frozen_tx, "nonce": INT_MAX, "fee": INT_MAX, "gas_limit": INT_MAX, "amount": INT_MAX,
             "chain_id": {"$concat": ["k", {"$text": [31, "0-"]}, "9"]}, "signature": {"$sig": 6}})
        yes("originate", "transaction", "the origination of a contract",
            tx("originate", code="contract Counter { storage { count: int } }", initial_storage={"count": 7}),
            mutate=True, free=("initial_storage",))
        yes("originate_no_storage", "transaction", "an origination that sets no field: the map is empty, not absent",
            tx("originate", code="contract Counter { storage { count: int } }", initial_storage={}))
        yes("originate_one_byte", "transaction", "a code of one byte: whether a code compiles is not a matter of form",
            tx("originate", code="x", initial_storage={}))
        values = {"low": INT_MIN, "high": INT_MAX, "open": True, "shut": False, "owner": {"$address": 3},
                  "note": "café à Liège", "empty": "", "long": {"$text": [limit["value_bytes"], "x"]}}
        yes("originate_values", "transaction", "fields that hold every kind of value, at the ends of their ranges",
            tx("originate", code="contract C {}", initial_storage=values))
        yes("originate_256_fields", "transaction", "256 fields, under names of 64 characters",
            tx("originate", code="contract C {}", initial_storage={"$map": [
                limit["contract_fields"], {"$concat": [{"$text": [61, "n"]}, {"$index": 100}]}, {"$index": 0}]}))
        yes("originate_longest_code", "transaction", "a code of 65,536 bytes",
            tx("originate", code={"$text": [limit["code_bytes"], "x"]}, initial_storage={}))
        yes("call", "transaction", "a call without parameter and without amount: the map is empty, the amount is 0",
            tx("call", recipient={"$address": 2}, amount=0, entry="increment", params={}),
            mutate=True, free=("params",))
        yes("call_values", "transaction", "a call that moves the largest amount, and whose parameters hold every "
            "kind of value, at the ends of their ranges",
            tx("call", recipient={"$address": 2}, amount=INT_MAX, entry="set_all", params=values))
        yes("call_longest_names", "transaction", "an entry point and a parameter whose names have 64 characters, with "
            "capital letters, digits and underscores",
            tx("call", recipient={"$address": 2}, amount=0, entry={"$concat": ["_", {"$text": [21, "aZ9"]}]},
               params={"$map": [1, {"$concat": ["Z", {"$text": [21, "_0a"]}]}, True]}))
        yes("call_256_fields", "transaction", "a call with 256 parameters",
            tx("call", recipient={"$address": 2}, amount=0, entry="f",
               params={"$map": [limit["contract_fields"], {"$concat": ["field_", {"$index": 0}]}, {"$index": 0}]}))
        yes("propose_parameter", "transaction", "a protocol proposal that changes one parameter",
            tx("governance_propose", params={"track": "protocol", "payload": {"params": {"i_max_ppm": 40000}},
                                             "salt": 0}), mutate=True)
        yes("propose_parameters_high", "transaction", "every parameter, each at the top of its range",
            tx("governance_propose", params={"track": "protocol", "salt": INT_MAX, "payload": {"params": {
                "i_min_ppm": 1000000, "i_max_ppm": 1000000, "target_staking_ratio_ppm": 1000000,
                "target_block_time_ms": 3600000, "treasury_share_ppm": 1000000, "proposer_bonus_ppm": 1000000,
                "fee_floor_enabled": True, "fee_floor_base": 10**12, "fee_floor_per_byte": 10**9,
                "max_block_bytes": limit["block_bytes"]}}}))
        yes("propose_parameters_low", "transaction", "every parameter, each at the bottom of its range",
            tx("governance_propose", params={"track": "protocol", "salt": 0, "payload": {"params": {
                "i_min_ppm": 0, "i_max_ppm": 0, "target_staking_ratio_ppm": 0, "target_block_time_ms": 1,
                "treasury_share_ppm": 0, "proposer_bonus_ppm": 0, "fee_floor_enabled": False, "fee_floor_base": 0,
                "fee_floor_per_byte": 0, "max_block_bytes": limit["transaction_bytes"]}}}))
        proposal = self.frozen["kern.gov.id"]["object"]
        value = yes("propose_swap", "transaction", "a protocol proposal that changes the state root function: the "
                    "proposal of the profile vectors, so its identifier is theirs",
                    tx("governance_propose", sender=proposal["submitter"],
                       params={"track": "protocol", "payload": proposal["payload"], "salt": proposal["salt"]}),
                    mutate=True)
        self.proposal = sch.proposal_id(self.network_id, value).hex()
        assert self.proposal == self.frozen["kern.gov.id"]["digest"]
        yes("propose_swap_and_parameter", "transaction", "a protocol proposal that does both",
            tx("governance_propose", params={"track": "protocol", "salt": 7, "payload": {
                "params": {"fee_floor_enabled": True}, "swap": "state_root_function", "to": "json"}}), mutate=True)
        yes("propose_treasury", "transaction", "a treasury proposal with a memo",
            tx("governance_propose", params={"track": "treasury", "salt": 1, "payload": {
                "recipients": [{"address": {"$address": 2}, "amount": 5000000},
                               {"address": {"$address": 3}, "amount": 1}],
                "memo": "Grant 12: documentation"}}), mutate=True)
        yes("propose_treasury_64", "transaction", "64 recipients, and a memo of 256 bytes",
            tx("governance_propose", params={"track": "treasury", "salt": 2, "payload": {
                "recipients": {"$list": [limit["recipients"], {"address": {"$address": {"$index": 100}}, "amount": 1}]},
                "memo": {"$text": [256, "m"]}}}))
        yes("propose_treasury_total", "transaction", "amounts that add up to 2^63 - 1, twice to the same address, "
            "and a memo of one byte",
            tx("governance_propose", params={"track": "treasury", "salt": INT_MAX, "payload": {
                "memo": "m", "recipients": [{"address": {"$address": 2}, "amount": INT_MAX - 1},
                                            {"address": {"$address": 2}, "amount": 1}]}}))
        yes("propose_treasury_one", "transaction", "one recipient, who receives 2^63 - 1",
            tx("governance_propose", params={"track": "treasury", "salt": 0, "payload": {"recipients": [
                {"address": {"$address": 2}, "amount": INT_MAX}]}}))
        yes("governance_vote", "transaction", "a vote on that proposal",
            tx("governance_vote", params={"track": "protocol", "proposal_id": self.proposal, "vote": "yes"}),
            mutate=True)
        yes("governance_vote_no", "transaction", "a vote against a treasury proposal",
            tx("governance_vote", params={"track": "treasury", "proposal_id": self.proposal, "vote": "no"}))
        yes("governance_vote_abstain", "transaction", "an abstention",
            tx("governance_vote", params={"track": "protocol", "proposal_id": self.proposal, "vote": "abstain"}))
        yes("release_payment", "transaction", "a guardian releases a payment that waits, named by the identifier "
            "of its proposal", tx("release_payment", params={"proposal_id": self.proposal}), mutate=True)
        yes("cancel_payment", "transaction", "the first guardian cancels a payment that waits",
            tx("cancel_payment", params={"proposal_id": self.proposal}), mutate=True)
        yes("slash_equivocation", "transaction", "a report of two votes of one validator on one proposal",
            tx("slash_equivocation", params={"proposal_id": self.proposal, "equivocator": {"$address": 2}}),
            mutate=True)
        yes("slash_consensus_equivocation", "transaction", "two votes of one validator for two blocks, as evidence",
            tx("slash_consensus_equivocation", params={
                "msg_a": {"kind": "endorse", "level": 7, "round": 0, "block_hash": "a1" * 48,
                          "validator": {"$address": 2}, "signature": {"$sig": 8}},
                "msg_b": {"kind": "endorse", "level": 7, "round": 0, "block_hash": "b2" * 48,
                          "validator": {"$address": 2}, "signature": {"$sig": 9}}}), mutate=True)
        yes("slash_consensus_equivocation_ends", "transaction", "two pre-endorsements at the ends of the ranges of a "
            "level and of a round: that they are the two halves of one offence is not a matter of form",
            tx("slash_consensus_equivocation", params={
                "msg_a": {"kind": "preendorse", "level": 0, "round": 0, "block_hash": "a1" * 48,
                          "validator": {"$address": 2}, "signature": {"$sig": 8}},
                "msg_b": {"kind": "preendorse", "level": INT_MAX, "round": ROUND_MAX, "block_hash": "b2" * 48,
                          "validator": {"$address": 2}, "signature": {"$sig": 9}}}))
        yes("delegate_stake", "transaction", "a delegation of the smallest amount",
            tx("delegate_stake", amount=1, params={"validator": {"$address": 2}}), mutate=True)
        yes("delegate_stake_highest", "transaction", "a delegation of the largest amount",
            tx("delegate_stake", amount=INT_MAX, params={"validator": {"$address": 2}}))
        yes("undelegate_stake", "transaction", "the end of a delegation: no field of its own",
            tx("undelegate_stake"), mutate=True)
        attestation = self.frozen["kern.attestation.id"]["object"]
        value = yes("attest", "transaction", "an attestation with a bond: the attestation of the profile vectors, "
                    "so its identifier is theirs",
                    tx("attest", sender=attestation["issuer"], nonce=attestation["attest_nonce"], amount=1000000,
                       params={"schema_id": attestation["schema_id"], "subject": attestation["subject"],
                               "claim": attestation["claim"]}), mutate=True, free=("params.claim",))
        self.attestation = sch.attestation_id(self.network_id, value).hex()
        assert self.attestation == self.frozen["kern.attestation.id"]["digest"]
        deep: Any = [0]
        for _ in range(limit["transaction_nesting"] - 4):
            deep = [deep]
        yes("attest_deepest", "transaction", "a claim that takes the transaction to 32 levels: the number at the "
            "bottom is not a level",
            tx("attest", amount=0, params={"schema_id": "s", "subject": "x", "claim": {"a": deep}}))
        yes("attest_largest_claim", "transaction", "the largest bond and a claim of 16,384 bytes, under the longest "
            "names: a schema name of 128 characters with every kind of character it may have, and a subject of 256 "
            "characters from both ends of its alphabet",
            tx("attest", amount=INT_MAX, params={
                "schema_id": {"$text": [16, "Az09._-x"]}, "subject": {"$text": [128, " ~"]},
                "claim": {"text": {"$text": [limit["claim_bytes"] - 11, "x"]}}}))
        yes("attest_smallest", "transaction", "an empty claim, about a subject of one space",
            tx("attest", amount=0, params={"schema_id": "s", "subject": " ", "claim": {}}))
        yes("revoke_attestation", "transaction", "the revocation of that attestation",
            tx("revoke_attestation", params={"attestation_id": self.attestation}), mutate=True)
        yes("slash_attestation_equivocation", "transaction", "a report of two attestations that contradict each other",
            tx("slash_attestation_equivocation", params={"attestation_id_1": self.attestation,
                                                         "attestation_id_2": "c3" * 48}), mutate=True)
        yes("rotate_key", "transaction", "a change of key: the new key, and a second signature made with it",
            tx("rotate_key", params={"new_public_key": {"$key": 2}}, second_signature={"$sig": 2}), mutate=True)
        largest = self.largest(1, 1)
        yes("transaction_largest", "transaction", "a transaction of 131,072 bytes", largest)

        no("transfer", "out_of_range", "a negative amount", set={"amount": -1})
        no("transfer", "out_of_range", "a negative fee", set={"fee": -1})
        no("transfer", "out_of_range", "a negative nonce", set={"nonce": -1})
        no("transfer", "out_of_range", "a negative gas limit", set={"gas_limit": -1})
        no("transfer", "bad_text", "a kind that does not exist", set={"kind": "mint"})
        no("transfer", "bad_address", "a sender that is an address of another network",
           set={"sender": "kn1VwTAqJ8uFjeNr5FzW54xUbMjE9sr9g7PrYyKtyHRRvDH5QADRewCQ7Xc6w2imSEDmWnfEk2v"})
        no("transfer", "bad_address", "a recipient one character short", set={"recipient": other[:-1]})
        no("transfer", "bad_address", "a recipient with a character that is not of base 58",
           set={"recipient": other[:-1] + "0"})
        no("transfer", "bad_address", "a recipient with one character changed: the checksum no longer holds",
           set={"recipient": other[:40] + ("2" if other[40] != "2" else "3") + other[41:]})
        body = bytes([*ref.ADDRESS_PREFIX[:2], ref.ADDRESS_PREFIX[2] - 1]) + filler("address", 2, 48)
        elsewhere = ref.base58(body + ref.H("kern.checksum", self.network_id, body)[:4])
        assert len(elsewhere) == 75 and elsewhere[:2] == other[:2]
        no("transfer", "bad_address", "a recipient under another prefix, with the checksum of that prefix",
           set={"recipient": elsewhere})
        no("transfer", "bad_address", "a recipient with the digit 1 in front: 76 characters that spell the same number",
           set={"recipient": "1" + other})
        no("transfer", "bad_text", "a chain name with a capital letter", set={"chain_id": "Kern-devnet"})
        no("transfer", "bad_text", "a chain name that starts with a digit", set={"chain_id": "1kern"})
        no("transfer", "bad_text", "a chain name of 65 characters", set={"chain_id": {"$text": [65, "k"]}})
        no("transfer", "bad_text", "an empty chain name", set={"chain_id": ""})
        no("transfer", "bad_signature", "a signature of another scheme",
           set={"signature": {"$concat": ["ksig2.", {"$text": [4498, "A"]}]}})
        no("transfer", "bad_signature", "a signature one character short",
           set={"signature": {"$concat": ["ksig1.", {"$text": [4497, "A"]}]}})
        no("transfer", "bad_signature", "a signature whose unused bits are not zero",
           set={"signature": {"$concat": ["ksig1.", {"$text": [4497, "A"]}, "B"]}})
        no("transfer_first", "bad_key", "a public key of another scheme",
           set={"public_key": {"$concat": ["kpk2.", {"$text": [2646, "A"]}]}})
        no("transfer_first", "bad_key", "a public key one character short",
           set={"public_key": {"$concat": ["kpk1.", {"$text": [2645, "A"]}]}})
        no("transfer", "unknown_field", "a transfer with a code", set={"code": "contract C {}"})
        no("transfer", "unknown_field", "a transfer with parameters", set={"params": {}})
        no("transfer", "unknown_field", "a transfer with a second signature", set={"second_signature": {"$sig": 2}})
        no("transfer", "unknown_field", "the public key under its name of today", set={"sender_pubkey": {"$key": 1}})
        no("originate", "bad_text", "an empty code", set={"code": ""})
        no("originate_longest_code", "bad_text", "a code of 65,537 bytes",
           set={"code": {"$text": [limit["code_bytes"] + 1, "x"]}})
        no("originate", "unknown_field", "an origination with an amount", set={"amount": 0})
        no("originate", "bad_text", "a field whose name starts with a digit", set={"initial_storage": {"1st": 1}})
        no("originate", "bad_text", "a field whose name has a hyphen", set={"initial_storage": {"my-field": 1}})
        no("originate", "bad_text", "a field whose name has 65 characters",
           set={"initial_storage": {"$map": [1, {"$text": [65, "n"]}, 1]}})
        no("originate", "wrong_type", "a field that holds a list", set={"initial_storage": {"count": [7]}})
        no("originate", "wrong_type", "a field that holds an object", set={"initial_storage": {"count": {"v": 7}}})
        no("originate", "bad_text", "a field that holds a text of 4,097 bytes",
           set={"initial_storage": {"note": {"$text": [limit["value_bytes"] + 1, "x"]}}})
        no("originate", "out_of_range", "257 fields",
           set={"initial_storage": {"$map": [limit["contract_fields"] + 1, {"$concat": ["f", {"$index": 0}]}, 0]}})
        no("call", "wrong_type", "parameters given as a list, as a call may give them today", set={"params": [5]})
        no("call_256_fields", "out_of_range", "a 257th parameter", set={"params.field_256": 0})
        no("call", "out_of_range", "a call that moves a negative amount", set={"amount": -1})
        no("call", "bad_text", "an entry point whose name starts with a digit", set={"entry": "9lives"})
        no("call", "bad_text", "an empty entry point", set={"entry": ""})
        no("propose_parameter", "bad_text", "a track that does not exist", set={"params.track": "council"})
        no("propose_parameter", "inconsistent", "a payload that changes nothing", set={"params.payload": {}})
        no("propose_parameter", "inconsistent", "an empty set of parameters", set={"params.payload.params": {}})
        no("propose_parameter", "unknown_field", "a parameter under one of the names that take a fraction today",
           set={"params.payload.params": {"i_max": 40000}})
        for name in ("i_min_ppm", "i_max_ppm", "target_staking_ratio_ppm", "treasury_share_ppm", "proposer_bonus_ppm"):
            no("propose_parameter", "out_of_range", f"{name} above a million parts per million",
               set={"params.payload.params": {name: 1000001}})
        no("propose_parameter", "out_of_range", "a block time of zero",
           set={"params.payload.params": {"target_block_time_ms": 0}})
        no("propose_parameter", "out_of_range", "a block time above an hour",
           set={"params.payload.params": {"target_block_time_ms": 3600001}})
        no("propose_parameter", "out_of_range", "a base of the fee floor above 10^12",
           set={"params.payload.params": {"fee_floor_base": 10**12 + 1}})
        no("propose_parameter", "out_of_range", "a fee floor per byte above 10^9",
           set={"params.payload.params": {"fee_floor_per_byte": 10**9 + 1}})
        no("propose_parameter", "wrong_type", "a switch given as a number",
           set={"params.payload.params": {"fee_floor_enabled": 1}})
        no("propose_parameter", "wrong_type", "a rate given as a text",
           set={"params.payload.params": {"i_max_ppm": "40000"}})
        no("propose_parameter", "out_of_range", "a block size below the size of one transaction",
           set={"params.payload.params": {"max_block_bytes": limit["transaction_bytes"] - 1}})
        no("propose_parameter", "out_of_range", "a block size above the bound",
           set={"params.payload.params": {"max_block_bytes": limit["block_bytes"] + 1}})
        no("propose_parameter", "out_of_range", "a negative salt", set={"params.salt": -1})
        no("propose_swap", "inconsistent", "a swap without its target", remove=["params.payload.to"])
        no("propose_parameter", "inconsistent", "a target without a swap", set={"params.payload.to": "trie"})
        no("propose_swap", "bad_text", "a function that does not exist", set={"params.payload.to": "merkle"})
        no("propose_swap", "bad_text", "a swap of something else", set={"params.payload.swap": "consensus"})
        no("propose_swap", "unknown_field", "a treasury field in a protocol payload",
           set={"params.payload.recipients": [{"address": {"$address": 2}, "amount": 1}]})
        no("propose_treasury", "out_of_range", "no recipient", set={"params.payload.recipients": []})
        no("propose_treasury_64", "out_of_range", "65 recipients",
           set={"params.payload.recipients.64": {"address": {"$address": 2}, "amount": 1}})
        no("propose_treasury", "out_of_range", "an amount of zero", set={"params.payload.recipients.0.amount": 0})
        no("propose_treasury_total", "out_of_range", "amounts that add up to 2^63",
           set={"params.payload.recipients.1.amount": 2})
        no("propose_treasury", "bad_address", "a recipient that is not an address",
           set={"params.payload.recipients.0.address": "treasury"})
        no("propose_treasury", "wrong_type", "a recipient whose address is a list",
           set={"params.payload.recipients.0.address": [1, 2]})
        no("propose_treasury", "bad_text", "an empty memo", set={"params.payload.memo": ""})
        no("propose_treasury_64", "bad_text", "a memo of 257 bytes", set={"params.payload.memo": {"$text": [257, "m"]}})
        no("propose_treasury", "bad_text", "a memo of 256 characters that is 257 bytes",
           set={"params.payload.memo": {"$concat": [{"$text": [255, "m"]}, "é"]}})
        no("propose_treasury", "unknown_field", "a protocol field in a treasury payload",
           set={"params.payload.swap": "state_root_function"})
        no("governance_vote", "bad_text", "a vote on a track that does not exist", set={"params.track": "council"})
        no("governance_vote", "bad_text", "a vote that does not exist", set={"params.vote": "maybe"})
        no("governance_vote", "bad_text", "an identifier of 32 characters, as today",
           set={"params.proposal_id": self.proposal[:32]})
        no("governance_vote", "bad_text", "an identifier in capital letters",
           set={"params.proposal_id": self.proposal.upper()})
        no("slash_consensus_equivocation", "bad_text", "a proposal given as evidence of a vote",
           set={"params.msg_a.kind": "propose"})
        no("slash_consensus_equivocation", "unknown_field", "a vote that carries the public key, as today",
           set={"params.msg_a.validator_pubkey": {"$key": 1}})
        no("delegate_stake", "out_of_range", "a delegation of nothing", set={"amount": 0})
        no("undelegate_stake", "unknown_field", "empty parameters, as today", set={"params": {}})
        no("attest", "out_of_range", "an attestation with a negative bond", set={"amount": -1})
        no("attest", "bad_text", "an empty schema name", set={"params.schema_id": ""})
        no("attest", "bad_text", "a schema name with a space", set={"params.schema_id": "kyc basic"})
        no("attest_largest_claim", "bad_text", "a schema name of 129 characters",
           set={"params.schema_id": {"$text": [129, "s"]}})
        no("attest", "bad_text", "a subject with a tabulation", set={"params.subject": "a\tb"})
        no("attest", "bad_text", "a subject with the character U+007F", set={"params.subject": "a\u007fb"})
        no("attest", "bad_text", "an empty subject", set={"params.subject": ""})
        no("attest", "bad_text", "a subject with a letter outside ASCII", set={"params.subject": "Liège"})
        no("attest_largest_claim", "bad_text", "a subject of 257 characters",
           set={"params.subject": {"$text": [257, "~"]}})
        no("attest", "wrong_type", "a claim that is a list", set={"params.claim": [1, 2]})
        no("attest", "wrong_type", "a claim that is a string", set={"params.claim": "level 2"})
        no("attest_largest_claim", "too_long", "a claim of 16,385 bytes",
           set={"params.claim": {"text": {"$text": [limit["claim_bytes"] - 10, "x"]}}})
        no("attest_deepest", "too_deep", "a claim that takes the transaction to 33 levels",
           set={"params.claim": {"a": [deep]}})
        for bottom, what in (([], "array"), ({}, "object")):
            empty: Any = bottom
            for _ in range(limit["transaction_nesting"] - 3):
                empty = [empty]
            no("attest_deepest", "too_deep", f"33 levels whose last one is an empty {what}: it is a level all the same",
               set={"params.claim": {"a": empty}})
        no("rotate_key", "missing_field", "a change of key without the second signature", remove=["second_signature"])
        no("rotate_key", "bad_key", "a new key of another scheme",
           set={"params.new_public_key": {"$concat": ["kpk2.", {"$text": [2646, "A"]}]}})
        no("rotate_key", "bad_signature", "a second signature of another scheme",
           set={"second_signature": {"$concat": ["ksig2.", {"$text": [4498, "A"]}]}})
        no("transaction_largest", "too_long", "a transaction of 131,073 bytes",
           set={"code": {"$text": [largest["code"]["$text"][0] + 1, "x"]}})

    def messages_and_certificates(self) -> None:
        yes, no, limit = self.yes, self.no, LIMITS
        value = yes("header", "header", "a header: the nine fields of the profile vectors, and the signature",
                    {**self.frozen["kern.block"]["object"], "signature": {"$sig": 40}}, mutate=True)
        self.level7 = level7 = sch.block_hash(self.network_id, value).hex()
        assert level7 == self.frozen["kern.block"]["digest"]
        yes("header_lowest", "header", "every number at the bottom of its range",
            {**self.frozen["kern.block"]["object"], "level": 0, "payload_round": 0, "timestamp": 0,
             "signature": {"$sig": 40}})
        yes("header_highest", "header", "every number at the top of its range",
            {**self.frozen["kern.block"]["object"], "level": INT_MAX, "payload_round": ROUND_MAX, "timestamp": INT_MAX,
             "signature": {"$sig": 40}})
        no("header", "out_of_range", "another structure version", set={"version": 2})
        no("header", "out_of_range", "a structure version of 0", set={"version": 0})
        no("header", "out_of_range", "a payload round of 2^32", set={"payload_round": ROUND_MAX + 1})
        for name in ("level", "payload_round", "timestamp"):
            no("header", "out_of_range", f"a header whose {name} is negative", set={name: -1})
        no("header", "bad_text", "a hash in capital letters", set={"parent_hash": value["parent_hash"].upper()})
        no("header", "bad_text", "a hash of 64 characters, as today", set={"state_root": value["state_root"][:64]})
        no("header", "bad_text", "a hash of 97 characters", set={"txs_root": value["txs_root"] + "0"})
        no("header", "bad_text", "a hash with a letter after f", set={"witness_root": "g" + value["witness_root"][1:]})
        no("header", "unknown_field", "the public key of the proposer, as today", set={"proposer_pubkey": {"$key": 1}})

        yes("preendorse", "vote", "a pre-endorsement of that block", self.message("preendorse", 7, 0, level7, 20),
            mutate=True)
        yes("endorse", "vote", "an endorsement of that block, at round 3", self.message("endorse", 7, 3, level7, 21),
            mutate=True)
        yes("propose", "propose message", "the proposal of a new payload: no valid round",
            self.message("propose", 7, 0, level7, 22), mutate=True)
        yes("propose_again", "propose message", "a payload proposed again at round 2, valid since round 1",
            self.message("propose", 7, 2, level7, 23, valid_round=1), mutate=True)
        yes("propose_highest_round", "propose message", "the highest round, valid since the round before",
            self.message("propose", 7, ROUND_MAX, level7, 24, valid_round=ROUND_MAX - 1))
        no("preendorse", "out_of_range", "a round of 2^32", set={"round": ROUND_MAX + 1})
        for name in ("level", "round"):
            no("preendorse", "out_of_range", f"a vote whose {name} is negative", set={name: -1})
        no("propose_highest_round", "out_of_range", "a proposal at round 2^32", set={"round": ROUND_MAX + 1})
        no("preendorse", "bad_text", "a proposal where a vote is expected", set={"kind": "propose"})
        no("preendorse", "unknown_field", "a vote with a valid round", set={"valid_round": 0})
        no("preendorse", "bad_text", "a hash one character short", set={"block_hash": level7[:-1]})
        no("preendorse", "bad_address", "a validator that is not an address", set={"validator": "validator-1"})
        no("propose", "bad_text", "a vote where a proposal is expected", set={"kind": "endorse"})
        no("propose_again", "inconsistent", "a valid round that is the round", set={"valid_round": 2})
        no("propose_again", "inconsistent", "a valid round after the round", set={"valid_round": 3})
        no("propose", "out_of_range", "a valid round of -1, which is how a new payload is said today",
           set={"valid_round": -1})

        yes("certificate", "certificate", "a certificate of three endorsements",
            self.certificate("endorse", 7, 0, level7), mutate=True, maps=("signatures",))
        yes("certificate_1024", "certificate", "a certificate of 1,024 pre-endorsements",
            self.certificate("preendorse", 7, 1, level7, limit["certificate_signatures"]))
        yes("certificate_one", "certificate", "a certificate of one signature, at the highest level and round: "
            "whether one validator holds the quorum is not a matter of form",
            self.certificate("endorse", INT_MAX, ROUND_MAX, level7, 1))
        no("certificate", "bad_text", "a certificate of proposals", set={"kind": "propose"})
        for name in ("level", "round"):
            no("certificate", "out_of_range", f"a certificate whose {name} is negative", set={name: -1})
        no("certificate", "out_of_range", "a certificate at round 2^32", set={"round": ROUND_MAX + 1})
        no("certificate", "out_of_range", "a certificate without a signature", set={"signatures": {}})
        one_more = self.certificate("preendorse", 7, 1, level7, limit["certificate_signatures"] + 1)
        no("certificate_1024", "out_of_range", "a certificate of 1,025 signatures",
           set={"signatures": one_more["signatures"]})
        no("certificate", "bad_address", "a signature under a name that is not an address",
           set={"signatures": {"validator-1": {"$sig": 30}}})
        no("certificate", "bad_signature", "an address with something that is not a signature",
           set={"signatures": {"$map": [1, {"$address": 30}, "signed"]}})
        no("certificate", "wrong_type", "signatures given as a list of texts, as today",
           set={"signatures": [{"$concat": [{"$address": 30}, ":", {"$sig": 30}]}]})

    def blocks(self) -> None:
        yes, no, tx, level7 = self.yes, self.no, self.tx, self.level7
        yes("block_empty", "block", "a block without a transaction: both roots are the root of an empty tree",
            self.block(8, 0, level7, [], 41), mutate=True)
        call = tx("call", nonce=2, sig=3, recipient={"$address": 2}, amount=0, entry="increment", params={})
        rotate = tx("rotate_key", nonce=3, sig=4, params={"new_public_key": {"$key": 2}}, second_signature={"$sig": 2})
        three = [{"$ref": "transfer_first"}, call, rotate]
        yes("block", "block", "a block of three transactions, whose witness leaves have the flags 1, 0 and 2",
            self.block(8, 0, level7, three, 42), mutate=True, free=("transactions.1.params",))
        yes("block_round_2", "block", "the same transactions in a block first proposed at round 2",
            self.block(8, 2, level7, three, 42))
        yes("block_9", "block", "an empty block on top of the block of three transactions",
            self.block(9, 0, self.hash_of("block"), [], 44))
        sixty_four = {"$list": [64, self.largest({"$index": 100}, {"$index": 100})]}
        yes("block_largest", "block", "a block whose 64 transactions add up to 8,388,608 bytes",
            self.block(8, 0, level7, sixty_four, 43))
        yes("block_largest_9", "block", "another one on top of it",
            self.block(9, 0, self.hash_of("block_largest"), sixty_four, 45))

        no("block", "inconsistent", "another root of the identifiers", set={"header.txs_root": "00" * 48})
        no("block", "inconsistent", "another root of the witness leaves", set={"header.witness_root": "00" * 48})
        no("block", "inconsistent", "the signature of a transaction replaced by another one",
           set={"transactions.1.signature": {"$sig": 99}})
        no("block", "inconsistent", "the public key of a transaction removed", remove=["transactions.0.public_key"])
        no("block", "inconsistent", "the last transaction repeated", set={"transactions.3": rotate})
        no("block", "inconsistent", "two transactions in the other order",
           set={"transactions.0": call, "transactions.1": {"$ref": "transfer_first"}})
        no("block_empty", "inconsistent", "a transaction added to a block that commits to none",
           set={"transactions.0": call})
        sixty_five = self.objects["block_largest"]["transactions"] + [self.objects["undelegate_stake"]]
        total = sum(sch.transaction_size(t) for t in sixty_five)
        no("block_largest", "too_long", f"one more transaction, with both roots as they should be: the 65 add up to "
           f"{total:,} bytes", set={"transactions.64": {"$ref": "undelegate_stake"}, **{
               f"header.{name}": root for name, root in self.roots(sixty_five).items()}})

        final = {"block": {"$ref": "block"}, "certificate": self.certificate("endorse", 8, 0, self.hash_of("block"))}
        yes("final_block", "final block", "the block of three transactions with the certificate that makes it final",
            final, mutate=True, maps=("certificate.signatures",), free=("block.transactions.1.params",))
        yes("final_block_later_round", "final block", "the same block made final at a later round",
            {"block": {"$ref": "block"}, "certificate": self.certificate("endorse", 8, 5, self.hash_of("block"))})
        yes("final_block_round_2", "final block", "the block first proposed at round 2, made final at that round",
            {"block": {"$ref": "block_round_2"},
             "certificate": self.certificate("endorse", 8, 2, self.hash_of("block_round_2"))})
        yes("final_block_9", "final block", "the block of level 9 with its certificate",
            {"block": {"$ref": "block_9"}, "certificate": self.certificate("endorse", 9, 0, self.hash_of("block_9"))})
        no("final_block", "inconsistent", "a certificate of pre-endorsements", set={"certificate.kind": "preendorse"})
        no("final_block", "inconsistent", "a certificate for another level", set={"certificate.level": 9})
        no("final_block", "inconsistent", "a certificate for another block", set={"certificate.block_hash": level7})
        no("final_block_round_2", "inconsistent", "a certificate of a round before the payload round",
           set={"certificate.round": 1})

    def frames(self) -> None:
        yes, no, limit, level7 = self.yes, self.no, LIMITS, self.level7
        level8, network = self.hash_of("block"), self.network_id.hex()
        yes("frame_hello", "frame", "what a node says first: its network and the level of its head",
            {"kind": "hello", "network_id": network, "level": 7}, mutate=True)
        yes("frame_hello_genesis", "frame", "the same from a node that holds the genesis alone",
            {"kind": "hello", "network_id": network, "level": 0})
        yes("frame_hello_highest", "frame", "the same at the highest level",
            {"kind": "hello", "network_id": network, "level": INT_MAX})
        yes("frame_proposal", "frame", "a new payload proposed at round 0",
            {"kind": "proposal", "block": {"$ref": "block"}, "proposal": self.message("propose", 8, 0, level8, 50)},
            mutate=True, free=("block.transactions.1.params",))
        proof = self.certificate("preendorse", 8, 1, level8)
        yes("frame_proposal_again", "frame", "the same payload proposed again at round 3, with the certificate of "
            "pre-endorsements of round 1",
            {"kind": "proposal", "block": {"$ref": "block"},
             "proposal": self.message("propose", 8, 3, level8, 51, valid_round=1), "proof": proof},
            mutate=True, maps=("proof.signatures",), free=("block.transactions.1.params",))
        round_2 = self.hash_of("block_round_2")
        yes("frame_proposal_again_round_2", "frame", "a payload first proposed at round 2, proposed again at round 4 "
            "with the certificate of round 3",
            {"kind": "proposal", "block": {"$ref": "block_round_2"},
             "proposal": self.message("propose", 8, 4, round_2, 54, valid_round=3),
             "proof": self.certificate("preendorse", 8, 3, round_2)})
        yes("frame_consensus", "frame", "a vote",
            {"kind": "consensus", "msg": self.message("endorse", 8, 0, level8, 52)}, mutate=True)
        yes("frame_block", "frame", "a final block",
            {"kind": "block", "block": {"$ref": "block"}, "certificate": self.certificate("endorse", 8, 0, level8)},
            mutate=True, maps=("certificate.signatures",), free=("block.transactions.1.params",))
        yes("frame_transaction", "frame", "a transaction", {"kind": "transaction", "tx": {"$ref": "transfer"}},
            mutate=True)
        yes("frame_get_blocks", "frame", "a request for the blocks of levels 8 to 519",
            {"kind": "get_blocks", "from": 8, "to": 519}, mutate=True)
        yes("frame_get_one_block", "frame", "a request for the first block after the genesis",
            {"kind": "get_blocks", "from": 1, "to": 1})
        yes("frame_get_last_block", "frame", "a request for the block of the highest level",
            {"kind": "get_blocks", "from": INT_MAX, "to": INT_MAX})
        yes("frame_blocks", "frame", "two final blocks, of levels 8 and 9",
            {"kind": "blocks", "blocks": [{"$ref": "final_block"}, {"$ref": "final_block_9"}]}, mutate=True,
            maps=("blocks.0.certificate.signatures", "blocks.1.certificate.signatures"),
            free=("blocks.0.block.transactions.1.params",))
        yes("frame_blocks_none", "frame", "the answer of a node that has none of the blocks asked for",
            {"kind": "blocks", "blocks": []})
        largest = self.hash_of("block_largest")
        yes("frame_proposal_largest", "frame", "the largest block proposed again with a proof of 1,024 signatures: "
            "the heaviest frame that carries one block",
            {"kind": "proposal", "block": {"$ref": "block_largest"},
             "proposal": self.message("propose", 8, 1, largest, 53, valid_round=0),
             "proof": self.certificate("preendorse", 8, 0, largest, limit["certificate_signatures"])})

        no("frame_hello", "bad_text", "a kind of frame that does not exist", set={"kind": "ping"})
        no("frame_hello", "bad_text", "a network identifier of 63 characters", set={"network_id": network[:-1]})
        no("frame_hello", "bad_text", "a network identifier of 65 characters", set={"network_id": network + "0"})
        no("frame_hello", "bad_text", "a network identifier in capital letters", set={"network_id": network.upper()})
        no("frame_hello", "unknown_field", "a member of another frame", set={"from": 1})
        no("frame_hello", "out_of_range", "a negative level", set={"level": -1})
        no("frame_proposal", "bad_text", "a vote sent as a proposal", set={"proposal.kind": "endorse"})
        no("frame_proposal", "inconsistent", "a proposal for another level", set={"proposal.level": 9})
        no("frame_proposal", "inconsistent", "a proposal for another block", set={"proposal.block_hash": level7})
        no("frame_proposal", "inconsistent", "a new payload proposed at a round that is not its payload round",
           set={"proposal.round": 1})
        no("frame_proposal", "inconsistent", "a proof without a valid round", set={"proof": proof})
        no("frame_proposal_again", "inconsistent", "a valid round without its proof", remove=["proof"])
        no("frame_proposal_again", "inconsistent", "a proof of another round", set={"proof.round": 2})
        no("frame_proposal_again", "inconsistent", "a proof made of endorsements", set={"proof.kind": "endorse"})
        no("frame_proposal_again", "inconsistent", "a proof for another block", set={"proof.block_hash": level7})
        no("frame_proposal_again", "inconsistent", "a proof for another level", set={"proof.level": 7})
        no("frame_proposal_again_round_2", "inconsistent", "a valid round before the payload round, with its proof",
           set={"proposal.valid_round": 1, "proof.round": 1})
        no("frame_proposal_again_round_2", "inconsistent", "a valid round without its proof, at the payload round",
           remove=["proof"], set={"proposal.round": 2, "proposal.valid_round": 1})
        no("frame_proposal", "unknown_field", "the body of a block of today", set={"block.commits": []})
        no("frame_consensus", "bad_text", "a proposal sent as a vote", set={"msg.kind": "propose"})
        no("frame_block", "missing_field", "a block sent without its certificate", remove=["certificate"])
        no("frame_block", "inconsistent", "a block sent with a certificate of pre-endorsements",
           set={"certificate.kind": "preendorse"})
        no("frame_get_blocks", "out_of_range", "a request that starts at the genesis", set={"from": 0})
        no("frame_get_blocks", "inconsistent", "a request whose end is before its start", set={"to": 7})
        no("frame_get_one_block", "out_of_range", "a request that ends at the genesis", set={"to": 0})
        no("frame_blocks", "inconsistent", "twice the same block", set={"blocks.1": {"$ref": "final_block"}})
        no("frame_blocks", "inconsistent", "two blocks in the other order",
           set={"blocks.0": {"$ref": "final_block_9"}, "blocks.1": {"$ref": "final_block"}})
        level10 = {**self.objects["block_9"]["header"], "level": 10}
        no("frame_blocks", "inconsistent", "blocks of levels 8 and 10, each with its certificate",
           set={"blocks.1.block.header.level": 10, "blocks.1.certificate.level": 10,
                "blocks.1.certificate.block_hash": sch.block_hash(self.network_id, level10).hex()})
        self.frame_bound(largest)
        self.no_object("frame", "too_long", "the two largest blocks in one frame", {"kind": "blocks", "blocks": [
            {"block": {"$ref": "block_largest"}, "certificate": self.certificate("endorse", 8, 0, largest)},
            {"block": {"$ref": "block_largest_9"},
             "certificate": self.certificate("endorse", 9, 0, self.hash_of("block_largest_9"))}]})

    def frame_bound(self, largest: str) -> None:
        """The bound of a frame, to the byte: three final blocks, the last
        one with a single transaction, as long as it takes."""
        limit = LIMITS["frame_bytes"]
        second = self.block(9, 0, largest, {"$list": [63, self.largest({"$index": 200}, {"$index": 200})]}, 46)
        parent = sch.block_hash(self.network_id, self.expand(second["header"])).hex()

        def frame(size: int) -> dict:
            third = self.block(10, 0, parent, [self.origination(size, 300, 300)], 47)
            return {"kind": "blocks", "blocks": [
                {"block": {"$ref": "block_largest"}, "certificate": self.certificate("endorse", 8, 0, largest)},
                {"block": second, "certificate": self.certificate("endorse", 9, 0, parent)},
                {"block": third, "certificate": self.certificate(
                    "endorse", 10, 9, sch.block_hash(self.network_id, self.expand(third["header"])).hex())}]}

        size = 65536 + limit - len(ref.canonical_json(self.expand(frame(65536))))
        self.yes("frame_blocks_largest", "frame", f"three final blocks in a frame of {limit:,} bytes: the largest "
                 "block, a block of 63 transactions, and a block whose only transaction is as long as it takes",
                 frame(size))
        self.no("frame_blocks_largest", "too_long",
                f"the same frame with one more digit in a round: {limit + 1:,} bytes",
                set={"blocks.2.certificate.round": 10})

    def texts(self) -> None:
        network, depth = self.network_id.hex(), LIMITS["json_nesting"]
        hello = '{"kind":"hello","level":7,"network_id":"' + network + '"}'
        self.text("frame", "accepted", "the canonical encoding of the frame hello", hello)
        self.text("json", "accepted", "64 arrays, one inside the other, around a number: the number is not a level",
                  {"$concat": [{"$text": [depth, "["]}, "0", {"$text": [depth, "]"]}]})
        self.text("json", "too_deep", "65 arrays, one inside the other",
                  {"$concat": [{"$text": [depth + 1, "["]}, {"$text": [depth + 1, "]"]}]})
        self.text("json", "accepted", "64 objects, one inside the other",
                  {"$concat": [{"$text": [depth - 1, '{"a":']}, "{}", {"$text": [depth - 1, "}"]}]})
        self.text("json", "too_deep", "65 objects, one inside the other",
                  {"$concat": [{"$text": [depth, '{"a":']}, "{}", {"$text": [depth, "}"]}]})
        self.text("json", "accepted", "100 arrays side by side in one array: a level that is closed no longer counts",
                  {"$concat": ["[", {"$text": [99, "[],"]}, "[]]"]})
        self.text("json", "accepted", "100 objects side by side in one array: the same with braces",
                  {"$concat": ["[", {"$text": [99, "{},"]}, "{}]"]})
        self.text("json", "accepted", "brackets inside a string open nothing",
                  {"$concat": ['["', {"$text": [100, "[{"]}, '"]']})
        self.text("json", "accepted", "a quotation mark after a reverse solidus does not close a string",
                  {"$concat": ['["\\"', {"$text": [100, "["]}, '"]']})
        self.text("json", "too_deep", "a reverse solidus written twice is one character: the quotation mark that "
                  "follows closes the string, and 65 arrays are open",
                  {"$concat": ['["\\\\",', {"$text": [depth, "["]}, {"$text": [depth, "]"]}, "]"]})
        self.text("frame", "not_canonical", "a space after a colon", hello.replace('"level":7', '"level": 7'))
        self.text("frame", "not_canonical", "members in another order",
                  '{"level":7,"kind":"hello","network_id":"' + network + '"}')
        self.text("frame", "not_canonical", "a level written with a fraction",
                  hello.replace('"level":7', '"level":7.0'))
        self.text("frame", "not_canonical", "a level beyond 64 bits",
                  hello.replace('"level":7', '"level":9223372036854775808'))
        self.text("frame", "not_canonical", "a member written twice", hello.replace('"level":7', '"level":7,"level":7'))
        self.text("frame", "not_canonical", "a line feed after the frame", hello + "\n")
        self.text("frame", "wrong_type", "a frame that is a list", "[" + hello + "]")
        signed = sch.signed_transaction(self.objects["transfer"]).decode("utf-8")
        self.text("transaction", "accepted",
                  "the body of an injection request: a transaction in its canonical encoding",
                  {"$concat": [signed[:-1], ',"signature":"', {"$sig": 1}, '"}']})
        self.text("transaction", "not_canonical", "the same transfer with a field at null, as a transaction has today",
                  {"$concat": [signed[:-1].replace('"amount":25,', '"amount":25,"code":null,'), ',"signature":"',
                               {"$sig": 1}, '"}']})
        # The length is read first, on the bytes, whatever they are.
        for schema, name in (("transaction", "transaction_bytes"), ("frame", "frame_bytes")):
            what = "the body of a request" if schema == "transaction" else "a frame"
            self.text(schema, "not_canonical",
                      f"{what} of {LIMITS[name]:,} spaces: not too long, and not canonical JSON",
                      {"$text": [LIMITS[name], " "]})
            self.text(schema, "too_long", f"{what} of {LIMITS[name] + 1:,} spaces: too long, whatever it holds",
                      {"$text": [LIMITS[name] + 1, " "]})


    def four_bytes(self) -> None:
        """The four bytes that precede a frame: what they announce, and
        where a node stops reading."""
        limit = LIMITS["frame_bytes"]
        for prefix, why in (
            ("0000006a", "the frame hello of the texts: 106 bytes follow"),
            ("00000100", "256 bytes follow: the most significant byte comes first, or this would read 65,536"),
            ("00000000", "nothing follows; the empty text is then refused, since it is not canonical JSON"),
            ("01000000", f"{limit:,} bytes follow: the largest frame, which travels as {limit + 4:,} bytes"),
            ("01000001", f"{limit + 1:,} bytes would follow: one more than a frame holds"),
            ("7fffffff", "2,147,483,647 bytes would follow"),
            ("80000000", "2,147,483,648 bytes would follow: the four bytes are a number without a sign"),
            ("ffffffff", "4,294,967,295 bytes would follow, the most four bytes can announce"),
        ):
            try:
                self.prefixes.append({"prefix": prefix, "announces": sch.announced(bytes.fromhex(prefix)), "why": why})
            except sch.Refused as refusal:
                self.prefixes.append({"prefix": prefix, "rule": refusal.rule, "why": why})
        assert [p.get("rule", "") for p in self.prefixes] == ["", "", "", "", "too_long", "too_long", "too_long",
                                                              "too_long"]
        self.text("frame", "not_canonical", "an empty frame: four bytes that announce nothing, and nothing", "")

    def requests_and_answers(self) -> None:
        """What a node answers to a `get_blocks`, and what the node that
        asked accepts as an answer."""
        limit, top = LIMITS["frame_bytes"], sch.INT_MAX
        third = limit - sch.BLOCKS_FRAME_BYTES - 2 - 2 * 6_000_000        # what is left for a third block, to the byte

        def answer(why: str, held: list[list[int]], first: int, last: int, levels: list[int]) -> None:
            assert sch.answer(dict(map(tuple, held)), first, last) == levels, why
            assert sch.answer_verdict(first, last, levels) == "accepted", why
            self.answers.append({"held": held, "from": first, "to": last, "levels": levels, "why": why})

        def run(first: int, last: int, size: int = 5_000) -> list[list[int]]:
            return [[level, size] for level in range(first, last + 1)]

        answer("every block asked for", run(1, 5), 2, 4, [2, 3, 4])
        answer("one block asked for", run(1, 9), 7, 7, [7])
        answer("the node holds fewer blocks than were asked for", run(1, 3), 2, 9, [2, 3])
        answer("a level is missing: the answer stops before it, and the blocks after it are not sent",
               run(1, 3) + run(5, 6), 2, 6, [2, 3])
        answer("the first level asked for is missing: an empty answer, although the node holds the next ones",
               run(3, 4), 2, 4, [])
        answer("the node holds nothing", [], 1, 3, [])
        answer("the node holds nothing that high", run(1, 3), 5, 9, [])
        answer(f"three blocks that fill a frame of {limit:,} bytes, to the byte, and a fourth that is held",
               [[10, 6_000_000], [11, 6_000_000], [12, third], [13, 5_000]], 10, 13, [10, 11, 12])
        answer("the same with one byte more in the third block: two blocks",
               [[10, 6_000_000], [11, 6_000_000], [12, third + 1], [13, 5_000]], 10, 13, [10, 11])
        answer("a small block after one that does not fit is not sent in its place",
               [[10, 13_000_000], [11, 5_000_000], [12, 5_000]], 10, 12, [10])
        answer("the two highest levels there are", [[top - 1, 5_000], [top, 5_000]], top - 1, top, [top - 1, top])

        def reply(why: str, first: int, last: int, levels: list[int], rule: str = "accepted") -> None:
            assert sch.answer_verdict(first, last, levels) == rule, why
            record: dict[str, Any] = {"from": first, "to": last, "levels": levels}
            self.replies.append({**record, "why": why} if rule == "accepted" else {**record, "rule": rule, "why": why})

        reply("the levels asked for", 2, 4, [2, 3, 4])
        reply("fewer than were asked for, from the first one", 2, 9, [2, 3])
        reply("no block", 2, 4, [])
        reply("the one level asked for", 7, 7, [7])
        reply("the two highest levels there are", top - 1, top, [top - 1, top])
        reply("the first level asked for was left out", 2, 4, [3, 4], "inconsistent")
        reply("a block below the first level asked for", 2, 4, [1, 2], "inconsistent")
        reply("a block above the last level asked for", 2, 4, [2, 3, 4, 5], "inconsistent")
        reply("one level was asked for, and two come", 7, 7, [7, 8], "inconsistent")
        reply("a level is left out in the middle", 2, 6, [2, 3, 5], "inconsistent")
        reply("the levels asked for, the highest first", 2, 4, [4, 3, 2], "inconsistent")
        reply("a level twice", 2, 4, [2, 2, 3], "inconsistent")
        reply("the level asked for, then the lowest level there is", top, top, [top, 0], "inconsistent")


def build() -> dict:
    return Builder().build()


def render(vectors: dict) -> str:
    """The text of schemas.json: one vector on each line, in ASCII."""
    lines = ["{"]
    for n, (name, value) in enumerate(vectors.items()):
        comma = "," if n < len(vectors) - 1 else ""
        if isinstance(value, (list, dict)) and value:
            items = [json.dumps(item) for item in value] if isinstance(value, list) else \
                [f"{json.dumps(member)}: {json.dumps(item)}" for member, item in value.items()]
            lines.append(f" {json.dumps(name)}: " + ("[" if isinstance(value, list) else "{"))
            lines += [f"  {item}{',' if m < len(items) - 1 else ''}" for m, item in enumerate(items)]
            lines.append(" " + ("]" if isinstance(value, list) else "}") + comma)
        else:
            lines.append(f" {json.dumps(name)}: {json.dumps(value)}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    FILE.write_text(render(build()), encoding="utf-8", newline="\n")
    print(f"wrote {FILE}")
