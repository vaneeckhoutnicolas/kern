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
    "$text": "[count, piece]: the piece written count times",
    "$concat": "[parts]: the parts one after the other, an integer in decimal",
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
        if name == "$text":
            count, piece = argument
            return piece * count
        if name == "$concat":
            return "".join(str(self.expand(part, index)) for part in argument)
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
    return out


DESCRIPTION = (
    "Vectors of the schemas of structure version 1 (docs/api-stability.md, section 9), chapter 1: what is signed and "
    "what travels. Built by tests/schema_vectors.py with tests/schema_reference.py; "
    "tests/vectors/kern/profile_check.go checks them with tables of its own (-schemas). "
    "`accepted` holds objects that are of their schema on the network `network_id`. `refused` holds objects that are "
    "not: an accepted object (`from`) with members removed (`remove`), then values put in place (`set`), or an "
    "object of its own; `rule` names the rule that refuses it, by a key of `rules`. A path is names of members and "
    "positions in lists joined by full stops, and a value put one position past the end of a list is added to it. "
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
    "`prefix` is the four bytes that precede the text in a frame."
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

    # -- recording --------------------------------------------------------

    def yes(self, name: str, schema: str, what: str, obj: Any, *, mutate: bool = False,
            maps: tuple[str, ...] = (), free: tuple[str, ...] = ()) -> Any:
        value = self.expand(obj)
        sch.check(schema, value, self.network_id)
        record = {"name": name, "schema": schema, "what": what, "object": obj, **pin(ref.canonical_json(value)),
                  **derived(name, schema, value, self.network_id)}
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
           set: dict[str, Any] | None = None) -> None:
        changed = self.edited(self.objects[base], remove, set)
        answer = sch.verdict(self.schemas[base], changed, self.network_id)
        assert answer == rule, f"{base}, {why}: {answer}, not {rule}"
        record: dict[str, Any] = {"from": base}
        if remove:
            record["remove"] = remove
        if set:
            record["set"] = set
        self.refused.append({**record, "rule": rule, "why": why, **pin(ref.canonical_json(changed))})

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

    # -- the vectors ------------------------------------------------------

    def build(self) -> dict:
        self.transactions()
        self.messages_and_certificates()
        self.blocks()
        self.frames()
        self.texts()
        return {"description": DESCRIPTION, "network_id": self.network_id.hex(), "limits": LIMITS,
                "rules": sch.RULES, "directives": DIRECTIVES, "accepted": self.accepted, "refused": self.refused,
                "accepted_texts": self.accepted_texts, "refused_texts": self.refused_texts}

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
