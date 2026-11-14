# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The schemas of structure version 1, written with the standard library.

Not a test file and not the node. docs/api-stability.md, section 9, gives
every object of structure version 1 its fields, their types and their
bounds. This file is that section as executable text: the tables of the
document are compared with the tables below, and tests/schema_vectors.py
builds tests/vectors/kern/schemas.json with it, which the Go program kept
next to that file checks with tables of its own, written independently.

Chapters 1 and 2 of three. Chapter 1: what is signed and what travels.
Transactions, block headers, blocks, consensus messages, certificates, the
frames peers exchange and the body of an injection request. Chapter 2:
what is kept. The state and the rules that tie its tables together, the
account of the state trie, the key registry, the genesis and the block of
level 0, and three rules that are not forms: what a block charges, in what
order proposals are decided, and how a request for blocks finds its
answer. The objects hashed outside blocks are chapter 3.

Nothing here is used by the node, which still writes the formats of
sections 2.1 to 2.7 of that document. The byte rules all schemas share
(canonical JSON, the hash function, Merkle trees, text forms, addresses)
are those of tests/profile_reference.py, the reference of the frozen
signature profile, which this file imports and does not change.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))      # the reference of the profile stands next to this file

import profile_reference as ref                               # noqa: E402

# ---------------------------------------------------------------------------
# The limits of structure version 1
# ---------------------------------------------------------------------------

LIMITS = {
    "json_nesting": 64,                 # arrays and objects in any JSON text received, measured before decoding
    "transaction_nesting": 32,          # arrays and objects in a transaction, itself included
    "frame_bytes": 16_777_216,          # the canonical JSON of a frame, without the four bytes that announce it
    "transaction_bytes": 131_072,       # the size of a transaction: its canonical encoding, witness included
    "block_bytes": 8_388_608,           # the sizes of the transactions of a block, added up
    "certificate_signatures": 1_024,    # the signatures of a certificate
    "code_bytes": 65_536,               # the source of a contract
    "value_bytes": 4_096,               # a text held by a contract
    "contract_fields": 256,             # the entries of `initial_storage`, or of the `params` of a call
    "claim_bytes": 16_384,              # the canonical encoding of a claim
    "recipients": 64,                   # the recipients of a treasury proposal
    "validators": 1_024,                # the validators of a network
    "guardians": 8,                     # the guardians of its treasury
}

INT_MAX = 2**63 - 1
INT_MIN = -(2**63)
ROUND_MAX = 2**32 - 1

RULES = {
    "not_canonical": "the bytes are not the canonical JSON of a value",
    "too_deep": "arrays and objects are nested beyond the bound",
    "too_long": "the encoding of a frame, a transaction, the transactions of a block or a claim is beyond its bound",
    "wrong_type": "the value is not of the JSON type its schema gives",
    "unknown_field": "the object has a member that its schema does not have",
    "missing_field": "the object lacks a member that its schema requires",
    "out_of_range": "an integer is outside its range, or a list or a map has too few or too many entries",
    "bad_text": "a string is not one of the values allowed, or has a wrong length or a character outside its alphabet",
    "bad_address": "a string is not an address of this network",
    "bad_key": "a string is not the text form of a public key of scheme 1",
    "bad_signature": "a string is not the text form of a signature of scheme 1",
    "inconsistent": "a rule that ties several fields together is broken",
}


class Refused(ValueError):
    """What a validator answers to a value that is not what its schema
    says: the code of the rule that is broken (a key of RULES), and where."""

    def __init__(self, rule: str, where: str, detail: str = ""):
        assert rule in RULES, rule
        super().__init__(f"{rule} at {where or 'the value itself'}: {detail or RULES[rule]}")
        self.rule, self.where = rule, where


def refuse(rule: str, where: str, detail: str = "") -> None:
    raise Refused(rule, where, detail)


@dataclass(frozen=True)
class Context:
    """What a validator knows besides the value: the network, whose
    identifier is in the checksum of every address."""

    network_id: bytes


def number(n: int) -> str:
    """An integer as the document writes it."""
    for power in (63, 32):
        if n == 2**power - 1:
            return f"2^{power} - 1"
        if n == -(2**power):
            return f"-2^{power}"
    return f"{n:,}"


def _join(path: str, member: object) -> str:
    return f"{path}.{member}" if path else str(member)


# ---------------------------------------------------------------------------
# Types. Each one checks a value and says, in the words of the document,
# what it accepts.
# ---------------------------------------------------------------------------

class Type:
    json = ""                                   # the JSON type, as the table of types names it

    def check(self, value: Any, cx: Context, where: str) -> None:
        raise NotImplementedError

    def words(self) -> str:
        """The values, as the table of types says them."""
        raise NotImplementedError

    def cell(self) -> str:
        """How a table of fields names this type."""
        return self.words()

    def depth(self) -> int:
        """How deep arrays and objects can nest in a value of this type."""
        return 0


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        refuse("wrong_type", where, "a string")
    return value


@dataclass(frozen=True)
class Int(Type):
    low: int
    high: int
    unit: str = ""
    json = "integer"

    def check(self, value, cx, where):
        if isinstance(value, bool) or not isinstance(value, int):
            refuse("wrong_type", where, "an integer")
        if not self.low <= value <= self.high:
            refuse("out_of_range", where, f"{number(self.low)} to {number(self.high)}")

    def words(self):
        if self.low == self.high:
            return number(self.low)
        return f"{number(self.low)} to {number(self.high)}" + (f", {self.unit}" if self.unit else "")

    def cell(self):
        return self.words() if self.low == self.high else f"integer, {self.words()}"


@dataclass(frozen=True)
class Bool(Type):
    json = "boolean"

    def check(self, value, cx, where):
        if not isinstance(value, bool):
            refuse("wrong_type", where, "true or false")

    def words(self):
        return "`true` or `false`"


@dataclass(frozen=True)
class Choice(Type):
    """One of a few fixed strings."""

    values: tuple[str, ...]
    json = "string"

    def check(self, value, cx, where):
        if _string(value, where) not in self.values:
            refuse("bad_text", where, f"one of {', '.join(self.values)}")

    def words(self):
        quoted = [f'`"{v}"`' for v in self.values]
        return quoted[0] if len(quoted) == 1 else ", ".join(quoted[:-1]) + " or " + quoted[-1]


@dataclass(frozen=True)
class Text(Type):
    """A string over an alphabet, with a length in characters."""

    low: int
    high: int
    pattern: str                                # a regular expression the whole string matches
    alphabet: str                               # the same thing, in words
    json = "string"

    def check(self, value, cx, where):
        if not low_high(len(_string(value, where)), self.low, self.high) or not re.fullmatch(self.pattern, value):
            refuse("bad_text", where, self.words())

    def words(self):
        length = f"{number(self.low)} characters" if self.low == self.high else \
            f"{number(self.low)} to {number(self.high)} characters"
        return f"{length}: {self.alphabet}"


@dataclass(frozen=True)
class FreeText(Type):
    """Any string, with a length in bytes of UTF-8."""

    low: int
    high: int
    json = "string"

    def check(self, value, cx, where):
        text = _string(value, where)
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            refuse("bad_text", where, "a string that is not valid Unicode")
        if not low_high(size, self.low, self.high):
            refuse("bad_text", where, self.words())

    def words(self):
        return f"any text of {number(self.low)} to {number(self.high)} bytes in UTF-8"


def low_high(n: int, low: int, high: int) -> bool:
    return low <= n <= high


_B58_VALUES = {c: i for i, c in enumerate(ref._B58)}


def address_hash(network_id: bytes, text: str) -> bytes:
    """The 48 bytes inside an address of this network, or ValueError: 75
    characters of base 58 that are the one spelling of the prefix, a hash
    and the checksum of both on this network (note, section 5)."""
    if not isinstance(text, str) or len(text) != 75 or any(c not in _B58_VALUES for c in text):
        raise ValueError("an address is 75 characters of base 58")
    n = 0
    for c in text:
        n = n * 58 + _B58_VALUES[c]
    if n >= 256**55:
        raise ValueError("an address is 55 bytes")
    raw = n.to_bytes(55, "big")
    if raw[:3] != ref.ADDRESS_PREFIX:
        raise ValueError("not the prefix of an address")
    if ref.address_from_hash(network_id, raw[3:51]) != text:
        raise ValueError("not the checksum of this network")
    return raw[3:51]


@dataclass(frozen=True)
class Address(Type):
    json = "string"

    def check(self, value, cx, where):
        text = _string(value, where)
        try:
            address_hash(cx.network_id, text)
        except ValueError as exc:
            refuse("bad_address", where, str(exc))

    def words(self):
        return "75 characters: an address of this network, with its checksum (note, section 5)"


@dataclass(frozen=True)
class Key(Type):
    json = "string"

    def check(self, value, cx, where):
        text = _string(value, where)
        try:
            ref.key_from_text(text)
        except ValueError as exc:
            refuse("bad_key", where, str(exc))

    def words(self):
        return "`kpk1.` and 2,646 characters: the one text form of a public key (note, section 5)"


@dataclass(frozen=True)
class Signature(Type):
    json = "string"

    def check(self, value, cx, where):
        text = _string(value, where)
        try:
            ref.signature_from_text(text)
        except ValueError as exc:
            refuse("bad_signature", where, str(exc))

    def words(self):
        return "`ksig1.` and 4,498 characters: the one text form of a signature (note, section 5)"


@dataclass(frozen=True)
class Named(Type):
    """A type the document defines once, in its table of types, and then
    calls by its name."""

    name: str
    inner: Type

    @property
    def json(self):                             # type: ignore[override]
        return self.inner.json

    def check(self, value, cx, where):
        self.inner.check(value, cx, where)

    def words(self):
        return self.inner.words()

    def cell(self):
        return f"`{self.name}`"

    def depth(self):
        return self.inner.depth()


@dataclass(frozen=True)
class List(Type):
    item: Type
    low: int
    high: int | None                            # None: bounded by the size of what holds the list
    json = "array"

    def check(self, value, cx, where):
        if not isinstance(value, list):
            refuse("wrong_type", where, "an array")
        if len(value) < self.low or (self.high is not None and len(value) > self.high):
            refuse("out_of_range", where, self.cell())
        for i, item in enumerate(value):
            self.item.check(item, cx, _join(where, i))

    def words(self):
        if self.high is None:
            count = "any number of" if self.low == 0 else f"{number(self.low)} or more"
        else:
            count = f"{number(self.low)} to {number(self.high)}"
        return f"list of {count} {self.item.cell()}"

    def depth(self):
        return 1 + self.item.depth()


@dataclass(frozen=True)
class Map(Type):
    """An object whose keys are data: addresses, or the names a contract
    declares."""

    key: Type
    value: Type
    low: int
    high: int | None                            # None: as many entries as there are things to hold
    json = "object"

    def check(self, value, cx, where):
        if not isinstance(value, dict):
            refuse("wrong_type", where, "an object")
        if len(value) < self.low or (self.high is not None and len(value) > self.high):
            refuse("out_of_range", where, self.cell())
        for key, item in value.items():
            self.key.check(key, cx, _join(where, key))
            self.value.check(item, cx, _join(where, key))

    def words(self):
        count = "any number of" if self.high is None else f"{number(self.low)} to {number(self.high)}"
        return f"map of {self.key.cell()} to {self.value.cell()}, {count} entries"

    def depth(self):
        return 1 + self.value.depth()


@dataclass(frozen=True)
class Value(Type):
    """What a contract holds in a field of its storage or takes as a
    parameter: Skald has four types, and an address is a string."""

    json = "integer, boolean or string"

    def check(self, value, cx, where):
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            Int(INT_MIN, INT_MAX).check(value, cx, where)
        elif isinstance(value, str):
            FreeText(0, LIMITS["value_bytes"]).check(value, cx, where)
        else:
            refuse("wrong_type", where, "an integer, a boolean or a string")

    def words(self):
        return (f"an integer from {number(INT_MIN)} to {number(INT_MAX)}, `true` or `false`, "
                f"or any text of 0 to {number(LIMITS['value_bytes'])} bytes in UTF-8")


@dataclass(frozen=True)
class Claim(Type):
    """What an attestation states: an object the protocol does not read.
    Any value of canonical JSON may stand inside it."""

    json = "object"

    def check(self, value, cx, where):
        if not isinstance(value, dict):
            refuse("wrong_type", where, "an object")
        try:
            size = len(ref.canonical_json(value))
        except ValueError as exc:
            refuse("wrong_type", where, str(exc))
        if size > LIMITS["claim_bytes"]:
            refuse("too_long", where, f"a claim of {number(size)} bytes")

    def words(self):
        return (f"any object of canonical JSON whose encoding is at most {number(LIMITS['claim_bytes'])} bytes "
                "(the protocol does not read it)")

    def depth(self):
        return LIMITS["transaction_nesting"] - 2          # inside `params`, inside the transaction


Rule = tuple[str, Callable[[dict, Context, str], None]]       # the sentence of the document, and its check


class Obj(Type):
    """An object with fixed fields. A field is required or optional; a
    member that is not a field is refused. `rules` tie fields together."""

    json = "object"

    def __init__(self, name: str, fields: list[tuple[str, Type, str]], rules: list[Rule] | None = None):
        self.name, self.fields, self.rules = name, fields, rules or []
        assert all(presence in ("required", "optional") for _, _, presence in fields)

    def check(self, value, cx, where):
        if not isinstance(value, dict):
            refuse("wrong_type", where, "an object")
        known = {name for name, _, _ in self.fields}
        for member in value:
            if member not in known:
                refuse("unknown_field", _join(where, member), f"not a field of {self.name}")
        for name, type_, presence in self.fields:
            if name in value:
                type_.check(value[name], cx, _join(where, name))
            elif presence == "required":
                refuse("missing_field", _join(where, name), f"required in {self.name}")
        for _, rule in self.rules:
            rule(value, cx, where)

    def words(self):
        return f"the object of the table `{self.name}`"

    def cell(self):
        return f"`{self.name}`"

    def rows(self) -> list[tuple[str, str, str]]:
        return [(f"`{name}`", type_.cell(), presence) for name, type_, presence in self.fields]

    def depth(self):
        return 1 + max((type_.depth() for _, type_, _ in self.fields), default=0)


class Variants(Type):
    """An object whose fields depend on one of them."""

    json = "object"

    def __init__(self, name: str, by: str, variants: dict[str, Obj]):
        self.name, self.by, self.variants = name, by, variants

    def pick(self, value: Any, where: str) -> Obj:
        if not isinstance(value, dict):
            refuse("wrong_type", where, "an object")
        if self.by not in value:
            refuse("missing_field", _join(where, self.by), f"required in {self.name}")
        chosen = self.variants.get(_string(value[self.by], _join(where, self.by)))
        if chosen is None:
            refuse("bad_text", _join(where, self.by), f"one of {', '.join(self.variants)}")
        return chosen

    def check(self, value, cx, where):
        self.pick(value, where).check(value, cx, where)

    def words(self):
        return f"the object of the table `{self.name}`"

    def cell(self):
        return f"`{self.name}`"

    def depth(self):
        return max(variant.depth() for variant in self.variants.values())


# ---------------------------------------------------------------------------
# The types of the document
# ---------------------------------------------------------------------------

_HEX = "the digits and the letters a to f"

LEVEL = Named("level", Int(0, INT_MAX))
ROUND = Named("round", Int(0, ROUND_MAX))
NONCE = Named("nonce", Int(0, INT_MAX))
AMOUNT = Named("amount", Int(0, INT_MAX, "in mukrn"))
GAS = Named("gas", Int(0, INT_MAX))
TIME = Named("time", Int(0, INT_MAX, "in seconds since 1 January 1970"))
ADDRESS = Named("address", Address())
HASH = Named("hash", Text(96, 96, r"[0-9a-f]{96}", _HEX))
KEY = Named("key", Key())
SIGNATURE = Named("signature", Signature())
NETWORK = Named("network", Text(64, 64, r"[0-9a-f]{64}", _HEX))
CHAIN = Named("chain", Text(1, 64, r"[a-z][a-z0-9-]*",
                            "the letters a to z, the digits and the hyphen, the first one a letter"))
NAME = Named("name", Text(1, 64, r"[A-Za-z_][A-Za-z0-9_]*",
                          "letters without accent, digits and the underscore, the first one not a digit"))
SCHEMA_NAME = Named("schema name", Text(1, 128, r"[A-Za-z0-9._-]+",
                                        "letters without accent, digits, the full stop, the hyphen and the underscore"))
SUBJECT = Named("subject", Text(1, 256, r"[\x20-\x7e]+", "the printable characters of ASCII, U+0020 to U+007E"))
CODE = Named("code", FreeText(1, LIMITS["code_bytes"]))
MEMO = Named("memo", FreeText(1, 256))
VALUE = Named("value", Value())
CLAIM = Named("claim", Claim())
FIELDS = Named("fields", Map(NAME, VALUE, 0, LIMITS["contract_fields"]))
POSITIVE = Named("positive amount", Int(1, INT_MAX, "in mukrn"))
PERIOD = Named("period", Int(1, ROUND_MAX, "in blocks"))

NAMED_TYPES = [LEVEL, ROUND, NONCE, AMOUNT, GAS, TIME, ADDRESS, HASH, KEY, SIGNATURE, NETWORK, CHAIN, NAME,
               SCHEMA_NAME, SUBJECT, CODE, MEMO, VALUE, CLAIM, FIELDS, POSITIVE, PERIOD]


# ---------------------------------------------------------------------------
# Consensus messages and certificates
# ---------------------------------------------------------------------------

def _valid_round_below_round(message, cx, where):
    if "valid_round" in message and message["valid_round"] >= message["round"]:
        refuse("inconsistent", _join(where, "valid_round"), "not lower than the round")


VOTE = Obj("vote", [
    ("kind", Choice(("preendorse", "endorse")), "required"),
    ("level", LEVEL, "required"),
    ("round", ROUND, "required"),
    ("block_hash", HASH, "required"),
    ("validator", ADDRESS, "required"),
    ("signature", SIGNATURE, "required"),
])

PROPOSE = Obj("propose message", [
    ("kind", Choice(("propose",)), "required"),
    ("level", LEVEL, "required"),
    ("round", ROUND, "required"),
    ("block_hash", HASH, "required"),
    ("validator", ADDRESS, "required"),
    ("valid_round", ROUND, "optional"),
    ("signature", SIGNATURE, "required"),
], [
    ("`valid_round` is lower than `round`.", _valid_round_below_round),
])

CERTIFICATE = Obj("certificate", [
    ("kind", Choice(("preendorse", "endorse")), "required"),
    ("level", LEVEL, "required"),
    ("round", ROUND, "required"),
    ("block_hash", HASH, "required"),
    ("signatures", Map(ADDRESS, SIGNATURE, 1, LIMITS["certificate_signatures"]), "required"),
])

PURPOSES = {"propose": "kern.propose", "preendorse": "kern.preendorse", "endorse": "kern.endorse"}


def signed_message(message: dict) -> bytes:
    """What the validator signs in a consensus message: every field but
    the signature, as canonical JSON, in the context of its kind."""
    return ref.canonical_json({k: v for k, v in message.items() if k != "signature"})


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

WITNESS_FIELDS = ("signature", "public_key", "second_signature")
KIND_FIELDS = ("recipient", "amount", "code", "initial_storage", "entry", "params")

PPM = Int(0, 1_000_000)
PARAMETERS = Obj("parameters", [
    ("i_min_ppm", PPM, "optional"),
    ("i_max_ppm", PPM, "optional"),
    ("target_staking_ratio_ppm", PPM, "optional"),
    ("target_block_time_ms", Int(1, 3_600_000), "optional"),
    ("treasury_share_ppm", PPM, "optional"),
    ("proposer_bonus_ppm", PPM, "optional"),
    ("fee_floor_enabled", Bool(), "optional"),
    ("fee_floor_base", Int(0, 10**12), "optional"),
    ("fee_floor_per_byte", Int(0, 10**9), "optional"),
    ("max_block_bytes", Int(LIMITS["transaction_bytes"], LIMITS["block_bytes"]), "optional"),
], [
    ("At least one parameter is present.",
     lambda v, cx, where: refuse("inconsistent", where, "no parameter") if not v else None),
])


def _a_change(payload, cx, where):
    if "params" not in payload and "swap" not in payload:
        refuse("inconsistent", where, "neither params nor swap")


def _to_with_swap(payload, cx, where):
    if ("swap" in payload) != ("to" in payload):
        refuse("inconsistent", where, "swap and to go together")


PROTOCOL_PAYLOAD = Obj("protocol payload", [
    ("params", PARAMETERS, "optional"),
    ("swap", Choice(("state_root_function",)), "optional"),
    ("to", Choice(("json", "trie")), "optional"),
], [
    ("`params` or `swap` is present, or both.", _a_change),
    ("`to` is present exactly when `swap` is.", _to_with_swap),
])

RECIPIENT = Obj("recipient", [
    ("address", ADDRESS, "required"),
    ("amount", Int(1, INT_MAX, "in mukrn"), "required"),
])


def _total_in_range(payload, cx, where):
    if sum(r["amount"] for r in payload["recipients"]) > INT_MAX:
        refuse("out_of_range", _join(where, "recipients"), "the amounts add up beyond 2^63 - 1")


TREASURY_PAYLOAD = Obj("treasury payload", [
    ("recipients", List(RECIPIENT, 1, LIMITS["recipients"]), "required"),
    ("memo", MEMO, "optional"),
], [
    (f"The amounts add up to {number(INT_MAX)} at most.", _total_in_range),
])

PROPOSAL = Variants("proposal", "track", {
    "protocol": Obj("proposal", [
        ("track", Choice(("protocol", "treasury")), "required"),
        ("payload", PROTOCOL_PAYLOAD, "required"),
        ("salt", Int(0, INT_MAX), "required"),
    ]),
    "treasury": Obj("proposal", [
        ("track", Choice(("protocol", "treasury")), "required"),
        ("payload", TREASURY_PAYLOAD, "required"),
        ("salt", Int(0, INT_MAX), "required"),
    ]),
})

PARAMS = {                                      # the `params` of the kinds that have fixed ones
    "governance_vote": Obj("governance_vote", [
        ("track", Choice(("protocol", "treasury")), "required"),
        ("proposal_id", HASH, "required"),
        ("vote", Choice(("yes", "no", "abstain")), "required"),
    ]),
    "release_payment": Obj("release_payment", [
        ("proposal_id", HASH, "required"),
    ]),
    "cancel_payment": Obj("cancel_payment", [
        ("proposal_id", HASH, "required"),
    ]),
    "slash_equivocation": Obj("slash_equivocation", [
        ("proposal_id", HASH, "required"),
        ("equivocator", ADDRESS, "required"),
    ]),
    "slash_consensus_equivocation": Obj("slash_consensus_equivocation", [
        ("msg_a", VOTE, "required"),
        ("msg_b", VOTE, "required"),
    ]),
    "delegate_stake": Obj("delegate_stake", [
        ("validator", ADDRESS, "required"),
    ]),
    "attest": Obj("attest", [
        ("schema_id", SCHEMA_NAME, "required"),
        ("subject", SUBJECT, "required"),
        ("claim", CLAIM, "required"),
    ]),
    "revoke_attestation": Obj("revoke_attestation", [
        ("attestation_id", HASH, "required"),
    ]),
    "slash_attestation_equivocation": Obj("slash_attestation_equivocation", [
        ("attestation_id_1", HASH, "required"),
        ("attestation_id_2", HASH, "required"),
    ]),
    "rotate_key": Obj("rotate_key", [
        ("new_public_key", KEY, "required"),
    ]),
}

# For each kind, the fields it has besides the common ones, each with its type.
KINDS: dict[str, dict[str, Type]] = {
    "transfer": {"recipient": ADDRESS, "amount": AMOUNT},
    "originate": {"code": CODE, "initial_storage": FIELDS},
    "call": {"recipient": ADDRESS, "amount": AMOUNT, "entry": NAME, "params": FIELDS},
    "governance_propose": {"params": PROPOSAL},
    "governance_vote": {"params": PARAMS["governance_vote"]},
    "release_payment": {"params": PARAMS["release_payment"]},
    "cancel_payment": {"params": PARAMS["cancel_payment"]},
    "slash_equivocation": {"params": PARAMS["slash_equivocation"]},
    "slash_consensus_equivocation": {"params": PARAMS["slash_consensus_equivocation"]},
    "delegate_stake": {"amount": Int(1, INT_MAX, "in mukrn"), "params": PARAMS["delegate_stake"]},
    "undelegate_stake": {},
    "attest": {"amount": AMOUNT, "params": PARAMS["attest"]},
    "revoke_attestation": {"params": PARAMS["revoke_attestation"]},
    "slash_attestation_equivocation": {"params": PARAMS["slash_attestation_equivocation"]},
    "rotate_key": {"params": PARAMS["rotate_key"]},
}


def nesting(value: Any) -> int:
    """How deep arrays and objects nest in a value: 0 for a string, a
    number or a boolean, 1 for an array or an object that holds none."""
    if isinstance(value, dict):
        return 1 + max((nesting(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((nesting(v) for v in value), default=0)
    return 0


def _transaction_bounds(tx, cx, where):
    size = len(ref.canonical_json(tx))
    if size > LIMITS["transaction_bytes"]:
        refuse("too_long", where, f"a transaction of {number(size)} bytes")


def _transaction_of(kind: str) -> Obj:
    fields: list[tuple[str, Type, str]] = [
        ("kind", Choice(tuple(KINDS)), "required"),
        ("sender", ADDRESS, "required"),
        ("nonce", NONCE, "required"),
        ("fee", AMOUNT, "required"),
        ("gas_limit", GAS, "required"),
        ("chain_id", CHAIN, "required"),
    ]
    fields += [(name, type_, "required") for name, type_ in KINDS[kind].items()]
    fields += [("signature", SIGNATURE, "required"), ("public_key", KEY, "optional")]
    if kind == "rotate_key":
        fields.append(("second_signature", SIGNATURE, "required"))
    return Obj("transaction", fields, [
        (f"Its canonical encoding, which is its size, is at most {number(LIMITS['transaction_bytes'])} bytes.",
         _transaction_bounds),
    ])


class Transaction(Variants):
    """A transaction as it travels: what its sender signs, and its
    witness. Its nesting is measured first, so that nothing deeper than
    the bound is ever walked."""

    def check(self, value, cx, where):
        if nesting(value) > LIMITS["transaction_nesting"]:
            refuse("too_deep", where, f"a transaction nested more than {LIMITS['transaction_nesting']} deep")
        super().check(value, cx, where)


TRANSACTION = Transaction("transaction", "kind", {kind: _transaction_of(kind) for kind in KINDS})


def signed_transaction(tx: dict) -> bytes:
    """What the sender signs, and what the identifier is the hash of: the
    transaction without its witness, as canonical JSON."""
    return ref.canonical_json({k: v for k, v in tx.items() if k not in WITNESS_FIELDS})


def transaction_id(network_id: bytes, tx: dict) -> bytes:
    return ref.H("kern.tx", network_id, signed_transaction(tx))


def transaction_size(tx: dict) -> int:
    """The size of a transaction, for the fee floor and the size of a
    block: the bytes of its canonical encoding, witness included."""
    return len(ref.canonical_json(tx))


def witness_leaf(network_id: bytes, tx: dict) -> bytes:
    """The leaf of the witness tree for this transaction (note, section 6.3)."""
    return ref.witness_leaf(
        network_id, transaction_id(network_id, tx), ref.signature_from_text(tx["signature"]),
        ref.key_from_text(tx["public_key"]) if "public_key" in tx else None,
        ref.signature_from_text(tx["second_signature"]) if "second_signature" in tx else None)


def proposal_id(network_id: bytes, tx: dict) -> bytes:
    """The identifier of the proposal a `governance_propose` submits."""
    return ref.H("kern.gov.id", network_id, ref.canonical_json(
        {"submitter": tx["sender"], "payload": tx["params"]["payload"], "salt": tx["params"]["salt"]}))


def attestation_id(network_id: bytes, tx: dict) -> bytes:
    """The identifier of the attestation an `attest` records."""
    return ref.H("kern.attestation.id", network_id, ref.canonical_json(
        {"issuer": tx["sender"], "schema_id": tx["params"]["schema_id"], "subject": tx["params"]["subject"],
         "claim": tx["params"]["claim"], "attest_nonce": tx["nonce"]}))


# ---------------------------------------------------------------------------
# Headers and blocks
# ---------------------------------------------------------------------------

HEADER_FIELDS = ("version", "level", "payload_round", "timestamp", "parent_hash", "state_root", "txs_root",
                 "witness_root", "proposer")

HEADER = Obj("header", [
    ("version", Int(1, 1), "required"),
    ("level", LEVEL, "required"),
    ("payload_round", ROUND, "required"),
    ("timestamp", TIME, "required"),
    ("parent_hash", HASH, "required"),
    ("state_root", HASH, "required"),
    ("txs_root", HASH, "required"),
    ("witness_root", HASH, "required"),
    ("proposer", ADDRESS, "required"),
    ("signature", SIGNATURE, "required"),
])


def signed_header(header: dict) -> bytes:
    """What the proposer signs, and what the hash of the block is the hash
    of: the nine fields of section 6.3 of the note, as canonical JSON."""
    return ref.canonical_json({k: v for k, v in header.items() if k != "signature"})


def block_hash(network_id: bytes, header: dict) -> bytes:
    return ref.H("kern.block", network_id, signed_header(header))


def _block_size(block, cx, where):
    size = sum(transaction_size(tx) for tx in block["transactions"])
    if size > LIMITS["block_bytes"]:
        refuse("too_long", _join(where, "transactions"), f"transactions of {number(size)} bytes")


def _txs_root(block, cx, where):
    ids = [transaction_id(cx.network_id, tx) for tx in block["transactions"]]
    if block["header"]["txs_root"] != ref.merkle_root(cx.network_id, ids).hex():
        refuse("inconsistent", _join(where, "header.txs_root"), "not the root of the identifiers")


def _witness_root(block, cx, where):
    leaves = [witness_leaf(cx.network_id, tx) for tx in block["transactions"]]
    if block["header"]["witness_root"] != ref.merkle_root(cx.network_id, leaves).hex():
        refuse("inconsistent", _join(where, "header.witness_root"), "not the root of the witness leaves")


BLOCK = Obj("block", [
    ("header", HEADER, "required"),
    ("transactions", List(TRANSACTION, 0, None), "required"),
], [
    (f"The sizes of its transactions add up to {number(LIMITS['block_bytes'])} bytes at most.", _block_size),
    ("`txs_root` is the root of the identifiers of its transactions, in the order of the list.", _txs_root),
    ("`witness_root` is the root of their witness leaves, in the same order.", _witness_root),
])


def _certificate_of(pair, cx, where):
    header, certificate = pair["block"]["header"], pair["certificate"]
    there = _join(where, "certificate")
    if certificate["kind"] != "endorse":
        refuse("inconsistent", there, "not a certificate of endorsements")
    if certificate["level"] != header["level"]:
        refuse("inconsistent", there, "not the level of the block")
    if certificate["block_hash"] != block_hash(cx.network_id, header).hex():
        refuse("inconsistent", there, "not the hash of the block")
    if certificate["round"] < header["payload_round"]:
        refuse("inconsistent", there, "a round before the payload round")


FINAL_BLOCK = Obj("final block", [
    ("block", BLOCK, "required"),
    ("certificate", CERTIFICATE, "required"),
], [
    ("The certificate is of the kind `endorse`, for the level and the hash of the block, "
     "at a round that is not lower than `payload_round`.", _certificate_of),
])


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------

def _proposal_names_block(frame, cx, where):
    header, message = frame["block"]["header"], frame["proposal"]
    if message["level"] != header["level"]:
        refuse("inconsistent", _join(where, "proposal.level"), "not the level of the block")
    if message["block_hash"] != block_hash(cx.network_id, header).hex():
        refuse("inconsistent", _join(where, "proposal.block_hash"), "not the hash of the block")


def _proof_with_valid_round(frame, cx, where):
    if ("valid_round" in frame["proposal"]) != ("proof" in frame):
        refuse("inconsistent", where, "valid_round and proof go together")


def _new_payload(frame, cx, where):
    message = frame["proposal"]
    if "valid_round" not in message and frame["block"]["header"]["payload_round"] != message["round"]:
        refuse("inconsistent", _join(where, "proposal.round"), "a new payload is proposed at its payload round")


def _payload_proposed_again(frame, cx, where):
    message = frame["proposal"]
    if "valid_round" not in message:
        return
    if frame["block"]["header"]["payload_round"] > message["valid_round"]:
        refuse("inconsistent", _join(where, "proposal.valid_round"), "a valid round before the payload round")
    proof = frame["proof"]
    if (proof["kind"], proof["level"], proof["round"], proof["block_hash"]) != (
            "preendorse", message["level"], message["valid_round"], message["block_hash"]):
        refuse("inconsistent", _join(where, "proof"), "not the certificate of pre-endorsements of the valid round")


def _blocks_frame(frame, cx, where):
    levels = [pair["block"]["header"]["level"] for pair in frame["blocks"]]
    if any(b != a + 1 for a, b in zip(levels, levels[1:])):
        refuse("inconsistent", _join(where, "blocks"), "levels that do not follow one another")


def _range(frame, cx, where):
    if frame["to"] < frame["from"]:
        refuse("inconsistent", _join(where, "to"), "lower than from")


_FRAME_KINDS = ("hello", "proposal", "consensus", "block", "transaction", "get_blocks", "blocks")
_KIND = ("kind", Choice(_FRAME_KINDS), "required")

FRAMES = {
    "hello": Obj("hello", [
        _KIND,
        ("network_id", NETWORK, "required"),
        ("level", LEVEL, "required"),
    ]),
    "proposal": Obj("proposal", [
        _KIND,
        ("block", BLOCK, "required"),
        ("proposal", PROPOSE, "required"),
        ("proof", CERTIFICATE, "optional"),
    ], [
        ("`proposal` names the level and the hash of the block.", _proposal_names_block),
        ("`proof` is present exactly when `proposal` has a `valid_round`.", _proof_with_valid_round),
        ("Without `valid_round`, `payload_round` is the round of `proposal`.", _new_payload),
        ("With it, `payload_round` is not higher than `valid_round`, and `proof` is of the kind `preendorse`, "
         "for the level and the hash of the block, at the round `valid_round`.", _payload_proposed_again),
    ]),
    "consensus": Obj("consensus", [
        _KIND,
        ("msg", VOTE, "required"),
    ]),
    "block": Obj("block", [
        _KIND,
        ("block", BLOCK, "required"),
        ("certificate", CERTIFICATE, "required"),
    ], FINAL_BLOCK.rules),
    "transaction": Obj("transaction", [
        _KIND,
        ("tx", TRANSACTION, "required"),
    ]),
    "get_blocks": Obj("get_blocks", [
        _KIND,
        ("from", Int(1, INT_MAX), "required"),
        ("to", Int(1, INT_MAX), "required"),
    ], [
        ("`to` is not lower than `from`.", _range),
    ]),
    "blocks": Obj("blocks", [
        _KIND,
        ("blocks", List(FINAL_BLOCK, 0, None), "required"),
    ], [
        ("The levels of the blocks follow one another, each one more than the one before.", _blocks_frame),
    ]),
}


class Frame(Variants):
    """A frame between peers. Its size is that of its canonical encoding,
    checked before anything else is."""

    def check(self, value, cx, where):
        if isinstance(value, dict):
            try:
                size = len(ref.canonical_json(value))
            except ValueError as exc:
                refuse("wrong_type", where, str(exc))
            if size > LIMITS["frame_bytes"]:
                refuse("too_long", where, f"a frame of {number(size)} bytes")
        super().check(value, cx, where)


FRAME = Frame("frame", "kind", FRAMES)


class AnyJson(Type):
    """Any value of canonical JSON: what the reception of a text checks
    before any schema is applied."""

    json = "any"

    def check(self, value, cx, where):
        try:
            ref.canonical_json(value)
        except ValueError as exc:
            refuse("wrong_type", where, str(exc))

    def words(self):
        return "any value of canonical JSON"


SCHEMAS: dict[str, Type] = {
    "json": AnyJson(),
    "transaction": TRANSACTION,
    "vote": VOTE,
    "propose message": PROPOSE,
    "certificate": CERTIFICATE,
    "header": HEADER,
    "block": BLOCK,
    "final block": FINAL_BLOCK,
    "frame": FRAME,
}


# ---------------------------------------------------------------------------
# The four bytes of a frame (section 9.8)
# ---------------------------------------------------------------------------

def frame_prefix(size: int) -> bytes:
    """The four bytes that travel before a frame whose canonical JSON is
    `size` bytes: that number, most significant byte first. They are not
    part of what they count."""
    return size.to_bytes(4, "big")


def announced(prefix: bytes) -> int:
    """How many bytes of canonical JSON follow the four bytes `prefix`, as
    a node reads them: an integer without a sign, most significant byte
    first. Raises Refused when they announce more than a frame can hold:
    the node reads no further. The bound is on what follows, so the four
    bytes themselves are not counted."""
    size = int.from_bytes(prefix, "big")
    if size > LIMITS["frame_bytes"]:
        refuse("too_long", "", f"a frame of {number(size)} bytes")
    return size


# ---------------------------------------------------------------------------
# A request for blocks and its answer (section 9.8)
# ---------------------------------------------------------------------------
# A schema checks one frame. An answer is also the answer to a request: the
# rules below tie the two frames together. Two of them can be checked by the
# node that asked, on the levels it receives; the two others say what the
# node that answers does with the blocks it holds.

BLOCKS_FRAME_BYTES = len(ref.canonical_json({"kind": "blocks", "blocks": []}))     # 29: a frame that holds no block


def _starts_at_from(first: int, last: int, levels: list[int]) -> bool:
    return not levels or levels[0] == first


def _stays_within_to(first: int, last: int, levels: list[int]) -> bool:
    return all(level <= last for level in levels)


ANSWER_RULES: list[tuple[str, Callable[[int, int, list[int]], bool]]] = [
    ("When the answer holds blocks, the first one is the block of level `from`.", _starts_at_from),
    ("It holds no block above `to`.", _stays_within_to),
]
ANSWERING_RULES = [
    "It holds every block the node has from `from` upward, in order, as far as the first of three things: a level "
    "the node does not hold, the level `to`, or a block that would take the frame beyond its bound. A node never "
    "leaves a level out to send a later one.",
    "An empty list says that the node does not hold the block of level `from`. It says nothing of the levels "
    "after it.",
]


def answer(held: Mapping[int, int], first: int, last: int) -> list[int]:
    """The levels of the blocks a node sends in answer to a `get_blocks`
    from `first` to `last`. `held` gives, for each level the node holds,
    the bytes of its final block in canonical JSON, as it stands in the
    frame.

    The longest run of levels that starts at `first`, goes no further than
    `last`, has no gap, and keeps the frame within its bound. A frame that
    holds no block is 29 bytes; each block adds its bytes, and each block
    after the first one byte more, a comma."""
    levels: list[int] = []
    size = BLOCKS_FRAME_BYTES
    level = first
    while level <= last and level in held:
        more = held[level] + (1 if levels else 0)
        if size + more > LIMITS["frame_bytes"]:
            break
        levels.append(level)
        size += more
        level += 1
    return levels


def answer_verdict(first: int, last: int, levels: list[int]) -> str:
    """`accepted`, or the code of the rule that refuses a `blocks` frame
    whose blocks are of the levels `levels` as the answer to a `get_blocks`
    from `first` to `last`: the rule of the frame itself, then the rules
    that tie it to the request."""
    follow = all(b == a + 1 for a, b in zip(levels, levels[1:]))
    if follow and all(holds(first, last, levels) for _, holds in ANSWER_RULES):
        return "accepted"
    return "inconsistent"


def check_answer(request: dict, reply: dict, network_id: bytes) -> None:
    """Raises Refused unless `reply`, a `blocks` frame, is an answer to
    `request`, a `get_blocks` frame, on this network. Each frame is checked
    against its schema first."""
    check("frame", request, network_id)
    check("frame", reply, network_id)
    if request["kind"] != "get_blocks" or reply["kind"] != "blocks":
        refuse("inconsistent", "kind", "not a request for blocks and its answer")
    levels = [pair["block"]["header"]["level"] for pair in reply["blocks"]]
    for sentence, holds in ANSWER_RULES:
        if not holds(request["from"], request["to"], levels):
            refuse("inconsistent", "blocks", sentence)


# ---------------------------------------------------------------------------
# Chapter 2: what is kept (sections 9.12 to 9.16)
# ---------------------------------------------------------------------------
# The state, the account of the state trie, the key registry, the genesis.
# A schema of chapter 1 checks one object that travels. A state does not
# travel: its schema says what a state of structure version 1 is, and the
# rules that tie its tables together can all be checked on the state alone.

BALLOT = Choice(("yes", "no", "abstain"))
BALLOTS = Map(ADDRESS, BALLOT, 0, LIMITS["validators"])
STILL_HELD = Int(0, ROUND_MAX, "in blocks")       # a period that can be none at all


def _tranches_add_up(holding, cx, where):
    levels = [tranche["level"] for tranche in holding["tranches"]]
    if any(b <= a for a, b in zip(levels, levels[1:])):
        refuse("inconsistent", _join(where, "tranches"), "levels that do not grow")
    if holding["amount"] != sum(tranche["amount"] for tranche in holding["tranches"]):
        refuse("inconsistent", _join(where, "amount"), "not the sum of the tranches")


_TRANCHES = ("`amount` is the sum of the amounts of `tranches`, whose levels grow.", _tranches_add_up)

CONTRACT = Obj("contract", [
    ("code", CODE, "required"),
    ("storage", FIELDS, "required"),
])

KEY_ENTRY = Obj("key entry", [
    ("from", LEVEL, "required"),
    ("public_key", KEY, "required"),
])

VALIDATOR = Obj("validator", [
    ("address", ADDRESS, "required"),
    ("stake", POSITIVE, "required"),
])

TRANCHE = Obj("tranche", [
    ("level", LEVEL, "required"),
    ("amount", POSITIVE, "required"),
])

DELEGATION = Obj("delegation", [
    ("validator", ADDRESS, "required"),
    ("amount", POSITIVE, "required"),
    ("tranches", List(TRANCHE, 1, None), "required"),
], [_TRANCHES])

UNBONDING = Obj("unbonding delegation", [
    ("delegator", ADDRESS, "required"),
    ("validator", ADDRESS, "required"),
    ("amount", POSITIVE, "required"),
    ("tranches", List(TRANCHE, 1, None), "required"),
    ("unbonding_from", LEVEL, "required"),
    ("release_at", LEVEL, "required"),
], [_TRANCHES])


def _revoked_after_issued(attestation, cx, where):
    if "revoked_at" in attestation and attestation["revoked_at"] < attestation["issued_at"]:
        refuse("inconsistent", _join(where, "revoked_at"), "before issued_at")


def _slashed_holds_nothing(attestation, cx, where):
    if attestation["slashed"] and attestation["bond"] != 0:
        refuse("inconsistent", _join(where, "bond"), "a slashed attestation that holds a bond")


ATTESTATION = Obj("attestation", [
    ("issuer", ADDRESS, "required"),
    ("schema_id", SCHEMA_NAME, "required"),
    ("subject", SUBJECT, "required"),
    ("claim", CLAIM, "required"),
    ("bond", AMOUNT, "required"),
    ("issued_at", LEVEL, "required"),
    ("revoked_at", LEVEL, "optional"),
    ("slashed", Bool(), "required"),
], [
    ("`revoked_at` is not lower than `issued_at`.", _revoked_after_issued),
    ("An attestation that is slashed holds no bond.", _slashed_holds_nothing),
])

SLASHED_VOTE = Obj("slashed vote", [
    ("validator", ADDRESS, "required"),
    ("kind", Choice(("preendorse", "endorse")), "required"),
    ("level", LEVEL, "required"),
    ("round", ROUND, "required"),
])

DOUBLE_VOTE = Obj("double vote", [
    ("voter", ADDRESS, "required"),
    ("phase", Choice(("exploration", "adoption")), "required"),
    ("level", LEVEL, "required"),
    ("punished", Bool(), "required"),
])

PROTOCOL_PHASES = ("submitted", "exploration", "cooldown", "adoption", "activated", "rejected")
TREASURY_PHASES = ("submitted", "voting", "passed", "executed", "rejected")
OVER = {"protocol": ("activated", "rejected"), "treasury": ("executed", "rejected")}


def _over_or_bonded(track: str) -> Rule:
    first, second = OVER[track]

    def check(proposal, cx, where):
        over = proposal["phase"] in OVER[track]
        if ("ended_at" in proposal) != over:
            refuse("inconsistent", _join(where, "ended_at"), "present exactly when the proposal is over")
        if ("bond" in proposal) == over:
            refuse("inconsistent", _join(where, "bond"), "present exactly when the proposal is not over")

    return (f"`ended_at` is present exactly when `phase` is `{first}` or `{second}`, "
            "and `bond` exactly when it is not.", check)


def _double_votes(proposal, cx, where):
    seen = set()
    for i, double in enumerate(proposal["double_votes"]):
        pair = (double["voter"], double["phase"])
        if pair in seen:
            refuse("inconsistent", _join(where, f"double_votes.{i}"), "a second double vote of a voter in a phase")
        seen.add(pair)
        if double["voter"] not in proposal[double["phase"] + "_votes"]:
            refuse("inconsistent", _join(where, f"double_votes.{i}"), "a double vote without a vote")


PROTOCOL_PROPOSAL = Obj("protocol proposal", [
    ("proposal_id", HASH, "required"),
    ("submitter", ADDRESS, "required"),
    ("payload", PROTOCOL_PAYLOAD, "required"),
    ("submitted_at", LEVEL, "required"),
    ("phase", Choice(PROTOCOL_PHASES), "required"),
    ("ended_at", LEVEL, "optional"),
    ("exploration_votes", BALLOTS, "required"),
    ("adoption_votes", BALLOTS, "required"),
    ("double_votes", List(DOUBLE_VOTE, 0, 2 * LIMITS["validators"]), "required"),
    ("bond", AMOUNT, "optional"),
], [
    _over_or_bonded("protocol"),
    ("A voter has one double vote in a phase at most, and a vote in that phase.", _double_votes),
])

def _released_while_it_waits(proposal, cx, where):
    if "released_by" in proposal and proposal["phase"] != "passed":
        refuse("inconsistent", _join(where, "released_by"), "on a proposal that does not wait")


TREASURY_PROPOSAL = Obj("treasury proposal", [
    ("proposal_id", HASH, "required"),
    ("submitter", ADDRESS, "required"),
    ("payload", TREASURY_PAYLOAD, "required"),
    ("submitted_at", LEVEL, "required"),
    ("phase", Choice(TREASURY_PHASES), "required"),
    ("ended_at", LEVEL, "optional"),
    ("votes", BALLOTS, "required"),
    ("released_by", ADDRESS, "optional"),
    ("bond", AMOUNT, "optional"),
], [
    _over_or_bonded("treasury"),
    ("`released_by` is present only when `phase` is `passed`.", _released_while_it_waits),
])

GOVERNANCE = Obj("governance", [
    ("protocol", List(PROTOCOL_PROPOSAL, 0, None), "required"),
    ("treasury", List(TREASURY_PROPOSAL, 0, None), "required"),
])


def _bounds_in_order(parameters, cx, where):
    if parameters["i_min_ppm"] > parameters["i_max_ppm"]:
        refuse("inconsistent", _join(where, "i_min_ppm"), "above i_max_ppm")


# The ten parameters a protocol proposal can change (section 9.5), each one
# with the range it has there. In the state every one of them has a value.
STATE_PARAMETERS = Obj("state parameters", [(name, type_, "required") for name, type_, _ in PARAMETERS.fields], [
    ("`i_min_ppm` is not above `i_max_ppm`.", _bounds_in_order),
])


def _unbonding_covers_an_epoch(constants, cx, where):
    if constants["delegation_unbonding_blocks"] < constants["epoch_blocks"]:
        refuse("inconsistent", _join(where, "delegation_unbonding_blocks"), "lower than epoch_blocks")


def _others_can_release(constants, cx, where):
    """Past this delay a payment that waits can be released without the
    first guardian: the delay ends before the wait does, or with it."""
    if constants["guardian_delay_blocks"] > constants["treasury_release_blocks"]:
        refuse("inconsistent", _join(where, "guardian_delay_blocks"), "above treasury_release_blocks")


CONSTANTS = Obj("constants", [
    ("epoch_blocks", PERIOD, "required"),
    ("delegation_unbonding_blocks", PERIOD, "required"),
    ("attestation_unbonding_blocks", STILL_HELD, "required"),
    ("protocol_proposal_blocks", PERIOD, "required"),
    ("protocol_exploration_blocks", PERIOD, "required"),
    ("protocol_cooldown_blocks", PERIOD, "required"),
    ("protocol_adoption_blocks", PERIOD, "required"),
    ("treasury_proposal_blocks", PERIOD, "required"),
    ("treasury_vote_blocks", PERIOD, "required"),
    ("guardian_delay_blocks", PERIOD, "required"),
    ("treasury_release_blocks", PERIOD, "required"),
    ("protocol_bond", AMOUNT, "required"),
    ("treasury_bond", AMOUNT, "required"),
], [
    ("`delegation_unbonding_blocks` is not lower than `epoch_blocks`.", _unbonding_covers_an_epoch),
    ("`guardian_delay_blocks` is not above `treasury_release_blocks`.", _others_can_release),
])

# The phases a proposal goes through before it is over, and what each one
# adds to the level at which the one before it ended: `submitted_at` for the
# first one.
PHASES = {
    "protocol": (("submitted", "protocol_proposal_blocks"), ("exploration", "protocol_exploration_blocks"),
                 ("cooldown", "protocol_cooldown_blocks"), ("adoption", "protocol_adoption_blocks")),
    "treasury": (("submitted", "treasury_proposal_blocks"), ("voting", "treasury_vote_blocks"),
                 ("passed", "treasury_release_blocks")),
}


def phase_ends(track: str, proposal: dict, constants: dict) -> dict[str, int]:
    """The level at which each phase of a proposal ends: the block of that
    level moves the proposal on."""
    ends, level = {}, proposal["submitted_at"]
    for phase, blocks in PHASES[track]:
        level += constants[blocks]
        ends[phase] = level
    return ends


def phase_window(track: str, proposal: dict, constants: dict) -> tuple[int, int]:
    """The level at which the phase of a proposal that is not over started,
    and the level at which it ends."""
    start = proposal["submitted_at"]
    for phase, end in phase_ends(track, proposal, constants).items():
        if phase == proposal["phase"]:
            return start, end
        start = end
    raise ValueError("a proposal that is over")


def ended_in_time(track: str, proposal: dict, constants: dict) -> bool:
    """Whether a proposal that is over ended at a level at which it could.
    A protocol proposal ends with a vote. A treasury proposal ends with its
    vote when the vote rejects it; one that passed is released or cancelled
    by a guardian in a later block, or is rejected at the end of its wait."""
    ends = phase_ends(track, proposal, constants)
    if track == "treasury":
        first = ends["voting"] + (1 if proposal["phase"] == "executed" else 0)
        return first <= proposal["ended_at"] <= ends["passed"]
    if proposal["phase"] == "activated":
        return proposal["ended_at"] == ends["adoption"]
    return proposal["ended_at"] in (ends["exploration"], ends["adoption"])


# -- the rules of a state ----------------------------------------------------

def _listed(state: dict) -> list[str]:
    return [validator["address"] for validator in state["validators"]]


def _validators_once(state, cx, where):
    listed = _listed(state)
    if len(set(listed)) != len(listed):
        refuse("inconsistent", _join(where, "validators"), "an address twice")
    if [entry["address"] for entry in state["consensus_set"]] != listed:
        refuse("inconsistent", _join(where, "consensus_set"), "not the addresses of validators, in their order")


def _validators_have_keys(state, cx, where):
    for i, address in enumerate(_listed(state)):
        if address not in state["keys"]:
            refuse("inconsistent", _join(where, f"validators.{i}"), "a validator without a key")


def _weights_are_backed(state, cx, where):
    """A weight is collateral: what the consensus counts for a validator is
    never more than its own stake and what is delegated to it now. The
    weights of a state therefore add up to its supply at most."""
    stakes: dict[str, int] = {}
    for validator in state["validators"]:
        stakes.setdefault(validator["address"], validator["stake"])
    delegated: dict[str, int] = {}
    for delegation in state["delegations"].values():
        delegated[delegation["validator"]] = delegated.get(delegation["validator"], 0) + delegation["amount"]
    for i, entry in enumerate(state["consensus_set"]):
        address = entry["address"]
        if address in stakes and entry["stake"] > stakes[address] + delegated.get(address, 0):
            refuse("inconsistent", _join(where, f"consensus_set.{i}.stake"), "more than the stake and the delegations")


def _one_kind(state, cx, where):
    """An address is an account or a contract, never both: a contract has
    no key. It has no nonce either, since an address that has sent a
    transaction has a key."""
    for address in state["contracts"]:
        if address in state["keys"]:
            refuse("inconsistent", _join(where, f"contracts.{address}"), "a contract that has a key")


def _treasury_has_no_key(state, cx, where):
    """Only a payment that was voted and released moves what the treasury
    holds: nobody signs for its address. It is then no validator, and it
    has sent nothing."""
    if state["treasury_address"] in state["keys"]:
        refuse("inconsistent", _join(where, "treasury_address"), "an address that has a key")


def _guardians_once(state, cx, where):
    if len(set(state["guardians"])) != len(state["guardians"]):
        refuse("inconsistent", _join(where, "guardians"), "an address twice")


def _guardians_only_guard(state, cx, where):
    """A guardian signs: it is an account, and not the treasury, which has
    no key. It is no validator either: the key of a validator is on a
    machine that signs all day, and that of a guardian is not."""
    listed = set(_listed(state))
    for i, guardian in enumerate(state["guardians"]):
        if guardian == state["treasury_address"] or guardian in state["contracts"] or guardian in listed:
            refuse("inconsistent", _join(where, f"guardians.{i}"), "the treasury, a contract or a validator")


def _who_has_a_key(state, cx, where):
    listed = set(_listed(state))
    for address in state["nonces"]:
        if address not in state["keys"]:
            refuse("inconsistent", _join(where, f"nonces.{address}"), "a nonce without a key")
    for address in state["keys"]:
        if address not in state["nonces"] and address not in listed:
            refuse("inconsistent", _join(where, f"keys.{address}"), "a key without a nonce, and not of a validator")


def _levels_of_keys(state, cx, where):
    for address, entries in state["keys"].items():
        levels = [entry["from"] for entry in entries]
        if any(b <= a for a, b in zip(levels, levels[1:])) or levels[-1] > state["level"] + 1:
            refuse("inconsistent", _join(where, f"keys.{address}"), "levels that do not grow, or one too far ahead")


def _first_key(state, cx, where):
    for address, entries in state["keys"].items():
        if ref.account_address(cx.network_id, ref.key_from_text(entries[0]["public_key"])) != address:
            refuse("inconsistent", _join(where, f"keys.{address}.0"), "not the key whose hash is the address")


def key_parts(public_key: bytes) -> tuple[bytes, bytes]:
    """The two parts of a public key: the ML-DSA part, its first 1,952
    bytes, and the Ed25519 part, its last 32."""
    return public_key[:ref.MLDSA_PUBLIC_KEY_BYTES], public_key[ref.MLDSA_PUBLIC_KEY_BYTES:]


def _keys_once(state, cx, where):
    recorded: set[bytes] = set()
    for address, entries in state["keys"].items():
        parts: tuple[set[bytes], set[bytes]] = (set(), set())
        for i, entry in enumerate(entries):
            public_key = ref.key_from_text(entry["public_key"])
            if public_key in recorded:
                refuse("inconsistent", _join(where, f"keys.{address}.{i}"), "a key recorded twice")
            recorded.add(public_key)
            for had, part in zip(parts, key_parts(public_key)):
                if part in had:
                    refuse("inconsistent", _join(where, f"keys.{address}.{i}"), "a part of an earlier key")
                had.add(part)


def held(state: dict) -> int:
    """Everything that exists in a state, in mukrn: what accounts hold, and
    what is bonded."""
    return (sum(state["balances"].values())
            + sum(validator["stake"] for validator in state["validators"])
            + sum(delegation["amount"] for delegation in state["delegations"].values())
            + sum(leaving["amount"] for leaving in state["delegation_unbonding"])
            + sum(attestation["bond"] for attestation in state["attestations"].values())
            + sum(proposal.get("bond", 0) for track in PHASES for proposal in state["governance"][track]))


def _supply(state, cx, where):
    if state["total_supply"] != held(state):
        refuse("inconsistent", _join(where, "total_supply"), f"not the sum of what exists, {number(held(state))}")


def _delegations_name_validators(state, cx, where):
    listed = set(_listed(state))
    pairs = [(f"delegations.{delegator}", delegator, delegation["validator"])
             for delegator, delegation in state["delegations"].items()]
    pairs += [(f"delegation_unbonding.{i}", leaving["delegator"], leaving["validator"])
              for i, leaving in enumerate(state["delegation_unbonding"])]
    for there, delegator, validator in pairs:
        if validator not in listed or validator == delegator:
            refuse("inconsistent", _join(where, there), "not a validator other than the delegator")


def _nothing_ahead(state, cx, where):
    levels: list[tuple[str, int]] = []
    for delegator, delegation in state["delegations"].items():
        levels += [(f"delegations.{delegator}", tranche["level"]) for tranche in delegation["tranches"]]
    for i, leaving in enumerate(state["delegation_unbonding"]):
        levels += [(f"delegation_unbonding.{i}", leaving["unbonding_from"])]
        levels += [(f"delegation_unbonding.{i}", tranche["level"]) for tranche in leaving["tranches"]]
    for identifier, attestation in state["attestations"].items():
        levels += [(f"attestations.{identifier}", attestation[name]) for name in ("issued_at", "revoked_at")
                   if name in attestation]
    levels += [(f"consensus_slashes.{i}", vote["level"]) for i, vote in enumerate(state["consensus_slashes"])]
    for track in PHASES:
        for i, proposal in enumerate(state["governance"][track]):
            there = f"governance.{track}.{i}"
            levels += [(there, proposal["ended_at"])] if "ended_at" in proposal else []
            levels += [(there, double["level"]) for double in proposal.get("double_votes", [])]
    for there, level in levels:
        if level > state["level"]:
            refuse("inconsistent", _join(where, there), "a level above the level of the state")


def _unbonding_is_due_later(state, cx, where):
    period = state["constants"]["delegation_unbonding_blocks"]
    leaving = state["delegation_unbonding"]
    for i, entry in enumerate(leaving):
        if entry["release_at"] != entry["unbonding_from"] + period or entry["release_at"] <= state["level"]:
            refuse("inconsistent", _join(where, f"delegation_unbonding.{i}.release_at"), "not the level it is due")
    if any(b["unbonding_from"] < a["unbonding_from"] for a, b in zip(leaving, leaving[1:])):
        refuse("inconsistent", _join(where, "delegation_unbonding"), "not in the order in which they ended")


def _bonds_are_released(state, cx, where):
    period = state["constants"]["attestation_unbonding_blocks"]
    for identifier, attestation in state["attestations"].items():
        if "revoked_at" in attestation and attestation["revoked_at"] + period <= state["level"] \
                and attestation["bond"] != 0:
            refuse("inconsistent", _join(where, f"attestations.{identifier}.bond"), "a bond that is overdue")


def _slashed_votes(state, cx, where):
    period = state["constants"]["delegation_unbonding_blocks"]
    seen = set()
    for i, vote in enumerate(state["consensus_slashes"]):
        offence = (vote["validator"], vote["kind"], vote["level"], vote["round"])
        if offence in seen:
            refuse("inconsistent", _join(where, f"consensus_slashes.{i}"), "the same vote twice")
        seen.add(offence)
        if vote["level"] + period <= state["level"]:
            refuse("inconsistent", _join(where, f"consensus_slashes.{i}"), "a vote too old to be kept")


def _proposals_in_order(state, cx, where):
    for track in PHASES:
        proposals = state["governance"][track]
        identifiers = [proposal["proposal_id"] for proposal in proposals]
        if len(set(identifiers)) != len(identifiers):
            refuse("inconsistent", _join(where, f"governance.{track}"), "an identifier twice")
        if any(b["submitted_at"] < a["submitted_at"] for a, b in zip(proposals, proposals[1:])):
            refuse("inconsistent", _join(where, f"governance.{track}"), "not in the order of submission")


def _bonds_of_proposals(state, cx, where):
    for track in PHASES:
        for i, proposal in enumerate(state["governance"][track]):
            if "bond" in proposal and proposal["bond"] != state["constants"][track + "_bond"]:
                refuse("inconsistent", _join(where, f"governance.{track}.{i}.bond"), "not the bond of its track")


def _phases_are_current(state, cx, where):
    for track in PHASES:
        for i, proposal in enumerate(state["governance"][track]):
            if proposal["phase"] in OVER[track]:
                continue
            start, end = phase_window(track, proposal, state["constants"])
            if not start <= state["level"] < end:
                refuse("inconsistent", _join(where, f"governance.{track}.{i}.phase"), "not the phase of this level")


def _over(state: dict):
    """The proposals of a state that are over, each with its track and where it stands."""
    for track in PHASES:
        for i, proposal in enumerate(state["governance"][track]):
            if proposal["phase"] in OVER[track] and "ended_at" in proposal:
                yield track, f"governance.{track}.{i}", proposal


def _released(state: dict):
    """The payments of a state that a guardian other than the first has released."""
    for i, proposal in enumerate(state["governance"]["treasury"]):
        if "released_by" in proposal:
            yield f"governance.treasury.{i}.released_by", proposal


def _released_by_another_guardian(state, cx, where):
    for there, proposal in _released(state):
        if proposal["released_by"] not in state["guardians"][1:]:
            refuse("inconsistent", _join(where, there), "not a guardian other than the first")


def _released_after_the_delay(state, cx, where):
    constants = state["constants"]
    for there, proposal in _released(state):
        voted = phase_ends("treasury", proposal, constants)["voting"]
        if voted + constants["guardian_delay_blocks"] > state["level"]:
            refuse("inconsistent", _join(where, there), "released before the delay had passed")


def _ended_in_time(state, cx, where):
    for track, there, proposal in _over(state):
        if not ended_in_time(track, proposal, state["constants"]):
            refuse("inconsistent", _join(where, there + ".ended_at"), "not a level at which it could end")


def _proposals_leave(state, cx, where):
    period = state["constants"]["delegation_unbonding_blocks"]
    for _track, there, proposal in _over(state):
        if proposal["ended_at"] + period <= state["level"]:
            refuse("inconsistent", _join(where, there), "a proposal over for too long")


def _voters_are_validators(state, cx, where):
    """A double vote needs no check of its own: its voter has a vote in
    the same phase, which the table of the proposal requires."""
    listed = set(_listed(state))
    voters: list[tuple[str, str]] = []
    for i, proposal in enumerate(state["governance"]["protocol"]):
        there = f"governance.protocol.{i}"
        voters += [(there, voter) for name in ("exploration_votes", "adoption_votes") for voter in proposal[name]]
    for i, proposal in enumerate(state["governance"]["treasury"]):
        voters += [(f"governance.treasury.{i}", voter) for voter in proposal["votes"]]
    voters += [(f"consensus_slashes.{i}", vote["validator"]) for i, vote in enumerate(state["consensus_slashes"])]
    for there, voter in voters:
        if voter not in listed:
            refuse("inconsistent", _join(where, there), "not a validator")


STATE = Obj("state", [
    ("level", LEVEL, "required"),
    ("chain_id", CHAIN, "required"),
    ("state_root_function", Choice(("json", "trie")), "required"),
    ("total_supply", AMOUNT, "required"),
    ("treasury_address", ADDRESS, "required"),
    ("guardians", List(ADDRESS, 3, LIMITS["guardians"]), "required"),
    ("balances", Map(ADDRESS, POSITIVE, 0, None), "required"),
    ("nonces", Map(ADDRESS, Int(1, INT_MAX), 0, None), "required"),
    ("contracts", Map(ADDRESS, CONTRACT, 0, None), "required"),
    ("keys", Map(ADDRESS, List(KEY_ENTRY, 1, None), 0, None), "required"),
    ("validators", List(VALIDATOR, 1, LIMITS["validators"]), "required"),
    ("consensus_set", List(VALIDATOR, 1, LIMITS["validators"]), "required"),
    ("delegations", Map(ADDRESS, DELEGATION, 0, None), "required"),
    ("delegation_unbonding", List(UNBONDING, 0, None), "required"),
    ("attestations", Map(HASH, ATTESTATION, 0, None), "required"),
    ("consensus_slashes", List(SLASHED_VOTE, 0, None), "required"),
    ("governance", GOVERNANCE, "required"),
    ("parameters", STATE_PARAMETERS, "required"),
    ("constants", CONSTANTS, "required"),
], [
    ("`validators` holds an address once, and `consensus_set` holds the same addresses in the same order.",
     _validators_once),
    ("The weight of a validator in `consensus_set` is not above its stake plus the amounts delegated to it.",
     _weights_are_backed),
    ("Every validator has a key in `keys`.", _validators_have_keys),
    ("An address of `contracts` is not in `keys`.", _one_kind),
    ("`treasury_address` is not in `keys`.", _treasury_has_no_key),
    ("`guardians` holds an address once.", _guardians_once),
    ("A guardian is not `treasury_address`, an address of `contracts` or a validator.", _guardians_only_guard),
    ("Every address of `nonces` is in `keys`, and every address of `keys` is in `nonces` or is a validator.",
     _who_has_a_key),
    ("In `keys`, the levels `from` of an address grow, and none is above `level` plus 1.", _levels_of_keys),
    ("The first key of an address is the key whose hash is that address.", _first_key),
    ("A key stands once in `keys`, and no key of an address has the ML-DSA part or the Ed25519 part of an earlier "
     "key of that address.", _keys_once),
    ("`total_supply` is the sum of `balances`, of the stakes of `validators`, of the amounts of `delegations` and of "
     "`delegation_unbonding`, of the bonds of `attestations` and of the bonds of the proposals of `governance`.",
     _supply),
    ("A delegation names a validator other than its delegator, and so does a delegation that is unbonding.",
     _delegations_name_validators),
    ("Nothing happened after `level`: the level of a tranche, `unbonding_from`, `issued_at`, `revoked_at`, the level "
     "of a slashed vote, `ended_at` and the level of a double vote are not above it.", _nothing_ahead),
    ("A delegation that is unbonding is released `delegation_unbonding_blocks` levels after `unbonding_from`, at a "
     "level above `level`, and the list is in the order in which the delegations ended.", _unbonding_is_due_later),
    ("An attestation revoked `attestation_unbonding_blocks` levels before `level`, or earlier, holds no bond.",
     _bonds_are_released),
    ("No two slashed votes are of the same validator, kind, level and round, and none is "
     "`delegation_unbonding_blocks` levels old or more.", _slashed_votes),
    ("The proposals of a track are in the order of their submission, and no two have the same `proposal_id`.",
     _proposals_in_order),
    ("The bond of a proposal is `protocol_bond` or `treasury_bond`, as its track says.", _bonds_of_proposals),
    ("A proposal that is not over is in the phase of its level: that phase started at `level` or before, and ends "
     "above it.", _phases_are_current),
    ("`released_by` is a guardian other than the first.", _released_by_another_guardian),
    ("When `released_by` is present, the end of `voting` plus `guardian_delay_blocks` is not above `level`.",
     _released_after_the_delay),
    ("A protocol proposal that is over ended when a vote did: at the end of `adoption` if it is activated, of "
     "`exploration` or of `adoption` if it is rejected. A treasury proposal that is over ended at the end of "
     "`voting` or while it waited: after the end of `voting` if it is executed, and not after the end of `passed`.",
     _ended_in_time),
    ("A proposal that is over ended less than `delegation_unbonding_blocks` levels before `level`.",
     _proposals_leave),
    ("A vote and a slashed vote are those of a validator.", _voters_are_validators),
])


def _hashes_together(account, cx, where):
    if ("code_hash" in account) != ("storage_root" in account):
        refuse("inconsistent", where, "code_hash and storage_root go together")


ACCOUNT = Obj("account", [
    ("balance", AMOUNT, "required"),
    ("nonce", NONCE, "required"),
    ("code_hash", HASH, "optional"),
    ("storage_root", HASH, "optional"),
], [
    ("`code_hash` and `storage_root` are present together.", _hashes_together),
])


# -- the genesis --------------------------------------------------------------

EMPTY_AT_FIRST = ("nonces", "contracts", "delegations", "delegation_unbonding", "attestations", "consensus_slashes")


def _starts_at_zero(genesis, cx, where):
    if genesis["state"]["level"] != 0:
        refuse("inconsistent", _join(where, "state.level"), "not 0")


def _nothing_yet(genesis, cx, where):
    state = genesis["state"]
    for name in EMPTY_AT_FIRST:
        if state[name]:
            refuse("inconsistent", _join(where, f"state.{name}"), "not empty")
    for track in PHASES:
        if state["governance"][track]:
            refuse("inconsistent", _join(where, f"state.governance.{track}"), "not empty")


def _keys_of_validators(genesis, cx, where):
    """Every key of a validator is current from level 0. There is then one
    only, since the levels of the keys of an address grow."""
    state = genesis["state"]
    for address in _listed(state):
        if any(entry["from"] != 0 for entry in state["keys"].get(address, [])):
            refuse("inconsistent", _join(where, f"state.keys.{address}"), "not one key, current from level 0")


def _snapshot_is_the_set(genesis, cx, where):
    if genesis["state"]["consensus_set"] != genesis["state"]["validators"]:
        refuse("inconsistent", _join(where, "state.consensus_set"), "not validators")


class Genesis(Obj):
    """A genesis is read on the network it names: its `network_id` is in
    the checksum of every address it holds, whatever network the reader
    had in mind."""

    def check(self, value, cx, where):
        if isinstance(value, dict) and "network_id" in value:
            NETWORK.check(value["network_id"], cx, _join(where, "network_id"))
            cx = Context(bytes.fromhex(value["network_id"]))
        super().check(value, cx, where)


GENESIS = Genesis("genesis", [
    ("version", Int(1, 1), "required"),
    ("scheme", Int(1, 1), "required"),
    ("network_id", NETWORK, "required"),
    ("timestamp", TIME, "required"),
    ("state", STATE, "required"),
], [
    ("The `level` of `state` is 0.", _starts_at_zero),
    ("`nonces`, `contracts`, `delegations`, `delegation_unbonding`, `attestations`, `consensus_slashes` and the two "
     "lists of `governance` are empty.", _nothing_yet),
    ("Each validator has one key, current from level 0.", _keys_of_validators),
    ("`consensus_set` is `validators`.", _snapshot_is_the_set),
])

SCHEMAS.update({"state": STATE, "account": ACCOUNT, "genesis": GENESIS})

CHAPTER_2 = (STATE, CONTRACT, KEY_ENTRY, VALIDATOR, DELEGATION, TRANCHE, UNBONDING, ATTESTATION, SLASHED_VOTE,
             GOVERNANCE, PROTOCOL_PROPOSAL, DOUBLE_VOTE, TREASURY_PROPOSAL, STATE_PARAMETERS, CONSTANTS, ACCOUNT,
             GENESIS)


def state_root(network_id: bytes, state: dict) -> bytes:
    """The root of a state, by the function the state names (note, section 4.6)."""
    return ref.state_root(network_id, state)


def accounts(network_id: bytes, state: dict) -> dict[str, dict]:
    """The accounts of a state, as the state trie holds them: one for each
    address of `balances`, `nonces` or `contracts`."""
    addresses = sorted(set().union(*(state[name] for name in ref.ACCOUNT_MAPS)))
    return {address: ref.account_object(network_id, state, address) for address in addresses}


FIRST_PARENT = "0" * 96


def first_header(genesis: dict) -> dict:
    """The nine fields of the block of level 0. Nobody signs it and it does
    not travel: a node computes it from its genesis."""
    network_id, state = bytes.fromhex(genesis["network_id"]), genesis["state"]
    nothing = ref.merkle_root(network_id, []).hex()
    return {"version": 1, "level": 0, "payload_round": 0, "timestamp": genesis["timestamp"],
            "parent_hash": FIRST_PARENT, "state_root": state_root(network_id, state).hex(),
            "txs_root": nothing, "witness_root": nothing, "proposer": state["validators"][0]["address"]}


# The same nine fields, as the document describes them.
FIRST_HEADER = [
    ("`version`", "1"),
    ("`level`", "0"),
    ("`payload_round`", "0"),
    ("`timestamp`", "the `timestamp` of the genesis"),
    ("`parent_hash`", "96 zeros"),
    ("`state_root`", "the root of the first state"),
    ("`txs_root`", "the root of a tree with no item"),
    ("`witness_root`", "the same root"),
    ("`proposer`", "the first address of `validators`"),
]


def first_block_hash(genesis: dict) -> bytes:
    """The hash of the block of level 0: the parent of the block of level 1."""
    return ref.H("kern.block", bytes.fromhex(genesis["network_id"]), ref.canonical_json(first_header(genesis)))


# -- what a block charges (section 9.16) --------------------------------------
# A block holds only transactions it charges. The rules below say when it
# does not: each one makes the block invalid. A schema verifies no signature,
# so the two rules of the note on signatures and keys are sentences of the
# document only.

BLOCK_RULES = {
    "block_too_large": "The sizes of its transactions add up to `max_block_bytes` at most.",
    "fee_under_floor": "When `fee_floor_enabled` is `true`, the fee of each transaction is at least "
                       "`fee_floor_base` plus `fee_floor_per_byte` times its size.",
    "wrong_chain": "The `chain_id` of each transaction is the `chain_id` of the state.",
    "wrong_nonce": "The `nonce` of each transaction is the nonce of its sender when its turn comes: the number of "
                   "transactions of that sender applied before it. A sender whose nonce is 2^63 - 1 sends nothing "
                   "more: its nonce could not go up.",
    "unpaid_fee": "The sender of each transaction holds its `fee` when its turn comes.",
    "sent_by_treasury": "No transaction is sent by `treasury_address`.",
}
SIGNATURE_RULES = [
    "The sender of each transaction has a key: the one `keys` holds for it, in which case the transaction carries "
    "no `public_key`, or the one the transaction carries, whose hash is the sender and which no address has had.",
    "Every signature verifies: `signature` with the key of the sender, and in a `rotate_key` `second_signature` "
    "with the new key.",
]


def _moved(table: dict, address: str, by: int) -> None:
    """A table of amounts after `by` is added to what an address holds. A
    balance of zero is not written."""
    now = table.get(address, 0) + by
    if now:
        table[address] = now
    else:
        table.pop(address, None)


def charge(state: dict, proposer: str, transactions: list[dict]) -> dict:
    """What a block of transfers does to the balances and the nonces of a
    state, or the rule that makes it invalid. `state` holds `chain_id`,
    `treasury_address`, `parameters`, `balances` and `nonces`.

    Each transaction pays its fee to the proposer and takes the next nonce
    of its sender, whatever its operation does next. A transfer whose
    sender does not hold the amount fails: it stays in the block, and has
    paid."""
    parameters = state["parameters"]
    if sum(transaction_size(tx) for tx in transactions) > parameters["max_block_bytes"]:
        return {"valid": False, "rule": "block_too_large"}
    balances, nonces = dict(state["balances"]), dict(state["nonces"])
    failed = []
    for i, tx in enumerate(transactions):
        floor = parameters["fee_floor_base"] + parameters["fee_floor_per_byte"] * transaction_size(tx)
        if parameters["fee_floor_enabled"] and tx["fee"] < floor:
            return {"valid": False, "rule": "fee_under_floor", "at": i}
        if tx["sender"] == state["treasury_address"]:
            return {"valid": False, "rule": "sent_by_treasury", "at": i}
        if tx["chain_id"] != state["chain_id"]:
            return {"valid": False, "rule": "wrong_chain", "at": i}
        if tx["nonce"] != nonces.get(tx["sender"], 0) or tx["nonce"] == INT_MAX:
            return {"valid": False, "rule": "wrong_nonce", "at": i}
        if balances.get(tx["sender"], 0) < tx["fee"]:
            return {"valid": False, "rule": "unpaid_fee", "at": i}
        _moved(balances, tx["sender"], -tx["fee"])
        _moved(balances, proposer, tx["fee"])
        nonces[tx["sender"]] = tx["nonce"] + 1
        if balances.get(tx["sender"], 0) < tx["amount"]:
            failed.append(i)
            continue
        _moved(balances, tx["sender"], -tx["amount"])
        _moved(balances, tx["recipient"], tx["amount"])
    return {"valid": True, "balances": balances, "nonces": nonces, "failed": failed}


# -- deciding proposals (section 9.16) ----------------------------------------

DECIDING_RULES = [
    "The proposals of the protocol track come first, then those of the treasury track; in each track they are "
    "taken in the order of the list.",
    "Each proposal is decided, and everything that follows from the decision is done, before the next one is "
    "looked at.",
    "A proposal whose vote does not pass is rejected.",
    "A protocol proposal whose second vote passes is activated: its `params` replace the parameters of those "
    "names, and its `swap` sets `state_root_function`. It is rejected instead when its `params` would leave "
    "`i_min_ppm` above `i_max_ppm`.",
    "A treasury proposal whose vote passes is not paid: it waits, in the phase `passed`, and its bond stays held.",
    "A payment that still waits at the end of `passed` is rejected.",
    "The bond of a proposal that is activated returns to its submitter. Half the bond of a proposal that is "
    "rejected is burned, rounded down, and `total_supply` is lowered by it; the rest goes to the treasury.",
]


def decide(before: dict, protocol: list[dict], treasury: list[dict]) -> dict:
    """What the proposals that are decided at a level do, taken in the
    order of their lists. `before` holds `parameters`,
    `state_root_function`, what the treasury holds (`treasury`) and the two
    bonds; a protocol proposal is its `payload` and whether its vote
    passes; a treasury proposal is the phase that ends, `voting` or
    `passed`, and when its vote ends whether it passes. Returns the phases
    the proposals are in afterwards, and what `before` has become, with
    what was burned. Nothing is paid here: a payment is made by the
    transaction of a guardian (`guard`)."""
    parameters = dict(before["parameters"])
    function, held_by_treasury, burned = before["state_root_function"], before["treasury"], 0
    phases: dict[str, list[str]] = {"protocol": [], "treasury": []}

    def lose(bond: int) -> None:
        nonlocal held_by_treasury, burned
        burned += bond // 2
        held_by_treasury += bond - bond // 2

    for proposal in protocol:
        after = {**parameters, **proposal["payload"].get("params", {})}
        if proposal["passes"] and after["i_min_ppm"] <= after["i_max_ppm"]:
            parameters = after
            function = proposal["payload"].get("to", function)
            phases["protocol"].append("activated")
        else:
            lose(before["protocol_bond"])
            phases["protocol"].append("rejected")
    for proposal in treasury:
        if proposal["phase"] == "voting" and proposal["passes"]:
            phases["treasury"].append("passed")
        else:
            lose(before["treasury_bond"])
            phases["treasury"].append("rejected")
    return {"protocol": phases["protocol"], "treasury": phases["treasury"], "parameters": parameters,
            "state_root_function": function, "treasury_holds": held_by_treasury, "burned": burned}


# -- what a guardian does (section 9.16) ---------------------------------------
# A payment that waits is paid or dropped by the transaction of a guardian.
# An operation that breaks one of these rules fails: it stays in its block,
# has paid its fee, and changes nothing else.

GUARDIAN_RULES = {
    "not_a_guardian": "Its sender is a guardian.",
    "not_waiting": "It names a proposal of the treasury track whose `phase` is `passed`.",
    "not_the_first": "Only the first guardian cancels.",
    "too_early": "A guardian other than the first releases a payment in a block whose level is the end of `voting` "
                 "plus `guardian_delay_blocks`, or higher.",
    "released_twice": "A guardian other than the first releases a payment once.",
    "unfunded": "A release that pays finds the sum of the amounts of the payment in the treasury. Otherwise it "
                "fails, and the payment goes on waiting.",
}


def guard(before: dict, operations: list[dict]) -> dict:
    """What the transactions of guardians in a block do to the payments
    that wait. `before` holds the level of the block (`level`), the
    `guardians`, what the treasury holds (`treasury`), `treasury_bond`,
    `guardian_delay_blocks`, and the treasury proposals by identifier
    (`payments`): each one is its `phase` as the block finds it, the level
    at which its vote ended (`voted`), the sum of its amounts (`total`),
    the part of that sum whose recipient is the treasury itself
    (`to_itself`) and, where there is one, `released_by`. An operation is
    its `sender`, its `kind` and the `proposal_id` it names.

    Returns what each operation did, `paid`, `recorded` or `cancelled`, or
    the rule that makes it fail; then what the treasury holds, what was
    burned, and each payment as the operations leave it."""
    guardians = before["guardians"]
    held_by_treasury, burned = before["treasury"], 0
    payments = {identifier: dict(payment) for identifier, payment in before["payments"].items()}
    did: list[str] = []
    for operation in operations:
        sender, payment = operation["sender"], payments.get(operation["proposal_id"])
        if sender not in guardians:
            did.append("not_a_guardian")
            continue
        if payment is None or payment["phase"] != "passed":
            did.append("not_waiting")
            continue
        first = sender == guardians[0]
        if operation["kind"] == "cancel_payment":
            if not first:
                did.append("not_the_first")
                continue
            burned += before["treasury_bond"] // 2
            held_by_treasury += before["treasury_bond"] - before["treasury_bond"] // 2
            payment["phase"] = "rejected"
            payment.pop("released_by", None)
            did.append("cancelled")
            continue
        if not first:
            if before["level"] < payment["voted"] + before["guardian_delay_blocks"]:
                did.append("too_early")
                continue
            if payment.get("released_by") == sender:
                did.append("released_twice")
                continue
            if "released_by" not in payment:
                payment["released_by"] = sender
                did.append("recorded")
                continue
        if payment["total"] > held_by_treasury:
            did.append("unfunded")
            continue
        held_by_treasury -= payment["total"] - payment["to_itself"]
        payment["phase"] = "executed"
        payment.pop("released_by", None)
        did.append("paid")
    return {"did": did, "treasury_holds": held_by_treasury, "burned": burned,
            "payments": {identifier: {name: payment[name] for name in ("phase", "released_by") if name in payment}
                         for identifier, payment in payments.items()}}


# -- one request for blocks at a time (section 9.8) ---------------------------

ASKING_RULES = [
    "A node has one `get_blocks` waiting on a connection at most: it sends no other before the answer comes.",
    "A `blocks` frame is the answer to the request that waits. A node that receives one while none waits refuses "
    "it, as it refuses an answer that breaks one of the two rules it can check.",
    "A node answers the requests of a connection in the order it receives them.",
    "A node that reads four bytes that announce more than a frame can hold closes the connection: it reads no "
    "further, so it cannot tell where the next frame would start.",
]


def exchange(steps: list[dict]) -> list[str]:
    """What happens on a connection, as the node that asks sees it. A step
    is a request the node sends (`ask`: the first and the last level), a
    `blocks` frame it receives (`blocks`: the levels of its blocks), or the
    four bytes it reads before a frame (`prefix`, in hexadecimal). Each
    step is `accepted` or `refused`; after four bytes that announce too
    much the connection is `closed`, and so is every step that follows."""
    verdicts: list[str] = []
    waiting: tuple[int, int] | None = None
    closed = False
    for step in steps:
        if closed:
            verdicts.append("closed")
        elif "ask" in step:
            verdicts.append("refused" if waiting else "accepted")
            waiting = waiting or (step["ask"][0], step["ask"][1])
        elif "blocks" in step:
            answer_to = waiting and answer_verdict(waiting[0], waiting[1], step["blocks"])
            verdicts.append("accepted" if answer_to == "accepted" else "refused")
            if answer_to == "accepted":
                waiting = None
        else:
            try:
                announced(bytes.fromhex(step["prefix"]))
                verdicts.append("accepted")
            except Refused:
                verdicts.append("refused")
                closed = True
    return verdicts


def serve(held: Mapping[int, int], requests: list[tuple[int, int]]) -> list[list[int]]:
    """What a node sends on a connection on which it received these
    requests: one answer for each, in the order it received them."""
    return [answer(held, first, last) for first, last in requests]


# ---------------------------------------------------------------------------
# Reception
# ---------------------------------------------------------------------------

def json_nesting(text: bytes) -> int:
    """How deep arrays and objects nest in a JSON text, read on its bytes:
    `[` and `{` open a level, `]` and `}` close one, and what stands
    between two quotes is a string and opens nothing."""
    depth = deepest = 0
    in_string = escaped = False
    for byte in text:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return deepest


def receive(schema: str, text: bytes, network_id: bytes) -> Any:
    """What a node does with bytes received from outside, a frame or the
    body of a request that injects a transaction: their length, then the
    nesting, measured before anything is decoded, then the canonical
    encoding, then the schema. Returns the value, or raises Refused."""
    longest = {"frame": LIMITS["frame_bytes"], "transaction": LIMITS["transaction_bytes"]}.get(schema)
    if longest is not None and len(text) > longest:
        refuse("too_long", "", f"{number(len(text))} bytes")
    if json_nesting(text) > LIMITS["json_nesting"]:
        refuse("too_deep", "", f"a text nested more than {LIMITS['json_nesting']} deep")
    try:
        value = ref.decode_canonical(text)
    except ValueError as exc:
        refuse("not_canonical", "", str(exc))
    check(schema, value, network_id)
    return value


def check(schema: str, value: Any, network_id: bytes) -> None:
    """Raises Refused unless `value` is an object of `schema` on this network."""
    SCHEMAS[schema].check(value, Context(network_id), "")


def verdict(schema: str, value: Any, network_id: bytes) -> str:
    """`accepted`, or the code of the rule that refuses the value."""
    try:
        check(schema, value, network_id)
    except Refused as refusal:
        return refusal.rule
    return "accepted"


# ---------------------------------------------------------------------------
# The tables of the document (docs/api-stability.md, section 9)
# ---------------------------------------------------------------------------

def _kind_cell(kind: str, name: str) -> str:
    """A cell of the table of kinds: empty when the kind does not have the
    field, `table below` when its `params` have a table of their own."""
    if name not in KINDS[kind]:
        return ""
    type_ = KINDS[kind][name]
    return "table below" if isinstance(type_, (Obj, Variants)) else type_.cell()


def tables() -> dict[str, list[tuple[str, ...]]]:
    """Every table of the document that states a schema, by the heading it
    stands under, as rows of cells. tests/test_schema_vectors.py compares
    the document with this."""
    out: dict[str, list[tuple[str, ...]]] = {}
    out["Limits"] = [(f"`{name}`", number(value)) for name, value in LIMITS.items()]
    out["Types"] = [(f"`{t.name}`", t.json, t.words()) for t in NAMED_TYPES]
    common = TRANSACTION.variants["transfer"]
    kind_fields = {name for fields in KINDS.values() for name in fields}
    out["Fields of every transaction"] = [
        (f"`{name}`", "one of the fifteen kinds below" if name == "kind" else type_.cell(),
         "signed" if name not in WITNESS_FIELDS else "witness", presence)
        for name, type_, presence in common.fields if name not in kind_fields
    ] + [("`second_signature`", SIGNATURE.cell(), "witness", "required in `rotate_key`, absent elsewhere")]
    out["Fields by kind"] = [
        (f"`{kind}`",) + tuple(_kind_cell(kind, name) for name in KIND_FIELDS)
        for kind in KINDS
    ]
    for kind, params in PARAMS.items():
        out[f"`params` of `{kind}`"] = params.rows()
    out["`params` of `governance_propose`"] = [
        ("`track`", PROPOSAL.variants["protocol"].fields[0][1].cell(), "required"),
        ("`payload`", "`protocol payload` or `treasury payload`, as `track` says", "required"),
        ("`salt`", PROPOSAL.variants["protocol"].fields[2][1].cell(), "required"),
    ]
    for obj in (PROTOCOL_PAYLOAD, PARAMETERS, TREASURY_PAYLOAD, RECIPIENT, VOTE, PROPOSE, CERTIFICATE, HEADER,
                BLOCK, FINAL_BLOCK):
        out[obj.name[0].upper() + obj.name[1:]] = obj.rows()
    for kind, frame in FRAMES.items():
        out[f"Frame `{kind}`"] = [row for row in frame.rows() if row[0] != "`kind`"]
    for obj in CHAPTER_2:
        out[heading(obj)] = obj.rows()
    out["Block of level 0"] = list(FIRST_HEADER)
    out["Ends of phases"] = [
        (track, f"`{phase}`",
         (f"the end of `{PHASES[track][i - 1][0]}`" if i else "`submitted_at`") + f" plus `{blocks}`")
        for track in PHASES for i, (phase, blocks) in enumerate(PHASES[track])]
    return out


def heading(obj: Obj) -> str:
    """The heading a table stands under in the document: the name of its
    object, with a capital."""
    return obj.name[0].upper() + obj.name[1:]


def depths() -> list[tuple[str, str]]:
    """How deep each object can nest, as the document lists it."""
    rows = [(f"`{kind}`", TRANSACTION.variants[kind].depth()) for kind in KINDS]
    rows += [(name, SCHEMAS[name].depth()) for name in ("vote", "propose message", "certificate", "header", "block",
                                                         "final block")]
    rows += [(f"frame `{kind}`", frame.depth()) for kind, frame in FRAMES.items()]
    rows += [(name, SCHEMAS[name].depth()) for name in ("state", "genesis")]
    return [(name if name.startswith("`") or name.startswith("frame") else f"`{name}`", str(depth))
            for name, depth in rows]


def rules() -> dict[str, list[str]]:
    """The sentences of the document that state a rule tying fields
    together, by the heading they stand under."""
    out = {obj.name[0].upper() + obj.name[1:]: [sentence for sentence, _ in obj.rules]
           for obj in (PROTOCOL_PAYLOAD, PARAMETERS, TREASURY_PAYLOAD, PROPOSE, BLOCK, FINAL_BLOCK)}
    out["Fields of every transaction"] = [sentence for sentence, _ in TRANSACTION.variants["transfer"].rules]
    for kind, frame in FRAMES.items():
        if frame.rules:
            out[f"Frame `{kind}`"] = [sentence for sentence, _ in frame.rules]
    out["Answering `get_blocks`"] = [sentence for sentence, _ in ANSWER_RULES] + ANSWERING_RULES
    out["One request at a time"] = list(ASKING_RULES)
    for obj in CHAPTER_2:
        if obj.rules:
            out[heading(obj)] = [sentence for sentence, _ in obj.rules]
    out["What a block charges"] = list(BLOCK_RULES.values()) + SIGNATURE_RULES
    out["Deciding proposals"] = list(DECIDING_RULES)
    out["What a guardian does"] = list(GUARDIAN_RULES.values())
    return out

