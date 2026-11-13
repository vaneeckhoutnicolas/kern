# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The schemas of structure version 1, written with the standard library.

Not a test file and not the node. docs/api-stability.md, section 9, gives
every object of structure version 1 its fields, their types and their
bounds. This file is that section as executable text: the tables of the
document are compared with the tables below, and tests/schema_vectors.py
builds tests/vectors/kern/schemas.json with it, which the Go program kept
next to that file checks with tables of its own, written independently.

Chapter 1 of three: what is signed and what travels. Transactions, block
headers, blocks, consensus messages, certificates, the frames peers
exchange and the body of an injection request. The state, the key
registry and the genesis are chapter 2; the objects hashed outside blocks
are chapter 3.

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
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))      # the reference of the profile stands next to this file

import profile_reference as ref                               # noqa: E402

# ---------------------------------------------------------------------------
# The limits of structure version 1
# ---------------------------------------------------------------------------

LIMITS = {
    "json_nesting": 64,                 # arrays and objects in any JSON text received, measured before decoding
    "transaction_nesting": 32,          # arrays and objects in a transaction, itself included
    "frame_bytes": 16_777_216,          # a frame between peers
    "transaction_bytes": 131_072,       # the size of a transaction: its canonical encoding, witness included
    "block_bytes": 8_388_608,           # the sizes of the transactions of a block, added up
    "certificate_signatures": 1_024,    # the signatures of a certificate
    "code_bytes": 65_536,               # the source of a contract
    "value_bytes": 4_096,               # a text held by a contract
    "contract_fields": 256,             # the entries of `initial_storage`, or of the `params` of a call
    "claim_bytes": 16_384,              # the canonical encoding of a claim
    "recipients": 64,                   # the recipients of a treasury proposal
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
    high: int
    json = "object"

    def check(self, value, cx, where):
        if not isinstance(value, dict):
            refuse("wrong_type", where, "an object")
        if not low_high(len(value), self.low, self.high):
            refuse("out_of_range", where, self.cell())
        for key, item in value.items():
            self.key.check(key, cx, _join(where, key))
            self.value.check(item, cx, _join(where, key))

    def words(self):
        return f"map of {self.key.cell()} to {self.value.cell()}, {number(self.low)} to {number(self.high)} entries"

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

NAMED_TYPES = [LEVEL, ROUND, NONCE, AMOUNT, GAS, TIME, ADDRESS, HASH, KEY, SIGNATURE, NETWORK, CHAIN, NAME,
               SCHEMA_NAME, SUBJECT, CODE, MEMO, VALUE, CLAIM, FIELDS]


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
        (f"`{name}`", "one of the thirteen kinds below" if name == "kind" else type_.cell(),
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
    return out


def depths() -> list[tuple[str, str]]:
    """How deep each object can nest, as the document lists it."""
    rows = [(f"`{kind}`", TRANSACTION.variants[kind].depth()) for kind in KINDS]
    rows += [(name, SCHEMAS[name].depth()) for name in ("vote", "propose message", "certificate", "header", "block",
                                                         "final block")]
    rows += [(f"frame `{kind}`", frame.depth()) for kind, frame in FRAMES.items()]
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
    return out

