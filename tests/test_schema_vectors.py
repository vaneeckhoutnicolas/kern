# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The schemas of structure version 1 are what the document says.

docs/api-stability.md, section 9, gives every object that is signed, that
travels or that is kept its fields, their types and their bounds, before
any of them is implemented. Three things hold that section, and this file
ties them together:

- tests/schema_reference.py, the section as executable text: every table
  and every rule of the document is compared with it here;
- tests/vectors/kern/schemas.json, built by tests/schema_vectors.py:
  objects that are accepted, objects that are refused and the rule that
  refuses each, what a block charges, what proposals decide, what the
  guardians of the treasury do and what two peers exchange, read back
  here as the Go program reads them;
- tests/vectors/kern/profile_check.go, which checks the same file with
  tables of its own; the continuous integration runs it.

Nothing below touches the node, which still writes the formats of
sections 2.1 to 2.7 of that document.
"""

from __future__ import annotations

import collections
import hashlib
import json
import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import profile_reference as ref
import schema_reference as sch
import schema_vectors as sv

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = (ROOT / "docs" / "api-stability.md").read_text(encoding="utf-8")
SECTION = DOCUMENT[DOCUMENT.index("\n## 9. Structure version 1\n"):DOCUMENT.index("\n## Reference\n")]
TEXT = sv.FILE.read_text(encoding="utf-8").replace("\r\n", "\n")       # git may have converted the line endings
FILE = json.loads(TEXT)
NETWORK = bytes.fromhex(FILE["network_id"])
PROFILE = json.loads(ref.VECTORS.read_text(encoding="utf-8"))
FROZEN = {entry["domain"]: entry for entry in PROFILE["objects"]}


@pytest.fixture(scope="module")
def read():
    """The file read as a second program reads it: directives carried out
    in the order of the file, each accepted object kept under its name."""
    vectors = sv.Vectors(NETWORK)
    accepted = []
    for record in FILE["accepted"]:
        vectors.objects[record["name"]] = vectors.expand(record["object"])
        accepted.append((record, vectors.objects[record["name"]]))
    schemas = {record["name"]: record["schema"] for record in FILE["accepted"]}
    refused = []
    for record in FILE["refused"]:
        if "from" in record:
            value = vectors.edited(vectors.objects[record["from"]], record.get("remove"), record.get("set"))
            refused.append((record, schemas[record["from"]], value))
        else:
            refused.append((record, record["schema"], vectors.expand(record["object"])))
    texts = [(record, vectors.expand(record["text"]).encode("utf-8"))
             for record in FILE["accepted_texts"] + FILE["refused_texts"]]
    return {"accepted": accepted, "refused": refused, "texts": texts, "objects": vectors.objects}


def by_name(name: str) -> dict:
    return next(record for record in FILE["accepted"] if record["name"] == name)


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------

def test_the_file_is_what_its_builder_writes():
    """Every vector is checked against the reference when the file is
    built: a file that is what the builder writes holds no vector the
    reference disagrees with."""
    assert sv.render(sv.build()) == TEXT
    assert TEXT.isascii()
    assert sv.pin(b"abc") == {"bytes": 3, "pin": hashlib.sha3_384(b"abc").digest()[:8].hex()}
    assert FILE["limits"] == sch.LIMITS and FILE["rules"] == sch.RULES and FILE["directives"] == sv.DIRECTIVES


def test_every_accepted_object_is_accepted_and_is_the_object_the_file_pins(read):
    assert len(read["accepted"]) == 100
    for record, value in read["accepted"]:
        assert sch.verdict(record["schema"], value, NETWORK) == "accepted", record["name"]
        encoding = ref.canonical_json(value)
        assert sv.pin(encoding) == {"bytes": record["bytes"], "pin": record["pin"]}, record["name"]
        # Received as bytes, an object of ordinary size gives the same value: its encoding is canonical.
        if record["bytes"] <= sch.LIMITS["transaction_bytes"]:
            assert sch.receive(record["schema"], encoding, NETWORK) == value, record["name"]


def test_every_refused_object_is_refused_by_the_rule_the_file_names(read):
    assert len(read["refused"]) == 325
    for record, schema, value in read["refused"]:
        assert sch.verdict(schema, value, NETWORK) == record["rule"], record["why"]
        assert sv.pin(ref.canonical_json(value)) == {"bytes": record["bytes"], "pin": record["pin"]}, record["why"]


def test_a_refused_object_is_a_change_or_two_away_from_an_accepted_one(read):
    """So that it is refused for the reason it gives: what it is made
    from is accepted, and it differs by what its vector says."""
    edited = [record for record in FILE["refused"] if "from" in record]
    assert len(edited) == 324
    for record in edited:
        assert 1 <= len(record.get("remove", [])) + len(record.get("set", {})) <= 3, record["why"]
    alone = [record for record in FILE["refused"] if "from" not in record]
    assert [record["why"] for record in alone] == ["the two largest blocks in one frame"]


def test_texts_are_received_as_the_file_says(read):
    assert len(read["texts"]) == 29
    for record, text in read["texts"]:
        assert sv.pin(text) == {"bytes": record["bytes"], "pin": record["pin"]}, record["why"]
        try:
            sch.receive(record["schema"], text, NETWORK)
            answer = "accepted"
        except sch.Refused as refusal:
            answer = refusal.rule
        assert answer == record.get("rule", "accepted"), record["why"]
    hello = FILE["accepted_texts"][0]
    assert hello["schema"] == "frame" and bytes.fromhex(hello["prefix"]) == hello["bytes"].to_bytes(4, "big")


# ---------------------------------------------------------------------------
# The four bytes of a frame
# ---------------------------------------------------------------------------

def test_the_four_bytes_of_a_frame_give_the_length_of_what_follows_and_are_not_counted(read):
    limit = sch.LIMITS["frame_bytes"]
    # Every accepted frame, object or text, comes with its four bytes: the length of its canonical JSON.
    frames = [record for record in FILE["accepted"] + FILE["accepted_texts"] if record["schema"] == "frame"]
    assert len(frames) == 17 and all(len(record["prefix"]) == 8 for record in frames)
    for record in frames:
        assert sch.announced(bytes.fromhex(record["prefix"])) == record["bytes"], record
        assert sch.frame_prefix(record["bytes"]).hex() == record["prefix"]
    # No other accepted record has them: they are not part of a transaction, a block or a certificate.
    others = [record for record in FILE["accepted"] + FILE["accepted_texts"] if record["schema"] != "frame"]
    assert others and not any("prefix" in record for record in others)
    # The largest frame fills the bound without them, and travels four bytes longer.
    largest = by_name("frame_blocks_largest")
    assert (largest["bytes"], largest["prefix"]) == (limit, "01000000")
    assert len(ref.canonical_json(read["objects"]["frame_blocks_largest"])) == limit
    assert sch.verdict("frame", read["objects"]["frame_blocks_largest"], NETWORK) == "accepted"

    assert len(FILE["prefixes"]) == 8
    for record in FILE["prefixes"]:
        four = bytes.fromhex(record["prefix"])
        assert len(four) == 4 and set(record) in ({"prefix", "announces", "why"}, {"prefix", "rule", "why"})
        if "rule" in record:
            with pytest.raises(sch.Refused) as refusal:
                sch.announced(four)
            assert refusal.value.rule == record["rule"] == "too_long"
        else:
            assert sch.announced(four) == record["announces"] <= limit
            assert sch.frame_prefix(record["announces"]) == four
    by_prefix = {record["prefix"]: record for record in FILE["prefixes"]}
    # The bound, to the unit; the order of the bytes; and a number without a sign.
    assert by_prefix["01000000"]["announces"] == limit and by_prefix["01000001"]["rule"] == "too_long"
    assert by_prefix["00000100"]["announces"] == 256 != int.from_bytes(bytes.fromhex("00000100"), "little")
    assert int.from_bytes(bytes.fromhex("80000000"), "big", signed=True) < 0 and "rule" in by_prefix["80000000"]
    assert by_prefix["00000000"]["announces"] == 0 and _text("an empty frame: four bytes that announce nothing, "
                                                           "and nothing")["rule"] == "not_canonical"
    # What the document says of them.
    frames_text = PARTS["9.8 Frames"]
    for sentence in ("The four bytes are a number without a sign, and they give exactly the number of bytes that follow "
                     "them.", "the four bytes are not counted", "after the four bytes `01 00 00 00`",
                     f"travels as {limit + 4:,} bytes", "A node that reads four bytes that announce more reads no further."):
        assert sentence in frames_text, sentence
    assert "the four bytes that announce it not counted" in PARTS["9.4 Receiving a text"]
    assert "without the four bytes that announce its length" in PARTS["Limits"]


# ---------------------------------------------------------------------------
# A request for blocks and its answer
# ---------------------------------------------------------------------------

def _frame_bytes(sizes: list[int]) -> int:
    """The canonical encoding of a `blocks` frame whose blocks have these sizes, counted without building it."""
    return sch.BLOCKS_FRAME_BYTES + sum(sizes) + max(0, len(sizes) - 1)


def test_what_a_node_answers_to_a_request_for_blocks(read):
    limit = sch.LIMITS["frame_bytes"]
    assert sch.BLOCKS_FRAME_BYTES == 29 == by_name("frame_blocks_none")["bytes"]
    # The count of the bytes is the count of a real frame: 29 bytes, the blocks, and a comma between two blocks.
    frame = read["objects"]["frame_blocks"]
    sizes = [len(ref.canonical_json(pair)) for pair in frame["blocks"]]
    assert len(sizes) >= 2 and _frame_bytes(sizes) == by_name("frame_blocks")["bytes"]
    largest = [len(ref.canonical_json(pair)) for pair in read["objects"]["frame_blocks_largest"]["blocks"]]
    assert len(largest) == 3 and _frame_bytes(largest) == limit

    assert len(FILE["answers"]) == 11
    for record in FILE["answers"]:
        held = {level: size for level, size in record["held"]}
        first, last, levels = record["from"], record["to"], record["levels"]
        assert len(held) == len(record["held"]) and 1 <= first <= last <= sch.INT_MAX, record["why"]
        assert sch.answer(held, first, last) == levels, record["why"]
        # The same answer, found another way: of all the runs that start at `from`, the longest one that the node
        # holds whole, that stops at `to`, and that fits.
        runs = [list(range(first, first + n)) for n in range(0, min(last - first + 1, len(held)) + 1)]
        fitting = [run for run in runs if all(level in held for level in run)
                   and _frame_bytes([held[level] for level in run]) <= limit]
        assert max(fitting, key=len) == levels, record["why"]
        # And it is an answer the node that asked accepts.
        assert sch.answer_verdict(first, last, levels) == "accepted", record["why"]
    whys = {record["why"]: record for record in FILE["answers"]}
    full = whys["three blocks that fill a frame of 16,777,216 bytes, to the byte, and a fourth that is held"]
    assert _frame_bytes([size for level, size in full["held"] if level in full["levels"]]) == limit
    over = whys["the same with one byte more in the third block: two blocks"]
    assert _frame_bytes([size for _, size in over["held"][:3]]) == limit + 1 and over["levels"] == [10, 11]
    hole = whys["a level is missing: the answer stops before it, and the blocks after it are not sent"]
    assert {level for level, _ in hole["held"]} > set(hole["levels"]) and 4 not in dict(map(tuple, hole["held"]))
    assert whys["the first level asked for is missing: an empty answer, although the node holds the next ones"][
        "levels"] == []
    assert whys["the two highest levels there are"]["levels"] == [sch.INT_MAX - 1, sch.INT_MAX]
    # No vector asks a node to send a block heavier than a frame: the limits of a block and of a certificate
    # rule it out (test_a_block_and_its_certificate_always_fit_in_a_frame).
    assert all(size <= by_name("frame_proposal_largest")["bytes"] for record in FILE["answers"]
               for _, size in record["held"])


def test_what_the_node_that_asked_accepts_as_an_answer(read):
    assert len(FILE["replies"]) == 13
    verdicts = []
    for record in FILE["replies"]:
        first, last, levels = record["from"], record["to"], record["levels"]
        assert sch.answer_verdict(first, last, levels) == record.get("rule", "accepted"), record["why"]
        verdicts.append(record.get("rule", "accepted"))
    assert verdicts.count("accepted") == 5 and set(verdicts) == {"accepted", "inconsistent"}
    # Each of the two rules, and the rule of the frame, refuses a vector that the two others let through.
    first_rule, second_rule = (holds for _, holds in sch.ANSWER_RULES)
    follow = lambda levels: all(b == a + 1 for a, b in zip(levels, levels[1:]))                     # noqa: E731
    alone = {"first": 0, "second": 0, "frame": 0}
    for record in FILE["replies"]:
        args = (record["from"], record["to"], record["levels"])
        broken = (not first_rule(*args), not second_rule(*args), not follow(record["levels"]))
        if sum(broken) == 1:
            alone[("first", "second", "frame")[broken.index(True)]] += 1
    assert all(alone.values()), alone

    # On frames, as two nodes exchange them.
    blocks = read["objects"]["frame_blocks"]
    levels = [pair["block"]["header"]["level"] for pair in blocks["blocks"]]
    assert len(levels) >= 2 and levels[0] >= 2

    def ask(first: int, last: int) -> dict:
        return {"kind": "get_blocks", "from": first, "to": last}

    for first, last in ((levels[0], levels[-1]), (levels[0], levels[-1] + 5), (levels[0], sch.INT_MAX)):
        sch.check_answer(ask(first, last), blocks, NETWORK)
    about_from, about_to = (sentence for sentence, _ in sch.ANSWER_RULES)
    assert "`from`" in about_from and "`to`" in about_to
    for first, last, sentence in ((levels[0] - 1, levels[-1], about_from), (levels[0] + 1, levels[-1], about_from),
                                  (levels[0], levels[-1] - 1, about_to), (levels[0], levels[0], about_to)):
        with pytest.raises(sch.Refused) as refusal:
            sch.check_answer(ask(first, last), blocks, NETWORK)
        assert refusal.value.rule == "inconsistent" and sentence in str(refusal.value), (first, last)
    # Each of the two frames is first a frame of its schema, whatever the levels say.
    fits = ask(levels[0], levels[-1])
    for request, reply in (({**fits, "more": 0}, blocks), (fits, {**blocks, "more": 0})):
        with pytest.raises(sch.Refused) as refusal:
            sch.check_answer(request, reply, NETWORK)
        assert refusal.value.rule == "unknown_field"
    # An empty answer answers any request, and each frame is first a frame of its schema.
    sch.check_answer(ask(1, 9), read["objects"]["frame_blocks_none"], NETWORK)
    sch.check_answer(read["objects"]["frame_get_blocks"], read["objects"]["frame_blocks_none"], NETWORK)
    for request, reply in ((ask(9, 1), blocks), (ask(0, 3), blocks), (blocks, blocks),
                           (ask(levels[0], levels[-1]), ask(levels[0], levels[-1])),
                           (ask(levels[0], levels[-1]), {**blocks, "blocks": blocks["blocks"][::-1]})):
        with pytest.raises(sch.Refused):
            sch.check_answer(request, reply, NETWORK)


def test_the_document_ties_an_answer_to_its_request():
    part = PARTS["Answering `get_blocks`"]
    assert [line[2:] for line in part.splitlines() if line.startswith("- ")] == sch.rules()["Answering `get_blocks`"]
    assert len(sch.ANSWER_RULES) == len(sch.ANSWERING_RULES) == 2
    for sentence in ("A frame that holds no block is 29 bytes", "each block after the first adds one byte more, a comma",
                     "is refused like a frame that is not of its schema",
                     "asks again from the level after the last one it received"):
        assert sentence in part, sentence
    # The frame keeps its one rule, and its text no longer states the answer by halves.
    assert "from the level `from` upward, and none when" not in SECTION
    # What a schema does not decide, and where it is decided.
    schema = PARTS["9.1 What a schema is"]
    for sentence in ("makes the block that holds it invalid too (note, section 6.3)", "it pays no fee",
                     "it stays there and pays its fee", "is a rule of the state: chapter 2 states it"):
        assert sentence in schema, sentence
    assert "neither follows from the other" in PARTS["Limits"]
    assert "is a rule of the state: chapter 2 says which combinations a network refuses" in PARTS["Parameters"]


def test_one_change_away_from_an_accepted_object_is_refused(read):
    """The mutations the file asks for: 2,782 objects, each one change
    away from an accepted one. All are refused but an accepted object
    without one of its optional members."""
    count = 0
    for record, value in read["accepted"]:
        if "mutations" not in record:
            continue
        asked = record["mutations"]
        for change, path, changed in sv.mutations(value, asked["maps"], asked["free"]):
            expected = "accepted" if change == "remove" and path in asked["optional"] else "refused"
            answer = sch.verdict(record["schema"], changed, NETWORK)
            assert (answer == "accepted") == (expected == "accepted"), (record["name"], change, path, answer)
            count += 1
    assert count == 2782
    optional = {(record["name"], path) for record, _ in read["accepted"] if "mutations" in record
                for path in record["mutations"]["optional"]}
    revoked = [f"attestations.{pair * 48}.revoked_at" for pair in ("a2", "a4")]
    assert optional == {
        ("transfer_first", "public_key"),
        ("propose_swap_and_parameter", "params.payload.params"),
        ("propose_treasury", "params.payload.memo"),
        ("propose_again", "valid_round"),
        # In a state: the level at which an attestation was revoked, one of two parameters of a proposal, a memo.
        ("state_full", revoked[0]),
        ("state_full", revoked[1]),
        ("state_full", "governance.protocol.3.payload.params.fee_floor_enabled"),
        ("state_full", "governance.protocol.3.payload.params.i_max_ppm"),
        ("state_full", "governance.treasury.1.payload.memo"),
    }
    # `ended_at` and `bond` of a proposal are optional in their table and tied by a rule: neither can be removed.
    assert not any(path.endswith((".ended_at", ".bond")) for _, path in optional)
    # Inside a block or a frame nothing is optional: a public key removed changes the witness root, and a
    # valid round removed leaves a proof without its reason.
    asked = {record["name"]: record["mutations"] for record, _ in read["accepted"] if "mutations" in record}
    removed = [path for change, path, _ in sv.mutations(read["objects"]["block"], [], asked["block"]["free"])
               if change == "remove"]
    assert "transactions.0.public_key" in removed
    assert asked["block"]["optional"] == asked["frame_proposal_again"]["optional"] == []


def test_what_the_vectors_cover():
    kinds = {record["object"]["kind"] for record in FILE["accepted"] if record["schema"] == "transaction"}
    assert kinds == set(sch.KINDS) and len(kinds) == 15
    frames = {record["object"]["kind"] for record in FILE["accepted"] if record["schema"] == "frame"}
    assert frames == set(sch.FRAMES) and len(frames) == 7
    assert {record["schema"] for record in FILE["accepted"]} == set(sch.SCHEMAS) - {"json"}
    texts = FILE["accepted_texts"] + FILE["refused_texts"]
    assert {record["schema"] for record in texts} == {"json", "frame", "transaction", "genesis"}
    # Every rule refuses at least one vector.
    shown = {record["rule"] for record in FILE["refused"] + FILE["refused_texts"]}
    assert shown == set(sch.RULES)
    # Most accepted objects ask for their mutations; the ones that do not are the large ones and the variants.
    assert sum("mutations" in record for record in FILE["accepted"]) == 41


# ---------------------------------------------------------------------------
# The profile: what an accepted object gives
# ---------------------------------------------------------------------------

def test_four_vectors_are_objects_of_the_profile_and_give_back_its_digests(read):
    objects = read["objects"]
    transfer = objects["transfer"]
    assert json.loads(sch.signed_transaction(transfer)) == FROZEN["kern.tx"]["object"]
    assert sch.signed_transaction(transfer).hex() == FROZEN["kern.tx"]["encoding"]
    assert by_name("transfer")["id"] == FROZEN["kern.tx"]["digest"]
    assert by_name("transfer")["signed"] == sch.signed_transaction(transfer).decode("utf-8")
    assert sch.signed_header(objects["header"]).hex() == FROZEN["kern.block"]["encoding"]
    assert by_name("header")["hash"] == FROZEN["kern.block"]["digest"]
    assert by_name("propose_swap")["proposal_id"] == FROZEN["kern.gov.id"]["digest"]
    assert by_name("attest")["attestation_id"] == FROZEN["kern.attestation.id"]["digest"]


def test_what_the_profile_computes_from_each_accepted_object(read):
    for record, value in read["accepted"]:
        assert {k: record[k] for k in sv.derived(record["name"], record["schema"], value, NETWORK)} == \
            sv.derived(record["name"], record["schema"], value, NETWORK), record["name"]
    # An identifier does not depend on the witness; a witness leaf does, and states what the witness holds.
    first, later = read["objects"]["transfer_first"], read["objects"]["transfer"]
    stripped = {k: v for k, v in first.items() if k != "public_key"}
    assert sch.transaction_id(NETWORK, first) == sch.transaction_id(NETWORK, stripped)
    assert sch.witness_leaf(NETWORK, first) != sch.witness_leaf(NETWORK, stripped)
    assert sch.transaction_size(first) - sch.transaction_size(stripped) == len(',"public_key":""') + 2651
    assert set(first) - set(later) == {"public_key"}
    rotate = read["objects"]["rotate_key"]
    flags = lambda tx: ("public_key" in tx) | 2 * ("second_signature" in tx)                 # noqa: E731
    assert [flags(tx) for tx in read["objects"]["block"]["transactions"]] == [1, 0, 2] and flags(rotate) == 2
    # The three sizes the document quotes.
    assert (by_name("transfer")["bytes"], by_name("transfer_first")["bytes"], by_name("rotate_key")["bytes"]) == \
        (4791, 7458, 11899)
    for size in ("4,791", "7,458", "11,899"):
        assert size in SECTION


def test_what_a_validator_signs_names_its_kind_and_never_its_signature(read):
    for name, context in (("preendorse", "kern.preendorse"), ("endorse", "kern.endorse"), ("propose", "kern.propose"),
                          ("propose_again", "kern.propose")):
        record = by_name(name)
        assert record["context"] == context and context in ref.PURPOSES
        signed = json.loads(record["signed"])
        assert "signature" not in signed and signed["kind"] == context.split(".")[1]
        assert ("valid_round" in signed) == (name == "propose_again")
    header = json.loads(by_name("header")["signed"])
    assert sorted(header) == sorted(sch.HEADER_FIELDS) and len(header) == 9


# ---------------------------------------------------------------------------
# The limits: each is reached by an accepted object and passed by a refused one
# ---------------------------------------------------------------------------

def _refused(why: str) -> dict:
    return next(record for record in FILE["refused"] + FILE["refused_texts"] if record["why"].startswith(why))


def _text(why: str) -> dict:
    return next(record for record in FILE["accepted_texts"] + FILE["refused_texts"] if record["why"].startswith(why))


def test_every_limit_is_reached_and_passed(read):
    limit, objects = sch.LIMITS, read["objects"]
    assert sch.nesting(objects["attest_deepest"]) == limit["transaction_nesting"] == 32
    assert _refused("a claim that takes the transaction to 33 levels")["rule"] == "too_deep"
    assert _text("64 arrays, one inside the other")["bytes"] == 2 * limit["json_nesting"] + 1
    assert _text("65 arrays, one inside the other")["rule"] == "too_deep"
    assert by_name("frame_blocks_largest")["bytes"] == limit["frame_bytes"]
    assert _refused("the same frame with one more digit in a round")["bytes"] == limit["frame_bytes"] + 1
    for name, what in (("frame_bytes", "a frame"), ("transaction_bytes", "the body of a request")):
        assert _text(f"{what} of {limit[name]:,} spaces")["rule"] == "not_canonical"
        assert _text(f"{what} of {limit[name] + 1:,} spaces")["rule"] == "too_long"
    assert by_name("transaction_largest")["bytes"] == limit["transaction_bytes"]
    assert _refused("a transaction of 131,073 bytes")["bytes"] == limit["transaction_bytes"] + 1
    sizes = [sch.transaction_size(tx) for tx in objects["block_largest"]["transactions"]]
    assert sizes == [limit["transaction_bytes"]] * 64 and sum(sizes) == limit["block_bytes"]
    assert _refused("one more transaction")["rule"] == "too_long"
    assert len(objects["certificate_1024"]["signatures"]) == limit["certificate_signatures"]
    assert _refused("a certificate of 1,025 signatures")["rule"] == "out_of_range"
    assert len(objects["originate_longest_code"]["code"]) == limit["code_bytes"]
    assert _refused("a code of 65,537 bytes")["rule"] == "bad_text"
    assert len(objects["call_values"]["params"]["long"]) == limit["value_bytes"]
    assert _refused("a field that holds a text of 4,097 bytes")["rule"] == "bad_text"
    assert len(objects["call_256_fields"]["params"]) == limit["contract_fields"]
    assert _refused("257 fields")["rule"] == "out_of_range"
    assert len(ref.canonical_json(objects["attest_largest_claim"]["params"]["claim"])) == limit["claim_bytes"]
    assert _refused("a claim of 16,385 bytes")["rule"] == "too_long"
    assert len(objects["propose_treasury_64"]["params"]["payload"]["recipients"]) == limit["recipients"]
    assert _refused("65 recipients")["rule"] == "out_of_range"
    assert sum(r["amount"] for r in objects["propose_treasury_total"]["params"]["payload"]["recipients"]) == sch.INT_MAX
    assert _refused("amounts that add up to 2^63")["rule"] == "out_of_range"


def test_both_ends_of_every_range_are_reached(read):
    """A block that holds a transaction outside its schema is invalid, so a
    client that refused what another accepts would split the chain as
    surely as one that accepted too much. For every range of the document
    the vectors hold an accepted object at each end."""
    objects, top = read["objects"], sch.INT_MAX
    low, high = objects["transfer_lowest"], objects["transfer_highest"]
    assert [(low[name], high[name]) for name in ("nonce", "fee", "gas_limit", "amount")] == [(0, top)] * 4
    assert (len(low["chain_id"]), len(high["chain_id"])) == (1, 64) and set("k0-9") == set(high["chain_id"])
    low, high = objects["header_lowest"], objects["header_highest"]
    assert [(low[name], high[name]) for name in ("level", "payload_round", "timestamp")] == \
        [(0, top), (0, sch.ROUND_MAX), (0, top)]
    votes = objects["slash_consensus_equivocation_ends"]["params"]
    assert [(votes[m]["level"], votes[m]["round"]) for m in ("msg_a", "msg_b")] == [(0, 0), (top, sch.ROUND_MAX)]
    assert (objects["propose_highest_round"]["round"], objects["propose"]["round"]) == (sch.ROUND_MAX, 0)
    one = objects["certificate_one"]
    assert (one["level"], one["round"], len(one["signatures"])) == (top, sch.ROUND_MAX, 1)
    assert (objects["frame_hello_genesis"]["level"], objects["frame_hello_highest"]["level"]) == (0, top)
    asked = [objects[name] for name in ("frame_get_one_block", "frame_get_last_block")]
    assert [(frame["from"], frame["to"]) for frame in asked] == [(1, 1), (top, top)]
    # Names: one character and 64, with every kind of character a name may have.
    names = objects["call_longest_names"]
    (parameter,) = names["params"]
    assert (len(names["entry"]), len(parameter), names["entry"][0]) == (64, 64, "_")
    assert objects["call_256_fields"]["entry"] == "f"
    assert {len(name) for name in objects["originate_256_fields"]["initial_storage"]} == {64}
    for holder in (objects["call_values"]["params"], objects["originate_values"]["initial_storage"]):
        assert (holder["low"], holder["high"], holder["open"], holder["shut"], holder["empty"]) == \
            (sch.INT_MIN, top, True, False, "")
        assert len(holder["long"]) == sch.LIMITS["value_bytes"] and not holder["note"].isascii()
    assert (objects["call"]["amount"], objects["call_values"]["amount"]) == (0, top)
    assert (objects["originate_one_byte"]["code"], objects["originate_no_storage"]["initial_storage"]) == ("x", {})
    # An attestation: both ends of its bond, of its names and of its claim.
    largest, smallest = objects["attest_largest_claim"], objects["attest_smallest"]
    assert (smallest["amount"], largest["amount"]) == (0, top)
    assert len(largest["params"]["schema_id"]) == 128 and set("Az09._-") <= set(largest["params"]["schema_id"])
    assert len(largest["params"]["subject"]) == 256 and set(largest["params"]["subject"]) == {" ", "~"}
    assert smallest["params"] == {"schema_id": "s", "subject": " ", "claim": {}}
    assert (objects["delegate_stake"]["amount"], objects["delegate_stake_highest"]["amount"]) == (1, top)
    # Governance: every parameter, both tracks, the three votes, one recipient and 64, a memo of one byte and of 256.
    lowest, highest = (objects[f"propose_parameters_{end}"]["params"] for end in ("low", "high"))
    for name, type_, _ in sch.PARAMETERS.fields:
        if isinstance(type_, sch.Int):
            assert (lowest["payload"]["params"][name], highest["payload"]["params"][name]) == (type_.low, type_.high)
    assert (lowest["payload"]["params"]["fee_floor_enabled"], highest["payload"]["params"]["fee_floor_enabled"]) == \
        (False, True)
    assert (lowest["salt"], highest["salt"]) == (0, top)
    treasury = {name: objects[name]["params"] for name in ("propose_treasury_one", "propose_treasury_total",
                                                           "propose_treasury_64")}
    assert (treasury["propose_treasury_one"]["salt"], treasury["propose_treasury_total"]["salt"]) == (0, top)
    assert [len(treasury[name]["payload"]["recipients"]) for name in treasury] == [1, 2, 64]
    assert treasury["propose_treasury_one"]["payload"]["recipients"][0]["amount"] == top
    assert objects["propose_treasury"]["params"]["payload"]["recipients"][1]["amount"] == 1
    memos = [treasury[name]["payload"]["memo"] for name in ("propose_treasury_total", "propose_treasury_64")]
    assert [len(memo) for memo in memos] == [1, 256]
    cast = [objects[name]["params"] for name in ("governance_vote", "governance_vote_no", "governance_vote_abstain")]
    assert {vote["vote"] for vote in cast} == {"yes", "no", "abstain"}
    assert {vote["track"] for vote in cast} == {"protocol", "treasury"}
    assert {objects[name]["params"]["payload"]["to"] for name in ("propose_swap", "propose_swap_and_parameter")} == \
        {"json", "trie"}
    assert "for every range an object at each of its ends" in PARTS["9.11 Vectors"]


def test_a_block_and_its_certificate_always_fit_in_a_frame(read):
    """The heaviest frame that carries one block: the largest block,
    proposed again, with a proof of as many signatures as a certificate
    can hold."""
    limit, frame = sch.LIMITS, read["objects"]["frame_proposal_largest"]
    assert sum(sch.transaction_size(tx) for tx in frame["block"]["transactions"]) == limit["block_bytes"]
    assert len(frame["proof"]["signatures"]) == limit["certificate_signatures"]
    assert by_name("frame_proposal_largest")["bytes"] == 13_093_853 < limit["frame_bytes"]
    assert "13,093,853 bytes" in SECTION
    # Only a reply that carries several blocks reaches the bound of a frame.
    assert by_name("frame_blocks_largest")["object"]["kind"] == "blocks"
    assert "Only a `blocks` frame can reach the bound" in SECTION
    # A smaller transaction adds a comma to a block for less than its own size, and no transaction is
    # smaller than one signature: the bound on the sizes bounds the block.
    smallest = sch.transaction_size(read["objects"]["undelegate_stake"])
    assert smallest > 4504 and limit["block_bytes"] // smallest < 2000
    # The same block with a certificate, as a `block` frame carries it, is lighter than the proposal.
    final = {"kind": "block", "block": frame["block"], "certificate": {**frame["proof"], "kind": "endorse"}}
    assert len(ref.canonical_json(final)) < by_name("frame_proposal_largest")["bytes"]
    # Two of them do not fit, and the frame is refused on its size before anything else is looked at.
    assert _refused("the two largest blocks in one frame")["bytes"] > limit["frame_bytes"]
    assert sch.verdict("frame", {"kind": "blocks", "blocks": "x" * limit["frame_bytes"]}, NETWORK) == "too_long"
    # The smallest block that a network can allow holds the largest transaction.
    low, high = sch.PARAMETERS.fields[-1][1].low, sch.PARAMETERS.fields[-1][1].high
    assert sch.PARAMETERS.fields[-1][0] == "max_block_bytes"
    assert (low, high) == (limit["transaction_bytes"], limit["block_bytes"])


# ---------------------------------------------------------------------------
# Reception
# ---------------------------------------------------------------------------

def test_a_text_is_measured_before_it_is_decoded():
    deep = b"[" * 65 + b"]" * 65
    with pytest.raises(sch.Refused) as refusal:
        sch.receive("json", deep + b" ", NETWORK)                 # too deep and not canonical: the nesting answers
    assert refusal.value.rule == "too_deep"
    with pytest.raises(sch.Refused) as refusal:
        sch.receive("json", b"[" * 64 + b"]" * 64 + b" ", NETWORK)
    assert refusal.value.rule == "not_canonical"
    with pytest.raises(sch.Refused) as refusal:
        sch.receive("frame", b" " * (sch.LIMITS["frame_bytes"] + 1), NETWORK)
    assert refusal.value.rule == "too_long"
    # The body of a request is one transaction: it is no longer than the largest one.
    with pytest.raises(sch.Refused) as refusal:
        sch.receive("transaction", b" " * (sch.LIMITS["transaction_bytes"] + 1), NETWORK)
    assert refusal.value.rule == "too_long"
    with pytest.raises(sch.Refused) as refusal:
        sch.receive("transaction", b" " * sch.LIMITS["transaction_bytes"], NETWORK)
    assert refusal.value.rule == "not_canonical"


def test_the_nesting_of_a_text_is_the_one_the_node_already_measures():
    """kern.nesting reads the bytes the same way since the correction of
    November 2026: the schemas make its two numbers rules, they do not
    change the measure."""
    from kern import nesting
    from kern.transaction import MAX_TX_NESTING

    assert (nesting.MAX_JSON_DEPTH, MAX_TX_NESTING) == (sch.LIMITS["json_nesting"], sch.LIMITS["transaction_nesting"])
    rng = random.Random(1311)

    def text() -> str:                                      # what the measure must not count
        return "".join(rng.choice('[]{}"\\a: ,\n') for _ in range(rng.randrange(0, 12)))

    def value(depth: int):
        kind = rng.randrange(6 if depth < 6 else 4)
        if kind == 0:
            return rng.randrange(-10, 10**6)
        if kind == 1:
            return rng.random() < 0.5
        if kind in (2, 3):
            return text()
        if kind == 4:
            return [value(depth + 1) for _ in range(rng.randrange(0, 4))]
        return {text() + str(i): value(depth + 1) for i in range(rng.randrange(0, 4))}

    deepest = 0
    for _ in range(2000):
        sample = value(0)
        encoding = ref.canonical_json(sample)
        measured = sch.json_nesting(encoding)
        assert measured == sch.nesting(sample) == nesting.json_depth(encoding), encoding
        assert nesting.nests_beyond(sample, measured) is False
        assert measured == 0 or nesting.nests_beyond(sample, measured - 1) is True
        deepest = max(deepest, measured)
    assert deepest >= 5


def test_an_address_is_read_back_from_its_text_and_only_on_its_network():
    rng = random.Random(75)
    other = bytes(range(0xC0, 0xE0))
    for _ in range(200):
        digest = rng.randbytes(48)
        text = ref.address_from_hash(NETWORK, digest)
        assert sch.address_hash(NETWORK, text) == digest
        with pytest.raises(ValueError):
            sch.address_hash(other, text)
        position = rng.randrange(75)
        changed = text[:position] + rng.choice([c for c in ref._B58 if c != text[position]]) + text[position + 1:]
        with pytest.raises(ValueError):
            sch.address_hash(NETWORK, changed)
    assert sch.address_hash(NETWORK, PROFILE["address"]["address"]).hex() == PROFILE["address"]["hash"]
    with pytest.raises(ValueError):
        sch.address_hash(NETWORK, PROFILE["address"]["address_other_network"])
    for text in ("", "kn1", PROFILE["address"]["address"] + "1", "1" * 75, "z" * 75, 75, None):
        with pytest.raises(ValueError):
            sch.address_hash(NETWORK, text)


def test_true_is_not_an_integer_and_one_is_not_a_boolean():
    """In Python `True` is an integer. In a schema it is not."""
    transfer = sv.Vectors(NETWORK).expand(by_name("transfer")["object"])
    for field in ("nonce", "fee", "gas_limit", "amount"):
        assert sch.verdict("transaction", {**transfer, field: True}, NETWORK) == "wrong_type"
    assert sch.verdict("header", {"version": True}, NETWORK) == "wrong_type"
    with pytest.raises(sch.Refused) as refusal:
        sch.PARAMETERS.check({"fee_floor_enabled": 1}, sch.Context(NETWORK), "")
    assert refusal.value.rule == "wrong_type"
    sch.VALUE.check(True, sch.Context(NETWORK), "")                        # a contract holds booleans
    sch.VALUE.check(1, sch.Context(NETWORK), "")


def test_an_integer_outside_64_bits_is_refused_even_when_no_text_carried_it():
    """Canonical JSON has no such integer, so no vector of the file can
    hold one. The schemas refuse it all the same when they are given an
    object directly."""
    call = sv.Vectors(NETWORK).expand(by_name("call_values")["object"])
    assert (call["params"]["low"], call["params"]["high"]) == (sch.INT_MIN, sch.INT_MAX)
    for beyond in (sch.INT_MAX + 1, sch.INT_MIN - 1):
        assert sch.verdict("transaction", {**call, "params": {"n": beyond}}, NETWORK) == "out_of_range"
        assert sch.verdict("transaction", {**call, "amount": beyond}, NETWORK) == "out_of_range"
    assert sch.verdict("vote", {**sv.Vectors(NETWORK).expand(by_name("endorse")["object"]),
                                "round": sch.ROUND_MAX + 1}, NETWORK) == "out_of_range"


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------

def _parts() -> dict[str, str]:
    """The text under each heading of section 9, down to the next heading."""
    parts, name = {}, None
    for line in SECTION.splitlines():
        heading = re.match(r"#{2,4} (.+)", line)
        if heading:
            name = heading.group(1)
            assert name not in parts, f"two headings named {name}"
            parts[name] = ""
        elif name is not None:
            parts[name] += line + "\n"
    return parts


def _table(text: str) -> list[tuple[str, ...]]:
    """The rows of the first table of a text, without its two heading lines."""
    lines = []
    for line in text.splitlines():
        if line.startswith("|"):
            lines.append(line)
        elif lines:
            break
    assert len(lines) >= 3 and set(lines[1]) <= set("|-"), text[:80]
    return [tuple(cell.strip() for cell in line.strip().strip("|").split("|")) for line in lines[2:]]


PARTS = _parts()


def test_the_section_says_what_it_is():
    opening = SECTION.split("\n### ", 1)[0]
    assert "> **Status.** Draft for review, chapters 1 and 2 of three" in opening
    assert "Structure version 1 migrates nothing." in opening
    assert "Nothing in this section is implemented." in opening
    assert "Structure version 1 is not version 1.0 of the software." in opening
    assert "hybrid-signatures.md" in opening
    # The formats of today stay described where they were, and say where their successors are written.
    for heading in ("### 2.1 Transaction format", "### 2.3 Block format", "### 2.7 Signature scheme"):
        assert heading in DOCUMENT
    today = DOCUMENT[DOCUMENT.index("### 2.7 Signature scheme"):DOCUMENT.index("### 2.8 ")]
    assert "written first, in section 9, and reviewed before any of them is implemented" in today
    # The node does not use the references.
    for module in sorted((ROOT / "kern").rglob("*.py")):
        source = module.read_text(encoding="utf-8")
        assert "schema_reference" not in source and "schema_vectors" not in source, module


def test_every_table_of_the_document_is_the_table_of_the_reference():
    tables = sch.tables()
    assert len(tables) == 51
    for name, rows in tables.items():
        assert name in PARTS, f"no heading {name!r} in the document"
        written = _table(PARTS[name])
        assert len(written) == len(rows), name
        for row, expected in zip(written, rows):
            assert row[:len(expected)] == expected, (name, row)
            assert len(row) == len(expected) or row[len(expected)], (name, row)   # a meaning, where there is a column
    # And the document has no other table that states a schema: each table stands under a heading of the reference,
    # the table of nesting and the table of differences excepted.
    with_a_table = {name for name, text in PARTS.items() if "\n|---" in "\n" + text}
    assert with_a_table == set(tables) | {"Nesting", "9.9 What changes from the formats of the devnet"}


def test_every_rule_of_the_reference_is_a_sentence_of_the_document():
    rules = sch.rules()
    assert sum(len(sentences) for sentences in rules.values()) == 87
    for name, sentences in rules.items():
        listed = [line[2:] for line in PARTS[name].splitlines() if line.startswith("- ")]
        assert listed[:len(sentences)] == sentences, name
    # No table of the document is followed by a rule the reference does not have.
    for name in sch.tables():
        if name in ("Types", "Limits", "Fields by kind"):
            continue                                                       # their lists are notes, not rules
        bullets = [line for line in PARTS[name].splitlines() if line.startswith("- ")]
        assert len(bullets) == len(rules.get(name, [])), name


def test_the_table_of_nesting_is_computed_from_the_schemas():
    assert _table(PARTS["Nesting"]) == sch.depths()
    assert sch.TRANSACTION.depth() == sch.LIMITS["transaction_nesting"]
    assert sch.FRAME.depth() == 37 < sch.LIMITS["json_nesting"]
    assert max(sch.TRANSACTION.variants[kind].depth() for kind in sch.KINDS if kind != "attest") == 5
    assert "Only a claim can take a transaction beyond 5 levels" in PARTS["Nesting"]
    assert "adds five levels around a transaction" in PARTS["Nesting"]


def test_the_document_names_every_kind_every_frame_and_every_limit():
    for kind in sch.KINDS:
        assert f"| `{kind}` |" in PARTS["Fields by kind"]
    for kind in sch.FRAMES:
        assert f"Frame `{kind}`" in PARTS
    for name, value in sch.LIMITS.items():
        assert f"| `{name}` | {value:,} |" in PARTS["Limits"]
    # What the node writes today is named where it changes, so that a reader of sections 2.1 to 2.7 finds it.
    differences = PARTS["9.9 What changes from the formats of the devnet"]
    assert len(_table(differences)) == 49
    for gone in ("`commits`", "`endorsements`", "`cert_round`", "`null`", "`valid_round`", "`_current_level`",
                 "`issuance_params`", "`fee_params`", "`withdrawn`", "`equivocations`"):
        assert gone in differences
    for row in _table(differences):
        assert len(row) == 4 and all(row), row


def test_the_document_and_the_ci_name_the_command_that_runs_the_go_program():
    command = "go run profile_check.go -schemas schemas.json"
    assert command in PARTS["9.11 Vectors"]
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"run: {command}" in workflow
    program = (sv.FILE.parent / "profile_check.go").read_text(encoding="utf-8")
    assert 'os.Args[1] == "-schemas"' in program and "go run profile_check.go -schemas schemas.json" in program
    # The Go program has the limits of the reference, written out on its side.
    for name, value in sch.LIMITS.items():
        assert re.search(rf"=\s*{value}\b", program), name


# ---------------------------------------------------------------------------
# Chapter 2: what is kept
# ---------------------------------------------------------------------------

KEPT = ("state", "account", "genesis")


def _kept(read, schema: str) -> dict:
    """The accepted objects of a schema of chapter 2, by name."""
    return {record["name"]: value for record, value in read["accepted"] if record["schema"] == schema}


def test_the_root_of_a_state_is_the_one_of_the_note(read):
    """Section 4.6 of the note, written out a second time: with `json`
    the state is hashed as it is; with `trie` the three tables keyed by
    address leave the object, and one hash stands for them."""
    states = _kept(read, "state")
    assert len(states) == 14
    for name, state in states.items():
        record = by_name(name)
        assert record["accounts_root"] == ref.accounts_root(NETWORK, state).hex(), name
        hashed = dict(state)
        if state["state_root_function"] == "trie":
            for table in ("balances", "nonces", "contracts"):
                del hashed[table]
            hashed["accounts_root"] = record["accounts_root"]
        assert "accounts_root" not in state and len(hashed) == (17 if state["state_root_function"] == "trie" else 19)
        assert record["state_root"] == ref.H("kern.state", NETWORK, ref.canonical_json(hashed)).hex(), name
    # One state under the two functions: the same accounts, and two roots.
    for one, other in (("state_first", "state_first_trie"), ("state_full_json", "state_full")):
        assert {**states[one], "state_root_function": "trie"} == states[other]
        assert by_name(one)["accounts_root"] == by_name(other)["accounts_root"]
        assert by_name(one)["state_root"] != by_name(other)["state_root"]
    # The examples of the note fix the two computations and are not states of this schema.
    for example in PROFILE["state"]:
        assert sch.verdict("state", example["state"], NETWORK) != "accepted"
        assert ref.state_root(NETWORK, example["state"]).hex() == example["root"]
    assert len(PROFILE["state"]) == 9 and {len(example["state"]) for example in PROFILE["state"]} == {6, 7}
    assert any(0 in example["state"]["balances"].values() for example in PROFILE["state"])
    # Their key registry has the shape of the schema: for an address, a list of keys, each with its level.
    registries = [example["state"]["keys"] for example in PROFILE["state"] if "keys" in example["state"]]
    assert len(registries) == 6
    for registry in registries:
        sch.STATE.fields[9][1].check(registry, sch.Context(NETWORK), "")
    assert sch.STATE.fields[9][0] == "keys"
    assert "one of which writes a balance of 0" in PARTS["Account"]


def test_the_accounts_of_a_state_are_what_the_trie_holds(read):
    full, accounts = read["objects"]["state_full"], by_name("state_full")["accounts"]
    assert set(accounts) == set(full["balances"]) | set(full["nonces"]) | set(full["contracts"]) and len(accounts) == 11
    assert [name for name in FILE["accepted"] if "accounts" in name] == [by_name("state_full")]
    for address, account in accounts.items():
        assert sch.verdict("account", account, NETWORK) == "accepted", address
        assert account["balance"] == full["balances"].get(address, 0), address
        assert account["nonce"] == full["nonces"].get(address, 0), address
        assert ("code_hash" in account) == ("storage_root" in account) == (address in full["contracts"])
    (address, contract), = full["contracts"].items()
    assert accounts[address]["code_hash"] == ref.H("kern.code", NETWORK, contract["code"].encode("utf-8")).hex()
    storage = ref.canonical_json(contract["storage"])
    assert accounts[address]["storage_root"] == ref.H("kern.storage", NETWORK, storage).hex()
    # An address with nothing but a balance, one with nothing but a nonce, and a validator that has a key and
    # no account at all: everything it has is staked, and it has sent nothing.
    assert {"balance": 1, "nonce": 0} in accounts.values()
    assert any(account["balance"] == 0 and account["nonce"] > 0 for account in accounts.values())
    idle = [validator["address"] for validator in full["validators"] if validator["address"] not in accounts]
    assert len(idle) == 1 and idle[0] in full["keys"]
    assert "An address can have a key and no account" in PARTS["Account"]


def test_every_rule_of_chapter_2_is_broken_alone_by_a_refused_object(read):
    """A refused state names the sentence it breaks. Without that one
    sentence the reference accepts it: it breaks no other rule, so it is
    refused for the reason it gives."""
    sentences = [sentence for obj in sch.CHAPTER_2 for sentence, _ in obj.rules]
    assert len(sentences) == 41 and len(set(sentences)) == 40          # two tables share the sentence on tranches
    broken: collections.Counter = collections.Counter()
    for record, schema, value in read["refused"]:
        if schema not in KEPT or record["rule"] != "inconsistent":
            assert "breaks" not in record, record["why"]
            continue
        assert record["breaks"] in sentences, record["why"]
        assert sch.verdict(schema, value, NETWORK) == "inconsistent"
        with sv.without(record["breaks"]):
            assert sch.verdict(schema, value, NETWORK) == "accepted", record["why"]
        broken[record["breaks"]] += 1
    assert set(broken) == set(sentences) and sum(broken.values()) == 104
    assert min(broken.values()) >= 1 and broken[sv.the_rule("Nothing happened after `level`")] == 8
    # `without` has put every rule back.
    assert [sentence for obj in sch.CHAPTER_2 for sentence, _ in obj.rules] == sentences
    # The sentence two tables share is broken in each of them.
    shared = sv.the_rule("whose levels grow")
    where = [path for record in FILE["refused"] if record.get("breaks") == shared for path in record["set"]]
    assert any(path.startswith("delegations.") for path in where)
    assert any(path.startswith("delegation_unbonding.") for path in where)
    # And every sentence is a sentence of the document, under the table of its object.
    for obj in sch.CHAPTER_2:
        for sentence, _ in obj.rules:
            assert f"- {sentence}\n" in PARTS[sch.heading(obj)], sentence


def test_a_state_is_refused_for_its_form_before_its_rules(read):
    refused = collections.Counter(record["rule"] for record, schema, _ in read["refused"] if schema in KEPT)
    assert refused == {"inconsistent": 104, "out_of_range": 18, "unknown_field": 9, "bad_text": 7, "missing_field": 7,
                       "bad_address": 5, "wrong_type": 1, "bad_key": 1}
    # The names of today are not names of structure version 1.
    for why in ("the level under its name of today", "the parameters of the issuance under their name of today",
                "an index that can be computed again", "a validator with its key", "a proposal with its history"):
        assert _refused(why)["rule"] == "unknown_field"
    assert _refused("a phase of the devnet")["rule"] == "bad_text"
    # No zero is written, and nothing has a default.
    for why in ("a balance of 0 written out", "a nonce of 0 written out"):
        assert _refused(why)["rule"] == "out_of_range"
    assert _refused("a parameter without a value")["rule"] == _refused("no treasury")["rule"] == "missing_field"
    for name, _, presence in sch.STATE.fields + sch.STATE_PARAMETERS.fields + sch.CONSTANTS.fields:
        assert presence == "required", name
    assert [name for name, _, _ in sch.STATE_PARAMETERS.fields] == [name for name, _, _ in sch.PARAMETERS.fields]
    assert [type_ for _, type_, _ in sch.STATE_PARAMETERS.fields] == [type_ for _, type_, _ in sch.PARAMETERS.fields]
    assert len(sch.STATE.fields) == 19 and len(sch.CONSTANTS.fields) == 13


def test_a_state_reaches_the_ends_of_its_ranges(read):
    objects, top = read["objects"], sch.INT_MAX
    low, high, staked = (objects[name] for name in ("state_lowest", "state_highest", "state_highest_stake"))
    assert (low["level"], high["level"]) == (0, top)
    assert (low["total_supply"], high["total_supply"], staked["total_supply"]) == (1, top, top)
    assert low["balances"] == {} and list(high["balances"].values()) == [top - 13]
    assert list(high["nonces"].values()) == [top]
    assert [entry["from"] for entries in high["keys"].values() for entry in entries] == [0, top]
    assert (low["validators"][0]["stake"], staked["validators"][0]["stake"], staked["consensus_set"][0]["stake"]) == \
        (1, top, top)
    assert (len(low["chain_id"]), len(high["chain_id"])) == (1, 64)
    assert {low["state_root_function"], high["state_root_function"]} == {"json", "trie"}
    for fields, member in ((sch.STATE_PARAMETERS.fields, "parameters"), (sch.CONSTANTS.fields, "constants")):
        for name, type_, _ in fields:
            type_ = type_.inner if isinstance(type_, sch.Named) else type_
            ends = (type_.low, type_.high) if isinstance(type_, sch.Int) else (False, True)
            assert (low[member][name], high[member][name]) == ends, name
    assert (high["constants"]["epoch_blocks"], high["constants"]["attestation_unbonding_blocks"]) == \
        (sch.ROUND_MAX, sch.ROUND_MAX) and low["constants"]["attestation_unbonding_blocks"] == 0
    slashed = high["consensus_slashes"][0]
    assert (slashed["level"], slashed["round"]) == (top, sch.ROUND_MAX)
    # As many validators as a network can have, and one more.
    assert len(objects["state_1024_validators"]["validators"]) == sch.LIMITS["validators"] == 1024
    assert len(objects["state_1024_validators"]["keys"]) == 1024
    assert _refused("1,025 validators")["rule"] == _refused("a genesis with 1,025 validators")["rule"] == "out_of_range"
    assert (objects["genesis_earliest"]["timestamp"], objects["genesis_1024_validators"]["timestamp"]) == (0, top)
    assert (objects["account_highest"]["balance"], objects["account_highest"]["nonce"]) == (top, top)
    # What the block of the next level does is not done yet, and what the block of this level did is done.
    edge, constants = objects["state_about_to_change"], objects["state_about_to_change"]["constants"]
    revoked = edge["attestations"]["a2" * 48]
    assert revoked["revoked_at"] + constants["attestation_unbonding_blocks"] == edge["level"] + 1
    assert revoked["bond"] > 0
    assert edge["governance"]["protocol"][0]["ended_at"] + constants["delegation_unbonding_blocks"] == edge["level"] + 1
    assert edge["consensus_slashes"][0]["level"] + constants["delegation_unbonding_blocks"] == edge["level"] + 1
    assert edge["delegation_unbonding"][0]["release_at"] == edge["level"] + 1
    for why in ("a bond that should have returned at this level", "a proposal that ended 300 levels ago",
                "a slashed vote 300 levels old", "a delegation that should have been released"):
        assert _refused(why)["rule"] == "inconsistent"
    # What the block of this level did is done, and is not ahead of the state: every level a state records can
    # be the level of the state itself, and one more is refused.
    done, level = objects["state_just_changed"], objects["state_just_changed"]["level"]
    recorded = [tranche["level"] for delegation in done["delegations"].values() for tranche in delegation["tranches"]]
    recorded += [leaving["unbonding_from"] for leaving in done["delegation_unbonding"]]
    recorded += [done["attestations"]["a4" * 48][name] for name in ("issued_at", "revoked_at")]
    recorded += [vote["level"] for vote in done["consensus_slashes"]]
    recorded += [proposal["ended_at"] for proposal in done["governance"]["protocol"] if "ended_at" in proposal]
    recorded += [double["level"] for proposal in done["governance"]["protocol"] for double in proposal["double_votes"]]
    recorded += [done["governance"]["protocol"][3]["submitted_at"]]
    assert recorded.count(level) == 13 and max(recorded) == level
    assert max(entry["from"] for entries in done["keys"].values() for entry in entries) == level + 1
    constants = done["constants"]
    for track in ("protocol", "treasury"):                     # two proposals of a track submitted at one level
        submitted = [proposal["submitted_at"] for proposal in done["governance"][track]]
        assert submitted == sorted(submitted)
    voting = [proposal for proposal in done["governance"]["treasury"] if proposal["phase"] == "voting"]
    assert len(voting) == 2 and {sch.phase_window("treasury", proposal, constants) for proposal in voting} == \
        {(level, level + constants["treasury_vote_blocks"])}
    # A proposal ends with its second vote whether it is activated or rejected, and a validator can have voted
    # two ways in each of its two phases.
    ended = [(proposal["phase"], proposal["ended_at"] - proposal["submitted_at"])
             for proposal in done["governance"]["protocol"][:2]]
    assert ended == [("activated", 400), ("rejected", 400)]
    twice = done["governance"]["protocol"][0]["double_votes"]
    assert [double["phase"] for double in twice] == ["exploration", "adoption"]
    assert twice[0]["voter"] == twice[1]["voter"]
    assert [leaving["unbonding_from"] for leaving in done["delegation_unbonding"]] == [level, level]
    # Slashed votes that differ by one thing only are four offences.
    first = done["consensus_slashes"][0]
    differ = [sum(vote[name] != first[name] for name in first) for vote in done["consensus_slashes"][1:]]
    assert differ == [1, 1, 1, 1] and len({json.dumps(vote, sort_keys=True) for vote in done["consensus_slashes"]}) == 5
    nothing_ahead = sv.the_rule("Nothing happened after `level`")
    ahead = [record for record in FILE["refused"] if record.get("breaks") == nothing_ahead]
    assert all(level + 1 in record["set"].values() for record in ahead) and len(ahead) == 8


def test_a_weight_is_never_more_than_what_backs_it(read):
    """So the weights of a state add up to its supply at most, and no sum a
    client makes over a state leaves 64 bits."""
    for name, state in _kept(read, "state").items():
        delegated: collections.Counter = collections.Counter()
        for delegation in state["delegations"].values():
            delegated[delegation["validator"]] += delegation["amount"]
        for validator, entry in zip(state["validators"], state["consensus_set"]):
            assert entry["address"] == validator["address"]
            assert 1 <= entry["stake"] <= validator["stake"] + delegated[validator["address"]], name
        assert sum(entry["stake"] for entry in state["consensus_set"]) <= state["total_supply"] <= sch.INT_MAX
        assert sch.held(state) == state["total_supply"]
    full = read["objects"]["state_full"]
    weights = [entry["stake"] - validator["stake"]
               for validator, entry in zip(full["validators"], full["consensus_set"])]
    assert weights[0] > 0 > weights[1]                 # a weight above the stake, with a delegation, and one below
    for why in ("a weight one above the stake of a validator", "a weight that counts a delegation that is unbonding"):
        assert _refused(why)["breaks"] == sv.the_rule("is not above its stake")
    # Nobody signs for the treasury: it has no key in any state, so it is no validator and has sent nothing. It
    # can be the address of a contract. Its guardians sign: each is an account, once, and no validator.
    for name, state in _kept(read, "state").items():
        treasury, listed = state["treasury_address"], [validator["address"] for validator in state["validators"]]
        assert treasury not in state["keys"] and treasury not in state["nonces"], name
        assert treasury not in listed, name
        guardians = state["guardians"]
        assert 3 <= len(guardians) == len(set(guardians)) <= sch.LIMITS["guardians"] == 8, name
        assert not set(guardians) & ({treasury} | set(listed) | set(state["contracts"])), name
    housed = read["objects"]["state_treasury_contract"]
    assert housed["treasury_address"] in housed["contracts"]
    for why in ("the treasury at the address of an account that has a key",
                "the treasury at the address of a validator",
                "a genesis whose treasury is the address of one of its validators"):
        assert _refused(why)["breaks"] == "`treasury_address` is not in `keys`."
    assert "One thing moves what it holds: a treasury proposal that the validators voted and that a guardian " \
        "released." in PARTS["State"]
    assert "the weights of a state add up to `total_supply` at most" in PARTS["Validator"]


def test_a_genesis_is_its_first_state_and_the_block_of_level_0_is_computed_from_it(read):
    files = _kept(read, "genesis")
    assert len(files) == 4
    nothing = ref.merkle_root(NETWORK, []).hex()
    assert nothing == PROFILE["merkle"][0]["root"] and PROFILE["merkle"][0]["items"] == []
    assert [name.strip("`") for name, _ in sch.FIRST_HEADER] == list(sch.HEADER_FIELDS)
    hashes = set()
    for name, genesis in files.items():
        record, state = by_name(name), genesis["state"]
        assert genesis["state"] == read["objects"][record["object"]["state"]["$ref"]]
        assert sch.verdict("state", state, NETWORK) == "accepted" and state["level"] == 0
        assert sorted(genesis) == ["network_id", "scheme", "state", "timestamp", "version"]
        header = json.loads(record["hashed"])
        assert ref.canonical_json(header).decode("utf-8") == record["hashed"]
        assert header == {
            "version": 1, "level": 0, "payload_round": 0, "timestamp": genesis["timestamp"], "parent_hash": "0" * 96,
            "state_root": by_name(record["object"]["state"]["$ref"])["state_root"], "txs_root": nothing,
            "witness_root": nothing, "proposer": state["validators"][0]["address"]}
        # The nine fields a header has without its signature, hashed like the header of any block: with a
        # signature they would be a header, and nobody signs the block of level 0.
        assert sch.verdict("header", header, NETWORK) == "missing_field"
        signed = {**header, "signature": sv.Vectors(NETWORK).expand({"$sig": 1})}
        assert sch.verdict("header", signed, NETWORK) == "accepted"
        assert record["block_hash"] == ref.H("kern.block", NETWORK, record["hashed"].encode("utf-8")).hex()
        assert record["block_hash"] == sch.block_hash(NETWORK, header).hex()
        hashes.add(record["block_hash"])
        # Read on the network it names, whatever network the reader had in mind; its state alone is not.
        assert sch.verdict("genesis", genesis, bytes(32)) == "accepted"
        assert sch.verdict("state", state, bytes(32)) == "bad_address"
        assert sch.nesting(genesis) == 5
    assert len(hashes) == 4                             # another state root or another moment, another block
    assert by_name("genesis")["hashed"] != by_name("genesis_trie")["hashed"]
    assert (sch.STATE.depth(), sch.GENESIS.depth()) == (33, 34)
    assert "A genesis holds no attestation, and nests 5 deep." in PARTS["Nesting"]
    # Refused: what the document names.
    assert _refused("a genesis without its moment")["rule"] == "missing_field"
    assert _refused("the same genesis under the identifier of another network")["rule"] == "bad_address"
    for why in ("another structure version", "another signature scheme"):
        assert _refused(why)["rule"] == "out_of_range"
    for why in ("a genesis whose rates of issuance are crossed", "a genesis whose supply is not the sum",
                "a genesis with a validator that has no key", "a first state of level 1",
                "a first state that holds a contract", "a first state that holds a proposal",
                "a first state in which a validator has already sent"):
        assert _refused(why)["rule"] == "inconsistent"
    # Received as a text: no bound on its length, the nesting first, then the encoding, then the schema.
    written = _text("a genesis as a node reads it")
    assert written["bytes"] == by_name("genesis")["bytes"] and "rule" not in written
    assert _text("the same text with a line feed at its end")["rule"] == "not_canonical"
    spaces = _text("16,777,217 spaces: a frame of that length is too long")
    assert spaces["schema"] == "genesis" and spaces["rule"] == "not_canonical"
    assert _text("a frame of 16,777,217 spaces")["rule"] == "too_long"
    assert _text("65 arrays, one inside the other: the nesting of a genesis")["rule"] == "too_deep"
    assert sch.receive("genesis", ref.canonical_json(files["genesis"]), NETWORK) == files["genesis"]


def test_what_a_block_charges(read):
    """Blocks of transfers on a part of a state: what each one leaves, or
    the rule that makes it invalid and the transaction that breaks it."""
    assert len(FILE["charges"]) == 25 and FILE["block_rules"] == sch.BLOCK_RULES
    vectors, invalid = sv.Vectors(NETWORK), collections.Counter()
    for record in FILE["charges"]:
        state, transactions = record["state"], vectors.expand(record["transactions"])
        assert all(sch.verdict("transaction", tx, NETWORK) == "accepted" and tx["kind"] == "transfer"
                   for tx in transactions), record["why"]
        sch.STATE_PARAMETERS.check(state["parameters"], sch.Context(NETWORK), "")
        result = sch.charge(state, record["proposer"], transactions)
        if "rule" in record:
            assert "then" not in record
            assert result == {"valid": False, **{name: record[name] for name in ("rule", "at") if name in record}}
            invalid[record["rule"]] += 1
            continue
        then = record["then"]
        assert result == {"valid": True, **then}, record["why"]
        # Nothing is created and nothing is lost; no zero is written.
        assert sum(then["balances"].values()) == sum(state["balances"].values())
        assert 0 not in then["balances"].values() and 0 not in then["nonces"].values()
        # Every transaction has paid and has taken a nonce, the ones whose transfer failed included.
        sent = collections.Counter(tx["sender"] for tx in transactions)
        assert then["nonces"] == {address: state["nonces"].get(address, 0) + sent[address]
                                  for address in set(state["nonces"]) | set(sent)}
        assert all(0 <= position < len(transactions) for position in then["failed"])
    assert set(invalid) == set(sch.BLOCK_RULES) and sum(invalid.values()) == 13
    whys = {record["why"]: record for record in FILE["charges"]}
    failed = whys["a transfer whose sender holds the fee and not the amount: it fails, stays in the block and has paid"]
    assert failed["then"]["failed"] == [0] and list(failed["then"]["nonces"].values()) == [1]
    # The whole block is weighed before any transaction is looked at; the other rules name a transaction.
    assert [("at" in record) for record in FILE["charges"] if record.get("rule") == "block_too_large"] == [False, False]
    assert all("at" in record for record in FILE["charges"]
               if record.get("rule", "block_too_large") != "block_too_large")
    # The last nonce: 2^63 - 1 is the highest a state holds, so the last transaction of an account has the nonce
    # before it.
    last = whys["the last transaction an account can send: its nonce becomes 2^63 - 1, the highest a state holds"]
    assert list(last["then"]["nonces"].values()) == [sch.INT_MAX]
    over = whys["a sender whose nonce is 2^63 - 1 sends nothing more: its nonce could not go up"]
    assert (over["rule"], over["at"], list(over["state"]["nonces"].values())) == ("wrong_nonce", 0, [sch.INT_MAX])
    # `max_block_bytes` bounds a block whether the fee floor is on or not, and a block can fill it to the byte.
    large = next(record for record in FILE["charges"] if record.get("rule") == "block_too_large")
    assert large["state"]["parameters"]["fee_floor_enabled"] is False
    filled = whys["28 transfers that fill a block of 134,054 bytes to the byte"]
    sizes = [sch.transaction_size(tx) for tx in vectors.expand(filled["transactions"])]
    assert len(sizes) == 28 and sum(sizes) == filled["state"]["parameters"]["max_block_bytes"] == 134_054
    assert "then" in filled and filled["then"]["failed"] == []
    over_by_one = whys["the same block when `max_block_bytes` is one byte less"]
    assert over_by_one["rule"] == "block_too_large" and over_by_one["transactions"] == filled["transactions"]
    assert over_by_one["state"]["parameters"]["max_block_bytes"] == sum(sizes) - 1
    # Only a vote moves what the treasury holds: no transaction is sent by its address, whatever it holds, and
    # anyone can send to it.
    treasuries = {record["state"]["treasury_address"] for record in FILE["charges"]}
    assert len(treasuries) == 1
    (treasury,) = treasuries
    sent = [record for record in FILE["charges"] if record.get("rule") == "sent_by_treasury"]
    assert [record["at"] for record in sent] == [0, 1]
    for record in sent:
        guilty = vectors.expand(record["transactions"])[record["at"]]
        assert guilty["sender"] == treasury
        assert record["state"]["balances"][treasury] >= guilty["fee"] + guilty["amount"] and guilty["nonce"] == 0
    for record in FILE["charges"]:
        if "then" in record:
            assert all(tx["sender"] != treasury for tx in vectors.expand(record["transactions"])), record["why"]
    given = whys["a transfer to the treasury: anyone can give to it"]
    assert given["then"]["balances"][treasury] - given["state"]["balances"][treasury] == 30
    # The document: the six rules of the vectors, then the two of the note on keys and signatures.
    part = PARTS["What a block charges"]
    listed = [line[2:] for line in part.splitlines() if line.startswith("- ")]
    assert listed == list(sch.BLOCK_RULES.values()) + sch.SIGNATURE_RULES and len(listed) == 8
    for sentence in ("A block that breaks one of them is invalid: this is the rule that section 9.1 announced.",
                     "`max_block_bytes` bounds every block, whether the fee floor is on or not.",
                     "their tests come with the implementation"):
        assert sentence in part, sentence


def test_proposals_are_decided_one_after_the_other_in_the_order_of_their_lists(read):
    assert len(FILE["decisions"]) == 19
    context = sch.Context(NETWORK)
    for record in FILE["decisions"]:
        before, then = record["before"], record["then"]
        assert sch.decide(before, record["protocol"], record["treasury"]) == then, record["why"]
        sch.STATE_PARAMETERS.check(before["parameters"], context, "")
        sch.STATE_PARAMETERS.check(then["parameters"], context, "")        # the two rates are never left crossed
        for proposal in record["protocol"]:
            sch.PROTOCOL_PAYLOAD.check(proposal["payload"], context, "")
        assert all(set(proposal) in ({"phase", "passes"}, {"phase"}) and proposal["phase"] in ("voting", "passed")
                   and ("passes" in proposal) == (proposal["phase"] == "voting") for proposal in record["treasury"])
        assert (len(then["protocol"]), len(then["treasury"])) == (len(record["protocol"]), len(record["treasury"]))
        # Every mukrn is accounted for: half a lost bond is burned, rounded down, and the rest reaches the
        # treasury. No decision pays anything: what the treasury holds only goes up here.
        lost = [before["protocol_bond"]] * then["protocol"].count("rejected") \
            + [before["treasury_bond"]] * then["treasury"].count("rejected")
        assert then["burned"] == sum(bond // 2 for bond in lost)
        assert then["treasury_holds"] == before["treasury"] + sum(lost) - then["burned"] >= before["treasury"]
        # A protocol proposal whose vote fails is rejected. A treasury proposal whose vote passes waits, and
        # every other one is rejected: a vote that fails, a wait that ends.
        for proposal, phase in zip(record["protocol"], then["protocol"]):
            assert proposal["passes"] or phase == "rejected"
        for proposal, phase in zip(record["treasury"], then["treasury"]):
            assert phase == ("passed" if proposal.get("passes") else "rejected")
            assert "executed" not in then["treasury"]
    # The order of a list is part of the state: the same proposals in the other order, another result.
    def key(record: dict, turned: bool) -> str:
        step = -1 if turned else 1
        return json.dumps([record["before"], record["protocol"][::step], record["treasury"][::step]], sort_keys=True)
    as_written = {key(record, False): record for record in FILE["decisions"]}
    turned = [record for record in FILE["decisions"]
              if key(record, True) in as_written and as_written[key(record, True)]["then"] != record["then"]]
    assert len(turned) == 6                                           # three pairs, all of the protocol track
    assert {len(record["protocol"]) for record in turned} == {2}
    assert {len(record["treasury"]) for record in turned} == {0}
    whys = {record["why"]: record for record in FILE["decisions"]}
    lapsed = whys["a payment that nobody released by the end of its wait: it is rejected, and its bond is lost the "
                  "same way"]
    assert lapsed["treasury"] == [{"phase": "passed"}] and lapsed["then"]["treasury"] == ["rejected"]
    assert (lapsed["then"]["burned"], lapsed["then"]["treasury_holds"]) == (5, 1005)
    odd = whys["a bond of an odd amount: the half that is burned is rounded down"]
    assert (odd["before"]["protocol_bond"], odd["then"]["burned"], odd["then"]["treasury_holds"]) == (101, 50, 1051)
    part = PARTS["Deciding proposals"]
    listed = [line[2:] for line in part.splitlines() if line.startswith("- ")]
    assert listed == sch.DECIDING_RULES and len(listed) == 7
    assert "Decisions are settled one at a time" in part and "No decision pays anything" in part


def test_a_payment_needs_a_vote_and_a_guardian(read):
    """Transactions of guardians in one block: what each one does to a
    payment that waits, or the rule that makes it fail."""
    assert len(FILE["payments"]) == 32 and FILE["guardian_rules"] == sch.GUARDIAN_RULES
    done = ("paid", "recorded", "cancelled")
    seen: collections.Counter = collections.Counter()
    for record in FILE["payments"]:
        before, then = record["before"], record["then"]
        assert sch.guard(before, record["operations"]) == then, record["why"]
        assert set(then["payments"]) == set(before["payments"]) and len(then["did"]) == len(record["operations"])
        seen.update(then["did"])
        first, others = before["guardians"][0], before["guardians"][1:]
        released = {name: payment.get("released_by") for name, payment in before["payments"].items()}
        waits = {name for name, payment in before["payments"].items() if payment["phase"] == "passed"}
        left = cancelled = 0
        for operation, did in zip(record["operations"], then["did"]):
            sender, name = operation["sender"], operation["proposal_id"]
            assert operation["kind"] in ("release_payment", "cancel_payment") and set(operation) == \
                {"sender", "kind", "proposal_id"}
            assert did in done or did in sch.GUARDIAN_RULES, did
            if did not in done:
                continue
            # Only a guardian does anything, and only to a payment that waits.
            payment = before["payments"][name]
            assert sender in before["guardians"] and name in waits, record["why"]
            late = before["level"] >= payment["voted"] + before["guardian_delay_blocks"]
            if did == "cancelled":
                assert sender == first and operation["kind"] == "cancel_payment"
                cancelled += 1
                waits.discard(name)
            elif did == "recorded":
                assert sender in others and late and released[name] is None
                released[name] = sender
            else:
                # Paid by the first guardian alone, or by a second one of the others once the delay has passed.
                assert operation["kind"] == "release_payment"
                assert sender == first or (late and released[name] in others and released[name] != sender)
                left += payment["total"] - payment["to_itself"]
                waits.discard(name)
        # Every mukrn is accounted for, and a payment that does not wait is left as it was.
        bond = before["treasury_bond"]
        assert then["burned"] == cancelled * (bond // 2)
        assert then["treasury_holds"] == before["treasury"] - left + cancelled * (bond - bond // 2) >= 0
        for name, payment in before["payments"].items():
            after = then["payments"][name]
            assert set(after) <= {"phase", "released_by"} and ("released_by" in after) <= (after["phase"] == "passed")
            if payment["phase"] != "passed":
                assert after == {"phase": payment["phase"]}, record["why"]
            assert after["phase"] in ("passed", "executed", "rejected") or after["phase"] == payment["phase"]
    assert set(seen) == set(done) | set(sch.GUARDIAN_RULES) and min(seen.values()) >= 2
    whys = {record["why"]: record for record in FILE["payments"]}
    # The delay of the guardians other than the first, on both sides of its end.
    early = whys["another guardian releases one level before its delay has passed"]
    on_time = whys["another guardian releases at the level at which its delay has passed: its release is recorded, "
                   "and nothing is paid"]
    assert (early["before"]["level"], on_time["before"]["level"]) == (949, 950)
    assert {**early["before"], "level": 950} == on_time["before"]
    assert (early["then"]["did"], on_time["then"]["did"]) == (["too_early"], ["recorded"])
    assert on_time["then"]["treasury_holds"] == on_time["before"]["treasury"]
    # Everything the treasury holds, and one mukrn more.
    whole = whys["a payment of everything the treasury holds"]
    more = whys["one mukrn more than the treasury holds: the release fails, and the payment goes on waiting"]
    assert (whole["then"]["did"], whole["then"]["treasury_holds"]) == (["paid"], 0)
    assert (more["then"]["did"], more["then"]["payments"]) == (["unfunded"], {"p": {"phase": "passed"}})
    assert more["before"]["payments"]["p"]["total"] == more["before"]["treasury"] + 1
    # Who is first is the order of the list.
    order = whys["who is first is the order of the list: with another list, the same address waits like the others"]
    assert order["before"]["guardians"] == ["second", "first", "third"]
    assert order["then"]["did"] == ["too_early", "not_the_first", "paid"]
    # The order of a block is part of what it does: the same operations in the other order, another result.
    def key(record: dict, turned: bool) -> str:
        return json.dumps([record["before"], record["operations"][::-1 if turned else 1]], sort_keys=True)
    as_written = {key(record, False): record for record in FILE["payments"]}
    turned = [record for record in FILE["payments"]
              if key(record, True) in as_written and as_written[key(record, True)]["then"] != record["then"]]
    assert len(turned) == 4                                            # two pairs
    # The checks come in the order of the rules: the sender, the payment, then what the operation asks.
    assert list(sch.GUARDIAN_RULES) == ["not_a_guardian", "not_waiting", "not_the_first", "too_early",
                                        "released_twice", "unfunded"]
    for why, did in (("the sender is looked at first", "not_a_guardian"), ("then the payment", "not_waiting"),
                     ("then the delay", "too_early")):
        record = next(record for record in FILE["payments"] if record["why"].startswith(why))
        assert set(record["then"]["did"]) == {did}
    part = PARTS["What a guardian does"]
    listed = [line[2:] for line in part.splitlines() if line.startswith("- ")]
    assert listed == list(sch.GUARDIAN_RULES.values()) == sch.rules()["What a guardian does"] and len(listed) == 6
    for sentence in ("A payment needs both a vote and a guardian.", "it cannot name another payment",
                     "The first guardian, and no other, cancels a payment that waits.",
                     "the first block in which a guardian can act is the next one"):
        assert sentence in part, sentence


def test_a_state_holds_its_guardians_and_the_payments_that_wait(read):
    objects = read["objects"]
    state = objects["state_payments"]
    level, constants, guardians = state["level"], state["constants"], state["guardians"]
    assert guardians == objects["state_full"]["guardians"] and len(objects["state_8_guardians"]["guardians"]) == 8
    assert _refused("two guardians")["rule"] == _refused("nine guardians")["rule"] == "out_of_range"
    assert _refused("no guardians")["rule"] == "missing_field"
    delay, wait = constants["guardian_delay_blocks"], constants["treasury_release_blocks"]
    assert (delay, wait) == (50, 150)
    payments = state["governance"]["treasury"]
    assert [payment["phase"] for payment in payments] == \
        ["executed"] * 2 + ["rejected"] * 3 + ["passed"] * 5 + ["voting"]
    ends = [sch.phase_ends("treasury", payment, constants) for payment in payments]
    assert all(end["passed"] == end["voting"] + wait for end in ends)
    # A payment is made after its vote, in the last block of its wait at the latest; a proposal is rejected by
    # its vote, by the first guardian afterwards, or by the end of its wait.
    over = [(payment["phase"], payment["ended_at"] - end["voting"]) for payment, end in zip(payments, ends)
            if "ended_at" in payment]
    assert over == [("executed", 1), ("executed", wait), ("rejected", wait), ("rejected", 1), ("rejected", 0)]
    # The five that wait: one whose wait ends at the next level, one a guardian released, one released at the
    # very level at which the delay had passed, one that only the first guardian can release yet, and one
    # whose vote passed at this level.
    waiting = [(payment, end) for payment, end in zip(payments, ends) if payment["phase"] == "passed"]
    assert all(end["voting"] <= level < end["passed"] and "bond" in payment for payment, end in waiting)
    assert [end["passed"] - level for _, end in waiting][0] == 1 and [end["voting"] for _, end in waiting][-1] == level
    released = [(payment["released_by"], level - end["voting"]) for payment, end in waiting if "released_by" in payment]
    assert released == [(guardians[1], 2 * delay), (guardians[2], delay)]
    assert [level - end["voting"] for payment, end in waiting if "released_by" not in payment] == [149, 49, 0]
    assert all("released_by" not in payment for payment in payments if payment["phase"] != "passed")
    for name in ("state_full", "state_just_changed", "state_about_to_change"):
        assert not any(payment["phase"] == "passed" for payment in objects[name]["governance"]["treasury"])
    # The guardians that acted have a key, as any account that has sent a transaction has.
    assert all(guardian in state["keys"] and state["nonces"][guardian] >= 1 for guardian in guardians)
    # Every rule a guardian adds to the state is broken alone by a state, on both sides of its bound.
    for why, words in (
            ("a guardian listed twice", "`guardians` holds an address once"),
            ("the treasury among its own guardians", "A guardian is not `treasury_address`"),
            ("a contract among the guardians", "A guardian is not `treasury_address`"),
            ("a validator as the first guardian", "A guardian is not `treasury_address`"),
            ("a release recorded for the first guardian", "`released_by` is a guardian other than the first"),
            ("a release by an address that is not a guardian", "`released_by` is a guardian other than the first"),
            ("a release by another guardian one level before its delay had passed", "When `released_by` is present"),
            ("a payment that still waits at the level at which its wait ends", "in the phase of its level"),
            ("a payment that waits before its vote has ended", "in the phase of its level"),
            ("a payment made at the level at which its vote ended", "ended when a vote did"),
            ("a payment made one level after its wait ended", "ended when a vote did"),
            ("a payment rejected one level after its wait ended", "ended when a vote did"),
            ("a payment already made that still names who released it", "`released_by` is present only"),
            ("a delay for the other guardians that ends after the wait", "is not above `treasury_release_blocks`")):
        assert _refused(why)["breaks"] == sv.the_rule(words), why
    # The ends of the two periods: a state holds them at their lowest together, and at their highest together.
    for name in ("state_lowest", "state_highest"):
        both = objects[name]["constants"]
        assert both["guardian_delay_blocks"] == both["treasury_release_blocks"]
    # The two kinds of chapter 1 that a guardian sends name a proposal, and nothing else.
    for kind in ("release_payment", "cancel_payment"):
        assert set(objects[kind]["params"]) == {"proposal_id"} and sch.TRANSACTION.variants[kind].depth() == 2
        assert [name for name, _, _ in sch.PARAMS[kind].fields] == ["proposal_id"]
    text = PARTS["State"]
    for sentence in ("**The guardians.** `guardians` lists three to eight accounts, fixed by the genesis",
                     "It holds nothing of the treasury, pays nothing that was not voted, and names no recipient."):
        assert sentence in text, sentence
    assert "The first is not above the second" in PARTS["Constants"]


def test_one_request_for_blocks_waits_on_a_connection_at_a_time():
    assert (len(FILE["exchanges"]), len(FILE["served"])) == (8, 3)
    for record in FILE["exchanges"]:
        verdicts = record["verdicts"]
        assert sch.exchange(record["steps"]) == verdicts and len(verdicts) == len(record["steps"]), record["why"]
        assert all(len(step) == 1 and next(iter(step)) in ("ask", "blocks", "prefix") for step in record["steps"])
        # A connection that is closed stays closed, and only four bytes that announce too much close one.
        if "closed" in verdicts:
            first = verdicts.index("closed")
            assert set(verdicts[first:]) == {"closed"} and verdicts[first - 1] == "refused"
            assert "prefix" in record["steps"][first - 1]
        # One request waits at most: between two requests that are sent, an answer was accepted.
        waiting = False
        for step, verdict in zip(record["steps"], verdicts):
            if "ask" in step:
                assert (verdict == "accepted") is not waiting
                waiting = True
            elif "blocks" in step and verdict == "accepted":
                assert waiting
                waiting = False
            elif "blocks" in step:
                assert verdict in ("refused", "closed")
    seen = {verdict for record in FILE["exchanges"] for verdict in record["verdicts"]}
    assert seen == {"accepted", "refused", "closed"}
    for record in FILE["served"]:
        held = {level: size for level, size in record["held"]}
        requests = [(first, last) for first, last in record["requests"]]
        assert sch.serve(held, requests) == record["answers"] == [sch.answer(held, *request) for request in requests]
        assert len(record["answers"]) == len(requests) >= 2
    part = PARTS["One request at a time"]
    listed = [line[2:] for line in part.splitlines() if line.startswith("- ")]
    assert listed == sch.ASKING_RULES == sch.rules()["One request at a time"]
    assert "neither frame needs an identifier" in part


def test_the_document_says_what_is_kept_and_what_a_block_does():
    """The parts of chapter 2 that no table holds."""
    assert [name for name in PARTS if name.startswith("9.1") and name[3].isdigit()] == [
        "9.10 Another signature scheme, later", "9.11 Vectors", "9.12 The state", "9.13 Accounts and the state trie",
        "9.14 The key registry", "9.15 The genesis and the block of level 0", "9.16 What a block does to the state"]
    state = PARTS["9.12 The state"]
    assert [line.split("**")[1] for line in state.splitlines() if line.startswith("- **")] == \
        ["No default.", "Nothing derived, no history.", "No zero written."]
    assert "They do not say that a state can be reached" in state
    steps = PARTS["9.16 What a block does to the state"]
    assert re.findall(r"^(\d)\. ", steps, flags=re.M) == list("12345678")
    assert "**The ends of the ranges.**" in steps and "No network reaches these numbers." in steps
    registry = PARTS["9.14 The key registry"] + PARTS["Key entry"]
    assert re.findall(r"^(\d)\. ", registry, flags=re.M) == list("123")
    for sentence in ("records the new key from level `H` + 1 (note, section 6.4)",
                     "A `rotate_key` whose second signature does not verify is another matter: the block that holds "
                     "it is invalid (section 9.16)."):
        assert sentence in registry, sentence
    genesis = PARTS["Genesis"] + PARTS["Block of level 0"]
    for sentence in ("**The first state is given, not computed.**", "**Read on the network it names.**",
                     "it never travels: `get_blocks` starts at level 1 (section 9.8)",
                     "nothing takes the time of the machine in its place"):
        assert sentence in genesis, sentence
    # The phases of a proposal end where the table of the document says, and the vectors use those ends.
    constants = sv.CONSTANTS_OF_THE_VECTORS
    proposal = {"submitted_at": 400}
    assert sch.phase_ends("protocol", proposal, constants) == {"submitted": 500, "exploration": 600, "cooldown": 700,
                                                               "adoption": 800}
    assert sch.phase_ends("treasury", proposal, constants) == {"submitted": 600, "voting": 700, "passed": 850}
    assert [(track, phase.strip("`")) for track, phase, _ in sch.tables()["Ends of phases"]] == \
        [(track, phase) for track in ("protocol", "treasury") for phase, _ in sch.PHASES[track]]
    assert "withdrawn" not in sch.PROTOCOL_PHASES + sch.TREASURY_PHASES
    # Section 2 says what the node does today, where chapter 2 touches it.
    today = DOCUMENT[DOCUMENT.index("### 2.4 State-root commitment"):DOCUMENT.index("### 2.5 ")]
    assert 'The node starts with `"json"`' in today and "For v1.0 mainnet" not in today
    from kern.chain import empty_state
    assert empty_state()["state_root_function"] == "json"
    kinds = DOCUMENT[DOCUMENT.index("### 2.1 Transaction format"):DOCUMENT.index("### 2.2 ")]
    from kern.transaction import OpKind
    for kind in OpKind:
        assert f"- `{kind.value}`\n" in kinds, kind
    # Structure version 1 adds `rotate_key` and the two kinds a guardian of the treasury sends.
    assert len(OpKind) == 12 and len(sch.KINDS) == 15
    assert set(sch.KINDS) - {kind.value for kind in OpKind} == {"rotate_key", "release_payment", "cancel_payment"}
