# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The schemas of structure version 1 are what the document says.

docs/api-stability.md, section 9, gives every object that is signed or
that travels its fields, their types and their bounds, before any of them
is implemented. Three things hold that section, and this file ties them
together:

- tests/schema_reference.py, the section as executable text: every table
  and every rule of the document is compared with it here;
- tests/vectors/kern/schemas.json, built by tests/schema_vectors.py:
  objects that are accepted, objects that are refused and the rule that
  refuses each, read back here as the Go program reads them;
- tests/vectors/kern/profile_check.go, which checks the same file with
  tables of its own; the continuous integration runs it.

Nothing below touches the node, which still writes the formats of
sections 2.1 to 2.7 of that document.
"""

from __future__ import annotations

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
    assert len(read["accepted"]) == 77
    for record, value in read["accepted"]:
        assert sch.verdict(record["schema"], value, NETWORK) == "accepted", record["name"]
        encoding = ref.canonical_json(value)
        assert sv.pin(encoding) == {"bytes": record["bytes"], "pin": record["pin"]}, record["name"]
        # Received as bytes, an object of ordinary size gives the same value: its encoding is canonical.
        if record["bytes"] <= sch.LIMITS["transaction_bytes"]:
            assert sch.receive(record["schema"], encoding, NETWORK) == value, record["name"]


def test_every_refused_object_is_refused_by_the_rule_the_file_names(read):
    assert len(read["refused"]) == 173
    for record, schema, value in read["refused"]:
        assert sch.verdict(schema, value, NETWORK) == record["rule"], record["why"]
        assert sv.pin(ref.canonical_json(value)) == {"bytes": record["bytes"], "pin": record["pin"]}, record["why"]


def test_a_refused_object_is_a_change_or_two_away_from_an_accepted_one(read):
    """So that it is refused for the reason it gives: what it is made
    from is accepted, and it differs by what its vector says."""
    edited = [record for record in FILE["refused"] if "from" in record]
    assert len(edited) == 172
    for record in edited:
        assert 1 <= len(record.get("remove", [])) + len(record.get("set", {})) <= 3, record["why"]
    alone = [record for record in FILE["refused"] if "from" not in record]
    assert [record["why"] for record in alone] == ["the two largest blocks in one frame"]


def test_texts_are_received_as_the_file_says(read):
    assert len(read["texts"]) == 23
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


def test_one_change_away_from_an_accepted_object_is_refused(read):
    """The mutations the file asks for: 1,585 objects, each one change
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
    assert count == 1585
    optional = {(record["name"], path) for record, _ in read["accepted"] if "mutations" in record
                for path in record["mutations"]["optional"]}
    assert optional == {
        ("transfer_first", "public_key"),
        ("propose_swap_and_parameter", "params.payload.params"),
        ("propose_treasury", "params.payload.memo"),
        ("propose_again", "valid_round"),
    }
    # Inside a block or a frame nothing is optional: a public key removed changes the witness root, and a
    # valid round removed leaves a proof without its reason.
    asked = {record["name"]: record["mutations"] for record, _ in read["accepted"] if "mutations" in record}
    removed = [path for change, path, _ in sv.mutations(read["objects"]["block"], [], asked["block"]["free"])
               if change == "remove"]
    assert "transactions.0.public_key" in removed
    assert asked["block"]["optional"] == asked["frame_proposal_again"]["optional"] == []


def test_what_the_vectors_cover():
    kinds = {record["object"]["kind"] for record in FILE["accepted"] if record["schema"] == "transaction"}
    assert kinds == set(sch.KINDS) and len(kinds) == 13
    frames = {record["object"]["kind"] for record in FILE["accepted"] if record["schema"] == "frame"}
    assert frames == set(sch.FRAMES) and len(frames) == 7
    assert {record["schema"] for record in FILE["accepted"]} == set(sch.SCHEMAS) - {"json"}
    texts = FILE["accepted_texts"] + FILE["refused_texts"]
    assert {record["schema"] for record in texts} == {"json", "frame", "transaction"}
    # Every rule refuses at least one vector.
    shown = {record["rule"] for record in FILE["refused"] + FILE["refused_texts"]}
    assert shown == set(sch.RULES)
    # Most accepted objects ask for their mutations; the ones that do not are the large ones and the variants.
    assert sum("mutations" in record for record in FILE["accepted"]) == 34


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
    assert "> **Status.** Draft for review, chapter 1 of three" in opening
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
    assert len(tables) == 30
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
    assert sum(len(sentences) for sentences in rules.values()) == 17
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
    assert len(_table(differences)) == 23
    for gone in ("`commits`", "`endorsements`", "`cert_round`", "`null`", "`valid_round`"):
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
