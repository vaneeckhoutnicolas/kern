# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Nothing the node receives is decoded before its nesting is known.

`json.loads` recurses once for each array or object inside another. A
message, or the body of a request, made of arrays nested by the tens of
thousands is not refused by it like any malformed text: depending on the
version of the interpreter and on the recursion limit of the process,
which py_ecc raises to 100,000 when the node imports it, the decoder
raises RecursionError, which no caller expected, or runs out of stack
and takes the process with it.

The node measures the nesting on the bytes (kern.nesting) and refuses
beyond 64 before decoding. A transaction nests 32 deep at most, so that
every frame a node builds from what it admitted is one the others read.
"""

import ast
import asyncio
import itertools
import json
import json.scanner
import random
import subprocess
import sys
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from kern import keys, network  # noqa: E402
from kern.crypto import KernKeypair  # noqa: E402
from kern.rpc import build_app  # noqa: E402
from kern.storage import Storage  # noqa: E402
from kern.transaction import OpKind, Transaction, make_transfer  # noqa: E402


def nested(levels: int, inner: str = "") -> str:
    return "[" * levels + inner + "]" * levels


def deep_list(levels: int) -> list:
    """A list nested `levels` deep, built without a decoder. Kept to a few
    thousand levels: if a test fails, pytest prints the values it held,
    and printing descends them."""
    value: list = []
    for _ in range(levels - 1):
        value = [value]
    return value


# ---------------------------------------------------------------------------
# The depth read on the bytes
# ---------------------------------------------------------------------------

def obvious_depth(text: bytes) -> int:
    """The same reading, one byte at a time: what kern.nesting.json_depth
    must return for every string of bytes."""
    depth = deepest = 0
    in_string = skip = False
    for byte in text:
        if skip:
            skip = False
        elif byte == 0x5C:                                   # a backslash takes the next byte away
            skip = True
        elif byte == 0x22:
            in_string = not in_string
        elif not in_string and byte in b"[{":
            depth += 1
            deepest = max(deepest, depth)
        elif not in_string and byte in b"]}":
            depth -= 1
    return deepest


def value_depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max(map(value_depth, value.values()), default=0)
    if isinstance(value, list):
        return 1 + max(map(value_depth, value), default=0)
    return 0


def random_value(rng: random.Random, levels: int):
    kind = rng.randrange(7) if levels else rng.randrange(4)
    if kind == 0:
        return rng.randrange(-5, 10**6)
    if kind in (1, 2):
        return "".join(rng.choice('[]{}"\\ a:,é \n') for _ in range(rng.randrange(8)))
    if kind == 3:
        return rng.choice([True, False, None])
    if kind in (4, 5):
        return [random_value(rng, levels - 1) for _ in range(rng.randrange(4))]
    return {"".join(rng.choice('[{"\\k') for _ in range(rng.randrange(3))) + str(i): random_value(rng, levels - 1)
            for i in range(rng.randrange(4))}


def test_the_depth_read_on_the_bytes_is_the_obvious_one_for_every_short_text():
    from kern.nesting import json_depth

    count = 0
    for length in range(7):
        for symbols in itertools.product(b'[]{}"\\a', repeat=length):
            text = bytes(symbols)
            assert json_depth(text) == obvious_depth(text), text
            count += 1
    assert count == 137_257                                  # every text of 6 bytes or fewer on 7 symbols


def test_the_depth_read_on_the_bytes_is_the_obvious_one_for_long_texts():
    from kern.nesting import json_depth

    rng = random.Random(20261113)
    for _ in range(400):
        weights = [rng.randrange(1, 9) for _ in range(8)]
        text = bytes(rng.choices(b'[]{}"\\a,', weights=weights, k=rng.randrange(1, 3000)))
        assert json_depth(text) == obvious_depth(text)
    for text in (b"", b"1", b'"[[[["', b'["]]]]",[[1]]]', b'"\\\\"[', b'"\\"[', b"]]]][", b'"[' + b"\\", b'{"a":[{"b":[]}]}'):
        assert json_depth(text) == obvious_depth(text), text
    assert [json_depth(t) for t in (b"", b"1", b"[]", b'{"a":[{"b":[]}]}', b'"[[[["', b"]]]][")] == [0, 0, 1, 4, 0, 0]


def test_the_depth_of_a_json_text_is_the_nesting_of_its_value():
    from kern.nesting import json_depth

    rng = random.Random(64)
    for _ in range(500):
        value = random_value(rng, rng.randrange(1, 12))
        for text in (json.dumps(value), json.dumps(value, ensure_ascii=False),
                     json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False)):
            assert json_depth(text.encode("utf-8")) == value_depth(value), text
    assert value_depth(json.loads(nested(64))) == 64


class Probe(json.JSONDecoder):
    """The decoder of the standard library, in its Python form, which
    notes how deep it descends before it returns or gives up."""

    def __init__(self):
        super().__init__()
        self.depth = self.deepest = 0
        self.parse_object = self._counting(self.parse_object)
        self.parse_array = self._counting(self.parse_array)
        self.scan_once = json.scanner.py_make_scanner(self)

    def _counting(self, parse):
        def counted(*args, **kwargs):
            self.depth += 1
            self.deepest = max(self.deepest, self.depth)
            try:
                return parse(*args, **kwargs)
            finally:
                self.depth -= 1
        return counted


def test_a_decoder_never_descends_deeper_than_the_depth_read_on_the_bytes():
    """Also for a text that is not JSON: the decoder stops at the first
    error, and up to there the two readings are the same."""
    from kern.nesting import json_depth

    rng = random.Random(1202)
    broken = 0
    for _ in range(1500):
        text = bytearray(json.dumps(random_value(rng, rng.randrange(1, 10)), ensure_ascii=False).encode("utf-8"))
        for _ in range(rng.randrange(4)):                    # damage it: cut, insert, overwrite
            at = rng.randrange(len(text) + 1)
            text[at:at + rng.randrange(2)] = bytes(rng.choices(b'[]{}"\\,:a ', k=rng.randrange(3)))
        try:
            decoded = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            continue
        probe = Probe()
        try:
            probe.decode(decoded)
        except ValueError:
            broken += 1
        assert probe.deepest <= json_depth(bytes(text)), bytes(text)
    assert broken > 300                                      # the damaged texts are part of the trial


HOSTILE = {
    "one long string": lambda n: b"[" * 100 + b'"' + b"a" * n + b'"',
    "escaped quotes": lambda n: b"[" * 100 + b'"' + b'\\"' * (n // 2) + b'"',
    "quotes": lambda n: b"[" * 100 + b'"' * n,
    "short strings": lambda n: b'["a",' * (n // 5),
    "empty arrays": lambda n: b"[]," * (n // 3),
    "nested arrays": lambda n: b"[" * (n // 2) + b"]" * (n // 2),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_measuring_a_megabyte_takes_a_few_megabytes_whatever_it_holds(name):
    """A pattern search that removes the strings costs up to 120 times
    the size of a text made of one long string, and 40 times that of a
    text made of quotes. Both the node and the canonical decoder of
    kern.keys measure with kern.nesting.json_depth."""
    from kern.nesting import json_depth

    text = HOSTILE[name](1 << 20)
    for measure in (json_depth, keys._check_nesting):
        tracemalloc.start()
        try:
            measure(text)
        except ValueError:
            pass                                             # kern.keys refuses the deep ones
        finally:
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
        assert peak < 16 * len(text), (name, measure.__name__, peak)
    assert json_depth(text) == obvious_depth(text)


# ---------------------------------------------------------------------------
# What is decoded
# ---------------------------------------------------------------------------

def test_a_text_nested_too_deep_is_refused_before_it_is_decoded(monkeypatch):
    from kern import nesting

    assert nesting.MAX_JSON_DEPTH == 64
    assert value_depth(nesting.decode(nested(64).encode())) == 64
    assert value_depth(nesting.decode(nested(63, "[],[],[]").encode())) == 64      # more brackets than levels
    assert nesting.decode(b'{"a": ["]]]]", {"b": 1}]}') == {"a": ["]]]]", {"b": 1}]}
    assert nesting.decode(b"[" + b"[{}]," * 500 + b"[]]") == [[{}]] * 500 + [[]]     # many brackets, three levels

    def never(*_args, **_kwargs):
        raise AssertionError("decoded")
    monkeypatch.setattr(nesting.json, "loads", never)
    for text in (nested(65), nested(64, "[],[]"), nested(100_000), "[" * 65, '{"a":' * 64 + "[1]" + "}" * 64, "[" * 60 + '"["' + "[" * 5):
        with pytest.raises(ValueError, match="nested more than 64 deep"):
            nesting.decode(text.encode())
    with pytest.raises(AssertionError, match="decoded"):
        nesting.decode(b"[1]")                               # the patch is the one decode() goes through


def test_what_is_decoded_is_json_in_utf8():
    from kern import nesting

    assert nesting.decode('["é "]'.encode("utf-8")) == ["é "]
    for text in (b"", b"{", b"[1,]", b"\xff[1]", '["é"]'.encode("latin-1"),
                 "[1]".encode("utf-16"), "[1]".encode("utf-16-le"), "[1]".encode("utf-32")):
        with pytest.raises(ValueError):
            nesting.decode(text)


def test_nests_beyond_reads_a_value_level_by_level():
    from kern.nesting import nests_beyond

    for value, depth in ((7, 0), ("[[", 0), (None, 0), ([], 1), ({}, 1), ((), 1), ([1, [2, {"a": []}]], 4),
                         ({"a": {"b": {"c": 1}}}, 3), (json.loads(nested(40)), 40)):
        assert [limit for limit in range(45) if not nests_beyond(value, limit)] == list(range(depth, 45)), value
    shared: list = []
    for _ in range(200):                                     # the same list twice at every level
        shared = [shared, shared]
    assert nests_beyond(shared, 31) and nests_beyond(shared, 200) and not nests_beyond(shared, 201)
    loop: list = []
    loop.append(loop)                                        # a list that holds itself
    assert nests_beyond(loop, 31)
    assert nests_beyond(deep_list(5_000), 31) and not nests_beyond(deep_list(31), 31)


# ---------------------------------------------------------------------------
# Frames of the peer-to-peer protocol
# ---------------------------------------------------------------------------

def read_frame(payload: bytes):
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(len(payload).to_bytes(4, "big") + payload)
        reader.feed_eof()
        return await network._read_msg(reader)
    return asyncio.run(go())


def test_a_frame_nested_deeper_than_64_is_refused_like_any_malformed_frame():
    at_the_limit = ('{"kind":"transaction","tx":' + nested(63) + "}").encode()
    assert value_depth(read_frame(at_the_limit)) == 64
    assert read_frame(('{"kind":"transaction","tx":' + nested(64) + "}").encode()) is None
    assert read_frame(nested(5000).encode()) is None
    assert read_frame(b'{"kind":"hello","level":3}') == {"kind": "hello", "level": 3}
    assert read_frame(b'{"kind":') is None and read_frame(b"[1]") is None and read_frame(b"\xff{}") is None


CHILD_FRAME = r'''
import asyncio, sys
sys.path.insert(0, sys.argv[1])
sys.setrecursionlimit(100_000)                     # what py_ecc does when the node imports it
from kern import network
payload = b"[" * 100_000 + b"]" * 100_000
async def main():
    reader = asyncio.StreamReader()
    reader.feed_data(len(payload).to_bytes(4, "big") + payload)
    reader.feed_eof()
    try:
        return "refused" if await network._read_msg(reader) is None else "read"
    except BaseException as exc:
        return "raised " + type(exc).__name__
print(asyncio.run(main()))
'''

CHILD_REQUEST = r'''
import asyncio, sys
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
sys.setrecursionlimit(100_000)                     # what py_ecc does when the node imports it
from aiohttp.test_utils import TestClient, TestServer
from kern.rpc import build_app
async def main():
    client = TestClient(TestServer(build_app(SimpleNamespace())))
    await client.start_server()
    try:
        response = await client.post("/chain/inject_transaction", data=b"[" * 100_000 + b"]" * 100_000)
        return response.status
    finally:
        await client.close()
print(asyncio.run(main()))
'''


@pytest.mark.parametrize("child, expected", [(CHILD_FRAME, "refused"), (CHILD_REQUEST, "400")],
                         ids=["a frame from a peer", "the body of a request"])
def test_a_hundred_thousand_nested_arrays_do_not_take_the_process_down(child, expected):
    """In a process of its own, with the recursion limit the node runs
    with: before the bound, Python 3.11 died there of a segmentation
    fault, and later versions let a RecursionError out."""
    done = subprocess.run([sys.executable, "-B", "-c", child, str(ROOT)],
                          capture_output=True, text=True, timeout=120)
    assert (done.returncode, done.stdout.strip()) == (0, expected), done.stderr[-2000:]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

def post(body: bytes, node=None, headers=None):
    async def go():
        client = TestClient(TestServer(build_app(node or SimpleNamespace())))
        await client.start_server()
        try:
            response = await client.post("/chain/inject_transaction", data=body, headers=headers)
            return response.status, await response.json()
        finally:
            await client.close()
    return asyncio.run(go())


def test_a_request_that_is_not_json_or_nests_too_deep_is_answered_400(tmp_path):
    for body in (b"{", b"", b"\xff", nested(65).encode(), ("[" * 70).encode()):
        status, answer = post(body)
        assert status == 400 and answer["error"].startswith("malformed request body"), body
    status, answer = post(nested(65).encode())
    assert "nested more than 64 deep" in answer["error"]
    # A body in another encoding is not read as that encoding.
    status, answer = post('{"kind":"transfer"}'.encode("utf-16"), headers={"Content-Type": "application/json; charset=utf-16"})
    assert status == 400 and answer["error"].startswith("malformed request body")
    # What decodes goes on to the gate of transactions, as before.
    status, answer = post(b"[1]")
    assert status == 400 and answer["error"].startswith("malformed transaction")

    alice, bob = KernKeypair.generate(), KernKeypair.generate()
    tx = make_transfer(alice, recipient=bob.address, amount=1, nonce=0)
    storage = Storage(str(tmp_path))
    node = SimpleNamespace(storage=storage, network=None,           # a node that takes what its mempool has room for
                           admit_transaction=lambda taken: None if storage.add_to_mempool(taken) else "mempool full")
    assert post(json.dumps(tx.to_dict()).encode(), node) == (200, {"hash": tx.hash_hex()})


def test_every_entry_from_the_network_decodes_through_the_bound():
    """kern/network.py and kern/rpc.py are where bytes from outside become
    values: neither calls json.loads, nor the json() of a request, which
    would decode before measuring."""
    for name in ("network.py", "rpc.py"):
        tree = ast.parse((ROOT / "kern" / name).read_text(encoding="utf-8"))
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        assert not calls & {"loads", "load", "json"}, name
        assert "decode" in calls, name


# ---------------------------------------------------------------------------
# Transactions, and the frames built around them
# ---------------------------------------------------------------------------

def a_call(params=None, initial_storage=None) -> Transaction:
    return Transaction(kind=OpKind.CALL, sender="kn1sender", sender_pubkey="key", nonce=0, fee=1000,
                       gas_limit=10_000, recipient="KT1contract", entry="run",
                       params=params, initial_storage=initial_storage)


def test_a_transaction_nests_32_deep_at_most():
    from kern.transaction import MAX_TX_NESTING

    assert MAX_TX_NESTING == 32
    deepest = json.loads(nested(31))                         # the transaction itself is the first level
    for field in ("params", "initial_storage"):
        tx = a_call(**{field: deepest})
        assert value_depth(tx.to_dict()) == 32
        assert Transaction.from_dict(tx.to_dict()).to_dict() == tx.to_dict()
        assert a_call(**{field: {"a": json.loads(nested(30))}}).hash() != tx.hash()
        with pytest.raises(ValueError, match="nested more than 32 deep"):
            a_call(**{field: [deepest]})
        with pytest.raises(ValueError, match="nested more than 32 deep"):
            Transaction.from_dict({**tx.to_dict(), field: {"a": deepest}})
    with pytest.raises(ValueError, match="nested more than 32 deep"):
        Transaction.from_dict({**a_call().to_dict(), "params": deep_list(5_000)})


class Captured:
    """A writer that keeps what the network writes to a peer."""

    def __init__(self):
        self.frames = []

    def write(self, data: bytes) -> None:
        self.frames.append(data[4:])

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_every_frame_built_around_the_deepest_transaction_is_read():
    """The bound of transactions exists for this: what a node admitted,
    it can pass on. A transaction frame adds one level, a block and a
    proposal three, the reply to a catch-up request four."""
    from kern.nesting import MAX_JSON_DEPTH, json_depth
    from kern.transaction import MAX_TX_NESTING

    tx = a_call(params=json.loads(nested(MAX_TX_NESTING - 1))).to_dict()
    block = {"header": {"level": 1, "payload_round": 0}, "transactions": [tx], "commits": ["a"], "endorsements": []}
    proposal = {"block": block, "proposal": {"kind": "propose", "level": 1, "signature": "s"},
                "proof": {"level": 1, "round": 0, "signatures": {"a": "s"}}}

    async def noop(*_args):
        pass

    async def go():
        net = network.Network("127.0.0.1", 0, on_block=noop, on_tx=noop, get_head_level=lambda: 0,
                              get_blocks_fn=lambda lo, hi: [block])
        peer = Captured()
        net._writers.append(peer)
        await net.broadcast_tx(tx)
        await net.broadcast_block(block)
        await net.broadcast_proposal(proposal)
        await net._dispatch({"kind": "get_blocks", "from": 0, "to": 0}, peer)
        return peer.frames
    frames = asyncio.run(go())
    assert [json.loads(f)["kind"] for f in frames] == ["transaction", "block", "proposal", "blocks"]
    assert [json_depth(f) for f in frames] == [33, 35, 35, 36]
    assert max(map(json_depth, frames)) <= MAX_JSON_DEPTH
    for frame in frames:
        assert read_frame(frame) == json.loads(frame)


def test_the_canonical_decoder_of_the_profile_refuses_at_the_same_depth():
    assert keys.MAX_NESTING == 64
    assert value_depth(keys.decode_canonical(nested(64).encode())) == 64
    assert value_depth(keys.decode_canonical(nested(63, "[],[],[]").encode())) == 64
    for text in (nested(65), nested(64, "[],[]"), "[" * 65, '{"a":' * 64 + "[1]" + "}" * 64):
        with pytest.raises(ValueError, match="nested more than 64 deep"):
            keys.decode_canonical(text.encode())
