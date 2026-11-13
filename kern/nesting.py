# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.nesting
------------

How deep arrays and objects nest, measured without recursion.

`json.loads` descends one level of recursion for each array or object
inside another. How far it can go before it fails, and how it fails,
depends on the version of the interpreter and on the recursion limit of
the process, which a library may have raised. Text received from outside
is therefore measured on its bytes before it is decoded, and refused
beyond MAX_JSON_DEPTH: what is decoded afterwards is shallow, whatever
the interpreter.

    json_depth(text)            the nesting of a JSON text, read on its bytes
    decode(text)                the value of a JSON text in UTF-8, refused when it nests too deep
    nests_beyond(value, limit)  the same question for a value already in memory
"""

from __future__ import annotations

import json
from itertools import accumulate
from typing import Any

# Arrays and objects nested deeper than this are refused before decoding.
# The frames of the peer-to-peer protocol stay far below it: a transaction
# nests 32 deep at most (kern.transaction), and the deepest frame, a reply
# to a catch-up request, adds four levels around a transaction.
MAX_JSON_DEPTH = 64

# A backslash takes the byte that follows it out of the reading: an
# escaped backslash first, so that the backslash of `\\"` does not hide
# the quote that closes the string.
_ESCAPED = (b"\\\\", b'\\"', b"\\[", b"\\]", b"\\{", b"\\}")
_NOT_MARKS = bytes(byte for byte in range(256) if byte not in b'[]{}"')
_QUOTE = bytes(byte == 0x22 for byte in range(256))                       # 1 where a quote is
_STEP = bytes(1 if byte in b"[{" else 255 if byte in b"]}" else 0         # +1, and -1 as a signed byte
              for byte in range(256))


def json_depth(text: bytes) -> int:
    """How deep arrays and objects nest in a JSON text in UTF-8.

    Read on the bytes, without decoding and without recursion: `[` and
    `{` open a level, `]` and `}` close one, and whatever stands between
    two quotes is a string and opens nothing. In UTF-8 these bytes are
    never part of another character. A text that is not JSON gets a
    number too: up to its first error it is read as a decoder reads it,
    so a decoder never descends deeper than the number returned.

    The cost is a few passes over the text and a few copies of it,
    whatever the text holds.
    """
    for escaped in _ESCAPED:
        text = text.replace(escaped, b"")
    marks = text.translate(None, _NOT_MARKS)             # the quotes and the brackets, in order
    steps = marks.translate(_STEP)
    if b'"' in marks:
        # A bracket is inside a string when an odd number of quotes
        # precedes it. The parity of the quotes up to each mark is a
        # running exclusive or: computed on all marks at once, each a
        # byte of one integer, by doubling shifts.
        size = len(marks)
        inside = int.from_bytes(marks.translate(_QUOTE), "little")
        shift = 8
        while shift < 8 * size:
            inside ^= inside << shift
            shift *= 2
        outside = ~(inside * 255)                                         # a full byte where a mark counts
        steps = (int.from_bytes(steps, "little") & outside).to_bytes(size, "little")
    return max(accumulate(memoryview(steps).cast("b"), initial=0))


def decode(text: bytes) -> Any:
    """The value of a JSON text in UTF-8. Raises ValueError when the text
    nests arrays and objects more than MAX_JSON_DEPTH deep, which is
    settled before anything is decoded, when it is not UTF-8, and when
    it is not JSON."""
    # No more levels than opening brackets: most texts are settled by counting them.
    if text.count(b"[") + text.count(b"{") > MAX_JSON_DEPTH and json_depth(text) > MAX_JSON_DEPTH:
        raise ValueError(f"arrays and objects nested more than {MAX_JSON_DEPTH} deep")
    return json.loads(text.decode("utf-8"))


def nests_beyond(value: object, limit: int) -> bool:
    """Whether the lists and dicts of a value nest more than `limit` deep:
    a number or a string is 0 deep, an empty list 1. Level by level,
    without recursion, never further than `limit` + 1 levels, and each
    list or dict once per level, so that a value that holds the same list
    many times, or itself, costs no more than its distinct parts."""
    level = [value]
    for _ in range(limit + 1):
        holders = {id(item): item for item in level if isinstance(item, (dict, list, tuple))}
        if not holders:
            return False
        level = [inner for holder in holders.values()
                 for inner in (holder.values() if isinstance(holder, dict) else holder)]
    return True
