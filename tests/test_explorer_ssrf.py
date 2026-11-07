# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""CodeQL py/partial-ssrf (alert #1): user-controlled values must never
reshape the URL the explorer sends to the node RPC."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.crypto import KernKeypair
from kern_explorer.client import KernRpcClient


class _Recorder:
    def __init__(self):
        self.paths = []


def _client_recording():
    c = KernRpcClient("http://127.0.0.1:1")
    rec = _Recorder()

    async def fake_get(path):
        rec.paths.append(path)
        return {}
    c._get = fake_get  # type: ignore[method-assign]
    return c, rec


@pytest.mark.parametrize("bad", [
    "../admin", "kn1abc/../../x", "kn1x?y=1", "kn1x#frag", "%2e%2e%2f",
    "http://evil", "", "kn1" + "0" * 34, 42,
])
def test_address_outside_allowlist_is_refused(bad):
    c, rec = _client_recording()
    for call in (c.balance, c.nonce, c.contract):
        with pytest.raises(ValueError):
            asyncio.run(call(bad))
    assert rec.paths == []
    asyncio.run(c.close())


def test_real_address_passes_unchanged():
    addr = KernKeypair.from_seed(bytes([7]) * 32).address
    c, rec = _client_recording()
    asyncio.run(c.balance(addr))
    assert rec.paths == [f"/chain/balance/{addr}"]
    asyncio.run(c.close())


@pytest.mark.parametrize("bad", [-1, True, "3", 1.0])
def test_block_level_must_be_non_negative_int(bad):
    c, _ = _client_recording()
    with pytest.raises(ValueError):
        asyncio.run(c.block(bad))
    asyncio.run(c.close())


def test_block_hash_must_be_hex64():
    c, rec = _client_recording()
    with pytest.raises(ValueError):
        asyncio.run(c.block_by_hash("../" + "a" * 61))
    asyncio.run(c.block_by_hash("ab" * 32))
    assert rec.paths == ["/chain/block/by_hash/" + "ab" * 32]
    asyncio.run(c.close())
