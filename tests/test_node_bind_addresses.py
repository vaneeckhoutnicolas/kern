# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Listening addresses of a node (--rpc-bind, --p2p-bind).

Before this change kern/node.py listened on 0.0.0.0, every network
interface, for both the RPC and the peer-to-peer layer, with no way to
change it, although docs/setup-validator.md and docs/setup-explorer-ops.md
already told operators to start the node with `--rpc-bind 127.0.0.1` and
`--p2p-bind 0.0.0.0` (the node refused both options). The RPC now listens
on the loopback address unless the operator chooses otherwise; the
peer-to-peer layer keeps listening on every interface, since peers must
reach it."""

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from kern import node as node_mod
from kern.node import Node
from kern.storage import Storage

from test_phase_e_invalid_first_proposal import _chain, _keys


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _parse(*extra):
    return node_mod.build_parser().parse_args(["start", "--data-dir", "d", *extra])


def test_cli_defaults_keep_the_rpc_on_loopback():
    args = _parse()
    assert (args.rpc_bind, args.p2p_bind) == ("127.0.0.1", "0.0.0.0")


def test_cli_accepts_the_options_of_the_operator_guides():
    args = _parse("--rpc-bind", "0.0.0.0", "--p2p-bind", "10.0.0.5")
    assert (args.rpc_bind, args.p2p_bind) == ("0.0.0.0", "10.0.0.5")
    assert _parse("--rpc-bind", "::1").rpc_bind == "::1"


@pytest.mark.parametrize("bad", ["localhost", "0.0.0.0:8732", "300.1.1.1", ""])
def test_cli_refuses_what_is_not_an_ip_address(bad):
    with pytest.raises(SystemExit):
        _parse("--rpc-bind", bad)


def _listening(tmp_path, **hosts):
    """Start a node without a baker key, return the RPC and P2P addresses
    it listens on, stop it."""
    keys = _keys()
    storage = Storage(str(tmp_path))
    node = Node(str(tmp_path), _chain(keys), storage, None, rpc_port=_free_port(),
                p2p_port=_free_port(), peers=[], block_time=1.0, **hosts)

    async def go():
        task = asyncio.create_task(node.start())
        for _ in range(200):
            if node._app_runner is not None and node._app_runner.addresses:
                break
            await asyncio.sleep(0.01)
        rpc = sorted(a[0] for a in node._app_runner.addresses)
        p2p = sorted(s.getsockname()[0] for s in node.network._server.sockets)
        await node.stop()
        await task
        return rpc, p2p

    return asyncio.run(go())


def test_node_rpc_listens_on_loopback_by_default(tmp_path):
    rpc, p2p = _listening(tmp_path)
    assert rpc == ["127.0.0.1"]
    assert p2p == ["0.0.0.0"]


def test_node_listens_where_the_operator_asks(tmp_path):
    rpc, p2p = _listening(tmp_path, rpc_host="0.0.0.0", p2p_host="127.0.0.1")
    assert rpc == ["0.0.0.0"]
    assert p2p == ["127.0.0.1"]
