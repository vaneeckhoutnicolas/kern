# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""networks/devnet_bootstrap.py must produce a devnet that can start.

The generated docker-compose file could not start a single node: its
command repeated the image's entrypoint (`python -m kern.node`), passed
`--peers` (the node takes `--peer`, once per peer), gave the RPC and the
peer-to-peer layer the same port, and never initialized the data
directory. Docker is not available in the test environment, so each
service's command is checked against the node's own argument parser, and
the genesis is initialized with the node's own `init`."""

import json
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern import node as node_mod

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "networks"))

import devnet_bootstrap  # noqa: E402


def _generate(out, n=3):
    devnet_bootstrap.build(out, n, initial_stake=1_000_000_000_000,
                           initial_balance=10**12, faucet_balance=10**15)
    return json.loads((out / "docker-compose.yml").read_text(encoding="utf-8"))


def _node_commands(service):
    """The `python -m kern.node ...` invocations a service runs."""
    entry = service.get("entrypoint")
    cmd = service["command"]
    # A one-item list: compose splits a plain string into words, and
    # `sh -c` would then run only the first word (found with a real
    # `docker compose up`: every node exited at once with status 0).
    assert entry == ["sh", "-c"], "expected a shell command"
    assert isinstance(cmd, list) and len(cmd) == 1 and isinstance(cmd[0], str), cmd
    out = []
    for part in cmd[0].split(";"):
        words = shlex.split(part)
        if words and words[0] == "exec":
            words = words[1:]
        assert words[:3] == ["python", "-m", "kern.node"], part
        out.append(words[3:])
    return out


def test_every_service_command_is_accepted_by_the_node(tmp_path):
    compose = _generate(tmp_path / "devnet")
    bakers = {n: s for n, s in compose["services"].items() if n.startswith("baker")}
    names = sorted(bakers)
    for name, svc in bakers.items():
        init, start = _node_commands(svc)
        a = node_mod.build_parser().parse_args(init)
        assert (a.cmd, a.data_dir, a.genesis) == ("init", "/data", "/genesis.json")
        s = node_mod.build_parser().parse_args(start)
        assert s.cmd == "start" and s.data_dir == "/data"
        assert s.rpc_port != s.p2p_port
        # Inside the container the RPC must listen beyond loopback for the
        # published port to work; the host publishes it on its loopback only.
        assert s.rpc_bind == "0.0.0.0"
        assert svc["ports"] == [f"127.0.0.1:{18732 + names.index(name)}:{s.rpc_port}"]
        assert sorted(p.split(":")[0] for p in s.peer) == sorted(set(names) - {name})
        assert all(p.endswith(f":{s.p2p_port}") for p in s.peer)
        assert s.baker_key == f"/keys/{name}.json"


def test_the_build_context_is_the_repository(tmp_path):
    for out in (tmp_path / "devnet", ROOT / "networks" / "devnet-test-tmp"):
        try:
            compose = _generate(out)
            for svc in (s for s in compose["services"].values() if "build" in s):
                ctx = (out / svc["build"]["context"]).resolve()
                assert ctx == ROOT
                assert (ctx / svc["build"]["dockerfile"]).is_file()
        finally:
            if out.parent == ROOT / "networks":
                import shutil
                shutil.rmtree(out, ignore_errors=True)


def test_the_generated_genesis_initializes_a_node(tmp_path):
    _generate(tmp_path / "devnet")
    data = tmp_path / "data"
    rc = node_mod.main(["init", "--genesis", str(tmp_path / "devnet" / "genesis.json"),
                        "--data-dir", str(data)])
    assert rc == 0


def test_the_generator_does_not_depend_on_the_platform_encoding(tmp_path):
    """On Windows the default file encoding is cp1252, which cannot write
    the arrows of the generated README: every run failed there with
    UnicodeEncodeError. Python reports any file opened without an explicit
    encoding as an EncodingWarning; turned into an error, it catches the
    fault on any platform."""
    code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "import devnet_bootstrap as d; "
            "d.build(Path(sys.argv[2]), 3, 10**12, 10**12, 10**15)")
    r = subprocess.run([sys.executable, "-X", "warn_default_encoding",
                        "-W", "error::EncodingWarning", "-c", code,
                        str(ROOT / "networks"), str(tmp_path / "devnet")],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    readme = (tmp_path / "devnet" / "README.md").read_text(encoding="utf-8")
    assert "\u2192" in readme                            # the arrows are written



def test_one_image_heimdall_by_default_monitoring_on_request(tmp_path):
    compose = _generate(tmp_path / "plain")
    svcs = compose["services"]
    assert set(svcs) == {"baker0", "baker1", "baker2", "heimdall"}
    assert {s["image"] for s in svcs.values()} == {devnet_bootstrap.IMAGE}
    assert [n for n, s in svcs.items() if "build" in s] == ["baker0"]
    h = svcs["heimdall"]
    assert h["environment"]["KERN_RPC"] == "http://baker0:8732"
    assert h["ports"] == [f"127.0.0.1:{devnet_bootstrap.EXPLORER_PORT}:{devnet_bootstrap.EXPLORER_PORT}"]
    assert all(p.startswith("127.0.0.1:") for s in svcs.values() for p in s.get("ports", []))

    out = tmp_path / "mon"
    devnet_bootstrap.build(out, 3, 10**12, 10**12, 10**15, explorer=True, monitoring=True)
    compose = json.loads((out / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"prometheus", "grafana"} <= set(compose["services"])
    prom = (out / "prometheus.yml").read_text(encoding="utf-8")
    for target in ("baker0:8732", "baker1:8732", "baker2:8732", "heimdall:8800"):
        assert f"'{target}'" in prom
    for svc in ("prometheus", "grafana"):
        for vol in compose["services"][svc]["volumes"]:
            src = vol.split(":")[0]
            if src.startswith(".") or "/" in src:
                assert (out / src).exists(), vol            # every mounted file exists

    out = tmp_path / "bare"
    devnet_bootstrap.build(out, 2, 10**12, 10**12, 10**15, explorer=False)
    assert set(json.loads((out / "docker-compose.yml").read_text(encoding="utf-8"))["services"]) \
        == {"baker0", "baker1"}


def test_the_image_installs_the_explorer_extra_of_pyproject():
    """docker/Dockerfile installs Heimdall's dependencies by name; they must
    stay those of the [explorer] extra."""
    import re
    try:
        import tomllib
    except ModuleNotFoundError:                          # Python 3.10
        import tomli as tomllib                          # type: ignore
    extra = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["optional-dependencies"]["explorer"]
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    pinned = re.findall(r'"([A-Za-z0-9_.\[\]-]+>=[0-9.]+)"', dockerfile)
    assert sorted(pinned) == sorted(extra)
    assert "COPY kern_explorer/" in dockerfile


def test_alert_rules_use_only_prometheus_template_functions():
    """Prometheus refuses to start with an unknown template function in a
    rule (kern-alerts.yml used `div`, so the monitoring stack never ran;
    found with promtool 2.51.0)."""
    import re
    known = {"humanize", "humanize1024", "humanizeDuration", "humanizePercentage",
             "humanizeTimestamp", "printf", "title", "toUpper", "toLower", "reReplaceAll",
             "query", "first", "label", "value", "sortByLabel", "strvalue", "args",
             "tmpl", "safeHtml", "match", "graphLink", "tableLink", "externalURL",
             "pathPrefix", "stripPort", "stripDomain", "parseDuration", "toTime", "len",
             "index", "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge", "html", "js",
             "urlquery", "print", "println", "call", "slice"}
    text = (ROOT / "kern_explorer" / "monitoring" / "alerts" / "kern-alerts.yml").read_text(
        encoding="utf-8")
    used = set()
    for expr in re.findall(r"\{\{(.*?)\}\}", text):
        for part in expr.split("|")[1:]:
            used.add(part.split()[0])
    assert used and used <= known, used - known
