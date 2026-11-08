#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Local multi-node devnet in Docker, in one command.

Every validator runs in its own container, with its own data volume and
signing journal, connected over a real network; Heimdall indexes the chain;
Prometheus and Grafana are optional. Works the same on Linux, macOS and
Windows (PowerShell): it only needs Python and Docker with the compose
plugin.

    python scripts/devnet.py doctor             # is everything there? (also run by up)
    python scripts/devnet.py up                 # 4 validators + Heimdall
    python scripts/devnet.py up --validators 7 --monitoring
    python scripts/devnet.py status             # head of every node
    python scripts/devnet.py check              # same block at every level?
    python scripts/devnet.py stop baker2        # stop one validator
    python scripts/devnet.py start baker2       # start it again
    python scripts/devnet.py logs baker0
    python scripts/devnet.py down [--reset]     # --reset deletes the chain

`up` generates networks/devnet/ with networks/devnet_bootstrap.py when it
does not exist (keys, genesis, docker-compose.yml), builds the image, starts
everything and waits for the first finalized blocks. To change the number
of validators or add monitoring on an existing devnet, run `down --reset`
first, or pass --regenerate.

Devnet keys are public test keys: never use them anywhere else."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "networks" / "devnet"

sys.path.insert(0, str(ROOT / "networks"))
sys.path.insert(0, str(ROOT))


def _bootstrap():
    import devnet_bootstrap
    return devnet_bootstrap


# The devnet RPC listens on this machine's loopback only; never send these
# requests through a proxy.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_json(url: str, timeout: float = 3.0):
    with _OPENER.open(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ------------------------------------------------------------------ devnet

def compose_file(out: Path) -> Path:
    return out / "docker-compose.yml"


def node_ports(out: Path) -> Dict[str, int]:
    """Validator name -> RPC port on this machine, read from the compose file."""
    compose = json.loads(compose_file(out).read_text(encoding="utf-8"))
    ports = {}
    for name, svc in compose["services"].items():
        if name.startswith("baker"):
            host_port = svc["ports"][0].split(":")[1]
            ports[name] = int(host_port)
    return dict(sorted(ports.items(), key=lambda kv: int(kv[0][5:])))


def heads(ports: Dict[str, int], get: Callable = http_json) -> Dict[str, Optional[dict]]:
    out: Dict[str, Optional[dict]] = {}
    for name, port in ports.items():
        try:
            out[name] = get(f"http://127.0.0.1:{port}/chain/head")
        except (OSError, ValueError, urllib.error.URLError):
            out[name] = None
    return out


def block_id(block: dict) -> str:
    """A stable identity for a block: its hash when the RPC gives one,
    otherwise its header (which the hash commits to)."""
    if "hash" in block:
        return str(block["hash"])
    return json.dumps(block["header"], sort_keys=True)


def divergences(ports: Dict[str, int], get: Callable = http_json) -> tuple:
    """Compare every level up to the lowest head among the nodes that
    answer. Returns (highest common level checked, [levels that differ],
    [nodes that did not answer])."""
    hs = heads(ports, get)
    up = {n: h for n, h in hs.items() if h is not None}
    down = sorted(set(ports) - set(up))
    if len(up) < 2:
        return -1, [], down
    top = min(int(h["level"]) for h in up.values())
    bad: List[int] = []
    for level in range(0, top + 1):
        ids = {block_id(get(f"http://127.0.0.1:{ports[n]}/chain/block/{level}")) for n in up}
        if len(ids) != 1:
            bad.append(level)
    return top, bad, down


# ------------------------------------------------------------------ docker

def docker_compose(out: Path, *args: str, check: bool = True) -> int:
    cmd = ["docker", "compose", "-f", str(compose_file(out)), *args]
    return subprocess.run(cmd, cwd=out, check=check).returncode


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    hint: str = ""
    # A command that fixes it, offered to the user (never run without a yes).
    fix: List[str] = field(default_factory=list)


def _install_docker_hint() -> tuple:
    if sys.platform == "win32":
        cmd = ["winget", "install", "-e", "--id", "Docker.DockerDesktop"]
        return ("Install Docker Desktop: winget install -e --id Docker.DockerDesktop "
                "(administrator rights; it sets up WSL 2 and may ask for a restart). "
                "Then start Docker Desktop and open a new terminal.",
                cmd if shutil.which("winget") else [])
    if sys.platform == "darwin":
        cmd = ["brew", "install", "--cask", "docker"]
        return ("Install Docker Desktop: brew install --cask docker, then start it "
                "from Applications.", cmd if shutil.which("brew") else [])
    return ("Install Docker Engine and the compose plugin for your distribution: "
            "https://docs.docker.com/engine/install/ , then let your user run docker "
            "(sudo usermod -aG docker $USER, and log in again).", [])


def _docker_desktop_exe() -> Optional[Path]:
    """Docker Desktop on Windows, when it is installed in the usual place."""
    if sys.platform != "win32":
        return None
    exe = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / \
        "Docker Desktop.exe"
    return exe if exe.is_file() else None


def _start_engine_hint() -> str:
    if sys.platform in ("win32", "darwin"):
        return "Start Docker Desktop and wait until it shows the engine running."
    return "Start the Docker service: sudo systemctl start docker"


def check_ports(ports: List[int]) -> List[Check]:
    """One check per port that something already listens on (127.0.0.1)."""
    busy = []
    for port in ports:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            busy.append(Check(f"port {port}", False, "already in use",
                              f"Free port {port} (another program, or an old devnet: "
                              "python scripts/devnet.py down)."))
        finally:
            s.close()
    return busy


def diagnose(ports: List[int]) -> List[Check]:
    checks: List[Check] = []
    v = sys.version_info
    checks.append(Check("python", v >= (3, 11), f"{v.major}.{v.minor}",
                        "Kern needs Python 3.11 or later: https://www.python.org/downloads/"))
    missing = [m for m in ("nacl", "aiohttp", "py_ecc") if importlib.util.find_spec(m) is None]
    checks.append(Check("python packages", not missing, ", ".join(missing) or "ok",
                        "Install the requirements: python -m pip install -r requirements.txt",
                        [sys.executable, "-m", "pip", "install", "-r",
                         str(ROOT / "requirements.txt")]))
    has_docker = shutil.which("docker") is not None
    desktop = _docker_desktop_exe() if not has_docker else None
    if has_docker:
        checks.append(Check("docker", True, "found"))
    elif desktop is not None:
        # Installed, but this terminal does not find the CLI: Docker Desktop
        # was never started, or the terminal was opened before the install.
        checks.append(Check("docker", False, "Docker Desktop installed, CLI not on PATH",
                            "Start Docker Desktop, accept its terms on first start, wait "
                            "until the engine is running, then open a new terminal.",
                            [str(desktop)]))
    else:
        hint, fix = _install_docker_hint()
        checks.append(Check("docker", False, "not found", hint, fix))
    if has_docker:
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        checks.append(Check("compose", r.returncode == 0, "",
                            "Install the Docker compose plugin "
                            "(included in Docker Desktop): https://docs.docker.com/compose/install/"))
        r = subprocess.run(["docker", "info"], capture_output=True, text=True)
        checks.append(Check("engine", r.returncode == 0,
                            "running" if r.returncode == 0 else "not running",
                            _start_engine_hint()))
    checks += check_ports(ports)
    return checks


def report(checks: List[Check]) -> bool:
    """Print the checks (plain ASCII: Windows consoles), return True if all pass."""
    for c in checks:
        status = "ok     " if c.ok else "MISSING"
        print(f"  {status} {c.name}" + (f" ({c.detail})" if c.detail else ""))
    failed = [c for c in checks if not c.ok]
    for c in failed:
        print(f"\n  {c.name}: {c.hint}")
    return not failed


def offer_fixes(checks: List[Check]) -> None:
    """For each failed check that has a fixing command, ask before running
    it. Only on an interactive terminal; nothing is ever installed silently."""
    if not sys.stdin.isatty():
        return
    for c in checks:
        if c.ok or not c.fix:
            continue
        answer = input(f"\nRun `{' '.join(c.fix)}` now? [y/N] ").strip().lower()
        if answer in ("y", "yes", "o", "oui"):
            if c.fix[0].lower().endswith("docker desktop.exe"):
                subprocess.Popen(c.fix)               # starts and returns
            else:
                subprocess.run(c.fix)
            print("Done. Open a new terminal (so that new programs are found), "
                  "then run: python scripts/devnet.py doctor")
            return


def planned_ports(out: Path, args) -> List[int]:
    """Ports `up` will publish. None to check when the devnet already exists
    (its own containers may hold them)."""
    if compose_file(out).exists():
        return []
    b = _bootstrap()
    ports = [b.BASE_RPC_PORT + i for i in range(args.validators)]
    if not args.no_explorer:
        ports.append(b.EXPLORER_PORT)
    if args.monitoring:
        ports += [b.PROMETHEUS_PORT, b.GRAFANA_PORT]
    return ports


def require_docker() -> None:
    checks = [c for c in diagnose([]) if c.name in ("docker", "compose", "engine")]
    if not all(c.ok for c in checks):
        report(checks)
        sys.exit(1)


# ------------------------------------------------------------------ commands

def cmd_doctor(args) -> int:
    ports: List[int] = []
    if not compose_file(args.out).exists():
        b = _bootstrap()
        ports = [b.BASE_RPC_PORT + i for i in range(4)] + [b.EXPLORER_PORT]
    checks = diagnose(ports)
    if report(checks):
        print("\nready: python scripts/devnet.py up")
        return 0
    offer_fixes(checks)
    return 1


def cmd_up(args) -> int:
    out: Path = args.out
    # Check everything before writing anything.
    checks = diagnose(planned_ports(out, args) if not args.regenerate else [])
    if not all(c.ok for c in checks):
        print("The devnet cannot start yet:")
        report(checks)
        offer_fixes(checks)
        return 1
    if args.regenerate and out.exists():
        if compose_file(out).exists():
            docker_compose(out, "down", "-v", check=False)
        shutil.rmtree(out)
    if not compose_file(out).exists():
        _bootstrap().build(out, args.validators, args.stake, args.balance, args.faucet,
                           explorer=not args.no_explorer, monitoring=args.monitoring)
    elif args.validators_given or args.monitoring or args.no_explorer:
        print(f"note: {out} already exists and is reused as it is; "
              "add --regenerate to apply new options (this resets the chain).")
    require_docker()
    docker_compose(out, "up", "-d", "--build")
    ports = node_ports(out)
    print(f"waiting for {len(ports)} validators to finalize blocks...")
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        hs = heads(ports)
        levels = [h["level"] for h in hs.values() if h is not None]
        if len(levels) == len(ports) and min(levels) >= 3:
            break
        time.sleep(2)
    else:
        print("error: the validators did not all reach level 3 in time; "
              "see `python scripts/devnet.py logs`.", file=sys.stderr)
        print_status(ports)
        return 1
    print_status(ports)
    print_urls(out, ports)
    return 0


def print_status(ports: Dict[str, int]) -> None:
    for name, h in heads(ports).items():
        if h is None:
            print(f"  {name:8} port {ports[name]}  not answering")
        else:
            print(f"  {name:8} port {ports[name]}  level {h['level']:>6}  "
                  f"{block_id(h)[:16]}")


def print_urls(out: Path, ports: Dict[str, int]) -> None:
    compose = json.loads(compose_file(out).read_text(encoding="utf-8"))
    b = _bootstrap()
    first = next(iter(ports.values()))
    print(f"\nRPC          http://127.0.0.1:{first}/chain/head  (one port per validator)")
    if "heimdall" in compose["services"]:
        print(f"Heimdall     http://127.0.0.1:{b.EXPLORER_PORT}")
    if "prometheus" in compose["services"]:
        print(f"Prometheus   http://127.0.0.1:{b.PROMETHEUS_PORT}")
        print(f"Grafana      http://127.0.0.1:{b.GRAFANA_PORT}  (admin / admin)")


def cmd_status(args) -> int:
    print_status(node_ports(args.out))
    return 0


def cmd_check(args) -> int:
    ports = node_ports(args.out)
    top, bad, down = divergences(ports)
    if top < 0:
        print("error: fewer than two validators answer; nothing to compare.", file=sys.stderr)
        return 1
    if down:
        print(f"not answering (skipped): {', '.join(down)}")
    if bad:
        print(f"DIVERGENCE at level(s) {bad[:20]} among {len(ports) - len(down)} validators")
        return 2
    print(f"ok: {len(ports) - len(down)} validators hold the same block at every level 0..{top}")
    return 0


def cmd_down(args) -> int:
    if not compose_file(args.out).exists():
        print(f"no devnet in {args.out}")
        return 0
    require_docker()
    docker_compose(args.out, "down", *(["-v"] if args.reset else []))
    if args.reset:
        shutil.rmtree(args.out)
        print(f"chain data and {args.out} deleted")
    return 0


def cmd_service(action: str):
    def run(args) -> int:
        require_docker()
        return docker_compose(args.out, action, *args.services, check=False)
    return run


def cmd_logs(args) -> int:
    require_docker()
    extra = ["--tail", str(args.tail)] + (["-f"] if args.follow else [])
    return docker_compose(args.out, "logs", *extra, *args.services, check=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="devnet.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--out", type=Path, default=DEFAULT_OUT,
                   help="devnet directory (default networks/devnet)")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="generate if needed, build, start, wait for blocks")
    up.add_argument("--validators", type=int, default=None,
                    help="number of validators for a new devnet (default 4)")
    up.add_argument("--monitoring", action="store_true",
                    help="add Prometheus and Grafana (images from Docker Hub)")
    up.add_argument("--no-explorer", action="store_true", help="without Heimdall")
    up.add_argument("--regenerate", action="store_true",
                    help="delete the existing devnet and its chain first")
    up.add_argument("--timeout", type=float, default=180.0,
                    help="seconds to wait for the first blocks (default 180)")
    up.add_argument("--stake", type=int, default=1_000_000_000)
    up.add_argument("--balance", type=int, default=5_000_000_000)
    up.add_argument("--faucet", type=int, default=100_000_000_000)
    up.set_defaults(func=cmd_up)

    sub.add_parser("doctor", help="check Python, Docker and ports; offer to fix what is missing"
                   ).set_defaults(func=cmd_doctor)
    sub.add_parser("status", help="head of every validator").set_defaults(func=cmd_status)
    sub.add_parser("check", help="every validator holds the same block at every level"
                   ).set_defaults(func=cmd_check)

    down = sub.add_parser("down", help="stop the devnet")
    down.add_argument("--reset", action="store_true",
                      help="also delete the chain data and the generated directory")
    down.set_defaults(func=cmd_down)

    for action, text in (("stop", "stop services (for example baker2)"),
                         ("start", "start stopped services"),
                         ("restart", "restart services")):
        sp = sub.add_parser(action, help=text)
        sp.add_argument("services", nargs="+")
        sp.set_defaults(func=cmd_service(action))

    lg = sub.add_parser("logs", help="service logs")
    lg.add_argument("services", nargs="*")
    lg.add_argument("--tail", type=int, default=100)
    lg.add_argument("-f", "--follow", action="store_true")
    lg.set_defaults(func=cmd_logs)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    args.out = args.out.resolve()
    if args.cmd == "up":
        args.validators_given = args.validators is not None
        if args.validators is None:
            args.validators = 4
        if args.validators < 1:
            sys.exit("error: --validators must be at least 1")
    elif not compose_file(args.out).exists() and args.cmd not in ("down", "doctor"):
        sys.exit(f"error: no devnet in {args.out}; run `python scripts/devnet.py up` first.")
    try:
        return args.func(args)
    except subprocess.CalledProcessError as e:
        print(f"error: `{' '.join(e.cmd[:2])} ... {' '.join(e.cmd[4:])}` failed "
              f"(exit status {e.returncode}); see the Docker output above.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
