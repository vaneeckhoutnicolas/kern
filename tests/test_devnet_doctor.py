# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""`python scripts/devnet.py doctor`, also run first by `up`.

On a Windows machine without Docker, `up` generated networks/devnet and only
then stopped with "docker not found", without saying how to get Docker. The
launcher now checks everything before it writes anything, and gives the
command to run for the platform. It never installs anything itself.

Every test here fails on 4fd8369 (the devnet lot before this change)."""

import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "networks"))
sys.path.insert(0, str(ROOT))

import devnet  # noqa: E402


def _docker(monkeypatch, *, installed=True, compose=True, running=True):
    # Never look at the real "Program Files": on a machine where Docker
    # Desktop is installed, the launcher (rightly) finds it.
    monkeypatch.setenv("ProgramFiles", str(Path(__file__).parent / "no-such-program-files"))
    monkeypatch.setattr(devnet.shutil, "which",
                        lambda name: "/usr/bin/docker" if installed and name == "docker" else None)

    def run(cmd, **kw):
        ok = {("docker", "compose"): compose, ("docker", "info"): running}.get(tuple(cmd[:2]), True)
        return subprocess.CompletedProcess(cmd, 0 if ok else 1, "", "")
    monkeypatch.setattr(devnet.subprocess, "run", run)


def _names(checks):
    return {c.name: c for c in checks}


def test_without_docker_on_windows_the_hint_is_the_winget_command(monkeypatch):
    _docker(monkeypatch, installed=False)
    monkeypatch.setattr(devnet.sys, "platform", "win32")
    c = _names(devnet.diagnose(ports=[]))["docker"]
    assert not c.ok
    assert "winget install -e --id Docker.DockerDesktop" in c.hint


def test_hints_follow_the_platform(monkeypatch):
    _docker(monkeypatch, installed=False)
    monkeypatch.setattr(devnet.sys, "platform", "darwin")
    assert "brew install --cask docker" in _names(devnet.diagnose(ports=[]))["docker"].hint
    monkeypatch.setattr(devnet.sys, "platform", "linux")
    assert "docs.docker.com/engine/install" in _names(devnet.diagnose(ports=[]))["docker"].hint


def test_installed_but_not_started(monkeypatch):
    _docker(monkeypatch, running=False)
    monkeypatch.setattr(devnet.sys, "platform", "win32")
    checks = _names(devnet.diagnose(ports=[]))
    assert checks["docker"].ok and checks["compose"].ok
    assert not checks["engine"].ok and "Docker Desktop" in checks["engine"].hint


def test_a_busy_port_is_reported():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    try:
        checks = [c for c in devnet.check_ports([port]) if not c.ok]
    finally:
        s.close()
    assert len(checks) == 1 and str(port) in checks[0].name


def test_up_writes_nothing_when_docker_is_missing(monkeypatch, tmp_path, capsys):
    _docker(monkeypatch, installed=False)
    monkeypatch.setattr(devnet.sys, "platform", "win32")
    out = tmp_path / "devnet"
    rc = devnet.main(["--out", str(out), "up"])
    assert rc == 1
    assert not out.exists()
    text = capsys.readouterr().out
    assert "winget install -e --id Docker.DockerDesktop" in text


def test_doctor_reports_ok_when_everything_is_there(monkeypatch, capsys):
    _docker(monkeypatch)
    monkeypatch.setattr(devnet, "check_ports", lambda ports: [])
    assert devnet.main(["doctor"]) == 0
    assert "ready" in capsys.readouterr().out


def test_docker_desktop_installed_but_not_on_the_path(monkeypatch, tmp_path):
    """Seen on Windows: winget said Docker Desktop 4.98.0 was installed, yet
    `docker` was not found (never started, or a terminal opened before the
    install). Offering winget again only fails; the hint is to start Docker
    Desktop and open a new terminal, and the offered command starts it."""
    _docker(monkeypatch, installed=False)
    monkeypatch.setattr(devnet.sys, "platform", "win32")
    pf = tmp_path / "Program Files"
    exe = pf / "Docker" / "Docker" / "Docker Desktop.exe"
    cli = pf / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
    for f in (exe, cli):
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"")
    monkeypatch.setenv("ProgramFiles", str(pf))
    c = _names(devnet.diagnose(ports=[]))["docker"]
    assert not c.ok and "installed" in c.detail
    assert "winget" not in c.hint and "new terminal" in c.hint
    assert c.fix == [str(exe)]
