"""Tests for Nmap text-output parsing."""

from types import SimpleNamespace

import pytest

from halgate.guardrails.shell_guard import ShellResult
from halgate.scope import Engagement, ScopeGate
from halgate.tools.scan import _parse_nmap


def test_parse_nmap_extracts_standard_port_table_rows() -> None:
    output = """\
Nmap scan report for target.example (192.0.2.10)
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
80/tcp    open     http          nginx 1.24.0
443/tcp   open     ssl/http      nginx 1.24.0
53/udp    open     domain        dnsmasq 2.90
3306/tcp  filtered mysql
Nmap done: 1 IP address (1 host up) scanned in 2.41 seconds
"""

    assert _parse_nmap(output) == [{
        "host": "target.example (192.0.2.10)",
        "ports": [
            {"port": "80", "proto": "tcp", "state": "open",
             "service": "http nginx 1.24.0"},
            {"port": "443", "proto": "tcp", "state": "open",
             "service": "ssl/http nginx 1.24.0"},
            {"port": "53", "proto": "udp", "state": "open",
             "service": "domain dnsmasq 2.90"},
            {"port": "3306", "proto": "tcp", "state": "filtered",
             "service": "mysql"},
        ],
    }]


def test_parse_nmap_ignores_non_port_lines() -> None:
    output = """\
Nmap scan report for 192.0.2.11
Host is up.
All 1000 scanned ports on 192.0.2.11 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
"""

    assert _parse_nmap(output) == [{"host": "192.0.2.11", "ports": []}]


@pytest.mark.asyncio
async def test_scan_preserves_nmap_stderr_diagnostics(packages, monkeypatch) -> None:
    from halgate.guardrails import shell_guard
    from halgate.tools.scan import handle_scan

    class FakeGuard:
        def __init__(self, *_args, **_kwargs):
            pass

        def check(self, command):
            assert "-Pn" in command
            return True, ""

        async def execute(self, *_args, **_kwargs):
            return ShellResult(
                rc=0,
                stdout=b"Nmap scan report for 192.0.2.10\n80/tcp open http\n",
                stderr=b"Strange read error from 192.0.2.10 (22 - 'Invalid argument')\n",
                truncated=False,
            )

    monkeypatch.setattr(shell_guard, "ShellGuard", FakeGuard)
    engagement = Engagement("eng", "lab", "192.0.2.0/24", "defensive")
    ctx = SimpleNamespace(
        gate=ScopeGate([engagement], packages, {}),
        config=SimpleNamespace(
            packages=packages,
            shell=SimpleNamespace(workdir="."),
        ),
        extra={},
    )

    result = await handle_scan(ctx, ["192.0.2.10"], "eng", reason="test")

    assert result["hosts"][0]["ports"][0]["port"] == "80"
    assert "Strange read error" in result["stderr"]
    assert result["partial"] is True


@pytest.mark.asyncio
async def test_scan_returns_nonzero_nmap_exit_as_failure(packages, monkeypatch) -> None:
    from halgate.guardrails import shell_guard
    from halgate.tools.scan import handle_scan

    class FakeGuard:
        def __init__(self, *_args, **_kwargs):
            pass

        def check(self, _command):
            return True, ""

        async def execute(self, *_args, **_kwargs):
            return ShellResult(rc=1, stdout=b"partial output", stderr=b"socket failure",
                               truncated=False)

    monkeypatch.setattr(shell_guard, "ShellGuard", FakeGuard)
    engagement = Engagement("eng", "lab", "192.0.2.0/24", "defensive")
    ctx = SimpleNamespace(
        gate=ScopeGate([engagement], packages, {}),
        config=SimpleNamespace(
            packages=packages,
            shell=SimpleNamespace(workdir="."),
        ),
        extra={},
    )

    result = await handle_scan(ctx, ["192.0.2.10"], "eng", reason="test")

    assert result["error"] == "scan failed (nmap exit code 1)"
    assert result["stdout"] == "partial output"
    assert result["stderr"] == "socket failure"
