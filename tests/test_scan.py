"""Tests for Nmap text-output parsing."""

from harness.tools.scan import _parse_nmap


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
