from types import SimpleNamespace

import pytest

from harness.scope import Engagement, ScopeGate
from harness.tools.tcp_probe import TCP_PROBE_SCHEMA, handle_tcp_probe


@pytest.mark.asyncio
async def test_tcp_probe_reads_passive_banner_from_in_scope_service(packages, monkeypatch) -> None:
    async def fake_connect(address, port, server_name, use_tls, read_banner, timeout):
        assert (address, port, server_name, use_tls, read_banner, timeout) == (
            "127.0.0.1", 2222, "127.0.0.1", False, True, 5.0)
        return {"connected": True, "tls": None, "banner": "SSH-2.0-test-server\\r\\n"}

    monkeypatch.setattr("harness.tools.tcp_probe._connect", fake_connect)
    engagement = Engagement("eng", "local", "127.0.0.1", "read-only")
    ctx = SimpleNamespace(gate=ScopeGate([engagement], packages, {}))
    result = await handle_tcp_probe(ctx, "127.0.0.1", 2222, "eng", tls="off",
                                    reason="read the SSH banner")

    assert result["connected"] is True
    assert result["tls"] is None
    assert result["banner"] == "SSH-2.0-test-server\\r\\n"


def test_tcp_probe_schema_has_no_payload_and_scope_is_enforced(packages) -> None:
    properties = TCP_PROBE_SCHEMA["parameters"]["properties"]
    assert "payload" not in properties

    engagement = Engagement("eng", "subnet", "192.168.1.0/24", "read-only")
    gate = ScopeGate([engagement], packages, {})
    ok, reason, _ = gate.authorize(
        "tcp_probe", {"host": "192.168.2.8", "port": 443}, "eng",
        resolver=lambda _: [__import__("ipaddress").ip_address("192.168.2.8")])
    assert not ok
    assert "outside engagement network" in reason
