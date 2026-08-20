import asyncio
import socket
from types import SimpleNamespace

import pytest

from harness.dispatch import (
    AUTO_APPROVE, ApprovalResult, dispatch_parallel,
)
from harness.llm.client import ToolCall
from harness.scope import Engagement, ScopeGate
from harness.tools.callback_endpoint import (
    DEFAULT_EXPIRY_SECONDS,
    READ_CALLBACK_ENDPOINT_SCHEMA,
    REQUEST_CALLBACK_ENDPOINT_SCHEMA,
    handle_read_callback_endpoint,
    handle_request_callback_endpoint,
)


def make_ctx(packages):
    engagements = [
        Engagement("eng-a", "alpha", "127.0.0.1", "offensive"),
        Engagement("eng-b", "beta", "192.168.50.0/24", "offensive"),
    ]
    gate = ScopeGate(engagements, packages, {})
    return SimpleNamespace(gate=gate, extra={},
                           config=SimpleNamespace(
                               callback=SimpleNamespace(advertised_host=None)))


@pytest.fixture
def listener_capability() -> None:
    """Skip listener integration tests when the runtime forbids local binds."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
    except OSError as e:
        pytest.skip(f"local TCP listeners are unavailable: {e}")
    finally:
        probe.close()


async def _raw_callback(port: int, payload: bytes, read_response: bool = False) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        if read_response:
            await reader.read(2048)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    await asyncio.sleep(0.25)


async def _dns_query(port: int, name: str) -> bytes:
    labels = b"".join(
        bytes([len(part)]) + part.encode() for part in name.rstrip(".").split("."))
    query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
             labels + b"\x00\x00\x01\x00\x01")
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, query, ("127.0.0.1", port))
        response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 512), timeout=1)
        return response
    finally:
        sock.close()


def test_approval_gating_and_schema() -> None:
    assert "request_callback_endpoint" not in AUTO_APPROVE
    assert "read_callback_endpoint" in AUTO_APPROVE

    props = REQUEST_CALLBACK_ENDPOINT_SCHEMA["parameters"]["properties"]
    assert set(props) >= {"reason", "protocol", "bind", "port",
                          "max_requests", "max_bytes", "expires_seconds",
                          "path_prefix", "query_name", "engagement_id"}
    assert REQUEST_CALLBACK_ENDPOINT_SCHEMA["parameters"]["required"] == [
        "reason", "protocol", "engagement_id"]
    assert "5-1800 seconds" in props["expires_seconds"]["description"]
    read_props = READ_CALLBACK_ENDPOINT_SCHEMA["parameters"]["properties"]
    assert set(read_props) == {"endpoint_id", "engagement_id",
                               "wait_seconds", "close"}


def test_scope_policy(packages) -> None:
    ro = [Engagement("eng-ro", "readonly", "10.0.0.0/24", "read-only")]
    gate = ScopeGate(ro, packages, {})
    ok, reason, _ = gate.authorize(
        "request_callback_endpoint",
        {"reason": "x", "protocol": "http", "engagement_id": "eng-ro"},
        "eng-ro")
    assert not ok
    assert "disabled" in reason
    assert not gate.any_active_engagement_permits("request_callback_endpoint")

    eng = [Engagement("eng-a", "alpha", "127.0.0.1", "offensive")]
    gate_a = ScopeGate(eng, packages, {})
    ok, reason, _ = gate_a.authorize(
        "request_callback_endpoint",
        {"reason": "x", "protocol": "http", "engagement_id": "eng-a"},
        "eng-a")
    assert ok, reason
    assert gate_a.any_active_engagement_permits("request_callback_endpoint")


@pytest.mark.asyncio
async def test_reason_and_protocol_validation(packages) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(ctx, "  ", "http", "eng-a")
    assert "error" in res and "reason" in res["error"]
    res = await handle_request_callback_endpoint(ctx, "why", "gopher", "eng-a")
    assert "error" in res
    res = await handle_request_callback_endpoint(ctx, "why", "http", "eng-a",
                                                 bind="10.0.0.5")
    assert "error" in res and "bind" in res["error"]
    assert not ctx.extra.get("callback_endpoints")


@pytest.mark.asyncio
async def test_http_provision_capture_read_and_auto_close(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "confirm exfil path", "http", "eng-a")
    assert res["status"] == "listening"
    assert res["port"] >= 0
    endpoint_id, port = res["endpoint_id"], res["port"]

    await asyncio.wait_for(_raw_callback(
        port, b"GET /confirm/abc?x=1 HTTP/1.1\r\n"
              b"Host: example\r\nConnection: close\r\n\r\n",
        read_response=True), timeout=1)
    out = await handle_read_callback_endpoint(ctx, endpoint_id, "eng-a")
    assert out["captured_count"] == 1
    cap = out["captured"][0]
    assert cap["method"] == "GET"
    assert cap["path"] == "/confirm/abc"
    assert cap["query"] == "x=1"
    assert cap["matched"] is True
    assert out["confirmed"] == 1
    assert out["status"] == "completed"
    # The listener must have torn itself down once confirmations were met.
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_listener_output_is_sent_to_a_dedicated_pane(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    output = []
    ctx.extra["listener_pane_callback"] = (
        lambda endpoint_id, stream, text, engagement_id:
        output.append((endpoint_id, stream, text, engagement_id)))

    res = await handle_request_callback_endpoint(
        ctx, "show listener output", "tcp", "eng-a")
    await _raw_callback(res["port"], b"listener-output")

    assert output[0][1:] == ("stdout", "listening on tcp://127.0.0.1:%s (tcp)\n" % res["port"], "eng-a")
    assert any(stream == "stdout" and "listener-output" in text
               for _, stream, text, _ in output)


@pytest.mark.asyncio
async def test_path_prefix_scopes_confirmations(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "confirm RCE via specific path", "http", "eng-a",
        path_prefix="/confirm/", max_requests=1)
    endpoint_id, port = res["endpoint_id"], res["port"]

    await _raw_callback(port, b"GET /noise HTTP/1.1\r\n"
                              b"Host: example\r\nConnection: close\r\n\r\n",
                        read_response=True)
    out = await handle_read_callback_endpoint(ctx, endpoint_id, "eng-a")
    assert out["captured_count"] == 1
    assert out["captured"][0]["matched"] is False
    assert out["confirmed"] == 0
    assert out["status"] == "listening"

    await _raw_callback(port, b"GET /confirm/ok HTTP/1.1\r\n"
                              b"Host: example\r\nConnection: close\r\n\r\n",
                        read_response=True)
    out = await handle_read_callback_endpoint(ctx, endpoint_id, "eng-a")
    assert out["captured_count"] == 2
    assert out["confirmed"] == 1
    assert out["status"] == "completed"


@pytest.mark.asyncio
async def test_tcp_capture_and_close(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    ctx.config.callback.advertised_host = "198.51.100.10"
    res = await handle_request_callback_endpoint(
        ctx, "confirm raw socket beacon", "tcp", "eng-a", bind="0.0.0.0")
    assert res["url_display"] == f"tcp://198.51.100.10:{res['port']}"
    assert res["engineered_url"] == res["url_display"]
    endpoint_id, port = res["endpoint_id"], res["port"]

    await _raw_callback(port, b"raw-bytes-123")
    out = await handle_read_callback_endpoint(ctx, endpoint_id, "eng-a",
                                              close=True)
    cap = out["captured"][0]
    assert cap["protocol"] == "tcp"
    assert cap["text"] == "raw-bytes-123"
    assert out["status"] == "closed"
    assert "may have been missed" in out["note"]
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_dns_provision_records_question_and_returns_nxdomain(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    ctx.config.callback.advertised_host = "198.51.100.10"
    res = await handle_request_callback_endpoint(
        ctx, "confirm DNS-only callback", "dns", "eng-a", bind="0.0.0.0",
        query_name="unique.callback.test")
    assert res["url_display"] == f"dns://198.51.100.10:{res['port']}"
    assert res["query_name"] == "unique.callback.test."
    assert res["dns_usage"]["resolver_host"] == "198.51.100.10"
    assert f"-p {res['port']}" in res["dns_usage"]["dig"]
    assert ":<port>" in res["dns_usage"]["important"]

    response = await _dns_query(res["port"], "unique.callback.test")
    assert response[:2] == b"\x12\x34"
    assert int.from_bytes(response[2:4], "big") & 0xF == 3  # NXDOMAIN

    out = await handle_read_callback_endpoint(ctx, res["endpoint_id"], "eng-a")
    assert out["status"] == "completed"
    assert out["confirmed"] == 1
    assert out["captured"][0]["query_name"] == "unique.callback.test."
    assert out["captured"][0]["query_type"] == 1


@pytest.mark.asyncio
async def test_dns_rejects_loopback_for_remote_callback(packages) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(ctx, "DNS callback", "dns", "eng-a")
    assert "error" in res
    assert "bind='0.0.0.0'" in res["error"]


@pytest.mark.asyncio
async def test_external_callback_requires_operator_advertised_host(packages) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "external confirmation", "http", "eng-a", bind="0.0.0.0")
    assert "error" in res and "callback.advertised_host" in res["error"]


@pytest.mark.asyncio
async def test_expiry_closes_listener(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "short-lived confirm", "http", "eng-a", expires_seconds=5)
    endpoint_id, port = res["endpoint_id"], res["port"]
    await asyncio.sleep(5.4)
    out = await handle_read_callback_endpoint(ctx, endpoint_id, "eng-a")
    assert out["status"] == "expired"
    assert out["captured_count"] == 0
    assert "may have been missed" in out["note"]
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_default_listener_lifetime_is_extended(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "allow time for callback", "http", "eng-a")
    assert res["expires_in_seconds"] == DEFAULT_EXPIRY_SECONDS == 300


@pytest.mark.asyncio
async def test_fixated_port_conflict_fails_closed(packages, listener_capability) -> None:
    blocker = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    blocked_port = blocker.sockets[0].getsockname()[1]
    try:
        ctx = make_ctx(packages)
        res = await handle_request_callback_endpoint(
            ctx, "conflict", "http", "eng-a", port=blocked_port)
        assert "error" in res and "bind failed" in res["error"]
        assert not ctx.extra.get("callback_endpoints")
    finally:
        blocker.close()
        await blocker.wait_closed()


@pytest.mark.asyncio
async def test_read_is_engagement_bound_and_unknown_safe(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    res = await handle_request_callback_endpoint(
        ctx, "binding", "http", "eng-a")
    out = await handle_read_callback_endpoint(ctx, res["endpoint_id"], "eng-b")
    assert "error" in out and "different engagement" in out["error"]
    out = await handle_read_callback_endpoint(ctx, "nope", "eng-a")
    assert "error" in out
    out = await handle_read_callback_endpoint(ctx, res["endpoint_id"], "eng-a",
                                              wait_seconds=0.2)
    assert out["status"] == "listening"


class _Exec:
    def __init__(self, ctx):
        self.ctx = ctx

    async def call(self, name, args):
        if name == "request_callback_endpoint":
            return await handle_request_callback_endpoint(self.ctx, **args)
        raise AssertionError(f"unexpected tool {name}")


class _Audit:
    def __init__(self):
        self.decisions = []
        self.approvals = []

    def guard_decision(self, tool, allowed, reason, engagement_id=None):
        self.decisions.append((tool, allowed, reason))

    def approval(self, tool, approved, summarized, engagement_id=None):
        self.approvals.append((tool, approved))

    def tool_call(self, name, args, engagement_id):
        pass

    def tool_result(self, *args, **kwargs):
        pass


async def test_dispatch_approval_gate_provisions_only_when_approved(
        config, packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    gate = ctx.gate
    tc = ToolCall(
        id="t1", name="request_callback_endpoint",
        arguments={"reason": "confirm", "protocol": "http",
                   "engagement_id": "eng-a"})

    async def deny(tc, eng):
        return ApprovalResult(approved=False)

    async def allow(tc, eng):
        return ApprovalResult(approved=True)

    denied = await dispatch_parallel(
        calls=[tc], executor=_Exec(ctx), gate=gate, audit=_Audit(),
        config=config, approver=deny, redactor=None)
    assert denied[0].get("error") == "denied by operator"
    assert not ctx.extra.get("callback_endpoints")

    approved = await dispatch_parallel(
        calls=[tc], executor=_Exec(ctx), gate=gate, audit=_Audit(),
        config=config, approver=allow, redactor=None)
    assert "endpoint_id" in approved[0]
    entry = ctx.extra["callback_endpoints"][approved[0]["endpoint_id"]]
    assert entry["engagement_id"] == "eng-a"
    assert entry["status"] == "listening"


@pytest.mark.asyncio
async def test_read_records_audit_when_attached(packages, listener_capability) -> None:
    ctx = make_ctx(packages)
    events = []
    ctx.extra["audit"] = SimpleNamespace(
        callback_endpoint_event=lambda action, eid, detail, eng=None:
        events.append((action, eng)))
    res = await handle_request_callback_endpoint(ctx, "audit", "http", "eng-a")
    out = await handle_read_callback_endpoint(ctx, res["endpoint_id"], "eng-a",
                                              close=True)
    assert out["status"] == "closed"
    assert [a for a, _ in events] == ["provisioned", "closed"]
    assert all(eng == "eng-a" for _, eng in events)
