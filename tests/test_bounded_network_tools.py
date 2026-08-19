from types import SimpleNamespace

import pytest

from harness.scope import Engagement, ScopeGate
from harness.tools import multipart_upload, websocket
from harness.tools.binary_inspect import handle_binary_inspect
from harness.tools.multipart_upload import handle_multipart_upload


@pytest.mark.asyncio
async def test_binary_inspect_is_local_and_reports_gzip() -> None:
    result = await handle_binary_inspect(
        SimpleNamespace(), "1f8b0800000000000003cb48cdc9c9070086a6103605000000", "eng", "hex")
    assert result["formats"] == ["gzip"]
    assert result["decompressed"]["text_preview"] == "hello"


def test_websocket_scope_uses_its_http_equivalent(packages) -> None:
    engagement = Engagement("eng", "net", "192.168.1.0/24", "read-only")
    gate = ScopeGate([engagement], packages, {})
    ok, reason, _ = gate.authorize(
        "websocket", {"url": "wss://192.168.1.9/socket"}, "eng",
        resolver=lambda _host: [__import__("ipaddress").ip_address("192.168.1.9")])
    assert ok, reason


@pytest.mark.asyncio
async def test_multipart_rejects_paths_outside_private_scratch(packages, tmp_path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    engagement = Engagement("eng", "net", "192.168.1.0/24", "offensive", scratch_dir=str(scratch))
    ctx = SimpleNamespace(gate=ScopeGate([engagement], packages, {}))
    result = await handle_multipart_upload(
        ctx, "https://192.168.1.9/upload", str(tmp_path / "outside.txt"), "eng", reason="test")
    assert "outside" in result["error"] or "escapes" in result["error"]


@pytest.mark.asyncio
async def test_multipart_redacts_set_cookie_headers(packages, tmp_path, monkeypatch) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    upload = scratch / "report.txt"
    upload.write_text("contents")
    engagement = Engagement("eng", "net", "192.168.1.0/24", "offensive",
                            scratch_dir=str(scratch))

    class Response:
        status_code = 200
        headers = __import__("httpx").Headers([
            ("set-cookie", "sid=secret; HttpOnly"), ("x-result", "ok")])

        async def aiter_bytes(self):
            yield b"uploaded"

        async def aclose(self):
            pass

    class Client:
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        def build_request(self, *args, **kwargs):
            return __import__("httpx").Request(*args, **kwargs)

        async def send(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(multipart_upload.httpx, "AsyncClient", Client)
    ctx = SimpleNamespace(gate=ScopeGate([engagement], packages, {}),
                          config=SimpleNamespace(packages=packages), extra={})
    result = await handle_multipart_upload(
        ctx, "https://192.168.1.9/upload", str(upload), "eng", reason="test")

    assert result["headers"]["set-cookie"] == "[redacted]"
    assert ("set-cookie", "[redacted]") in result["header_items"]


@pytest.mark.asyncio
async def test_websocket_frame_reads_apply_timeout_after_header() -> None:
    reader = __import__("asyncio").StreamReader()
    reader.feed_data(b"\x81\x7e")  # a text frame with a missing extended length

    with pytest.raises(__import__("asyncio").TimeoutError):
        await websocket._read_frame(reader, SimpleNamespace(), 0.01)


@pytest.mark.asyncio
async def test_websocket_oversized_frame_does_not_wait_for_payload() -> None:
    reader = __import__("asyncio").StreamReader()
    reader.feed_data(b"\x82\x7f" + (websocket._MAX_MESSAGE + 1).to_bytes(8, "big"))

    result = await websocket._read_frame(reader, SimpleNamespace(), 0.01)

    assert result == {"type": "oversized", "truncated": True}
