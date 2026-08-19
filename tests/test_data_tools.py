"""Bounded local response-inspection and HTTP-session tools."""
from types import SimpleNamespace

import pytest

from harness.tools import auth_session, data, http_session


@pytest.mark.asyncio
async def test_json_extract_uses_only_limited_paths() -> None:
    result = await data.handle_json_extract(
        SimpleNamespace(), '{"data":{"items":[{"name":"one"}]}}',
        "$.data.items[0].name", "eng1")
    assert result["value"] == '"one"'

    rejected = await data.handle_json_extract(
        SimpleNamespace(), "{}", "$..items", "eng1")
    assert "only" in rejected["error"]


@pytest.mark.asyncio
async def test_base64_decode_is_local_and_bounded() -> None:
    result = await data.handle_base64_decode(
        SimpleNamespace(), "aGVsbG8=", "eng1")
    assert result == {"text": "hello", "bytes": 5, "truncated": False}


@pytest.mark.asyncio
async def test_jwt_inspect_decodes_claims_without_key_verification() -> None:
    result = await data.handle_jwt_inspect(
        SimpleNamespace(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTcwMDAwMDAwMH0.c2ln",
        "eng1")
    assert result["header"]["alg"] == "HS256"
    assert result["claims"]["sub"] == "alice"
    assert result["verification"].startswith("not performed")


@pytest.mark.asyncio
async def test_http_session_retains_cookies_per_engagement(monkeypatch) -> None:
    seen_headers = []

    async def fake_http(ctx, url, engagement_id, method, headers, body, **_):
        seen_headers.append(headers)
        return {"status": 200, "headers": {"set-cookie": "sid=abc; Path=/"}, "body": "ok"}

    monkeypatch.setattr(http_session, "handle_http", fake_http)
    ctx = SimpleNamespace(extra={})
    await http_session.handle_http_session(ctx, "https://target/login", "eng1", reason="login")
    result = await http_session.handle_http_session(ctx, "https://target/me", "eng1", reason="follow up")

    assert seen_headers[1]["Cookie"] == "sid=abc"
    assert result["cookies_retained"] == 1


@pytest.mark.asyncio
async def test_http_session_does_not_send_cookies_to_another_origin(monkeypatch) -> None:
    seen_headers = []

    async def fake_http(ctx, url, engagement_id, method, headers, body, **_):
        seen_headers.append(dict(headers))
        return {"status": 200, "headers": {"set-cookie": "sid=abc; Path=/"},
                "body": "ok"}

    monkeypatch.setattr(http_session, "handle_http", fake_http)
    ctx = SimpleNamespace(extra={})
    await http_session.handle_http_session(ctx, "https://one.test/login", "eng1",
                                           reason="login")
    await http_session.handle_http_session(ctx, "https://two.test/me", "eng1",
                                           reason="other host")
    await http_session.handle_http_session(ctx, "https://one.test/me", "eng1",
                                           reason="same host")
    assert "Cookie" not in seen_headers[1]
    assert seen_headers[2]["Cookie"] == "sid=abc"


@pytest.mark.asyncio
async def test_http_session_honors_cookie_deletion_and_path_variants(monkeypatch) -> None:
    seen_headers = []
    responses = iter([
        "sid=root; Path=/",
        "sid=admin; Path=/admin",
        "sid=; Path=/; Max-Age=0",
        "",
    ])

    async def fake_http(ctx, url, engagement_id, method, headers, body, **_):
        seen_headers.append(dict(headers))
        return {"status": 200, "headers": {"set-cookie": next(responses)},
                "body": "ok"}

    monkeypatch.setattr(http_session, "handle_http", fake_http)
    ctx = SimpleNamespace(extra={})
    await http_session.handle_http_session(ctx, "https://target/login", "eng1", reason="login")
    await http_session.handle_http_session(ctx, "https://target/admin/login", "eng1", reason="admin login")
    await http_session.handle_http_session(ctx, "https://target/admin/home", "eng1", reason="admin request")
    await http_session.handle_http_session(ctx, "https://target/after-logout", "eng1", reason="verify logout")

    assert seen_headers[2]["Cookie"] == "sid=admin; sid=root"
    assert "Cookie" not in seen_headers[3]


@pytest.mark.asyncio
async def test_auth_session_stores_token_without_returning_it(monkeypatch) -> None:
    seen_headers = []

    async def fake_session(ctx, url, engagement_id, method, headers, body, session, **_):
        seen_headers.append(headers)
        return {"status": 200, "headers": {},
                "body": '{"authentication":{"token":"secret-token"}}'}

    monkeypatch.setattr(auth_session, "handle_http_session", fake_session)
    ctx = SimpleNamespace(extra={})
    stored = await auth_session.handle_auth_session(
        ctx, "https://target/login", "eng1", method="POST", session="admin",
        extract_token_path="$.authentication.token", reason="login")
    reused = await auth_session.handle_auth_session(
        ctx, "https://target/admin", "eng1", session="admin", reason="follow up")

    assert stored["token_stored"] is True
    assert "secret-token" not in stored["body"]
    assert seen_headers[1]["Authorization"] == "Bearer secret-token"
    assert reused["token_reused"] is True


@pytest.mark.asyncio
async def test_auth_session_rejects_cross_origin_token_reuse(monkeypatch) -> None:
    async def fake_session(ctx, url, engagement_id, method, headers, body, session, **_):
        return {"status": 200, "headers": {},
                "body": '{"authentication":{"token":"secret-token"}}'}

    monkeypatch.setattr(auth_session, "handle_http_session", fake_session)
    ctx = SimpleNamespace(extra={})
    await auth_session.handle_auth_session(
        ctx, "https://one.test/login", "eng1", session="admin",
        extract_token_path="$.authentication.token", reason="login")
    result = await auth_session.handle_auth_session(
        ctx, "https://two.test/me", "eng1", session="admin", reason="follow up")
    assert result["error"] == "stored session token is bound to a different origin"
