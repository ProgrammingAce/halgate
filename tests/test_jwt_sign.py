"""Bounded, approval-gated HS256 JWT signing from the encrypted keystore."""

import base64
import hashlib
import hmac
import json
import time

import pytest

from halgate.audit.logger import AuditLogger
from halgate.dispatch import (
    AUTO_APPROVE, ApprovalResult, dispatch_parallel,
)
from halgate.guardrails.redactor import Redactor
from halgate.llm.client import ToolCall
from halgate.memory.keystore import KeyStore
from halgate.scope import Engagement, ScopeGate, ScopePackage
from halgate.tools.jwt_sign import JWT_SIGN_SCHEMA, handle_jwt_sign

CRED_ID = "cred_" + "a" * 32
KEY = "unit-test-hs256-key"


def _decode(part: str):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _ctx(packages, extra=None, pkg="offensive", target="127.0.0.1"):
    engagement = Engagement("eng-a", "alpha", target, pkg)
    gate = ScopeGate([engagement], packages, {})
    ctx = type("Ctx", (), {})()
    ctx.gate = gate
    ctx.extra = dict(extra or {})
    return ctx


class _Keystore:
    def __init__(self, secrets=None):
        self._secrets = dict(secrets or {})

    def known_ids(self):
        return [{"id": i, "type": "jwt_signing_key", "ts": "",
                 "engagement": None} for i in self._secrets]

    async def reveal(self, short_id):
        return self._secrets.get(short_id)


def _signing_package(**overrides) -> ScopePackage:
    base = dict(name="offensive", jwt_sign_enabled=True,
                jwt_max_ttl_seconds=600,
                jwt_allowed_claims=["iss", "sub", "aud", "jti"])
    base.update(overrides)
    return ScopePackage(**base)


def test_approval_gating_and_closed_schema() -> None:
    assert "jwt_sign" not in AUTO_APPROVE
    props = JWT_SIGN_SCHEMA["parameters"]["properties"]
    assert set(props) == {"credential_ref", "algorithm", "claims", "ttl_seconds",
                          "session", "reason", "engagement_id"}
    for secret_like in ("key", "secret", "token"):
        assert secret_like not in props
    assert JWT_SIGN_SCHEMA["parameters"]["required"] == [
        "claims", "reason", "engagement_id"]


def test_package_policy_is_declared_and_bounded(packages) -> None:
    assert packages["offensive"].permits("jwt_sign")
    assert packages["offensive"].jwt_unsigned_enabled
    assert packages["defensive"].permits("jwt_sign") is False
    assert packages["read-only"].permits("jwt_sign") is False
    pkg = ScopePackage.from_yaml("t", {"jwt": {"sign": True,
                                               "max_ttl_seconds": 999999,
                                               "allowed_claims": ["iss"]}})
    assert pkg.jwt_sign_enabled and pkg.jwt_allowed_claims == ["iss"]
    assert pkg.jwt_max_ttl_seconds == 86400  # hard cap, never more than a day
    default = ScopePackage.from_yaml("t", {})
    assert not default.permits("jwt_sign")
    assert not default.jwt_sign_enabled
    assert not default.jwt_unsigned_enabled
    assert default.jwt_max_ttl_seconds == 300


def test_scope_gate_allows_arbitrary_json_claims() -> None:
    packages = {"offensive": _signing_package()}
    eng = Engagement("eng", "net", "127.0.0.1", "offensive")
    gate = ScopeGate([eng], packages, {})
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"iss": "svc"},
         "ttl_seconds": 600, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID,
         "claims": {"scope": "admin", "exp": 9_999_999_999,
                    "https://example.test/roles": ["admin"],
                    "nested": {"enabled": True}},
         "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"iss": "svc"},
         "ttl_seconds": 86_401, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"iss": "x",
                                               **{f"c{i}": "v" for i in range(32)}},
         "ttl_seconds": 60, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason


def test_scope_gate_requires_explicit_unsigned_jwt_permission() -> None:
    eng = Engagement("eng", "net", "127.0.0.1", "offensive")
    disabled = ScopeGate([eng], {"offensive": _signing_package()}, {})
    ok, reason, _ = disabled.authorize(
        "jwt_sign", {"algorithm": "none", "claims": {"iss": "svc"},
                     "ttl_seconds": 60, "reason": "parser test",
                     "engagement_id": "eng"}, "eng")
    assert not ok and "none disabled" in reason

    enabled_pkg = _signing_package(jwt_unsigned_enabled=True)
    enabled = ScopeGate([eng], {"offensive": enabled_pkg}, {})
    ok, reason, _ = enabled.authorize(
        "jwt_sign", {"algorithm": "none", "claims": {"iss": "svc"},
                     "ttl_seconds": 60, "reason": "parser test",
                     "engagement_id": "eng"}, "eng")
    assert ok, reason


@pytest.mark.asyncio
async def test_disabled_package_is_denied() -> None:
    packages = {"defensive": ScopePackage(
        name="defensive", jwt_sign_enabled=False, jwt_max_ttl_seconds=600)}
    ctx = _ctx(packages, pkg="defensive")
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                "eng-a", reason="t")
    assert "disabled for engagement package" in res["error"]
    assert "auth_session_tokens" not in ctx.extra


@pytest.mark.asyncio
async def test_rejects_raw_secrets_and_unknown_refs() -> None:
    ctx = _ctx({"offensive": _signing_package()})
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    for bad_ref in (KEY, "mysupersecretkey123", "cred_" + "g" * 32,
                    "Credential_" + "a" * 32, "cred_" + "A" * 64):
        res = await handle_jwt_sign(ctx, bad_ref, {"iss": "svc"}, 60,
                                    "eng-a", reason="t")
        assert "error" in res, bad_ref
    ctx.extra["keystore"] = _Keystore()
    res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                "eng-a", reason="t")
    assert "unknown credential reference" in res["error"]
    ctx.extra.pop("keystore")
    res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                "eng-a", reason="t")
    assert "keystore unavailable" in res["error"]


@pytest.mark.asyncio
async def test_keystore_failure_is_fail_closed(config) -> None:
    good = KeyStore(config.audit, "jwt-keystore")
    cred = await good.store("jwt_signing_key", KEY, "test", None)
    from tests.conftest import BROKEN_GPG
    config.audit.gpg_executable = str(BROKEN_GPG)
    broken = KeyStore(config.audit, "jwt-keystore")
    ctx = _ctx({"offensive": _signing_package()})
    ctx.extra["keystore"] = broken
    res = await handle_jwt_sign(ctx, cred, {"iss": "svc"}, 60,
                                "eng-a", reason="t")
    assert "decryption failed" in res["error"]
    assert "auth_session_tokens" not in ctx.extra


@pytest.mark.asyncio
async def test_signs_hs256_verifiable_with_stdlib_only() -> None:
    ctx = _ctx({"offensive": _signing_package()})
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    before = int(time.time())
    res = await handle_jwt_sign(ctx, CRED_ID,
                                {"iss": "svc", "sub": "op",
                                 "aud": ["api-a", "api-b"], "jti": "t-1"},
                                600, "eng-a", reason="mint api token")
    assert res["status"] == "signed"
    assert res["algorithm"] == "HS256"
    assert res["token"] == "[stored session credential]"
    assert res["claim_keys"] == ["aud", "iss", "jti", "sub"]
    assert res["expires_at"] - res["issued_at"] == 600
    stored = ctx.extra["auth_session_tokens"][("eng-a", "jwt")]
    assert stored["header"] == "Authorization" and stored["prefix"] == "Bearer "
    token = stored["value"]
    header, payload, signature = token.split(".")
    assert token.count(".") == 2

    head = _decode(header)
    assert head == {"alg": "HS256", "typ": "JWT"}
    claims = _decode(payload)
    assert claims["iss"] == "svc" and claims["aud"] == ["api-a", "api-b"]
    assert claims["jti"] == "t-1"
    assert claims["exp"] - claims["iat"] == 600
    assert before - 5 <= claims["iat"] <= int(time.time()) + 5

    signing_input = f"{header}.{payload}".encode("ascii")
    expected = base64.urlsafe_b64encode(
        hmac.new(KEY.encode(), signing_input, hashlib.sha256).digest()
    ).decode().rstrip("=")
    assert signature == expected, "signature must verify under plain hmac/SHA-256"


@pytest.mark.asyncio
async def test_mints_scope_enabled_unsigned_token_without_a_credential() -> None:
    ctx = _ctx({"offensive": _signing_package(jwt_unsigned_enabled=True)})
    res = await handle_jwt_sign(
        ctx, claims={"iss": "parser-test", "sub": "1"}, ttl_seconds=60,
        engagement_id="eng-a", reason="test unsigned-token handling",
        algorithm="none")

    assert res["status"] == "minted"
    assert res["algorithm"] == "none"
    assert res["credential"] is None
    token = ctx.extra["auth_session_tokens"][("eng-a", "jwt")]["value"]
    header, payload, signature = token.split(".")
    assert _decode(header) == {"alg": "none", "typ": "JWT"}
    assert _decode(payload)["iss"] == "parser-test"
    assert signature == ""


@pytest.mark.asyncio
async def test_unsigned_jwt_rejects_a_credential_reference() -> None:
    ctx = _ctx({"offensive": _signing_package(jwt_unsigned_enabled=True)})
    res = await handle_jwt_sign(
        ctx, CRED_ID, {"iss": "parser-test"}, 60, "eng-a", reason="test",
        algorithm="none")
    assert "must be omitted" in res["error"]


@pytest.mark.asyncio
async def test_token_bound_to_one_engagement_and_replaces_slot() -> None:
    packages = {"offensive": _signing_package()}
    eng_a = Engagement("eng-a", "alpha", "127.0.0.1", "offensive")
    eng_b = Engagement("eng-b", "beta", "192.168.50.0/24", "offensive")
    gate = ScopeGate([eng_a, eng_b], packages, {})
    ctx = type("Ctx", (), {})()
    ctx.gate = gate
    ctx.extra = {"keystore": _Keystore({CRED_ID: KEY})}

    res_a = await handle_jwt_sign(ctx, CRED_ID, {"iss": "a"}, 600, "eng-a",
                                  reason="r")
    first = ctx.extra["auth_session_tokens"][("eng-a", "jwt")]["value"]
    res_b = await handle_jwt_sign(ctx, CRED_ID, {"iss": "b"}, 600, "eng-b",
                                  reason="r")
    tokens = ctx.extra["auth_session_tokens"]
    assert res_a["status"] == "signed" and res_b["status"] == "signed"
    assert tokens[("eng-a", "jwt")]["value"] != tokens[("eng-b", "jwt")]["value"]
    res_a2 = await handle_jwt_sign(ctx, CRED_ID, {"iss": "a2"}, 600, "eng-a",
                                   reason="re-mint")
    assert res_a2["status"] == "signed"
    assert tokens[("eng-a", "jwt")]["value"] != first
    assert len(tokens) == 2


@pytest.mark.asyncio
async def test_audit_event_records_metadata_only() -> None:
    captured = []
    audit = type("A", (), {
        "jwt_signed": staticmethod(
            lambda engagement_id, credential_id, algorithm, claim_keys,
            ttl, exp: captured.append((engagement_id, credential_id,
                                      algorithm, claim_keys, ttl, exp))),
    })()
    ctx = _ctx({"offensive": _signing_package()})
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    ctx.extra["audit"] = audit
    res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                "eng-a", reason="t")
    assert res["status"] == "signed"
    assert captured == [("eng-a", CRED_ID, "HS256", ["iss"], 60,
                         res["expires_at"])]


def test_real_audit_logger_event_is_chained_and_leak_free(config) -> None:
    logger = AuditLogger(config.audit, "s1", "testinstance.1")
    before = logger.last_seq()
    logger.jwt_signed("eng-a", CRED_ID, "HS256", ["iss"], 60, 1234567890)
    with logger.path.open() as f:
        lines = [json.loads(line) for line in f if line.strip()]
    entry = lines[-1]
    assert entry["event"] == "jwt_signed"
    assert entry["payload"] == {
        "engagement_id": "eng-a", "credential_id": CRED_ID,
        "algorithm": "HS256", "claim_keys": ["iss"],
        "ttl_seconds": 60, "expires_at": 1234567890,
    }
    assert logger.last_seq() == before + 1
    assert KEY not in json.dumps(lines)


def test_tui_approval_reason_names_the_boundary() -> None:
    from halgate.tui import _approval_requirement_reason
    from halgate.llm.client import ToolCall
    text = _approval_requirement_reason(ToolCall(
        id="t", name="jwt_sign", arguments={"claims": {"iss": "svc"}}))
    assert "HS256" in text and "keystore" in text.lower()
    # jwt_sign can inherit an operator's session-only target approval.
    from halgate.tui import TARGET_AUTO_APPROVE_TOOLS
    assert "jwt_sign" in TARGET_AUTO_APPROVE_TOOLS


class _Exec:
    def __init__(self, ctx):
        self.ctx = ctx

    async def call(self, name, args):
        assert name == "jwt_sign"
        return await handle_jwt_sign(self.ctx, **args)


class _Audit:
    def guard_decision(self, tool, allowed, reason, engagement_id=None):
        pass

    def approval(self, tool, approved, summarized, engagement_id=None):
        pass

    def tool_call(self, name, args, engagement_id):
        pass

    def tool_result(self, *args, **kwargs):
        pass


@pytest.mark.asyncio
async def test_dispatch_denial_mints_nothing(config) -> None:
    packages = {"offensive": _signing_package()}
    ctx = _ctx(packages)
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    tc = ToolCall(
        id="t1", name="jwt_sign",
        arguments={"credential_ref": CRED_ID, "claims": {"iss": "svc"},
                   "ttl_seconds": 60, "reason": "mint",
                   "engagement_id": "eng-a"})

    async def deny(tc, eng):
        return ApprovalResult(approved=False)

    async def allow(tc, eng):
        return ApprovalResult(approved=True)

    redactor = Redactor(_Keystore({CRED_ID: KEY}))
    denied = await dispatch_parallel(
        calls=[tc], executor=_Exec(ctx), gate=ctx.gate, audit=_Audit(),
        config=config, approver=deny, redactor=redactor)
    assert denied[0].get("error") == "denied by operator"
    assert "auth_session_tokens" not in ctx.extra

    approved = await dispatch_parallel(
        calls=[tc], executor=_Exec(ctx), gate=ctx.gate, audit=_Audit(),
        config=config, approver=allow, redactor=redactor)
    assert approved[0]["status"] == "signed"
    slot = ctx.extra["auth_session_tokens"][("eng-a", "jwt")]
    assert slot["prefix"] == "Bearer "
    assert slot["value"].count(".") == 2
    assert KEY not in json.dumps(approved[0])


# ---------------------------------------------------------------------------
# Phase 2: HS384/HS512, per-engagement claim extensions, inject_at.
# ---------------------------------------------------------------------------

def test_from_yaml_defaults_algorithms_to_hs256() -> None:
    pkg = ScopePackage.from_yaml("t", {"jwt": {"sign": True}})
    assert pkg.jwt_algorithms == ["HS256"]
    pkg = ScopePackage.from_yaml(
        "t", {"jwt": {"sign": True, "algorithms": ["HS384", "HS512"]}})
    assert pkg.jwt_algorithms == ["HS384", "HS512"]
    pkg = ScopePackage.from_yaml(
        "t", {"jwt": {"sign": True, "algorithms": ["nonsense"]}})
    assert pkg.jwt_algorithms == ["NONSENSE"]
    pkg = ScopePackage(name="offensive", jwt_sign_enabled=True)
    assert pkg.jwt_algorithms == ["HS256"]


def test_scope_gate_rejects_package_undeclared_algorithm() -> None:
    packages = {"offensive": _signing_package()}
    eng = Engagement("eng", "net", "127.0.0.1", "offensive")
    gate = ScopeGate([eng], packages, {})
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"iss": "svc"},
         "algorithm": "HS384", "ttl_seconds": 60, "reason": "t",
         "engagement_id": "eng"},
        "eng")
    assert not ok and "algorithm HS384 not declared" in reason
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"iss": "svc"},
         "algorithm": "RS256", "ttl_seconds": 60, "reason": "t",
         "engagement_id": "eng"},
        "eng")
    assert not ok and "algorithm RS256 not declared" in reason


def test_scope_gate_accepts_package_declared_hs384_hs512() -> None:
    packages = {"offensive": _signing_package(
        jwt_algorithms=["HS256", "HS384", "HS512"])}
    eng = Engagement("eng", "net", "127.0.0.1", "offensive")
    gate = ScopeGate([eng], packages, {})
    for alg in ("HS256", "HS384", "HS512"):
        ok, reason, _ = gate.authorize(
            "jwt_sign",
            {"credential_ref": CRED_ID, "claims": {"iss": "svc"},
             "algorithm": alg, "ttl_seconds": 60, "reason": "t",
             "engagement_id": "eng"},
            "eng")
        assert ok, reason


def test_scope_gate_allows_time_claim_overrides() -> None:
    packages = {"offensive": _signing_package()}
    eng = Engagement("eng", "net", "127.0.0.1", "offensive",
                     jwt_claim_extensions=("role", "email"))
    gate = ScopeGate([eng], packages, {})
    # Claims do not need an engagement extension.
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"role": "admin",
                                               "email": "op@x.y"},
         "ttl_seconds": 60, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason
    # Caller-provided time claims are preserved rather than overwritten.
    eng2 = Engagement("eng", "net", "127.0.0.1", "offensive",
                      jwt_claim_extensions=("exp", "nbf"))
    gate2 = ScopeGate([eng2], packages, {})
    ok, reason, _ = gate2.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"exp": 9999999999},
         "ttl_seconds": 60, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason


def test_offensive_package_permits_locale_claim(packages) -> None:
    eng = Engagement("eng", "net", "127.0.0.1", "offensive")
    gate = ScopeGate([eng], packages, {})
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"locale": "en-US"},
         "ttl_seconds": 60, "reason": "locale-specific test token",
         "engagement_id": "eng"},
        "eng")
    assert ok, reason


def test_scope_gate_does_not_cap_claim_names() -> None:
    packages = {"offensive": _signing_package()}
    # Engagement extensions are retained for backwards-compatible session
    # metadata, but no longer constrain JWT claim names.
    exts = tuple(f"ext{i:02d}" for i in range(12))
    eng = Engagement("eng", "net", "127.0.0.1", "offensive",
                     jwt_claim_extensions=exts)
    gate = ScopeGate([eng], packages, {})
    ok, reason, _ = gate.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID,
         "claims": {f"ext{i:02d}": "v" for i in range(8)},
         "ttl_seconds": 60, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason
    # A claim outside the former effective-set cap is also accepted.
    eng2 = Engagement("eng", "net", "127.0.0.1", "offensive",
                      jwt_claim_extensions=exts + ("zzz_out_of_cap",))
    gate2 = ScopeGate([eng2], packages, {})
    ok, reason, _ = gate2.authorize(
        "jwt_sign",
        {"credential_ref": CRED_ID, "claims": {"zzz_out_of_cap": "v"},
         "ttl_seconds": 60, "reason": "t", "engagement_id": "eng"},
        "eng")
    assert ok, reason


@pytest.mark.asyncio
async def test_signs_hs384_and_hs512_verifiable_with_stdlib_only() -> None:
    packages = {"offensive": _signing_package(
        jwt_algorithms=["HS256", "HS384", "HS512"])}
    for alg, digest in (("HS256", hashlib.sha256),
                        ("HS384", hashlib.sha384),
                        ("HS512", hashlib.sha512)):
        ctx = _ctx(packages)
        ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
        res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                    "eng-a", reason="t", algorithm=alg)
        assert res["status"] == "signed", res
        assert res["algorithm"] == alg
        token = ctx.extra["auth_session_tokens"][("eng-a", "jwt")]["value"]
        header, payload, signature = token.split(".")
        assert _decode(header) == {"alg": alg, "typ": "JWT"}
        expected = base64.urlsafe_b64encode(
            hmac.new(KEY.encode(), f"{header}.{payload}".encode("ascii"),
                     digest).digest()
        ).decode().rstrip("=")
        assert signature == expected, f"{alg} signature must verify"


@pytest.mark.asyncio
async def test_unknown_algorithm_rejected_before_keystore() -> None:
    ctx = _ctx({"offensive": _signing_package()})
    ctx.extra["keystore"] = _Keystore({CRED_ID: KEY})
    res = await handle_jwt_sign(ctx, CRED_ID, {"iss": "svc"}, 60,
                                "eng-a", reason="t", algorithm="RS256")
    assert "error" in res
    assert "declared" in res["error"] or "must be one of" in res["error"]


async def _seed_token(ctx, engagement_id: str, session: str = "default",
                      value: str = "fake.token.value") -> None:
    ctx.extra.setdefault("auth_session_tokens", {})[(engagement_id, session)] = {
        "header": "Authorization", "prefix": "Bearer ",
        "value": value, "kind": "jwt",
    }


@pytest.mark.asyncio
async def test_auth_session_inject_at_places_stored_token_in_body(
        monkeypatch) -> None:
    from halgate.tools import auth_session
    received = []

    async def fake_session(ctx, url, engagement_id, method, headers, body,
                           session, **_):
        received.append({"headers": dict(headers), "body": body})
        return {"status": 200, "headers": {}, "body": "ok"}

    monkeypatch.setattr(auth_session, "handle_http_session", fake_session)
    ctx = _ctx({"offensive": _signing_package()})
    await _seed_token(ctx, "eng-a", "default", "secret.jwt.value")
    res = await auth_session.handle_auth_session(
        ctx, "https://target/api", "eng-a", method="POST",
        body=json.dumps({"user": {"id": "op"}, "payload": {"inner": 1}}),
        session="default", inject_at="$.user.token",
        reason="inject")
    assert "error" not in res, res
    sent = received[0]
    body = json.loads(sent["body"])
    assert body["user"]["token"] == "secret.jwt.value"
    assert body["user"]["id"] == "op"
    assert body["payload"] == {"inner": 1}
    assert res["token_injected_at"] == "$.user.token"
    # The raw token never re-enters the operator-facing result body.
    assert "secret.jwt.value" not in json.dumps(res)


@pytest.mark.asyncio
async def test_auth_session_inject_at_requires_stored_token() -> None:
    from halgate.tools import auth_session

    async def fake_session(ctx, url, engagement_id, method, headers, body,
                           session, **_):
        raise AssertionError("no request should be sent without a token")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(auth_session, "handle_http_session", fake_session)
    ctx = _ctx({"offensive": _signing_package()})
    res = await auth_session.handle_auth_session(
        ctx, "https://target/api", "eng-a", method="POST",
        body='{"a":1}', session="default", inject_at="$.token",
        reason="t")
    assert "error" in res
    assert "requires a stored session token" in res["error"]
    monkeypatch.undo()


@pytest.mark.asyncio
async def test_auth_session_inject_at_requires_valid_json_body() -> None:
    from halgate.tools import auth_session

    async def fake_session(ctx, url, engagement_id, method, headers, body,
                           session, **_):
        raise AssertionError("invalid body should not reach the transport")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(auth_session, "handle_http_session", fake_session)
    ctx = _ctx({"offensive": _signing_package()})
    await _seed_token(ctx, "eng-a", "default")
    res = await auth_session.handle_auth_session(
        ctx, "https://target/api", "eng-a", method="POST", body="not-json",
        session="default", inject_at="$.token",
        reason="t")
    assert "error" in res
    assert "JSON body" in res["error"]
    monkeypatch.undo()


def test_checkpoint_tolerates_missing_jwt_claim_extensions(tmp_path) -> None:
    import json as _json
    from halgate.sessions.checkpoint import SessionCheckpoint
    d = tmp_path / "s1"
    d.mkdir()
    (d / "meta.json").write_text(_json.dumps({
        "session_id": "s1", "name": "s1",
        "engagements": [{
            "id": "eng-a", "label": "a", "target": "127.0.0.1",
            "package": "offensive", "execution_mode": "host",
            "budget_overrides": {}, "status": "active", "created": "x",
        }],
    }))
    (d / "transcript.jsonl").write_text("")
    restored = SessionCheckpoint.load(str(tmp_path), "s1")
    assert restored.engagements[0].jwt_claim_extensions == ()


def test_checkpoint_round_trips_jwt_claim_extensions(tmp_path) -> None:
    import json as _json
    from halgate.sessions.checkpoint import SessionCheckpoint
    cp = SessionCheckpoint(str(tmp_path), "s1")
    cp.save("s1", "s1", [], [],
            [Engagement("eng-a", "a", "127.0.0.1", "offensive",
                        jwt_claim_extensions=("role", "email"))],
            llm_id="", resumed_from=None)
    meta = _json.loads((cp.dir / "meta.json").read_text())
    assert meta["engagements"][0]["jwt_claim_extensions"] == ["role", "email"]
    restored = SessionCheckpoint.load(str(tmp_path), "s1")
    assert restored.engagements[0].jwt_claim_extensions == ("role", "email")
