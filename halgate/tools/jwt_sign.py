"""Structured HMAC-SHA signing and explicitly scoped unsigned JWT minting."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

from .context import ToolContext

CREDENTIAL_REF_RE = re.compile(r"cred_[a-f0-9]{32}\Z")
UNSIGNED_ALGORITHM = "none"
HS_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
MAX_KEY_BYTES = 4096
MAX_TOKEN_LENGTH = 8192


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sign_hmac(algorithm: str, key: bytes, claims: dict,
              ttl_seconds: int | None) -> tuple[str, int | None, int | None]:
    """Produce a compact HMAC JWT (HS256/HS384/HS512).

    Returns (token, issued_at, expires_at)."""
    digest_cls = HS_ALGORITHMS.get(algorithm)
    if digest_cls is None:
        raise ValueError(f"unsupported HMAC algorithm: {algorithm}")
    payload_obj = dict(claims)
    issued_at = expires_at = None
    if ttl_seconds is not None:
        now = int(time.time())
        issued_at = payload_obj.setdefault("iat", now)
        expires_at = payload_obj.setdefault("exp", now + ttl_seconds)
    header = _b64url(json.dumps(
        {"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _b64url(json.dumps(
        payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64url(hmac.new(key, signing_input, digest_cls).digest())
    token = f"{header}.{payload}.{signature}"
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("signed token exceeds the 8192 char limit")
    return token, issued_at, expires_at


def mint_unsigned(claims: dict,
                  ttl_seconds: int | None) -> tuple[str, int | None, int | None]:
    """Produce an alg:none JWT for authorized parser-validation workflows."""
    payload_obj = dict(claims)
    issued_at = expires_at = None
    if ttl_seconds is not None:
        now = int(time.time())
        issued_at = payload_obj.setdefault("iat", now)
        expires_at = payload_obj.setdefault("exp", now + ttl_seconds)
    header = _b64url(json.dumps(
        {"alg": UNSIGNED_ALGORITHM, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _b64url(json.dumps(
        payload_obj,
        separators=(",", ":"), sort_keys=True).encode("utf-8"))
    token = f"{header}.{payload}."
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("unsigned token exceeds the 8192 char limit")
    return token, issued_at, expires_at


JWT_SIGN_SCHEMA = {
    "name": "jwt_sign",
    "description": (
        "Mint a bounded JWT using HMAC-SHA (HS256, HS384, or HS512 when the "
        "engagement package declares the algorithm; a referenced encrypted-"
        "keystore credential is required) or none (an unsigned token, only "
        "when the engagement package explicitly enables it for authorized "
        "parser testing). Never construct JWTs through shell commands. "
        "Claims are arbitrary JSON values, including custom and time claims. "
        "When ttl_seconds is supplied, iat and exp are added only when absent. "
        "The token is stored as a session credential bound to this "
        "engagement; the first auth_session request with the same engagement "
        "and session binds it to that origin. Use auth_session inject_at to place the token in "
        "a JSON body field. The key and token values never appear in "
        "arguments, results, logs, or model context. Requires explicit "
        "operator approval."
    ),
    "parameters": {"type": "object", "properties": {
        "credential_ref": {"type": "string",
                            "description": "Keystore credential id (cred_<uuid>) "
                                           "holding the signing key; omit for algorithm none"},
        "algorithm": {"type": "string",
                      "enum": ["HS256", "HS384", "HS512", "none"],
                      "description": "HMAC algorithm (default HS256; must be declared by the package)"},
        "claims": {"type": "object",
                   "description": "Claims to embed. With ttl_seconds, missing "
                                  "iat and exp are added; supplied time claims "
                                  "are preserved"},
        "ttl_seconds": {"type": "integer",
                        "description": "Optional lifetime in seconds; adds iat/exp unless supplied in claims"},
        "session": {"type": "string",
                    "description": "Named session the token is attached to "
                                   "(default: jwt)"},
        "reason": {"type": "string",
                   "description": "Concise reason this token is needed"},
        "engagement_id": {"type": "string"},
    }, "required": ["claims", "reason", "engagement_id"]},
}


async def handle_jwt_sign(ctx: ToolContext, credential_ref: Any = None,
                          claims: Any = None, ttl_seconds: Any = None,
                          engagement_id: str = "",
                          reason: str = "", session: str = "jwt",
                          algorithm: str = "HS256",
                          **_: Any) -> dict:
    gate = ctx.gate
    try:
        engagement = gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    if algorithm == "none":
        pass
    elif algorithm not in HS_ALGORITHMS:
        return {"error": (f"algorithm must be one of {', '.join(HS_ALGORITHMS)} "
                          "or none")}
    if algorithm == "none" and credential_ref not in (None, ""):
        return {"error": "credential_ref must be omitted for algorithm none"}
    if algorithm != "none" and (not isinstance(credential_ref, str)
                                or not CREDENTIAL_REF_RE.match(credential_ref)):
        return {"error": ("credential_ref must be an encrypted keystore "
                          "reference (cred_<uuid>); raw secret values are "
                          "not accepted")}
    if not isinstance(claims, dict):
        return {"error": "claims must be a JSON object"}
    if ttl_seconds is not None and (not isinstance(ttl_seconds, int)
                                    or isinstance(ttl_seconds, bool)
                                    or ttl_seconds < 1):
        return {"error": "ttl_seconds must be a positive integer when supplied"}
    ok, why = gate.check_jwt_sign(claims, ttl_seconds, engagement, algorithm)
    if not ok:
        return {"error": why}
    session_name = str(session or "jwt")[:80].strip() or "jwt"
    if any(char in session_name for char in "\r\n:"):
        return {"error": "session must be a valid session name"}
    if algorithm != "none":
        keystore = ctx.extra.get("keystore")
        if keystore is None:
            return {"error": "keystore unavailable: native encryption key not configured"}
        try:
            known = {str(e.get("id")) for e in keystore.known_ids()}
        except Exception as e:
            return {"error": f"keystore lookup failed: {e}"}
        if credential_ref not in known:
            return {"error": f"unknown credential reference: {credential_ref}"}
        try:
            secret = await keystore.reveal(credential_ref)
        except Exception as e:
            return {"error": f"credential decryption failed: {e}"}
        if not isinstance(secret, str) or not secret:
            return {"error": "credential reference resolved to an empty value"}
        key = secret.encode("utf-8")
        if not (1 <= len(key) <= MAX_KEY_BYTES):
            return {"error": "signing key length is outside 1-4096 bytes"}
        try:
            token, issued_at, expires_at = sign_hmac(algorithm, key, claims, ttl_seconds)
        except ValueError as e:
            return {"error": str(e)}
    else:
        try:
            token, issued_at, expires_at = mint_unsigned(claims, ttl_seconds)
        except ValueError as e:
            return {"error": str(e)}
    # Engagement-bound session credential: same slot auth_session reads, so
    # the token never re-enters LLM context, results, or the audit chain.
    tokens = ctx.extra.setdefault("auth_session_tokens", {})
    tokens[(engagement.id, session_name)] = {
        "header": "Authorization",
        "prefix": "Bearer ",
        "value": token,
        "kind": "jwt",
        "algorithm": algorithm,
        "credential": credential_ref,
        "signed_at": issued_at,
        "expires_at": expires_at,
    }
    emit = getattr(ctx.extra.get("audit"), "jwt_signed", None)
    if callable(emit):
        emit(engagement.id, credential_ref, algorithm,
             sorted(claims), ttl_seconds, expires_at)
    return {
        "status": "signed" if algorithm != "none" else "minted",
        "session": session_name,
        "algorithm": algorithm,
        "credential": credential_ref or None,
        "claim_keys": sorted(claims),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "token": "[stored session credential]",
        "usage": ("invoke auth_session with the same engagement_id and this "
                  "session to attach the token to requests, or pass "
                  "inject_at to place it in a JSON body field"),
    }
