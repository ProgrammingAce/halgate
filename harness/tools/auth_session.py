"""Named HTTP sessions that can retain an explicitly extracted auth token."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from .context import ToolContext
from .data import extract_json_path, replace_json_path
from .http_session import handle_http_session

AUTH_SESSION_SCHEMA = {
    "name": "auth_session",
    "description": "Make an HTTP request in a named, origin-bound engagement session, retaining cookies. Optionally extract one token from a limited JSON path and reuse it as a header only in later calls to that same origin. Use inject_at to place a stored session token into a JSON body field. Tokens are never displayed or accepted as key material.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string"}, "method": {"type": "string"},
        "headers": {"type": "object"}, "body": {"type": "string"},
        "session": {"type": "string", "description": "Named session (default: default)"},
        "extract_token_path": {"type": "string", "description": "Optional limited JSON path, e.g. $.authentication.token"},
        "token_header": {"type": "string", "description": "Header to retain token in (default: Authorization)"},
        "token_prefix": {"type": "string", "description": "Header prefix (default: Bearer )"},
        "inject_at": {"type": "string", "description": "Optional limited JSON path to inject the stored token into the request body, e.g. $.token"},
        "reason": {"type": "string"}, "engagement_id": {"type": "string"},
    }, "required": ["url", "engagement_id", "reason"]},
}


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    return scheme, host, parsed.port or (443 if scheme == "https" else 80)


async def handle_auth_session(ctx: ToolContext, url: str, engagement_id: str,
                              method: str = "GET", headers: dict | None = None,
                              body: str | None = None, session: str = "default",
                              extract_token_path: str | None = None,
                              token_header: str = "Authorization",
                              token_prefix: str = "Bearer ",
                              inject_at: str | None = None,
                              reason: str = "",
                              **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    name = str(session or "default")[:80]
    try:
        origin = _origin(url)
    except ValueError as e:
        return {"error": f"invalid URL: {e}"}
    header_name = str(token_header or "Authorization")[:80]
    if not header_name or any(char in header_name for char in "\r\n:"):
        return {"error": "token_header must be a valid header name"}
    if len(str(token_prefix)) > 80 or "\n" in str(token_prefix) or "\r" in str(token_prefix):
        return {"error": "token_prefix is invalid"}
    tokens = ctx.extra.setdefault("auth_session_tokens", {})
    token_state = tokens.get((engagement_id, name))
    request_headers = dict(headers or {})
    if token_state and token_state.get("origin") not in (None, origin):
        return {"error": "stored session token is bound to a different origin"}
    if token_state and token_state.get("origin") is None:
        token_state["origin"] = origin
    if token_state and not any(key.lower() == token_state["header"].lower()
                               for key in request_headers):
        request_headers[token_state["header"]] = token_state["prefix"] + token_state["value"]

    # Body injection: place the stored token into a JSON field before sending.
    request_body = body
    if inject_at and token_state and body:
        try:
            parsed_body = json.loads(body)
        except json.JSONDecodeError:
            return {"error": (f"inject_at requires a JSON body "
                              f"(got invalid JSON)")}
        try:
            replace_json_path(parsed_body, str(inject_at), token_state["value"])
        except (ValueError, KeyError, TypeError) as e:
            return {"error": f"inject_at path failed: {e}"}
        request_body = json.dumps(parsed_body, separators=(",", ":"))
    elif inject_at and not token_state:
        return {"error": (f"inject_at '{inject_at}' requires a stored session "
                          f"token in '{name}' for this engagement; "
                          "use jwt_sign or extract_token_path first")}

    result = await handle_http_session(ctx, url, engagement_id, method,
                                       request_headers, request_body, name,
                                       reason=reason)
    if not isinstance(result, dict) or "error" in result:
        return result
    stored = False
    if extract_token_path:
        try:
            parsed = json.loads(str(result.get("body") or ""))
            token = extract_json_path(parsed, str(extract_token_path))
            if not isinstance(token, str) or not token or len(token) > 16_384:
                return {"error": "token path must resolve to a non-empty string up to 16 KiB"}
            tokens[(engagement_id, name)] = {
                "header": header_name, "prefix": str(token_prefix), "value": token,
                "origin": origin,
            }
            replace_json_path(parsed, str(extract_token_path), "[stored session token]")
            result["body"] = json.dumps(parsed, ensure_ascii=False)
            stored = True
        except (json.JSONDecodeError, ValueError) as e:
            return {"error": f"token was not stored: {e}"}
    result["auth_session"] = name
    result["token_stored"] = stored
    result["token_reused"] = bool(token_state and not stored)
    # The agent can continue the workflow through the session name; the token
    # itself never needs to be repeated in an operator-facing tool result.
    if stored:
        result["token_header"] = header_name
    if inject_at:
        result["token_injected_at"] = str(inject_at)
    return result
