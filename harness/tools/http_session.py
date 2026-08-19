"""Engagement-scoped HTTP requests with a small in-memory cookie jar."""
from __future__ import annotations

import time
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlsplit

from .context import ToolContext
from .http import handle_http

HTTP_SESSION_SCHEMA = {
    "name": "http_session",
    "description": "Make an HTTP request while retaining cookies for one named, origin-bound session in the active engagement. Cookies are sent only to the same scheme, host, port, and matching path. Use for authorized login and follow-up requests; scope and HTTP method policy still apply.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string"}, "method": {"type": "string"},
        "headers": {"type": "object"}, "body": {"type": "string"},
        "session": {"type": "string", "description": "Session name (default: default)"},
        "reason": {"type": "string"}, "engagement_id": {"type": "string"},
    }, "required": ["url", "reason", "engagement_id"]},
}


def _origin_and_path(url: str) -> tuple[tuple[str, str, int], str]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return (scheme, host, port), parsed.path or "/"


def _path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    return (request_path.startswith(cookie_path)
            and (cookie_path.endswith("/")
                 or request_path[len(cookie_path):].startswith("/")))


def _cookie_expiry(morsel: Any) -> float | None:
    """Return an absolute expiry timestamp, respecting Max-Age precedence."""
    max_age = morsel["max-age"]
    if max_age:
        try:
            return time.time() + int(max_age)
        except ValueError:
            return None
    expires = morsel["expires"]
    if not expires:
        return None
    try:
        return parsedate_to_datetime(expires).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


async def handle_http_session(ctx: ToolContext, url: str, engagement_id: str,
                              method: str = "GET", headers: dict | None = None,
                              body: str | None = None, session: str = "default",
                              reason: str = "",
                              **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    name = str(session or "default")[:80]
    try:
        origin, request_path = _origin_and_path(url)
    except ValueError as e:
        return {"error": f"invalid URL: {e}"}
    jars = ctx.extra.setdefault("http_sessions", {})
    jar = jars.setdefault((engagement_id, name, origin), {})
    now = time.time()
    for key, cookie in list(jar.items()):
        if cookie.get("expires_at") is not None and cookie["expires_at"] <= now:
            del jar[key]
    request_headers = dict(headers or {})
    if jar and not any(key.lower() == "cookie" for key in request_headers):
        pairs = [f"{key[0]}={cookie['value']}" for key, cookie in
                 sorted(jar.items(), key=lambda item: len(item[0][1]), reverse=True)
                 if _path_matches(request_path, cookie["path"])]
        if pairs:
            request_headers["Cookie"] = "; ".join(pairs)
    result = await handle_http(ctx, url, engagement_id, method, request_headers,
                               body, reason=reason, retain_set_cookie_headers=True)
    set_cookies = result.pop("_set_cookie_headers", []) if isinstance(result, dict) else []
    # Keep compatibility with lightweight test adapters and older results.
    if not set_cookies and isinstance(result, dict):
        set_cookie = (result.get("headers") or {}).get("set-cookie", "")
        set_cookies = [set_cookie] if set_cookie else []
    for item in set_cookies:
        parsed = SimpleCookie()
        parsed.load(str(item))
        for key, morsel in parsed.items():
            cookie_path = morsel["path"] or "/"
            if not cookie_path.startswith("/"):
                cookie_path = "/"
            cookie_key = (key, cookie_path)
            expiry = _cookie_expiry(morsel)
            if expiry is not None and expiry <= time.time():
                jar.pop(cookie_key, None)
                continue
            jar[cookie_key] = {"value": morsel.value, "path": cookie_path,
                               "expires_at": expiry}
    if isinstance(result, dict) and "error" not in result:
        result["session"] = name
        result["cookies_retained"] = len(jar)
    return result
