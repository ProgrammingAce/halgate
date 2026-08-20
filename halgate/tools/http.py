"""http tool: make an HTTP request (method-gated)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Any
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..errors import BudgetExhaustedError
from .context import ToolContext

HTTP_SCHEMA = {
    "name": "http",
    "description": "Preferred tool for all HTTP/HTTPS requests. Use this instead "
                   "of curl through the shell tool. Supports methods, headers, and "
                   "bodies; the method is restricted by the engagement's scope "
                   "package and the response body is truncated to the configured limit. "
                   "Results include elapsed_ms and preserve repeated response headers "
                   "in header_items; Set-Cookie values are redacted from results but "
                   "retained privately for http_session.",
    "parameters": {
        "type": "object",
        "properties": {
            "method": {"type": "string",
                       "description": "HTTP method (GET, POST, etc.)"},
            "url": {"type": "string", "description": "Target URL"},
            "headers": {"type": "object",
                        "description": "Optional request headers"},
            "body": {"type": "string",
                     "description": "Optional request body"},
            "save_as": {"type": "string",
                        "description": "Optional relative filename under the "
                                       "engagement scratch directory. Saves the "
                                       "returned response body there so file tools "
                                       "can inspect it; e.g. 'select.html'."},
            "reason": {"type": "string",
                       "description": "Concise reason this request is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing the request"},
        },
        "required": ["url", "reason", "engagement_id"],
    },
}


async def handle_http(ctx: ToolContext, url: str, engagement_id: str,
                      method: str = "GET", headers: dict | None = None,
                      body: str | None = None, save_as: str | None = None,
                      reason: str = "",
                      retain_set_cookie_headers: bool = False,
                      **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    try:
        target = await _pinned_target(ctx, url, engagement)
        if isinstance(target, str):
            return {"error": target}
    except (OSError, ValueError) as e:
        return {"error": f"DNS resolution failed: {e}"}
    pinned_url, host_header, host = target
    max_bytes = ctx.config.packages[engagement.package].http_max_response
    request_headers = dict(headers or {})
    request_headers.setdefault("Host", host_header)
    request_body = body.encode() if body else b""
    try:
        _account_bytes(ctx, engagement_id, "max_bytes_out", len(request_body))
    except BudgetExhaustedError as e:
        return {"error": str(e)}
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=10),
            follow_redirects=False,
            max_redirects=5, trust_env=False) as client:
        try:
            request = client.build_request(
                method=method.upper(),
                url=pinned_url,
                headers=request_headers,
                content=request_body or None,
            )
            if pinned_url.startswith("https://"):
                request.extensions["sni_hostname"] = host
            started = time.monotonic()
            resp = await client.send(request, stream=True)
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        except httpx.ConnectError as e:
            return {"error": f"connection failed: {e}"}
        except httpx.TimeoutException:
            return {"error": "request timed out"}
        except httpx.HTTPError as e:
            return {"error": f"http error: {e}"}
        try:
            content, truncated = await _read_bounded_response(
                ctx, resp, engagement_id, max_bytes)
        except BudgetExhaustedError as e:
            return {"error": str(e)}
        finally:
            await resp.aclose()
    header_items = list(resp.headers.multi_items())
    set_cookies = resp.headers.get_list("set-cookie")
    public_header_items = [
        (key, "[redacted]" if key.lower() == "set-cookie" else value)
        for key, value in header_items]
    public_headers = {
        key: "[redacted]" if key.lower() == "set-cookie" else value
        for key, value in dict(resp.headers).items()}
    result: dict = {
        "status": resp.status_code,
        "headers": public_headers,
        "header_items": public_header_items,
        "body": content.decode(errors="replace"),
        "truncated": truncated,
        "size": len(content),
        "elapsed_ms": elapsed_ms,
    }
    if retain_set_cookie_headers:
        # Internal hand-off for http_session only; it removes this field
        # before returning a model-visible result.
        result["_set_cookie_headers"] = set_cookies
    if save_as:
        if not engagement.scratch_dir:
            return {"error": "saving an HTTP response requires an engagement scratch directory"}
        destination = _scratch_destination(engagement.scratch_dir, save_as)
        if destination is None:
            return {"error": "save_as must be a relative path inside the engagement scratch directory"}
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        except OSError as e:
            return {"error": f"could not save HTTP response: {e}"}
        result["saved_path"] = str(destination)
        result["saved_bytes"] = len(content)
    return result


def _account_bytes(ctx: ToolContext, engagement_id: str, kind: str,
                   amount: int) -> None:
    """Charge actual transfer bytes when dispatch supplied a budget manager."""
    if amount:
        budgets = ctx.extra.get("budgets")
        if budgets is not None:
            budgets.account(engagement_id, kind, amount)


async def _read_bounded_response(ctx: ToolContext, response: httpx.Response,
                                 engagement_id: str,
                                 max_bytes: int) -> tuple[bytes, bool]:
    """Read a response incrementally, never materializing an oversized body."""
    chunks: list[bytes] = []
    kept = 0
    async for chunk in response.aiter_bytes():
        _account_bytes(ctx, engagement_id, "max_bytes_in", len(chunk))
        remaining = max_bytes - kept
        if remaining <= 0:
            return b"".join(chunks), True
        chunks.append(chunk[:remaining])
        kept += min(len(chunk), remaining)
        if len(chunk) > remaining:
            return b"".join(chunks), True
    return b"".join(chunks), False


def _scratch_destination(scratch_dir: str, save_as: str) -> Path | None:
    """Resolve one relative response artifact without allowing scratch escape."""
    relative = Path(save_as)
    if relative.is_absolute():
        return None
    try:
        root = Path(scratch_dir).resolve(strict=True)
        destination = (root / relative).resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    return destination if destination.is_relative_to(root) else None


async def _pinned_target(ctx: ToolContext, url: str, engagement: Any) -> tuple[str, str, str] | str:
    """Resolve once, scope-check all addresses, then return a pinned request URL."""
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        return "URL has no host"
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = list({ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos})
    ok, reason = ctx.gate.check_url(url, engagement, resolver=lambda _host: addresses)
    if not ok:
        return reason
    address = str(addresses[0])
    netloc = f"[{address}]" if ":" in address else address
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)), parsed.netloc, host
