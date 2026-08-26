"""Scoped multipart uploads from an engagement's private scratch directory."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .context import ToolContext
from .http import _account_bytes, _pinned_target, _read_bounded_response
from ..errors import BudgetExhaustedError
from ..scope import path_within

MULTIPART_UPLOAD_SCHEMA = {
    "name": "multipart_upload",
    "description": "Upload one scratch-folder file to an approved in-scope HTTP endpoint using multipart/form-data. Relative paths are resolved inside the active engagement's private scratch directory.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string"}, "path": {"type": "string"},
        "field_name": {"type": "string", "description": "Multipart field name (default: file)"},
        "method": {"type": "string", "enum": ["POST", "PUT"]},
        "headers": {"type": "object"}, "reason": {"type": "string"},
        "engagement_id": {"type": "string"},
    }, "required": ["url", "path", "engagement_id", "reason"]},
}


async def handle_multipart_upload(ctx: ToolContext, url: str, path: str,
                                  engagement_id: str, field_name: str = "file",
                                  method: str = "POST", headers: dict | None = None,
                                  reason: str = "",
                                  **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
        if not engagement.scratch_dir:
            return {"error": "multipart uploads require an engagement scratch directory"}
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = Path(engagement.scratch_dir) / candidate
        allowed, reason = path_within(engagement.scratch_dir, str(candidate))
        if not allowed:
            return {"error": reason}
        if method.upper() not in {"POST", "PUT"}:
            return {"error": "multipart upload method must be POST or PUT"}
        target = await _pinned_target(ctx, url, engagement)
        if isinstance(target, str):
            return {"error": target}
        resolved_path = candidate.resolve(strict=True)
        if not resolved_path.is_file():
            return {"error": "upload path must be a regular file"}
        if resolved_path.stat().st_size > 10 * 1024 * 1024:
            return {"error": "upload file exceeds 10 MiB"}
    except (OSError, ValueError) as e:
        return {"error": f"upload setup failed: {e}"}
    pinned_url, host_header, host = target
    request_headers = dict(headers or {})
    request_headers.setdefault("Host", host_header)
    try:
        _account_bytes(ctx, engagement_id, "max_bytes_out",
                       resolved_path.stat().st_size)
    except BudgetExhaustedError as e:
        return {"error": str(e)}
    async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10),
                                 follow_redirects=False, trust_env=False) as client:
        try:
            with resolved_path.open("rb") as upload:
                request = client.build_request(method.upper(), pinned_url, headers=request_headers,
                    files={str(field_name or "file")[:80]: (resolved_path.name, upload)})
                if pinned_url.startswith("https://"):
                    request.extensions["sni_hostname"] = host
                response = await client.send(request, stream=True)
        except httpx.HTTPError as e:
            return {"error": f"upload failed: {e}"}
        try:
            body, truncated = await _read_bounded_response(
                ctx, response, engagement_id,
                ctx.config.packages[engagement.package].http_max_response)
        except BudgetExhaustedError as e:
            return {"error": str(e)}
        finally:
            await response.aclose()
    header_items = [
        (key, "[redacted]" if key.lower() == "set-cookie" else value)
        for key, value in response.headers.multi_items()]
    headers = {
        key: "[redacted]" if key.lower() == "set-cookie" else value
        for key, value in dict(response.headers).items()}
    return {"status": response.status_code, "headers": headers,
            "header_items": header_items,
            "body": body.decode(errors="replace"), "size": len(body),
            "truncated": truncated,
            "uploaded": {"name": resolved_path.name, "bytes": resolved_path.stat().st_size}}
