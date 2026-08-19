"""Explicit, scoped HTTP request replay for operator-approved testing."""
from __future__ import annotations

from typing import Any

from .context import ToolContext
from .http import handle_http

HTTP_REPLAY_SCHEMA = {
    "name": "http_replay",
    "description": "Replay one explicitly supplied HTTP request to an in-scope URL. Use for auditable request tampering or replay; normal HTTP method, scope, approval, and response-size limits apply.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string"}, "method": {"type": "string"},
        "headers": {"type": "object", "description": "Replacement request headers"},
        "body": {"type": "string", "description": "Replacement request body"},
        "reason": {"type": "string"}, "engagement_id": {"type": "string"},
    }, "required": ["url", "engagement_id", "reason"]},
}


async def handle_http_replay(ctx: ToolContext, url: str, engagement_id: str,
                             method: str = "GET", headers: dict | None = None,
                             body: str | None = None, reason: str = "",
                             **_: Any) -> dict:
    result = await handle_http(ctx, url, engagement_id, method, headers, body,
                               reason=reason)
    if "error" not in result:
        result["replayed"] = True
    return result
