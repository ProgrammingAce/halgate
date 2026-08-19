"""Bounded local data transforms for inspecting already-received responses."""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .context import ToolContext

_MAX_INPUT = 1_000_000
_MAX_OUTPUT = 50_000
_MAX_JWT = 64_000
_PATH_TOKEN = re.compile(r"(?:\.([A-Za-z_][A-Za-z0-9_-]*)|\[([0-9]+)\])")

JSON_EXTRACT_SCHEMA = {
    "name": "json_extract",
    "description": "Inspect already-received JSON locally. Use a limited path such as $.data.items[0].name; this tool has no network, shell, or filesystem access.",
    "parameters": {"type": "object", "properties": {
        "data": {"type": "string", "description": "JSON text to inspect"},
        "path": {"type": "string", "description": "Limited JSON path, starting with $"},
        "engagement_id": {"type": "string", "description": "Engagement binding"},
    }, "required": ["data", "path", "engagement_id"]},
}

BASE64_DECODE_SCHEMA = {
    "name": "base64_decode",
    "description": "Decode bounded Base64 text locally for inspection. It has no network, shell, or filesystem access.",
    "parameters": {"type": "object", "properties": {
        "data": {"type": "string", "description": "Base64 or URL-safe Base64 text"},
        "engagement_id": {"type": "string", "description": "Engagement binding"},
    }, "required": ["data", "engagement_id"]},
}

JWT_INSPECT_SCHEMA = {
    "name": "jwt_inspect",
    "description": "Decode a bounded JWT locally and report its header, claims, signature metadata, and time-claim status. It never signs, alters, verifies with a key, or transmits the token.",
    "parameters": {"type": "object", "properties": {
        "token": {"type": "string", "description": "Compact JWT (header.payload.signature)"},
        "engagement_id": {"type": "string", "description": "Engagement binding"},
    }, "required": ["token", "engagement_id"]},
}


async def handle_json_extract(ctx: ToolContext, data: str, path: str,
                              engagement_id: str, **_: Any) -> dict:
    if len(data) > _MAX_INPUT:
        return {"error": "JSON input exceeds 1,000,000 characters"}
    try:
        value: Any = json.loads(data)
    except json.JSONDecodeError as e:
        return {"error": f"invalid JSON: {e.msg}"}
    try:
        value = extract_json_path(value, path)
    except ValueError as e:
        return {"error": str(e)}
    rendered = json.dumps(value, indent=2, ensure_ascii=False)
    return {"path": path, "value": rendered[:_MAX_OUTPUT],
            "truncated": len(rendered) > _MAX_OUTPUT}


async def handle_base64_decode(ctx: ToolContext, data: str,
                               engagement_id: str, **_: Any) -> dict:
    if len(data) > _MAX_INPUT:
        return {"error": "Base64 input exceeds 1,000,000 characters"}
    compact = "".join(data.split())
    try:
        decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (ValueError, binascii.Error):
        return {"error": "invalid Base64 input"}
    text = decoded.decode("utf-8", errors="replace")
    return {"text": text[:_MAX_OUTPUT], "bytes": len(decoded),
            "truncated": len(text) > _MAX_OUTPUT}


async def handle_jwt_inspect(ctx: ToolContext, token: str,
                             engagement_id: str, **_: Any) -> dict:
    """Decode JWT structure only; cryptographic verification is intentionally absent."""
    if len(token) > _MAX_JWT:
        return {"error": "JWT exceeds 64,000 characters"}
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts):
        return {"error": "JWT must have three non-empty compact-serialization parts"}
    try:
        header = json.loads(_urlsafe_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_urlsafe_decode(parts[1]).decode("utf-8"))
        signature = _urlsafe_decode(parts[2])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return {"error": "JWT header or claims are not valid Base64URL JSON"}
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return {"error": "JWT header and claims must be JSON objects"}
    time_claims = {}
    for name in ("exp", "nbf", "iat"):
        if name in claims:
            value = claims[name]
            time_claims[name] = value
    return {
        "header": header,
        "claims": claims,
        "signature_bytes": len(signature),
        "algorithm": header.get("alg"),
        "time_claims": time_claims,
        "verification": "not performed (no key material accepted)",
    }


def _urlsafe_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def extract_json_path(value: Any, path: str) -> Any:
    """Resolve the same deliberately small JSON-path subset used by json_extract."""
    if not path.startswith("$"):
        raise ValueError("path must start with $")
    cursor = 1
    for match in _PATH_TOKEN.finditer(path, cursor):
        if match.start() != cursor:
            raise ValueError("path supports only .property and [index] selectors")
        key, index = match.groups()
        try:
            value = value[key] if key is not None else value[int(index)]
        except (KeyError, IndexError, TypeError):
            raise ValueError(f"path not found: {path}") from None
        cursor = match.end()
    if cursor != len(path):
        raise ValueError("path supports only .property and [index] selectors")
    return value


def replace_json_path(value: Any, path: str, replacement: Any) -> None:
    """Replace a value at a validated limited path in a mutable JSON object."""
    matches = list(_PATH_TOKEN.finditer(path, 1))
    if not matches or not path.startswith("$"):
        raise ValueError("path supports only .property and [index] selectors")
    cursor, parent = 1, value
    for match in matches[:-1]:
        if match.start() != cursor:
            raise ValueError("path supports only .property and [index] selectors")
        key, index = match.groups()
        parent = parent[key] if key is not None else parent[int(index)]
        cursor = match.end()
    final = matches[-1]
    if final.start() != cursor or final.end() != len(path):
        raise ValueError("path supports only .property and [index] selectors")
    key, index = final.groups()
    if key is not None:
        parent[key] = replacement
    else:
        parent[int(index)] = replacement
