"""Bounded, local-only inspection of encoded binary data."""
from __future__ import annotations

import base64
import binascii
import math
import zlib
from collections import Counter
from typing import Any

from .context import ToolContext

_MAX_INPUT = 1_000_000
_MAX_DECODED = 1_000_000
_PREVIEW = 256

BINARY_INSPECT_SCHEMA = {
    "name": "binary_inspect",
    "description": "Inspect bounded Base64 or hex binary data locally: format signatures, entropy, hex/text previews, and safe gzip/zlib decompression. It never executes, deserializes, or transmits the data.",
    "parameters": {"type": "object", "properties": {
        "data": {"type": "string", "description": "Base64 or hex encoded data"},
        "encoding": {"type": "string", "enum": ["auto", "base64", "hex"]},
        "engagement_id": {"type": "string"},
    }, "required": ["data", "engagement_id"]},
}


async def handle_binary_inspect(ctx: ToolContext, data: str, engagement_id: str,
                                encoding: str = "auto", **_: Any) -> dict:
    if len(data) > _MAX_INPUT:
        return {"error": "encoded input exceeds 1,000,000 characters"}
    raw, used = _decode(data, encoding)
    if raw is None:
        return {"error": "invalid encoded binary data"}
    if len(raw) > _MAX_DECODED:
        return {"error": "decoded input exceeds 1,000,000 bytes"}
    result: dict[str, Any] = {
        "encoding": used, "bytes": len(raw), "formats": _formats(raw),
        "entropy_bits_per_byte": round(_entropy(raw), 3),
        "hex_preview": raw[:_PREVIEW].hex(),
        "text_preview": raw[:_PREVIEW].decode("utf-8", errors="replace"),
        "truncated": len(raw) > _PREVIEW,
    }
    inflated = _inflate(raw)
    if inflated is not None:
        result["decompressed"] = {
            "bytes": len(inflated), "hex_preview": inflated[:_PREVIEW].hex(),
            "text_preview": inflated[:_PREVIEW].decode("utf-8", errors="replace"),
            "truncated": len(inflated) > _PREVIEW,
        }
    return result


def _decode(data: str, encoding: str) -> tuple[bytes | None, str]:
    compact = "".join(data.split())
    if encoding not in {"auto", "base64", "hex"}:
        return None, ""
    if encoding in {"auto", "hex"}:
        try:
            if len(compact) % 2 == 0:
                return bytes.fromhex(compact), "hex"
        except ValueError:
            if encoding == "hex":
                return None, ""
    if encoding in {"auto", "base64"}:
        try:
            return base64.b64decode(compact, validate=True), "base64"
        except (ValueError, binascii.Error):
            return None, ""
    return None, ""


def _formats(raw: bytes) -> list[str]:
    signatures = ((b"\x1f\x8b", "gzip"), (b"PK\x03\x04", "zip"),
                  (b"\x89PNG\r\n\x1a\n", "png"), (b"\x7fELF", "elf"),
                  (b"%PDF-", "pdf"), (b"\xca\xfe\xba\xbe", "java-serialized"))
    found = [name for magic, name in signatures if raw.startswith(magic)]
    if raw[:1] in (b"{", b"["):
        found.append("json-like")
    return found or ["unknown"]


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    size = len(raw)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _inflate(raw: bytes) -> bytes | None:
    """Decompress only when the expanded result fits the hard output cap."""
    try:
        if raw.startswith(b"\x1f\x8b"):
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif len(raw) >= 2 and raw[0] == 0x78:
            decoder = zlib.decompressobj()
        else:
            return None
        # max_length prevents a zip bomb from being materialized before it is
        # rejected. A full output buffer or unconsumed input means the limit
        # was exceeded, so intentionally return no decompressed payload.
        data = decoder.decompress(raw, _MAX_DECODED + 1)
        if len(data) > _MAX_DECODED or decoder.unconsumed_tail:
            return None
        data += decoder.flush(_MAX_DECODED + 1 - len(data))
        if len(data) > _MAX_DECODED or not decoder.eof:
            return None
        return data
    except zlib.error:
        return None
