"""Small, pinned WebSocket client for approved in-scope endpoints."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import os
import socket
import ssl
import struct
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .context import ToolContext

_MAX_MESSAGE = 16 * 1024
_MAX_HEADERS = 16 * 1024
_MAX_CONTROL_FRAMES = 10

WEBSOCKET_SCHEMA = {
    "name": "websocket",
    "description": "Connect to one in-scope ws/wss endpoint, optionally send one bounded text message, and capture up to ten bounded responses. Connections are pinned after scope-checked DNS resolution; no proxying or listener mode is available.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string", "description": "ws:// or wss:// endpoint"},
        "message": {"type": "string", "description": "Optional UTF-8 text message (max 16 KiB)"},
        "read_messages": {"type": "integer", "description": "Responses to capture (0-10; default 1)"},
        "timeout": {"type": "number", "description": "Per operation timeout, 1-10 seconds"},
        "reason": {"type": "string"}, "engagement_id": {"type": "string"},
    }, "required": ["url", "engagement_id", "reason"]},
}


async def handle_websocket(ctx: ToolContext, url: str, engagement_id: str,
                           message: str | None = None, read_messages: int = 1,
                           timeout: float = 5, reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
        parsed = urlsplit(url)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname or parsed.username or parsed.password:
            return {"error": "URL must be a credential-free ws:// or wss:// endpoint"}
        if message is not None and len(message.encode()) > _MAX_MESSAGE:
            return {"error": "message exceeds 16 KiB"}
        reads = min(10, max(0, int(read_messages)))
        timeout = min(10.0, max(1.0, float(timeout)))
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        addresses = await _resolve(parsed.hostname, port)
        scope_scheme = "https" if parsed.scheme == "wss" else "http"
        scope_url = urlunsplit((scope_scheme, parsed.netloc, parsed.path, parsed.query, ""))
        ok, reason = ctx.gate.check_url(scope_url, engagement, resolver=lambda _host: addresses)
        if not ok:
            return {"error": reason}
    except (OSError, ValueError) as e:
        return {"error": f"WebSocket setup failed: {e}"}

    address = str(addresses[0])
    tls_context = ssl.create_default_context() if parsed.scheme == "wss" else None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            address, port, ssl=tls_context,
            server_hostname=parsed.hostname if tls_context else None), timeout)
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
        return {"error": f"connection failed: {e}"}
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        host_header = parsed.netloc
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n")
        writer.write(request.encode("ascii"))
        await writer.drain()
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        if len(headers) > _MAX_HEADERS or not _valid_upgrade(headers, key):
            return {"error": "server did not accept WebSocket upgrade"}
        if message is not None:
            await _write_frame(writer, 0x1, message.encode())
        messages = []
        for _ in range(reads):
            frame = await _read_frame(reader, writer, timeout)
            if frame is None:
                break
            messages.append(frame)
        return {"connected": True, "peer": f"{address}:{port}", "tls": bool(tls_context),
                "sent": message is not None, "messages": messages, "truncated": any(x.get("truncated") for x in messages)}
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            asyncio.TimeoutError) as e:
        return {"error": f"WebSocket exchange failed: {e}"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _resolve(host: str, port: int) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return list({ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos})


def _valid_upgrade(headers: bytes, key: str) -> bool:
    lines = headers.decode("iso-8859-1", errors="replace").split("\r\n")
    if not lines or " 101 " not in f" {lines[0]} ":
        return False
    fields = {line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip()
              for line in lines[1:] if ":" in line}
    expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    return fields.get("sec-websocket-accept") == expected and "websocket" in fields.get("upgrade", "").lower()


async def _write_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    length = len(payload)
    header = bytes([0x80 | opcode])
    if length < 126:
        header += bytes([0x80 | length])
    else:
        header += bytes([0x80 | 126]) + struct.pack("!H", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    writer.write(header + mask + masked)
    await writer.drain()


async def _read_frame(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      timeout: float,
                      controls_remaining: int = _MAX_CONTROL_FRAMES) -> dict | None:
    first, second = await _read_exactly(reader, 2, timeout)
    opcode, length = first & 0x0F, second & 0x7F
    if length == 126:
        length = struct.unpack("!H", await _read_exactly(reader, 2, timeout))[0]
    elif length == 127:
        length = struct.unpack("!Q", await _read_exactly(reader, 8, timeout))[0]
    masked = bool(second & 0x80)
    if length > _MAX_MESSAGE:
        # Do not try to drain an unbounded peer-controlled frame length.  The
        # caller closes the connection after this bounded result.
        return {"type": "oversized", "truncated": True}
    mask = await _read_exactly(reader, 4, timeout) if masked else b""
    data = await _read_exactly(reader, length, timeout)
    if masked:
        data = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
    if opcode == 0x8:
        return None
    if opcode == 0x9:
        await _write_frame(writer, 0xA, data)
        if controls_remaining <= 0:
            return {"type": "control_limit", "truncated": True}
        return await _read_frame(reader, writer, timeout, controls_remaining - 1)
    if opcode == 0x1:
        return {"type": "text", "data": data.decode(errors="replace"), "truncated": False}
    return {"type": "binary", "data_base64": base64.b64encode(data).decode(), "truncated": False}


async def _read_exactly(reader: asyncio.StreamReader, size: int,
                        timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readexactly(size), timeout)
