"""Bounded TCP/TLS service fingerprinting without arbitrary payloads."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlunsplit

from .context import ToolContext

TCP_PROBE_SCHEMA = {
    "name": "tcp_probe",
    "description": "Fingerprint one in-scope TCP service without sending an application payload. It may perform a TLS handshake and passively read up to 4096 banner bytes; tls=auto can make one TLS attempt and one plain-TCP fallback connection.",
    "parameters": {"type": "object", "properties": {
        "host": {"type": "string", "description": "One target hostname or IP"},
        "port": {"type": "integer", "description": "One TCP port (1-65535)"},
        "tls": {"type": "string", "enum": ["auto", "on", "off"], "description": "TLS handshake mode (default: auto)"},
        "read_banner": {"type": "boolean", "description": "Passively read up to 4096 banner bytes"},
        "timeout": {"type": "number", "description": "Connection timeout in seconds (1-10)"},
        "reason": {"type": "string"},
        "engagement_id": {"type": "string"},
    }, "required": ["host", "port", "reason", "engagement_id"]},
}


async def handle_tcp_probe(ctx: ToolContext, host: str, port: int,
                           engagement_id: str, tls: str = "auto",
                           read_banner: bool = True, timeout: float = 5,
                           reason: str = "",
                           **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
        port = int(port)
        if not 1 <= port <= 65535:
            return {"error": "port must be between 1 and 65535"}
        if tls not in {"auto", "on", "off"}:
            return {"error": "tls must be auto, on, or off"}
        timeout = min(10.0, max(1.0, float(timeout)))
        addresses = await _resolve(host, port)
        ok, reason = ctx.gate.check_url(
            _scope_url(host, port), engagement,
            resolver=lambda _host: addresses)
        if not ok:
            return {"error": reason}
    except (OSError, ValueError) as e:
        return {"error": f"TCP probe setup failed: {e}"}

    address = str(addresses[0])
    if tls == "off":
        return await _connect(address, port, host, False, read_banner, timeout)
    if tls == "on":
        return await _connect(address, port, host, True, read_banner, timeout)

    # TLS first recognizes the common case without sending an application
    # payload. A plain fallback permits passive-banner protocols.
    tls_result = await _connect(address, port, host, True, read_banner, timeout)
    if tls_result.get("connected"):
        return tls_result
    plain_result = await _connect(address, port, host, False, read_banner, timeout)
    plain_result["tls_attempt_error"] = tls_result.get("error", "TLS unavailable")
    return plain_result


async def _resolve(host: str, port: int) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
        addresses = list({ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos})
        if not addresses:
            raise OSError("DNS returned no addresses")
        return addresses


async def _connect(address: str, port: int, server_name: str, use_tls: bool,
                   read_banner: bool, timeout: float) -> dict:
    ssl_context = ssl.create_default_context() if use_tls else None
    if ssl_context:
        # Assessment targets often use private certificates; this tool reports
        # certificate metadata rather than treating verification failure as a
        # network result.
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=ssl_context,
                                    server_hostname=server_name if use_tls else None),
            timeout=timeout)
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
        return {"error": f"connection failed: {e}"}
    try:
        result: dict[str, Any] = {"connected": True, "peer": f"{address}:{port}", "tls": None}
        if use_tls:
            ssl_object = writer.get_extra_info("ssl_object")
            cert = ssl_object.getpeercert() if ssl_object else {}
            result["tls"] = {
                "negotiated": True,
                "version": ssl_object.version() if ssl_object else None,
                "alpn": ssl_object.selected_alpn_protocol() if ssl_object else None,
                "subject": _certificate_name(cert.get("subject", ())),
                "issuer": _certificate_name(cert.get("issuer", ())),
            }
        if read_banner:
            try:
                banner = await asyncio.wait_for(reader.read(4096), timeout=min(2.0, timeout))
            except asyncio.TimeoutError:
                banner = b""
            result["banner"] = banner.decode(errors="replace")
            result["truncated"] = len(banner) == 4096
        return result
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


def _certificate_name(entries: tuple) -> str | None:
    for group in entries:
        for key, value in group:
            if key == "commonName":
                return value
    return None


def _scope_url(host: str, port: int) -> str:
    """Make a parseable HTTP URL solely for ScopeGate's host/IP validation."""
    try:
        normalized = str(ipaddress.ip_address(host))
        netloc = f"[{normalized}]:{port}" if ":" in normalized else f"{normalized}:{port}"
    except ValueError:
        netloc = f"{host}:{port}"
    return urlunsplit(("http", netloc, "", "", ""))
