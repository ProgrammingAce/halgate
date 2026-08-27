"""Operator-approved, engagement-bound callback listeners.

`request_callback_endpoint` proposes a listener (reason + protocol
requirement).  The dispatch approval gate presents the proposal to the
operator; this handler only runs after approval, then provisions the local
listener and binds it to the proposing engagement.  A listener exists to
serve narrowly scoped confirmations: the target calls back a bounded number
of times, the harness records each callback, and the agent can only read
confirmations back through `read_callback_endpoint`.  No custom responses,
no arbitrary I/O, no cross-engagement access.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .context import ToolContext

MAX_MATCHED_REQUESTS = 10
MAX_TOTAL_CAPTURES = 50
MAX_BYTES_MIN = 64
MAX_BYTES_MAX = 65536
MAX_BODY_RETAINED = 16384
EXPIRY_MIN = 5
DEFAULT_EXPIRY_SECONDS = 300
EXPIRY_MAX = 1800
ALLOWED_BINDS = ("127.0.0.1", "0.0.0.0")
READ_TIMEOUT = 5.0
MAX_WAIT_SECONDS = 30
_DNS_NAME = re.compile(r"(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.IGNORECASE)

REQUEST_CALLBACK_ENDPOINT_SCHEMA = {
    "name": "request_callback_endpoint",
    "description": (
        "Request an operator-approved local listener for a target-initiated "
        "callback. Provide the reason and the protocol requirement; the "
        "operator approves this exact proposal. When approved, the harness "
        "provisions the listener and binds it to this engagement only. "
        "Confirmations are read back with `read_callback_endpoint`. Do not "
        "bind ports through the shell tool."
    ),
    "parameters": {"type": "object", "properties": {
        "reason": {"type": "string",
                   "description": "Why this confirmation callback is needed "
                                  "(shown to the operator for approval)"},
        "protocol": {"type": "string", "enum": ["http", "tcp", "dns"],
                     "description": (
                         "Protocol the outbound callback must use. DNS is UDP: "
                         "for a remote target, explicitly set bind=0.0.0.0 and "
                         "use the returned dns_usage instructions exactly.")},
        "bind": {"type": "string", "enum": ["127.0.0.1", "0.0.0.0"],
                 "description": "Listener interface (default 127.0.0.1). "
                                "0.0.0.0 is reachable on external interfaces. "
                                "The harness derives a candidate advertised host "
                                "from the route to this engagement and shows it in "
                                "the mandatory approval prompt."},
        "port": {"type": "integer",
                 "description": "Fixed listener port 1-65535, or 0 to auto-assign "
                                "(default 0). DNS normally needs port 53; an "
                                "auto-assigned DNS port works only if the target's "
                                "resolver command supports an explicit port. A taken "
                                "requested port is an error, never silently rebound."},
        "max_requests": {"type": "integer",
                         "description": "Confirmations to capture before the "
                                        "listener closes, 1-10 (default 1)"},
        "max_bytes": {"type": "integer",
                      "description": "Maximum bytes captured per callback, "
                                     "64-65536 (default 16384)"},
        "expires_seconds": {"type": "integer",
                            "description": "Listener lifetime, 5-1800 seconds "
                                           "(default 300)"},
        "path_prefix": {"type": "string",
                        "description": "http only: only callbacks whose path "
                           "starts with this prefix count toward "
                           "max_requests"},
        "query_name": {"type": "string",
                       "description": "dns only: exact fully-qualified query "
                       "name that counts as a confirmation"},
        "engagement_id": {"type": "string"},
    }, "required": ["reason", "protocol", "engagement_id"]},
}

READ_CALLBACK_ENDPOINT_SCHEMA = {
    "name": "read_callback_endpoint",
    "description": (
        "Read confirmations captured by a previously approved callback "
        "listener bound to this engagement. Read-only confirmation access; "
        "it never sends data or changes listener state except an explicit "
        "teardown."
    ),
    "parameters": {"type": "object", "properties": {
        "endpoint_id": {"type": "string",
                        "description": "Endpoint identifier returned by the "
                                       "approved request"},
        "engagement_id": {"type": "string"},
        "wait_seconds": {"type": "number",
                         "description": "Wait up to N seconds (0-30) for a "
                                        "confirmation (default 0)"},
        "close": {"type": "boolean",
                  "description": "Tear the listener down after this read "
                                 "(default false)"},
    }, "required": ["endpoint_id", "engagement_id"]},
}


def _entry_fields(entry: dict) -> dict:
    return {
        "status": entry["status"],
    "protocol": entry["protocol"],
    "url": entry["url"],
    "advertised_host": entry.get("advertised_host"),
    "reason": entry["reason"],
    "bound_engagement": entry["engagement_id"],
    "captured": len(entry["captured"]),
    }


def _log(ctx: ToolContext, action: str, entry: dict) -> None:
    """Emit a dedicated audit event when the harness attached its logger."""
    audit = ctx.extra.get("audit")
    log = getattr(audit, "callback_endpoint_event", None)
    if callable(log):
        try:
            log(action, entry["id"], _entry_fields(entry),
                entry["engagement_id"])
        except Exception:
            pass


def _emit_output(ctx: ToolContext, entry: dict, stream: str, text: str) -> None:
    """Append listener output to its optional operator-visible pane.

    Callback listeners are asyncio servers rather than child processes, so
    they do not have OS stdout/stderr streams to drain.  This hook gives the
    TUI the equivalent live output stream without changing the listener's
    bounded capture behaviour.
    """
    callback = ctx.extra.get("listener_pane_callback")
    if callable(callback):
        try:
            callback(entry["id"], stream, text, entry["engagement_id"])
        except Exception:
            # A display failure must never affect listener availability.
            pass


def _endpoints(ctx: ToolContext) -> dict:
    return ctx.extra.setdefault("callback_endpoints", {})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat(timespec="seconds")


def _finish(ctx: ToolContext, entry: dict, status: str) -> None:
    """Transition a listening entry to a terminal state and stop the server."""
    if entry["status"] != "listening":
        return
    entry["status"] = status
    handle = entry.pop("expiry_handle", None)
    if handle is not None:
        handle.cancel()
    server: asyncio.Server | None = entry.get("server")
    if server is not None:
        server.close()
        try:
            asyncio.get_running_loop().create_task(server.wait_closed())
        except RuntimeError:  # pragma: no cover - called outside a loop
            pass
    transport: asyncio.DatagramTransport | None = entry.get("transport")
    if transport is not None:
        transport.close()
    _emit_output(ctx, entry, "stdout", f"listener {status}\n")


def _store_capture(ctx: ToolContext, entry: dict, record: dict) -> None:
    record = dict(record)
    record["received_at"] = _iso()
    entry["captured"].append(record)
    _emit_output(ctx, entry, "stdout", json.dumps(record, sort_keys=True) + "\n")
    matched_done = (record.get("matched") and
                    sum(1 for c in entry["captured"] if c.get("matched"))
                    >= entry["max_requests"])
    if matched_done or len(entry["captured"]) >= MAX_TOTAL_CAPTURES:
        _finish(ctx, entry, "completed")
    _log(ctx, "captured", entry)


async def _read_bounded(reader: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """Read until EOF or `limit` bytes; per-read timeout bounds idle peers."""
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(4096, limit - total)), timeout=READ_TIMEOUT)
        except asyncio.TimeoutError:
            break
        except (OSError, ConnectionError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), total == limit


def _peer(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    return f"{peer[0]}:{peer[1]}" if peer else "unknown"


async def _capture_tcp(entry: dict, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> dict:
    data, truncated = await _read_bounded(reader, entry["max_bytes"])
    return {
        "protocol": "tcp",
        "peer": _peer(writer),
        "bytes": len(data),
        "data_base64": base64.b64encode(data).decode() if data else "",
        "text": data.decode(errors="replace")[:MAX_BODY_RETAINED] if data else "",
        "truncated": truncated,
    }


async def _capture_http(entry: dict, reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> dict:
    limit = entry["max_bytes"]
    try:
        # readuntil stops at the header delimiter and leaves an already
        # buffered body available for the bounded body read below.  This lets
        # us acknowledge normal header-only callbacks immediately rather than
        # waiting for an idle read timeout.
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),
                                            timeout=READ_TIMEOUT)
    except asyncio.IncompleteReadError as e:
        header = e.partial
    except asyncio.TimeoutError:
        header = b""
    except asyncio.LimitOverrunError:
        return {"protocol": "http", "peer": _peer(writer),
                "request_line": "", "matched": False, "bytes": 0,
                "error": "HTTP headers exceed listener limit"}
    if not header:
        return {"protocol": "http", "peer": _peer(writer),
                "request_line": "", "matched": False, "bytes": 0}
    head, separator, body = header.partition(b"\r\n\r\n")
    complete = bool(separator)
    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
    request_line = lines[0][:512] if lines else ""
    parts = request_line.split(" ", 2)
    method = parts[0].upper() if parts and parts[0] else ""
    target = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()[:64]] = value.strip()[:256]
    try:
        content_length = min(int(headers.get("content-length") or 0),
                             max(0, limit - len(header)))
    except ValueError:
        content_length = 0
    body_incomplete = False
    if complete and len(body) < content_length:
        more, _ = await _read_bounded(reader, content_length - len(body))
        body += more
        body_incomplete = len(body) < content_length
    if request_line:
        try:
            writer.write(b"HTTP/1.1 200 OK\r\n"
                         b"Content-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            await asyncio.wait_for(writer.drain(), timeout=READ_TIMEOUT)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            pass
    prefix = entry.get("path_prefix")
    path = target.split("?", 1)[0].split("#", 1)[0]
    query = ""
    if "?" in target:
        path, query = target.split("?", 1)
    matched = prefix is None or (
        bool(prefix) and path.startswith(prefix))
    body_kept = body[:MAX_BODY_RETAINED]
    return {
        "protocol": "http",
        "peer": _peer(writer),
        "method": method,
        "path": path[:2048],
        "query": query[:1024],
        "headers": dict(sorted(list(headers.items())[:32])),
        "body_bytes": len(body),
        "body_base64": base64.b64encode(body_kept).decode() if body else "",
        "body_text": body_kept.decode(errors="replace")[:MAX_BODY_RETAINED]
        if body else "",
        "matched": matched,
        "bytes": len(header) + len(body),
        "truncated": body_incomplete or len(body) > len(body_kept),
    }


def _make_handler(ctx: ToolContext, entry: dict):
    async def _handle(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            if entry["protocol"] == "http":
                record = await _capture_http(entry, reader, writer)
            else:
                record = await _capture_tcp(entry, reader, writer)
        except (OSError, ConnectionError) as e:
            _emit_output(ctx, entry, "stderr", f"listener error: {e}\n")
            record = None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        if entry["status"] != "listening":
            return
        if record is None:
            return
        _store_capture(ctx, entry, record)
    return _handle


def _dns_name(packet: bytes, offset: int) -> tuple[str, int] | None:
    """Decode one DNS name without following compression pointers.

    DNS callback queries normally carry their question as uncompressed labels.
    Refusing pointers keeps this listener a bounded confirmation collector,
    rather than a general DNS parser exposed to untrusted datagrams.
    """
    labels: list[str] = []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            return ".".join(labels) + ".", offset
        if size > 63 or size & 0xC0:
            return None
        if offset + size > len(packet):
            return None
        label = packet[offset:offset + size]
        offset += size
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return None
    return None


def _capture_dns(entry: dict, packet: bytes, peer: Any) -> dict:
    peer_text = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) and len(peer) >= 2 else "unknown"
    record: dict[str, Any] = {"protocol": "dns", "peer": peer_text,
                              "bytes": len(packet), "matched": False}
    if len(packet) < 12:
        record["error"] = "malformed DNS packet: shorter than header"
        return record
    query_id = int.from_bytes(packet[:2], "big")
    flags = int.from_bytes(packet[2:4], "big")
    questions = int.from_bytes(packet[4:6], "big")
    record["query_id"] = query_id
    if questions != 1:
        record["error"] = f"unsupported DNS question count: {questions}"
        return record
    parsed = _dns_name(packet, 12)
    if parsed is None:
        record["error"] = "malformed or compressed DNS query name"
        return record
    name, offset = parsed
    if offset + 4 > len(packet):
        record["error"] = "malformed DNS question"
        return record
    qtype = int.from_bytes(packet[offset:offset + 2], "big")
    qclass = int.from_bytes(packet[offset + 2:offset + 4], "big")
    expected = entry.get("query_name")
    record.update({"query_name": name, "query_type": qtype,
                   "query_class": qclass,
                   "matched": expected is None or name.lower() == expected})
    # Return a minimal NXDOMAIN response.  The echoed question is enough for
    # standard resolvers to accept it and suppress a retry storm.
    response_flags = 0x8000 | 0x0080 | (flags & 0x0100) | 0x0003
    record["response"] = (query_id.to_bytes(2, "big") +
                          response_flags.to_bytes(2, "big") +
                          b"\x00\x01\x00\x00\x00\x00\x00\x00" +
                          packet[12:offset + 4])
    return record


class _DnsCallbackProtocol(asyncio.DatagramProtocol):
    def __init__(self, ctx: ToolContext, entry: dict):
        self.ctx = ctx
        self.entry = entry
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if self.entry["status"] != "listening":
            return
        record = _capture_dns(self.entry, data, addr)
        response = record.pop("response", None)
        if response is not None and self.transport is not None:
            self.transport.sendto(response, addr)
        _store_capture(self.ctx, self.entry, record)

    def error_received(self, exc: Exception) -> None:
        _emit_output(self.ctx, self.entry, "stderr", f"listener error: {exc}\n")


async def handle_request_callback_endpoint(ctx: ToolContext, reason: str,
                                           protocol: str,
                                           engagement_id: str,
                                           bind: str = "127.0.0.1",
                                           port: int = 0,
                                           max_requests: int = 1,
                                           max_bytes: int = 16384,
                                           expires_seconds: int = DEFAULT_EXPIRY_SECONDS,
                                           path_prefix: str | None = None,
                                           query_name: str | None = None,
                                           **_: Any) -> dict:
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    reason = (str(reason) or "").strip()
    if not reason:
        return {"error": "a reason is required so the operator can approve the proposal"}
    reason = reason[:1000]
    if protocol not in ("http", "tcp", "dns"):
        return {"error": "protocol must be http, tcp, or dns"}
    if bind not in ALLOWED_BINDS:
        return {"error": "bind must be 127.0.0.1 or 0.0.0.0"}
    if protocol == "dns" and bind != "0.0.0.0":
        return {"error": ("DNS callbacks from a remote target require "
                          "bind='0.0.0.0'; 127.0.0.1 is reachable only from "
                          "the harness host")}
    configured_host = _advertised_host(ctx)
    inferred_host = infer_callback_advertised_host(engagement)
    advertised_host = configured_host or inferred_host
    approved_host = _.get("_callback_approved_advertised_host")
    if (bind == "0.0.0.0" and approved_host is not None
            and str(approved_host) != str(advertised_host)):
        return {"error": ("callback route changed after approval; request a new "
                          "listener so the operator can review the current address")}
    if bind == "0.0.0.0" and not advertised_host:
        return {"error": ("could not determine a non-loopback local address "
                          "for this engagement's route; configure "
                          "callback.advertised_host explicitly")}
    try:
        port = int(port)
        max_requests = int(max_requests)
        max_bytes = int(max_bytes)
        expires_seconds = int(expires_seconds)
    except (TypeError, ValueError):
        return {"error": "port, max_requests, max_bytes, and expires_seconds must be integers"}
    if not (0 <= port <= 65535):
        return {"error": "port must be 0 (auto) or 1-65535"}
    max_requests = min(MAX_MATCHED_REQUESTS, max(1, max_requests))
    max_bytes = min(MAX_BYTES_MAX, max(MAX_BYTES_MIN, max_bytes))
    expires_seconds = min(EXPIRY_MAX, max(EXPIRY_MIN, expires_seconds))
    if path_prefix is not None:
        path_prefix = str(path_prefix)[:200]
        if protocol != "http":
            return {"error": "path_prefix only applies to the http protocol"}
        if not path_prefix.startswith("/"):
            return {"error": "path_prefix must start with '/'"}
    if query_name is not None:
        if protocol != "dns":
            return {"error": "query_name only applies to the dns protocol"}
        query_name = str(query_name).strip().lower().rstrip(".")
        if not _DNS_NAME.fullmatch(query_name):
            return {"error": "query_name must be a valid DNS name up to 253 characters"}
        query_name += "."

    entry: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "engagement_id": engagement.id,
        "reason": reason,
        "protocol": protocol,
        "bind": bind,
        "advertised_host": advertised_host if bind == "0.0.0.0" else None,
        "advertised_host_source": ("configured" if configured_host else "route-inferred")
        if bind == "0.0.0.0" else None,
        "port": None,
        "url": None,
        "url_display": None,
        "max_requests": max_requests,
        "max_bytes": max_bytes,
        "path_prefix": path_prefix,
        "query_name": query_name,
        "expires_at": _now() + timedelta(seconds=expires_seconds),
        "created_at": _iso(),
        "status": "listening",
        "captured": [],
        "server": None,
        "transport": None,
        "expiry_handle": None,
    }

    try:
        if protocol == "dns":
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _DnsCallbackProtocol(ctx, entry), local_addr=(bind, port))
            entry["transport"] = transport
            actual_port = transport.get_extra_info("sockname")[1]
        else:
            server = await asyncio.start_server(
                _make_handler(ctx, entry), bind, port)
            entry["server"] = server
            actual_port = server.sockets[0].getsockname()[1]
    except OSError as e:
        return {"error": f"listener bind failed (refusing to silently rebind): {e}"}

    entry["port"] = actual_port
    scheme = "http" if protocol == "http" else ("dns" if protocol == "dns" else "tcp")
    display_host = "127.0.0.1" if bind == "127.0.0.1" else advertised_host
    entry["url"] = f"{scheme}://{_url_host(display_host)}:{actual_port}"
    entry["url_display"] = entry["url"]
    endpoints = _endpoints(ctx)
    endpoints[entry["id"]] = entry
    loop = asyncio.get_running_loop()
    entry["expiry_handle"] = loop.call_later(
        expires_seconds, lambda: _finish(ctx, entry, "expired"))
    _log(ctx, "provisioned", entry)
    _emit_output(ctx, entry, "stdout",
                 f"listening on {entry['url_display']} ({protocol})\n")
    return {
        "endpoint_id": entry["id"],
        "engineered_url": entry["url"],
        "url_display": entry["url_display"],
        "protocol": protocol,
        "bind": bind,
        "advertised_host": entry["advertised_host"],
        "advertised_host_source": entry["advertised_host_source"],
        "port": actual_port,
        "max_requests": max_requests,
        "path_prefix": path_prefix,
        "query_name": query_name,
        "dns_usage": _dns_usage(display_host, actual_port, query_name)
        if protocol == "dns" else None,
        "expires_in_seconds": expires_seconds,
        "status": "listening",
        "note": ("For DNS, use the command in dns_usage that matches the "
                 "returned port; otherwise have the target issue exactly this confirmation callback, "
                 "then read the result with `read_callback_endpoint`. The "
                 "listener tears itself down after the captured confirmations "
                 "or when it expires."),
    }


def _advertised_host(ctx: ToolContext) -> str | None:
    config = getattr(ctx, "config", None)
    callback = getattr(config, "callback", None)
    host = getattr(callback, "advertised_host", None)
    return str(host) if host else None


def infer_callback_advertised_host(engagement: Any) -> str | None:
    """Return the IPv4 source address the OS would route to this engagement.

    UDP ``connect`` only selects a route locally; it sends no datagram.  The
    result is intentionally a proposal shown in the existing listener approval
    dialog, never a durable config mutation.  CIDR engagements use their first
    usable address solely to select the interface, not as a probe target.
    """
    target = str(getattr(engagement, "target", ""))
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.version != 4:
            return None
        destination = str(network.network_address if network.prefixlen == 32
                          else network.network_address + 1)
    except ValueError:
        destination = target
    if not destination or destination.startswith("/"):
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((destination, 9))
            address = ipaddress.ip_address(probe.getsockname()[0])
    except OSError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local:
        return None
    return str(address)


def _url_host(host: str) -> str:
    """Bracket an IPv6 literal when rendering a target-usable URL."""
    try:
        import ipaddress
        return f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
    except ValueError:
        return host


def _dns_usage(host: str, port: int, query_name: str | None) -> dict[str, str]:
    """Return exact, target-side forms for a DNS callback query."""
    name = query_name or "<query-name>"
    usage = {
        "query_name": name,
        "resolver_host": host,
        "resolver_port": str(port),
        "important": ("Use the advertised callback host, never 127.0.0.1. "
                      "`nslookup <name> <host>:<port>` is not valid syntax."),
    }
    if port == 53:
        usage.update({
            "standard_nslookup": f"nslookup {name} {host}",
            "standard_dig": f"dig @{host} {name}",
        })
    else:
        usage.update({
            "dig": f"dig @{host} -p {port} {name}",
            "busybox_nslookup": f"nslookup -port={port} {name} {host}",
            "nonstandard_port_warning": (
                "Use a non-standard port only after confirming the target has "
                "`dig` or BusyBox `nslookup -port`. Plain nslookup always sends "
                "to port 53 and will not reach this listener."),
        })
    return usage


async def handle_read_callback_endpoint(ctx: ToolContext, endpoint_id: str,
                                        engagement_id: str,
                                        wait_seconds: float = 0,
                                        close: bool = False,
                                        **_: Any) -> dict:
    entry = _endpoints(ctx).get(str(endpoint_id))
    if entry is None:
        return {"error": f"no approved callback endpoint named {endpoint_id!r}"}
    if entry["engagement_id"] != engagement_id:
        return {"error": ("callback endpoint is bound to a different "
                          "engagement; read it under its own engagement")}
    try:
        wait = min(MAX_WAIT_SECONDS, max(0.0, float(wait_seconds or 0)))
    except (TypeError, ValueError):
        wait = 0.0
    if wait > 0:
        confirmed = sum(1 for c in entry["captured"] if c.get("matched"))
        deadline = _now() + timedelta(seconds=wait)
        while (entry["status"] == "listening"
               and sum(1 for c in entry["captured"] if c.get("matched"))
               < max(confirmed, 1)
               and _now() < deadline):
            await asyncio.sleep(0.1)
    captured = entry["captured"]
    result = {
        "endpoint_id": entry["id"],
        "status": entry["status"],
        "protocol": entry["protocol"],
        "bound_engagement": entry["engagement_id"],
        "captured": captured,
        "captured_count": len(captured),
        "confirmed": sum(1 for c in captured if c.get("matched")),
        "max_requests": entry["max_requests"],
        "expires_at": entry["expires_at"].isoformat(timespec="seconds"),
    }
    if close and entry["status"] == "listening":
        _finish(ctx, entry, "closed")
        result["status"] = "closed"
        _log(ctx, "closed", entry)
    if result["status"] != "listening":
        result["note"] = (
            "This listener is closed. A callback that arrived after it closed "
            "may have been missed; request a new approved listener if another "
            "confirmation is needed.")
    return result
