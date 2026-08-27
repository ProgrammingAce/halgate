"""Bounded multicast DNS/DNS-SD discovery for an authorized LAN engagement."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from collections import defaultdict
from typing import Any

from .context import ToolContext

_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT = 5353
_DEFAULT_SERVICE = "_services._dns-sd._udp.local."

MDNS_BROWSE_SCHEMA = {
    "name": "mdns_browse",
    "description": (
        "Send one bounded mDNS/DNS-SD PTR query on the local LAN and return "
        "advertised service instances, including SRV and TXT friendly-name "
        "metadata when present. This is discovery only: it never connects to "
        "the advertised services."),
    "parameters": {"type": "object", "properties": {
        "service_type": {"type": "string", "description": "DNS-SD service type to query (default _services._dns-sd._udp.local.)"},
        "interface_address": {"type": "string", "description": "Local IPv4 address for multicast membership (default 0.0.0.0)"},
        "duration_seconds": {"type": "number", "description": "Listen duration, 1-10 seconds (default 3)"},
        "max_responses": {"type": "integer", "description": "Maximum datagrams to parse, 1-50 (default 20)"},
        "friendly_name_contains": {"type": "string", "description": "Optional case-insensitive result filter"},
        "reason": {"type": "string", "description": "Why LAN discovery is needed"},
        "engagement_id": {"type": "string"},
    }, "required": ["reason", "engagement_id"]},
}


def _dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode()) > 63 for label in labels):
        raise ValueError("service_type must be a valid DNS name")
    return b"".join(bytes([len(label.encode())]) + label.encode() for label in labels) + b"\0"


def _read_name(packet: bytes, offset: int, seen: set[int] | None = None) -> tuple[str, int]:
    """Decode a DNS name, following bounded compression pointers."""
    labels: list[str] = []
    origin = offset
    jumped = False
    seen = seen or set()
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return ".".join(labels) + ".", (origin if jumped else offset + 1)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen or pointer >= len(packet):
                raise ValueError("invalid compression pointer")
            seen.add(pointer)
            if not jumped:
                origin = offset + 2
                jumped = True
            offset = pointer
            continue
        if length & 0xC0 or length > 63 or offset + 1 + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += length + 1
    raise ValueError("truncated DNS name")


def _parse_records(packet: bytes) -> list[tuple[str, int, bytes | tuple[int, str] | str]]:
    if len(packet) < 12:
        return []
    questions, answers, authority, additional = struct.unpack("!HHHH", packet[4:12])
    offset = 12
    try:
        for _ in range(questions):
            _, offset = _read_name(packet, offset)
            offset += 4
        records = []
        for _ in range(min(100, answers + authority + additional)):
            owner, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                return records
            rtype, _klass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            start, offset = offset + 10, offset + 10 + rdlength
            if offset > len(packet):
                return records
            if rtype == 12:  # PTR
                target, _ = _read_name(packet, start)
                records.append((owner, rtype, target))
            elif rtype == 33 and rdlength >= 6:  # SRV
                port = int.from_bytes(packet[start + 4:start + 6], "big")
                target, _ = _read_name(packet, start + 6)
                records.append((owner, rtype, (port, target)))
            elif rtype == 16:  # TXT
                items, pos = [], start
                while pos < offset:
                    n = packet[pos]
                    pos += 1
                    if pos + n > offset:
                        break
                    items.append(packet[pos:pos + n].decode("utf-8", "replace"))
                    pos += n
                records.append((owner, rtype, items))
    except ValueError:
        return []
    return records


async def handle_mdns_browse(ctx: ToolContext, reason: str, engagement_id: str,
                             service_type: str = _DEFAULT_SERVICE,
                             interface_address: str = "0.0.0.0",
                             duration_seconds: float = 3,
                             max_responses: int = 20,
                             friendly_name_contains: str | None = None,
                             **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        ctx.gate._require_active(engagement_id)
        service_type = str(service_type).strip().lower().rstrip(".") + "."
        question = _dns_name(service_type)
        interface_address = str(ipaddress.IPv4Address(interface_address))
        duration = min(10.0, max(1.0, float(duration_seconds)))
        maximum = min(50, max(1, int(max_responses)))
    except (ValueError, TypeError) as e:
        return {"error": f"mDNS setup failed: {e}"}

    query = b"\0\0\0\0\0\x01\0\0\0\0\0\0" + question + b"\0\x0c\0\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", _MDNS_PORT))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton(_MDNS_GROUP) + socket.inet_aton(interface_address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(sock, query, (_MDNS_GROUP, _MDNS_PORT))
        packets: list[bytes] = []
        deadline = loop.time() + duration
        while len(packets) < maximum and loop.time() < deadline:
            try:
                packet, _peer = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 9000), timeout=deadline - loop.time())
                packets.append(packet)
            except asyncio.TimeoutError:
                break
    except OSError as e:
        return {"error": f"mDNS browse failed: {e}"}
    finally:
        sock.close()

    ptrs: dict[str, set[str]] = defaultdict(set)
    srvs: dict[str, tuple[int, str]] = {}
    txts: dict[str, list[str]] = {}
    for packet in packets:
        for owner, rtype, data in _parse_records(packet):
            if rtype == 12:
                ptrs[owner.lower()].add(str(data))
            elif rtype == 33:
                srvs[owner.lower()] = data  # type: ignore[assignment]
            elif rtype == 16:
                txts[owner.lower()] = data  # type: ignore[assignment]
    instances = sorted({instance for values in ptrs.values() for instance in values}, key=str.lower)
    needle = str(friendly_name_contains or "").lower().strip()
    results = []
    for instance in instances:
        srv = srvs.get(instance.lower())
        item = {"instance": instance, "service_types": sorted(
            owner for owner, values in ptrs.items() if instance in values),
            "host": srv[1] if srv else None, "port": srv[0] if srv else None,
            "txt": txts.get(instance.lower(), [])}
        if not needle or needle in " ".join(map(str, item.values())).lower():
            results.append(item)
    return {"service_type": service_type, "responses_received": len(packets),
            "services": results, "truncated": len(packets) >= maximum,
            "note": "Results are multicast advertisements observed locally; absence is not proof that a device is offline."}
