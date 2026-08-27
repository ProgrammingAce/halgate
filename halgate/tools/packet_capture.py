"""Short, filter-only tcpdump captures kept in engagement-private scratch."""
from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path
from typing import Any

from .context import ToolContext

_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_PROTOCOL_FILTERS = {
    "mdns": "udp port 5353",
    "dns": "udp port 53",
    "dhcp": "(udp port 67 or udp port 68)",
    "tcp_syn": "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
}

PACKET_CAPTURE_SCHEMA = {
    "name": "packet_capture",
    "description": ("Run an operator-approved, short tcpdump capture with one "
                    "built-in protocol filter. It writes a bounded PCAP only to "
                    "the engagement's private scratch directory; it cannot accept "
                    "an arbitrary BPF expression or output path."),
    "parameters": {"type": "object", "properties": {
        "interface": {"type": "string", "description": "Local capture interface, e.g. en0"},
        "protocol": {"type": "string", "enum": ["mdns", "dns", "dhcp", "tcp_syn"], "description": "Built-in capture filter"},
        "duration_seconds": {"type": "number", "description": "Capture duration, 1-60 seconds (default 10)"},
        "max_packets": {"type": "integer", "description": "Packet limit, 1-200 (default 50)"},
        "reason": {"type": "string", "description": "Why this capture is needed"},
        "engagement_id": {"type": "string"},
    }, "required": ["interface", "protocol", "reason", "engagement_id"]},
}


async def handle_packet_capture(ctx: ToolContext, interface: str, protocol: str,
                                reason: str, engagement_id: str,
                                duration_seconds: float = 10,
                                max_packets: int = 50, **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
        duration = min(60.0, max(1.0, float(duration_seconds)))
        limit = min(200, max(1, int(max_packets)))
    except (ValueError, TypeError) as e:
        return {"error": f"packet capture setup failed: {e}"}
    interface = str(interface).strip()
    if not _INTERFACE.fullmatch(interface):
        return {"error": "interface contains unsupported characters"}
    if protocol not in _PROTOCOL_FILTERS:
        return {"error": "protocol must be mdns, dns, dhcp, or tcp_syn"}
    if not engagement.scratch_dir:
        return {"error": "packet capture requires an engagement scratch directory"}
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return {"error": "tcpdump is not installed or not on PATH"}
    scratch = Path(engagement.scratch_dir)
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        pcap = scratch / f"capture-{protocol}-{time.monotonic_ns()}.pcap"
    except OSError as e:
        return {"error": f"cannot prepare capture file: {e}"}
    # Keep the built-in BPF expression as one argv element. The model never
    # supplies tcpdump syntax or an output path.
    cmd = [tcpdump, "-nn", "-U", "-s", "512", "-c", str(limit), "-i", interface,
           "-w", str(pcap), _PROTOCOL_FILTERS[protocol]]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        try:
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration)
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
            proc.terminate()
            _stdout, stderr = await proc.communicate()
    except OSError as e:
        return {"error": f"tcpdump could not start: {e}"}
    size = pcap.stat().st_size if pcap.exists() else 0
    if proc.returncode not in (0, -15) and not (timed_out and pcap.exists()):
        return {"error": f"tcpdump failed (exit {proc.returncode})", "stderr": stderr.decode(errors="replace")[:2000]}
    return {"pcap_path": str(pcap), "bytes": size, "protocol": protocol,
            "interface": interface, "duration_seconds": duration,
            "max_packets": limit, "timed_out": timed_out,
            "stderr": stderr.decode(errors="replace")[:2000],
            "note": "Capture is snaplen-limited to 512 bytes and packet-limited; use binary_inspect/read_file within this engagement to examine the PCAP."}
