"""scan tool: run nmap against target(s)."""
from __future__ import annotations

import shlex
import re
from typing import Any

from .context import ToolContext

SCAN_SCHEMA = {
    "name": "scan",
    "description": "Run an operator-approved nmap scan against target(s). Targets must be "
                   "within the engagement's network scope and package limits. Returns parsed "
                   "host/ports plus up to 50,000 characters of raw output.",
    "parameters": {
        "type": "object",
        "properties": {
            "targets": {"type": "array", "items": {"type": "string"},
                        "description": "IPs, CIDRs, or hostnames to scan"},
            "ports": {"type": "array", "items": {"type": "string"},
                      "description": "Port specs (e.g. ['80', '443', '1-100'])"},
            "scan_type": {"type": "string",
                          "description": "nmap scan type flag (default -sV)"},
            "reason": {"type": "string",
                       "description": "Concise reason this scan is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing the scan"},
        },
        "required": ["targets", "reason", "engagement_id"],
    },
}


# Normal Nmap table rows are not indented, for example:
# ``443/tcp  open  https  nginx 1.24``.  Match those rows explicitly rather
# than relying on whitespace, which is also used by Nmap's non-port output.
_NMAP_PORT_ROW = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)


async def handle_scan(ctx: ToolContext, targets: list[str],
                      engagement_id: str,
                      ports: list[str] | None = None,
                      scan_type: str = "-sV", reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    if isinstance(targets, str):
        targets = [t for t in targets.split() if t]
    if not targets:
        return {"error": "no targets specified"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    pkg = ctx.config.packages[engagement.package]
    workdir = engagement.scratch_dir or ctx.config.shell.workdir
    if not pkg.scan_enabled:
        return {"error": "scan disabled for this engagement package"}
    if len(targets) > pkg.scan_max_targets:
        return {"error": f"too many targets ({len(targets)} > {pkg.scan_max_targets})"}

    port_str = ",".join(ports) if ports else "1-1024"
    cmd = ["nmap", scan_type, "-p", port_str, *targets]
    # Use ShellGuard for safe execution
    from ..guardrails.shell_guard import ShellGuard
    cmd_str = " ".join(shlex.quote(c) for c in cmd)
    live = ctx.extra.get("live_output_callback")
    guard = ShellGuard(pkg.shell_allowlist, pkg.scan_timeout,
                       pkg.guardrails.shell_max_output,
                       workdir,
                       on_output=(lambda stream, text: live("scan", stream, text))
                       if callable(live) else None)
    allowed, reason = guard.check(cmd_str)
    if not allowed:
        return {"error": reason}
    result = await guard.execute_in_mode(
        cmd_str, timeout=pkg.scan_timeout,
        execution_mode=engagement.execution_mode,
        container_runtime=ctx.config.process.container_runtime,
        container_image=ctx.config.process.container_image,
        mount_dir=workdir,
    )
    output = result.stdout.decode(errors="replace")
    if result.timed_out:
        return {"error": "scan timed out", "partial_output": output[:2000]}
    hosts = _parse_nmap(output)
    return {
        "hosts": hosts,
        "raw": output[:50000],
        "truncated": len(output) > 50000,
        "rc": result.rc,
    }


def _parse_nmap(output: str) -> list[dict]:
    """Crude nmap output parser: extract host blocks."""
    hosts: list[dict] = []
    current: dict | None = None
    for line in output.splitlines():
        if line.startswith("Nmap scan report for"):
            if current:
                hosts.append(current)
            current = {"host": line.split("for", 1)[1].strip(),
                       "ports": []}
        elif current:
            match = _NMAP_PORT_ROW.match(line)
            if match:
                service = match["service"]
                if match["version"]:
                    service = f"{service} {match['version']}"
                current["ports"].append({
                    "port": match["port"], "proto": match["proto"],
                    "state": match["state"], "service": service,
                })
    if current:
        hosts.append(current)
    return hosts
