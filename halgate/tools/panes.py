"""panes tools: spawn, write, read, kill, list long-lived process panes."""
from __future__ import annotations

import shlex
from typing import Any

from .context import ToolContext

PANE_SPAWN_SCHEMA = {
    "name": "pane_spawn",
    "description": "Launch an engagement-owned long-lived process in a named pane. "
                   "The command uses the same guarded direct-argv syntax as shell and "
                   "runs until killed. Use for bounded listeners or interactive tools.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Human-readable pane name"},
            "command": {"type": "string",
                        "description": "Command line to execute"},
            "workdir": {"type": "string",
                        "description": "Working directory (optional)"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing the spawn"},
        },
        "required": ["name", "command", "engagement_id"],
    },
}

PANE_WRITE_SCHEMA = {
    "name": "pane_write",
    "description": "Send approved data to an engagement-owned pane's stdin; data is written exactly as supplied (no newline is added).",
    "parameters": {
        "type": "object",
        "properties": {
            "pane_id": {"type": "string", "description": "Target pane id"},
            "data": {"type": "string", "description": "Data to send"},
            "reason": {"type": "string", "description": "Why this input is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["pane_id", "data", "reason", "engagement_id"],
    },
}

PANE_READ_SCHEMA = {
    "name": "pane_read",
    "description": "Read available output from a pane. Waits up to a "
                   "timeout for data if buffer is empty.",
    "parameters": {
        "type": "object",
        "properties": {
            "pane_id": {"type": "string", "description": "Target pane id"},
            "timeout": {"type": "number",
                        "description": "Max wait seconds (default 5)"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["pane_id", "engagement_id"],
    },
}

PANE_KILL_SCHEMA = {
    "name": "pane_kill",
    "description": "Terminate a pane and its process group.",
    "parameters": {
        "type": "object",
        "properties": {
            "pane_id": {"type": "string", "description": "Pane to kill"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["pane_id", "engagement_id"],
    },
}

PANE_LIST_SCHEMA = {
    "name": "pane_list",
    "description": "List all active panes with their status.",
    "parameters": {
        "type": "object",
        "properties": {
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["engagement_id"],
    },
}


async def handle_pane_spawn(ctx: ToolContext, name: str, command: str,
                            engagement_id: str,
                            workdir: str | None = None, **_: Any) -> dict:
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    pkg = ctx.config.packages[engagement.package]
    if not pkg.process_enabled:
        return {"error": "process panes disabled for this engagement"}
    allowed, reason = ctx.gate.check_shell(command, engagement)
    if not allowed:
        return {"error": reason}
    if workdir:
        allowed, reason = ctx.gate.check_path(workdir, engagement)
        if not allowed:
            return {"error": reason}
    elif engagement.is_path_target:
        workdir = engagement.target
    try:
        cmd = shlex.split(command)
    except ValueError as e:
        return {"error": f"invalid command: {e}"}
    if not cmd:
        return {"error": "empty command"}
    name = " ".join(str(name or "").split())[:80] or "Process pane"
    try:
        pane = await ctx.process_mgr.spawn(name, cmd, workdir=workdir,
                                           engagement_id=engagement_id)
        return {"id": pane.id, "name": pane.name, "status": "running"}
    except ValueError as e:
        return {"error": str(e)}
    except OSError as e:
        return {"error": f"spawn failed: {e}"}


async def handle_pane_write(ctx: ToolContext, pane_id: str, data: str,
                            engagement_id: str, reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    try:
        pane = ctx.process_mgr.get(pane_id)
        if pane is None or pane.engagement_id != engagement_id:
            return {"error": "pane is not owned by this engagement"}
        await ctx.process_mgr.write(pane_id, data)
        return {"success": True, "bytes_written": len(data.encode())}
    except (KeyError, ValueError) as e:
        return {"error": str(e)}


async def handle_pane_read(ctx: ToolContext, pane_id: str,
                           engagement_id: str,
                           timeout: float = 5.0, **_: Any) -> dict:
    try:
        pane = ctx.process_mgr.get(pane_id)
        if pane is None or pane.engagement_id != engagement_id:
            return {"error": "pane is not owned by this engagement"}
        output = await ctx.process_mgr.read(pane_id, timeout=min(timeout, 30.0))
        return {"id": pane_id, "output": output}
    except KeyError as e:
        return {"error": str(e)}


async def handle_pane_kill(ctx: ToolContext, pane_id: str,
                           engagement_id: str, **_: Any) -> dict:
    try:
        pane = ctx.process_mgr.get(pane_id)
        if pane is None or pane.engagement_id != engagement_id:
            return {"error": "pane is not owned by this engagement"}
        pane = await ctx.process_mgr.kill(pane_id)
        return {"success": True, "id": pane_id, "exit_code": pane.exit_code}
    except KeyError as e:
        return {"error": str(e)}


async def handle_pane_list(ctx: ToolContext, engagement_id: str,
                           **_: Any) -> dict:
    return {"panes": [p for p in ctx.process_mgr.list()
                      if p["engagement_id"] == engagement_id]}
