"""shell tool: execute a guarded shell command."""
from __future__ import annotations

from typing import Any

from ..guardrails.shell_guard import ShellGuard
from .context import ToolContext

_DIRECT_EXECUTION_HELP = (
    "The command is parsed into an argv list and executed directly; it is not "
    "run by a shell. Quotes group literal arguments. Do not use pipes, output "
    "redirection, variable expansion, glob expansion, command substitution, or "
    "compound commands (for example |, >, $, *, ;, &&, or ||)."
)


SHELL_SCHEMA = {
    "name": "shell",
    "description": "Execute one guarded program invocation with direct argv "
                   "execution. " + _DIRECT_EXECUTION_HELP + " Output is "
                   "truncated to the configured limit. Use structured tools "
                   "when available.",
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string",
                        "description": "One program invocation, written like "
                                       "`nmap -sV 192.0.2.10`; quotes are allowed "
                                       "only to group literal arguments. "
                                       + _DIRECT_EXECUTION_HELP},
            "timeout": {"type": "integer",
                        "description": "Optional timeout in seconds"},
            "reason": {"type": "string",
                       "description": "Concise reason this command is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing the command"},
        },
        "required": ["command", "reason", "engagement_id"],
    },
}


async def handle_shell(ctx: ToolContext, command: str, engagement_id: str,
                       timeout: int | None = None, reason: str = "",
                       **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    gate = ctx.gate
    try:
        engagement = gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    pkg = ctx.config.packages[engagement.package]
    workdir = engagement.scratch_dir or ctx.config.shell.workdir
    live = ctx.extra.get("live_output_callback")
    guard = ShellGuard(pkg.shell_allowlist, pkg.guardrails.shell_timeout,
                       pkg.guardrails.shell_max_output,
                       workdir,
                       on_output=(lambda stream, text: live("shell", stream, text))
                       if callable(live) else None)
    allowed, reason = guard.check(command)
    if not allowed:
        return {"error": reason}
    result = await guard.execute(command, timeout=timeout)
    out = {
        "rc": result.rc,
        "argv": guard.parse(command),
        "stdout": result.stdout.decode(errors="replace"),
        "stderr": result.stderr.decode(errors="replace"),
        "truncated": result.truncated,
    }
    if result.timed_out:
        out["timed_out"] = True
    return out
