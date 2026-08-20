"""glob tool: find files by glob pattern."""
from __future__ import annotations

import glob as _globmod
from typing import Any

from .context import ToolContext

GLOB_SCHEMA = {
    "name": "glob",
    "description": "Find files matching a glob pattern (e.g. '**/*.py'). "
                   "Returns up to 200 matching paths.",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string",
                        "description": "Glob pattern to match"},
            "path": {"type": "string",
                     "description": "Base directory (default: the engagement scratch directory)"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing access"},
        },
        "required": ["pattern", "engagement_id"],
    },
}


async def handle_glob(ctx: ToolContext, pattern: str, engagement_id: str,
                      path: str | None = None, **_: Any) -> dict:
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    base = path or engagement.scratch_dir
    if not base:
        return {"error": "glob requires a path or an engagement scratch directory"}
    full_pattern = f"{base.rstrip('/')}/{pattern}" if base != "/" else pattern
    try:
        matches: list[str] = []
        truncated = False
        for match in _globmod.iglob(full_pattern, recursive=True):
            matches.append(match)
            if len(matches) > 200:
                matches.pop()
                truncated = True
                break
    except OSError as e:
        return {"error": f"glob failed: {e}"}
    matches.sort()
    return {"files": matches, "count": len(matches),
            "truncated": truncated}
