"""glob tool: find files by glob pattern."""
from __future__ import annotations

import glob as _globmod
from pathlib import Path
from typing import Any

from .context import ToolContext

GLOB_SCHEMA = {
    "name": "glob",
    "description": "Find files within the active engagement's allowed "
                   "filesystem scope using a glob pattern (e.g. '**/*.py'). "
                   "The base defaults to its private scratch directory; a "
                   "relative base is resolved there. Returns up to 200 paths.",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string",
                        "description": "Glob pattern to match"},
            "path": {"type": "string",
                     "description": "Optional base directory; defaults to the engagement scratch directory, and relative paths are resolved there"},
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
    base_path = Path(base)
    if not base_path.is_absolute():
        if not engagement.scratch_dir:
            return {"error": "glob requires an engagement scratch directory for relative paths"}
        base_path = Path(engagement.scratch_dir) / base_path
    allowed, reason = ctx.gate.check_path(str(base_path), engagement)
    if not allowed:
        return {"error": reason}
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        return {"error": "glob pattern must stay below its base directory"}
    full_pattern = str(base_path / pattern)
    try:
        matches: list[str] = []
        truncated = False
        for match in _globmod.iglob(full_pattern, recursive=True):
            allowed, _ = ctx.gate.check_path(match, engagement)
            if not allowed:
                continue
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
