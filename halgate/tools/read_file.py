"""read_file tool: read a file or directory listing."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .context import ToolContext

MAX_FILE_READ = 512 * 1024  # 512 KB per read
MAX_LINE_LIMIT = 2_000

READ_FILE_SCHEMA = {
    "name": "read_file",
    "description": "Read a text file or list a directory within the active "
                   "engagement's allowed filesystem scope. Relative paths are "
                   "resolved inside its private scratch directory. For files, "
                   "returns content (truncated at 512KB); directories return up "
                   "to 200 entries.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string",
                     "description": "File or directory path; relative paths are relative to the engagement scratch directory, and absolute paths must be in engagement scope"},
            "offset": {"type": "integer",
                       "description": "Line offset (1-indexed) for large files"},
            "limit": {"type": "integer",
                      "description": "Max lines to return (default and maximum 2000)"},
            "engagement_id": {"type": "string",
                              "description": "Engagement that authorizes access"},
        },
        "required": ["path", "engagement_id"],
    },
}


async def handle_read_file(ctx: ToolContext, path: str,
                           engagement_id: str,
                           offset: int = 1, limit: int = 2000,
                           **_: Any) -> dict:
    try:
        if isinstance(offset, bool) or isinstance(limit, bool):
            raise ValueError
        offset = int(offset)
        limit = int(limit)
        if offset < 1 or not 1 <= limit <= MAX_LINE_LIMIT:
            raise ValueError
    except (TypeError, ValueError):
        return {"error": f"offset must be at least 1 and limit must be 1-{MAX_LINE_LIMIT}"}
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    p = Path(path)
    if not p.is_absolute():
        if not engagement.scratch_dir:
            return {"error": "read_file requires an engagement scratch directory for relative paths"}
        p = Path(engagement.scratch_dir) / p
    allowed, reason = ctx.gate.check_path(str(p), engagement)
    if not allowed:
        return {"error": reason}
    if p.is_dir():
        try:
            entries = sorted(p.iterdir(), key=lambda e: e.name)
            listing = []
            for e in entries[:200]:
                entry = {"name": e.name}
                if e.is_dir():
                    entry["type"] = "dir"
                else:
                    entry["type"] = "file"
                    entry["size"] = e.stat().st_size
                listing.append(entry)
            return {"path": str(p), "type": "directory",
                    "entries": listing, "count": len(listing)}
        except PermissionError:
            return {"error": f"permission denied: {path}"}
        except OSError as e:
            return {"error": f"cannot list directory: {e}"}
    if not p.exists():
        return {"error": f"file not found: {path}"}
    if not p.is_file():
        return {"error": f"not a regular file: {path}"}
    try:
        with p.open("rb") as source:
            raw = source.read(MAX_FILE_READ + 1)
        size = p.stat().st_size
    except PermissionError:
        return {"error": f"permission denied: {path}"}
    except OSError as e:
        return {"error": str(e)}
    truncated = len(raw) > MAX_FILE_READ
    if truncated:
        raw = raw[:MAX_FILE_READ]
    text = raw.decode(errors="replace")
    all_lines = text.splitlines()
    total_lines = len(all_lines)
    selected = all_lines[offset - 1:offset - 1 + limit]
    return {
        "path": str(p),
        "type": "file",
        "content": "\n".join(selected),
        "total_lines": total_lines,
        "truncated": truncated or (offset - 1 + len(selected) < total_lines),
        "size": size,
    }
