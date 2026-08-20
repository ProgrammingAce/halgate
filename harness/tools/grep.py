"""grep tool: search file contents by regex."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .context import ToolContext

MAX_MATCHES = 100
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB per file
MAX_FILES_SCANNED = 1_000

GREP_SCHEMA = {
    "name": "grep",
    "description": "Search file contents using a regular expression. "
                   "Returns up to 100 matching lines with file and line number; "
                   "files of 5 MiB or more are skipped.",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string",
                        "description": "Regex pattern to search for"},
            "path": {"type": "string",
                     "description": "File or directory to search in"},
            "include": {"type": "string",
                        "description": "Glob filter for filenames (e.g. '*.py')"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing access"},
        },
        "required": ["pattern", "path", "engagement_id"],
    },
}


async def handle_grep(ctx: ToolContext, pattern: str, path: str,
                       engagement_id: str, include: str | None = None,
                      **_: Any) -> dict:
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return {"error": f"invalid regex: {e}"}

    p = Path(path)
    if p.is_file():
        candidates = iter((p,))
    elif p.is_dir():
        candidates = p.rglob(include) if include else p.rglob("*")
    else:
        return {"error": f"path not found: {path}"}

    matches: list[dict] = []
    files_scanned = 0
    truncated = False
    for f in candidates:
        if len(matches) >= MAX_MATCHES:
            truncated = True
            break
        try:
            if not f.is_file() or f.stat().st_size >= MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        if files_scanned >= MAX_FILES_SCANNED:
            truncated = True
            break
        files_scanned += 1
        try:
            text = f.read_text(errors="replace")
        except (OSError, PermissionError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                matches.append({"file": str(f), "line": i,
                                "text": line.strip()[:200]})
                if len(matches) >= MAX_MATCHES:
                    break
    return {"matches": matches, "count": len(matches),
            "truncated": truncated, "files_scanned": files_scanned}
