"""Read application source code from an engagement's private scratch folder."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..scope import path_within
from .context import ToolContext

MAX_SOURCE_BYTES = 2 * 1024 * 1024
DEFAULT_LINE_LIMIT = 400
MAX_LINE_LIMIT = 2_000

_LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cs": "csharp",
    ".css": "css", ".go": "go", ".h": "c", ".hpp": "cpp",
    ".html": "html", ".java": "java", ".js": "javascript",
    ".json": "json", ".jsx": "javascript", ".kt": "kotlin",
    ".md": "markdown", ".php": "php", ".py": "python",
    ".rb": "ruby", ".rs": "rust", ".sh": "shell", ".sql": "sql",
    ".swift": "swift", ".toml": "toml", ".ts": "typescript",
    ".tsx": "typescript", ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
}

READ_SOURCE_CODE_SCHEMA = {
    "name": "read_source_code",
    "description": (
        "Read a text source file from this engagement's scratch folder. "
        "Use a path relative to the scratch folder when possible. Returns "
        "language metadata and a bounded, line-numbered source chunk; use "
        "offset and limit to inspect larger files."
    ),
    "parameters": {"type": "object", "properties": {
        "path": {"type": "string", "description": "Source-file path, relative to the engagement scratch folder or an absolute path within it"},
        "offset": {"type": "integer", "description": "First source line to return (1-indexed; default 1)"},
        "limit": {"type": "integer", "description": "Maximum lines to return (default 400; maximum 2000)"},
        "engagement_id": {"type": "string", "description": "Engagement that owns the scratch folder"},
    }, "required": ["path", "engagement_id"]},
}


def _source_path(scratch: Path, path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else scratch / candidate


async def handle_read_source_code(ctx: ToolContext, path: str,
                                  engagement_id: str, offset: int = 1,
                                  limit: int = DEFAULT_LINE_LIMIT,
                                  **_: Any) -> dict:
    """Return a bounded, line-numbered code chunk without leaving scratch."""
    try:
        engagement = ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    if not engagement.scratch_dir:
        return {"error": "read_source_code requires an engagement scratch directory"}

    scratch = Path(engagement.scratch_dir)
    source = _source_path(scratch, str(path))
    in_scratch, reason = path_within(str(scratch), str(source))
    if not in_scratch:
        return {"error": f"source path is outside this engagement's scratch directory: {reason}"}
    if not source.is_file():
        return {"error": f"source file not found: {path}"}
    try:
        size = source.stat().st_size
        if size > MAX_SOURCE_BYTES:
            return {"error": f"source file exceeds the {MAX_SOURCE_BYTES // (1024 * 1024)} MiB read limit"}
        raw = source.read_bytes()
    except (OSError, PermissionError) as e:
        return {"error": f"cannot read source file: {e}"}
    if b"\0" in raw:
        return {"error": "source file appears to be binary"}

    try:
        offset = max(1, int(offset))
        limit = min(MAX_LINE_LIMIT, max(1, int(limit)))
    except (TypeError, ValueError):
        return {"error": "offset and limit must be integers"}
    lines = raw.decode("utf-8", errors="replace").splitlines()
    start = offset - 1
    selected = lines[start:start + limit]
    numbered = "\n".join(
        f"{line_number:>6} | {line}"
        for line_number, line in enumerate(selected, start=offset))
    try:
        relative_path = str(source.resolve().relative_to(scratch.resolve()))
    except ValueError:  # path_within above prevents this; retain fail-closed output.
        return {"error": "source path escapes the engagement scratch directory"}
    return {
        "path": str(source),
        "relative_path": relative_path,
        "language": _LANGUAGES.get(source.suffix.lower(), "text"),
        "content": numbered,
        "line_start": offset,
        "line_end": offset + len(selected) - 1 if selected else offset - 1,
        "total_lines": len(lines),
        "truncated": start + len(selected) < len(lines),
        "size": size,
    }
