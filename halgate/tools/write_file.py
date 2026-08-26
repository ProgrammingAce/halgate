"""write_file tool: write content to a file (creates parent dirs)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .context import ToolContext

WRITE_FILE_SCHEMA = {
    "name": "write_file",
    "description": "Write content to an engagement-authorized file. Relative paths are resolved inside the engagement's private scratch directory. Creates parent directories if needed and overwrites existing files; requires operator approval.",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Destination file path"},
            "content": {"type": "string",
                        "description": "Content to write"},
            "reason": {"type": "string", "description": "Why this write is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement authorizing the write"},
        },
        "required": ["path", "content", "reason", "engagement_id"],
    },
}


async def handle_write_file(ctx: ToolContext, path: str, content: str,
                            engagement_id: str, reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return {"success": True, "path": str(p), "bytes": len(content.encode())}
    except PermissionError:
        return {"error": f"permission denied: {path}"}
    except OSError as e:
        return {"error": f"write failed: {e}"}
