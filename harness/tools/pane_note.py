"""Store operator-requested notes in the TUI's right-hand panel."""
from __future__ import annotations

from typing import Any

from .context import ToolContext

PANE_NOTE_SCHEMA = {
    "name": "pane_note",
    "description": "Create or update a named read-only note in the right panel. "
                    "Body is rendered as Markdown; whitespace-aligned plain-text "
                    "tables are kept verbatim (align columns with spaces so they "
                    "stay aligned). Use for compact tables, findings, or summaries.",
    "parameters": {"type": "object", "properties": {
        "name": {"type": "string", "description": "Short panel title"},
        "content": {"type": "string",
                    "description": "Note body: Markdown text, or a plain-text "
                                   "table with columns aligned by spaces"},
        "engagement_id": {"type": "string", "description": "Engagement owning this note"},
    }, "required": ["name", "content", "engagement_id"]},
}


async def handle_pane_note(ctx: ToolContext, name: str, content: str,
                           engagement_id: str, **_: Any) -> dict:
    try:
        ctx.gate._require_active(engagement_id)
    except Exception as e:
        return {"error": str(e)}
    callback = ctx.extra.get("pane_note_callback")
    if not callable(callback):
        return {"error": "right-panel notes require the TUI"}
    title = " ".join(name.split())[:80]
    body = content.strip()[:20_000]
    if not title or not body:
        return {"error": "note name and content are required"}
    callback(title, body, engagement_id)
    return {"saved": True, "name": title, "chars": len(body)}
