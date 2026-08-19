"""memory tools: remember, recall, forget, edit, pin, unpin (exposed to LLM)."""
from __future__ import annotations

from typing import Any

from .context import ToolContext

REMEMBER_SCHEMA = {
    "name": "memory_remember",
    "description": "Store a long-term fact in memory. Use for important "
                   "findings, target details, session context.",
    "parameters": {
        "type": "object",
        "properties": {
            "text": {"type": "string",
                     "description": "The fact to remember"},
            "category": {"type": "string",
                         "description": "vulnerability|target_arch|credential|"
                                        "mitigation|scope|tool_note|insight|session"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["text", "engagement_id"],
    },
}

RECALL_SCHEMA = {
    "name": "memory_recall",
    "description": "Search long-term memory for relevant facts.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string",
                      "description": "Search query (empty for all)"},
            "subject": {"type": "string",
                        "description": "Filter: target|self"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["engagement_id"],
    },
}

FORGET_SCHEMA = {
    "name": "memory_forget",
    "description": "Delete a memory entry by its id.",
    "parameters": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Memory id to delete"},
            "reason": {"type": "string", "description": "Why this deletion is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["id", "reason", "engagement_id"],
    },
}

EDIT_SCHEMA = {
    "name": "memory_edit",
    "description": "Edit a memory's text content.",
    "parameters": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Memory id to edit"},
            "text": {"type": "string", "description": "New text content"},
            "reason": {"type": "string", "description": "Why this edit is needed"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["id", "text", "reason", "engagement_id"],
    },
}

PIN_SCHEMA = {
    "name": "memory_pin",
    "description": "Pin a memory so it survives consolidation.",
    "parameters": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Memory id to pin"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["id", "engagement_id"],
    },
}

UNPIN_SCHEMA = {
    "name": "memory_unpin",
    "description": "Unpin a memory.",
    "parameters": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Memory id to unpin"},
            "engagement_id": {"type": "string",
                              "description": "Engagement binding"},
        },
        "required": ["id", "engagement_id"],
    },
}


async def handle_remember(ctx: ToolContext, text: str, engagement_id: str,
                          category: str | None = None, **_: Any) -> dict:
    # source is injected by dispatcher, never from LLM: "inferred" by default
    return ctx.memory.remember(text, category=category,
                               source="inferred", subject="target")


async def handle_recall(ctx: ToolContext, engagement_id: str,
                        query: str = "", subject: str | None = None,
                        **_: Any) -> dict:
    return ctx.memory.recall(query=query, subject=subject)


async def handle_forget(ctx: ToolContext, id: str, engagement_id: str,
                        reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    return ctx.memory.forget(id)


async def handle_edit(ctx: ToolContext, id: str, text: str,
                      engagement_id: str, reason: str = "", **_: Any) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "reason must be a non-empty string"}
    return ctx.memory.edit(id, text)


async def handle_pin(ctx: ToolContext, id: str, engagement_id: str,
                     **_: Any) -> dict:
    return ctx.memory.pin(id, True)


async def handle_unpin(ctx: ToolContext, id: str, engagement_id: str,
                       **_: Any) -> dict:
    return ctx.memory.pin(id, False)
