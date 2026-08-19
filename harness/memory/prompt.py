"""Ranked, token-budgeted memory block for the system prompt."""
from __future__ import annotations

import math
from datetime import datetime

from .store import MemoryStore

_CATEGORY_LABELS = {
    "vulnerability": "VULN",
    "target_arch": "TARGET_ARCH",
    "credential": "CRED",
    "mitigation": "MITIGATION",
    "scope": "SCOPE",
    "tool_note": "TOOL_NOTE",
    "insight": "INSIGHT",
    "session": "SESSION",
}


def _age_days(ts: str) -> float:
    if not ts:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return max(0.0, (datetime.now().astimezone() - dt).total_seconds()
                   / 86400.0)
    except ValueError:
        return 0.0


def rank_memories(store: MemoryStore, query: str = "",
                  subject: str | None = None) -> list[tuple[float, dict]]:
    entries = store.read_long_term()
    if subject:
        entries = [e for e in entries if e.get("subject") == subject]
    q_tokens = store._text_tokens(query) if query else set()

    def score(e: dict) -> float:
        conf = float(e.get("confidence", 0))
        if conf < 0.3:
            return -1.0  # excluded
        s = 0.0
        if q_tokens:
            et = store._text_tokens(e.get("text", ""))
            if et:
                s += len(q_tokens & et) / len(q_tokens | et) * 10
        s += float(e.get("importance", 5)) / 10
        s += conf
        half = max(0.01, store._cfg.recency_halflife_days)
        s += 0.5 ** (_age_days(e.get("ts", "")) / half)
        if e.get("pinned"):
            s += 1000.0
        return s

    ranked = sorted(((score(e), e) for e in entries),
                    key=lambda p: p[0], reverse=True)
    return [(s, e) for s, e in ranked if s >= 0.0]


def build_memory_block(store: MemoryStore, query: str = "",
                       subject: str | None = None) -> str:
    """Compact block embedded in the system prompt (token-budgeted).

    Pinned entries are always included regardless of budget.
    """
    budget_chars = store._cfg.prompt_budget_tokens * 4
    ranked = rank_memories(store, query, subject)
    pinned = [e for _, e in ranked if e.get("pinned")]
    rest = [e for _, e in ranked if not e.get("pinned")]

    def line(e: dict) -> str:
        parts = []
        if e.get("pinned"):
            parts.append("[PIN]")
        if 0.3 <= float(e.get("confidence", 0)) < 0.5:
            parts.append("[tentative]")
        label = _CATEGORY_LABELS.get(e.get("category", ""),
                                     str(e.get("category", "")).upper())
        parts.append(f"[{label}]")
        return " ".join(parts) + " " + e.get("text", "").strip()

    total = len(ranked)
    out_lines: list[str] = []
    used = 0
    chosen: list[dict] = []
    for e in pinned:
        out_lines.append(line(e))
        used += len(line(e))
        chosen.append(e)
    for e in rest:
        l = line(e)
        if used + len(l) > budget_chars:
            break
        out_lines.append(l)
        used += len(l)
        chosen.append(e)
    if not out_lines and total == 0:
        return ""
    header = (f"[MEMORY: {len(chosen)} of {total} facts shown "
              f"({len(pinned)} pinned)]")
    return header + "\n" + "\n".join(out_lines)
