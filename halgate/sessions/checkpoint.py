"""Session checkpointing: save/load durable session state.

Directory: <sessions_dir>/<session_id>/
  meta.json          session metadata (config/scope hashes, llm, engagements)
  transcript.jsonl   full message history (already redacted by the harness)
  tool_state.json    active panes snapshot (to present for reapproval)
  audit_ref.json     audit log path + last seq for cross-reference

Checkpoints never contain plaintext secrets: message history is redacted
before it is ever appended, and meta stores hashes, not configs verbatim.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..scope import Engagement


@dataclass
class RestoredSession:
    session_id: str
    name: str
    messages: list[dict] = field(default_factory=list)
    panes: list[dict] = field(default_factory=list)
    engagements: list[Engagement] = field(default_factory=list)
    llm_id: str = ""
    resumed_from: str | None = None
    session_settings: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)


class SessionCheckpoint:
    def __init__(self, sessions_dir: str, session_id: str):
        self._dir = Path(sessions_dir) / session_id
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def dir(self) -> Path:
        return self._dir

    def save(self, session_id: str, name: str, messages: list[dict],
             panes: list[dict], engagements: list[Engagement], llm_id: str,
             resumed_from: str | None, created: str | None = None,
             audit_path: str | None = None, audit_seq: int = 0,
             extra_meta: dict | None = None,
             session_settings: dict | None = None) -> Path:
        meta = {
            "session_id": session_id,
            "name": name,
            "created": created or _now_iso(),
            "resumed_from": resumed_from,
            "llm_id": llm_id,
            "engagements": [
                {
                    "id": e.id, "label": e.label, "target": e.target,
                    "package": e.package,
                    "budget_overrides": e.budget_overrides,
                    "budgets_disabled": e.budgets_disabled,
                    "tool_overrides": e.tool_overrides,
                    "safety_overrides": e.safety_overrides,
                    "jwt_claim_extensions": list(e.jwt_claim_extensions),
                    "status": e.status, "created": e.created,
                }
                for e in engagements
            ],
            "turns": sum(1 for m in messages if m.get("role") == "assistant"),
            "hashes": {
                "engagements": hashlib.sha256(
                    json.dumps(sorted(
                        (e.package, e.target)
                        for e in engagements)).encode()).hexdigest(),
            },
            **(extra_meta or {}),
        }
        if session_settings is not None:
            meta["session_settings"] = session_settings
        meta_path = self._dir / "meta.json"
        existing = meta_path.read_text() if meta_path.exists() else None
        if existing:
            try:
                prev = json.loads(existing)
                meta["created"] = prev.get("created", meta["created"])
                meta["resumed_from"] = prev.get("resumed_from", resumed_from)
            except json.JSONDecodeError:
                pass
        meta_path.write_text(json.dumps(meta, indent=2))
        with (self._dir / "transcript.jsonl").open("w") as f:
            for m in messages:
                f.write(json.dumps(m, separators=(",", ":")) + "\n")
        (self._dir / "tool_state.json").write_text(
            json.dumps({"panes": panes}, indent=2))
        (self._dir / "audit_ref.json").write_text(json.dumps(
            {"path": audit_path, "last_seq": audit_seq,
             "updated": _now_iso()}, indent=2))
        return self._dir

    @classmethod
    def load(cls, sessions_dir: str, session_id: str) -> RestoredSession:
        d = Path(sessions_dir) / session_id
        if not d.exists():
            raise FileNotFoundError(f"no checkpoint for session {session_id}")
        meta = json.loads((d / "meta.json").read_text())
        messages: list[dict] = []
        transcript = d / "transcript.jsonl"
        if transcript.exists():
            with transcript.open() as f:
                for line in f:
                    line = line.strip()
                    if line:
                        messages.append(json.loads(line))
        tool_state = d / "tool_state.json"
        panes = []
        if tool_state.exists():
            panes = (json.loads(tool_state.read_text()).get("panes") or [])
        engagements = [
            Engagement(
                id=s["id"], label=s["label"], target=s["target"],
                package=s["package"],
                budget_overrides=s.get("budget_overrides", {}),
                budgets_disabled=bool(s.get("budgets_disabled", False)),
                tool_overrides=s.get("tool_overrides", {}),
                safety_overrides=s.get("safety_overrides", {}),
                status=s.get("status", "active"), created=s.get("created", ""),
                jwt_claim_extensions=tuple(s.get("jwt_claim_extensions", [])),
            )
            for s in meta.get("engagements", [])
        ]
        return RestoredSession(
            session_id=session_id,
            name=meta.get("name", session_id),
            messages=messages,
            panes=panes,
            engagements=engagements,
            llm_id=meta.get("llm_id", ""),
            resumed_from=meta.get("resumed_from"),
            session_settings=meta.get("session_settings", {}),
            meta=meta,
        )

    @classmethod
    def list_sessions(cls, sessions_dir: str) -> list[dict]:
        base = Path(sessions_dir)
        if not base.exists():
            return []
        seen: set[str] = set()
        out: list[dict] = []
        for d in base.iterdir():
            meta_path = d / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except json.JSONDecodeError:
                continue
            sid = meta.get("session_id", d.name)
            if sid in seen:
                continue
            seen.add(sid)
            engs = meta.get("engagements", [])
            out.append({
                "id": sid,
                "name": meta.get("name", d.name),
                "created": meta.get("created", ""),
                "turns": meta.get("turns", 0),
                "llm_id": meta.get("llm_id", ""),
                "engagements": [
                    f"{e.get('label', '?')} ({e.get('target', '?')}, "
                    f"{e.get('package', '?')})"
                    for e in engs
                ],
            })
        out.sort(key=lambda r: (r["created"], r["id"]), reverse=True)
        return out

    @classmethod
    def latest(cls, sessions_dir: str) -> str | None:
        sessions = cls.list_sessions(sessions_dir)
        return sessions[0]["id"] if sessions else None

    @classmethod
    def delete(cls, sessions_dir: str, session_id: str) -> bool:
        """Remove a session directory. Returns True if found and deleted."""
        import shutil
        base = Path(sessions_dir)
        for d in base.iterdir():
            meta_path = d / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except json.JSONDecodeError:
                continue
            if meta.get("session_id") == session_id or d.name == session_id:
                shutil.rmtree(d)
                return True
        return False


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")
