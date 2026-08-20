"""Sharded JSONL memory store.

Invariants:
- append-only lines; each instance writes only its own shard
- reads union all shards (cross-instance sharing)
- deletion is by time-scoped tombstones, never by rewriting other shards
- "edit-as-replace": new entry + tombstone of the old id
- content-hash ids (SHA-1 of text, namespaced by subject)
- pinned facts are immortal (consolidation re-injects them)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..config import MemoryConfig

try:
    import fcntl
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - non-POSIX
    _HAVE_FCNTL = False

_VALID_CATEGORIES = {
    "vulnerability", "target_arch", "credential", "mitigation", "scope",
    "tool_note", "insight", "session",
}
_VALID_SUBJECTS = {"target", "self"}
_VALID_SOURCES = {"stated", "scanned", "inferred", "reflected"}
_STOPWORDS = frozenset(
    "a an the and or of on in to is are was were be for with at by it this "
    "that as from".split())


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class MemoryStore:
    def __init__(self, cfg: MemoryConfig, instance_id: str):
        self._dir = Path(cfg.dir)
        self._cfg = cfg
        self._instance = instance_id
        os.makedirs(self._dir, exist_ok=True)

    # -- path helpers ------------------------------------------------------

    def _shard(self, base: str) -> Path:
        return self._dir / f"{base}.{self._instance}.jsonl"

    def _shard_glob(self, base: str) -> list[Path]:
        return sorted(
            p for p in self._dir.glob(f"{base}.*.jsonl")
            if ".bak." not in p.name and p.name != f"{base}.bak.jsonl"
        )

    @contextmanager
    def _locked(self, base: str):
        if not _HAVE_FCNTL:
            yield
            return
        lock_path = self._dir / f".{base}.lock"
        with lock_path.open("a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    # -- raw IO ------------------------------------------------------------

    def _read_lines(self, base: str) -> list[dict]:
        out: list[dict] = []
        for path in self._shard_glob(base):
            try:
                with path.open() as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            out.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
        return out

    def _append(self, base: str, obj: dict) -> None:
        path = self._shard(base)
        with path.open("a") as f:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")

    def _rewrite(self, base: str, objs: list[dict]) -> None:
        with self._locked(base):
            path = self._shard(base)
            with path.open("w") as f:
                for o in objs:
                    f.write(json.dumps(o, separators=(",", ":")) + "\n")

    # -- reads --------------------------------------------------------------

    def _read_tombstones(self) -> dict[str, str]:
        """id -> latest tombstone timestamp, across all shards."""
        latest: dict[str, str] = {}
        for obj in self._read_lines("tombstones"):
            mid = obj.get("id")
            ts = obj.get("ts", "")
            if mid and ts >= latest.get(mid, ""):
                latest[mid] = ts
        return latest

    def read_long_term(self) -> list[dict]:
        """Union of all long_term shards minus tombstones, deduped by id,
        near-dups collapsed, sorted ts ascending."""
        tombstones = self._read_tombstones()
        live: dict[str, dict] = {}
        for obj in self._read_lines("long_term"):
            mid, ts = obj.get("id"), obj.get("ts", "")
            if not mid:
                continue
            if tombstones.get(mid, "") and ts <= tombstones[mid]:
                continue  # time-scoped suppression
            prev = live.get(mid)
            if prev is None or ts >= prev.get("ts", ""):
                live[mid] = dict(obj)
        # collapse near-duplicates (same subject, high similarity): keep
        # pinned > higher confidence > longer text > later ts.
        entries = list(live.values())
        kept: list[dict] = []
        for e in entries:
            for k in kept:
                if e.get("subject") == k.get("subject") \
                        and self._text_similarity(e.get("text", ""),
                                                  k.get("text", "")) \
                        >= self._cfg.dup_similarity:
                    if self._rank(e) >= self._rank(k):
                        kept[kept.index(k)] = e
                    break
            else:
                kept.append(e)
        kept.sort(key=lambda e: e.get("ts", ""))
        return kept

    @staticmethod
    def _rank(e: dict) -> tuple:
        return (bool(e.get("pinned")), e.get("confidence", 0),
                len(e.get("text", "")), e.get("ts", ""))

    def read_short_term(self) -> list[dict]:
        tombstones = self._read_tombstones()
        out = []
        for obj in self._read_lines("short_term"):
            mid = obj.get("id")
            if mid and tombstones.get(mid, "") and \
                    obj.get("ts", "") <= tombstones[mid]:
                continue
            out.append(obj)
        return out

    # -- internals ----------------------------------------------------------

    def _mem_id(self, text: str, subject: str = "target") -> str:
        key = text if subject == "target" else f"[{subject}] {text}"
        return hashlib.sha1(key.encode()).hexdigest()[:8]

    def resolve_confidence(self, claimed: float | None, source: str) -> float:
        def clamp(v: float, cap: float) -> float:
            return min(cap, max(0.0, v)) if v is not None else 0.5
        if source == "stated":
            return max(0.9, clamp(claimed, 1.0))
        if source == "scanned":
            return min(0.7, clamp(claimed, 0.5))
        if source in ("inferred", "reflected"):
            return min(0.6, clamp(claimed, 0.5))
        return clamp(claimed, 0.5)

    def _text_tokens(self, text: str) -> set[str]:
        return {t for t in re.findall(r"[a-z0-9_]+", text.lower())
                if t not in _STOPWORDS and len(t) > 1}

    def _text_similarity(self, a: str, b: str) -> float:
        """Jaccard overlap of content-word tokens. 0.0 if either <2 words."""
        ta, tb = self._text_tokens(a), self._text_tokens(b)
        if len(ta) < 2 or len(tb) < 2:
            return 0.0
        return len(ta & tb) / len(ta | tb)

    def _add_tombstone(self, ids: set[str]) -> None:
        ts = _now_iso()
        for mid in sorted(ids):
            self._append("tombstones", {"id": mid, "ts": ts})

    def _remove_tombstone(self, ids: set[str]) -> None:
        """Lift (rewrite only this instance's shard) tombstones for ids."""
        objs = [o for o in self._read_lines("tombstones")
                if o.get("id") not in ids]
        if objs:
            self._rewrite("tombstones", objs)
        else:
            self._rewrite("tombstones", [])

    # -- operations ----------------------------------------------------------

    def remember(self, text: str, category: str | None = None,
                 confidence: float | None = None, source: str = "inferred",
                 subject: str = "target") -> dict:
        text = (text or "").strip()
        if not text:
            return {"success": False, "error": "empty text"}
        if category is None:
            category = "insight" if source == "inferred" else "target_arch"
        if category not in _VALID_CATEGORIES:
            return {"success": False, "error": f"invalid category: {category}"}
        if subject not in _VALID_SUBJECTS:
            return {"success": False, "error": f"invalid subject: {subject}"}
        if source not in _VALID_SOURCES:
            return {"success": False, "error": f"invalid source: {source}"}
        mem_id = self._mem_id(text, subject)

        existing = self.read_long_term()
        # exact duplicate (same text+subject) — but a stated correction of a
        # weaker prior supersedes.
        for e in existing:
            if e.get("id") == mem_id:
                if source == "stated" and e.get("source") in ("inferred",
                                                              "scanned",
                                                              "reflected"):
                    break  # supersede below
                return {"success": False,
                        "error": "duplicate memory", "id": mem_id}
        # near-duplicate suppression
        superseded: list[dict] = []
        for e in existing:
            if e.get("subject") != subject:
                continue
            if self._text_similarity(e.get("text", ""), text) \
                    >= self._cfg.dup_similarity:
                if source == "stated":
                    superseded.append(e)
                else:
                    return {"success": False,
                            "error": "near-duplicate memory",
                            "id": e.get("id")}
        # entry count cap (superseding corrections are exempt)
        if not superseded and len(existing) >= self._cfg.max_entries:
            return {"success": False,
                    "error": f"memory at capacity ({self._cfg.max_entries})"}
        # inferred daily cap
        if source == "inferred":
            today = _now_iso()[:10]
            inferred_today = sum(1 for e in existing
                                 if e.get("source") == "inferred"
                                 and e.get("ts", "")[:10] == today)
            if inferred_today >= self._cfg.inferred_daily_cap:
                return {"success": False,
                        "error": f"inferred daily cap reached "
                                 f"({self._cfg.inferred_daily_cap})"}
        if category == "insight" and source in ("inferred", "reflected"):
            supersede_ids = {e.get("id") for e in superseded}
            insight_count = sum(1 for e in existing
                                if e.get("category") == "insight"
                                and e.get("id") not in supersede_ids)
            if insight_count >= 3:
                return {"success": False,
                        "error": "insight category capped at 3"}
        confidence = self.resolve_confidence(confidence, source)
        entry = {
            "id": mem_id,
            "ts": _now_iso(),
            "first_seen": _now_iso(),
            "last_confirmed": None,
            "category": category,
            "subject": subject,
            "text": text[: self._cfg.max_text_chars],
            "confidence": confidence,
            "source": source,
            "importance": 5,
            "pinned": bool(source == "stated" and category == "scope"),
            "related_ids": [e.get("id") for e in superseded],
        }
        if superseded:
            self._add_tombstone({e["id"] for e in superseded})
        self._append("long_term", entry)
        return {"success": True, "id": mem_id}

    def recall(self, query: str = "", subject: str | None = None) -> dict:
        entries = self.read_long_term()
        if subject:
            entries = [e for e in entries if e.get("subject") == subject]

        def score(e: dict) -> float:
            if not query:
                return 1.0
            qt = self._text_tokens(query)
            if not qt:
                return 1.0
            et = self._text_tokens(e.get("text", ""))
            if not et:
                return 0.0
            return len(qt & et) / len(qt | et)

        ranked = sorted(
            entries,
            key=lambda e: (bool(e.get("pinned")), score(e),
                           e.get("confidence", 0)),
            reverse=True,
        )
        top = ranked[: self._cfg.recall_limit]
        # bump last_confirmed for returned matches (append-only updates)
        for e in top:
            self._append("long_term", {
                **e, "last_confirmed": _now_iso(),
            })
        return {"success": True, "count": len(top),
                "memories": top}

    def forget(self, mem_id: str) -> dict:
        found = any(e.get("id") == mem_id for e in self.read_long_term())
        if not found:
            return {"success": False, "error": f"no memory with id {mem_id}"}
        self._add_tombstone({mem_id})
        return {"success": True, "id": mem_id}

    def edit(self, mem_id: str, new_text: str) -> dict:
        new_text = (new_text or "").strip()
        if not new_text:
            return {"success": False, "error": "empty text"}
        entries = self.read_long_term()
        old = next((e for e in entries if e.get("id") == mem_id), None)
        if old is None:
            return {"success": False, "error": f"no memory with id {mem_id}"}
        subject = old.get("subject", "target")
        new_id = self._mem_id(new_text, subject)
        if new_id == mem_id:
            return {"success": True, "id": mem_id, "previous_id": mem_id,
                    "changed": False}
        if any(e.get("id") == new_id for e in entries):
            return {"success": False,
                    "error": "collision: new text already exists "
                             f"(id {new_id})"}
        new_entry = {
            "id": new_id,
            "ts": _now_iso(),
            "first_seen": old.get("first_seen", _now_iso()),
            "last_confirmed": None,
            "category": old.get("category"),
            "subject": subject,
            "text": new_text[: self._cfg.max_text_chars],
            "confidence": old.get("confidence", 0.5),
            "source": old.get("source", "inferred"),
            "importance": old.get("importance", 5),
            "pinned": bool(old.get("pinned")),
            "related_ids": [mem_id],
        }
        self._append("long_term", new_entry)
        self._add_tombstone({mem_id})
        return {"success": True, "id": new_id, "previous_id": mem_id,
                "changed": True}

    def pin(self, mem_id: str, pinned: bool) -> dict:
        entries = self.read_long_term()
        old = next((e for e in entries if e.get("id") == mem_id), None)
        if old is None:
            return {"success": False, "error": f"no memory with id {mem_id}"}
        if bool(old.get("pinned")) == bool(pinned):
            return {"success": True, "id": mem_id, "pinned": bool(pinned),
                    "changed": False}
        self._append("long_term", {**old, "pinned": bool(pinned),
                                    "ts": _now_iso()})
        return {"success": True, "id": mem_id, "pinned": bool(pinned),
                "changed": True}

    def count(self) -> int:
        return len(self.read_long_term())

    def trim_short_term(self, keep: int | None = None) -> None:
        keep = keep or self._cfg.short_term_keep
        entries = self.read_short_term()
        if len(entries) <= keep:
            return
        # rewriting is only safe on THIS instance's shard; union trim is
        # approximated by rewriting our shard to its last `keep` entries.
        mine = [o for o in self._read_lines("short_term")]
        self._rewrite("short_term", mine[-keep:] if keep > 0 else [])
