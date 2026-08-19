"""Content-addressed evidence artifacts and provenance records."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import EvidenceConfig


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class EvidenceStore:
    """Writes content-addressed artifacts under <evidence_dir>/<session>/<sha256>."""

    def __init__(self, cfg: EvidenceConfig, session_id: str):
        self._root = Path(cfg.dir) / session_id
        self._root.mkdir(parents=True, exist_ok=True)
        self._meta_path = self._root / "metadata.jsonl"
        self._cfg = cfg
        self._session = session_id

    def store(self, content: bytes, source_tool: str, source_event: str,
              engagement_id: str | None = None,
              mime_type: str | None = None,
              encrypted: bool = False,
              args: dict | None = None) -> str:
        """Store content-addressed artifact. Returns artifact sha256 hash."""
        digest = hashlib.sha256(content).hexdigest()
        artifact_path = self._root / digest
        if not artifact_path.exists():
            if len(content) > self._cfg.max_artifact_bytes:
                raise ValueError(
                    f"artifact too large: {len(content)} > "
                    f"{self._cfg.max_artifact_bytes}")
            with artifact_path.open("wb") as f:
                f.write(content)
        meta = {
            "artifact": digest,
            "ts": _now_iso(),
            "session": self._session,
            "engagement_id": engagement_id,
            "source_tool": source_tool,
            "source_event": source_event,
            "mime_type": mime_type or "application/octet-stream",
            "bytes": len(content),
            "encrypted": encrypted,
            "args": args or {},
        }
        with self._meta_path.open("a") as f:
            f.write(json.dumps(meta, separators=(",", ":")) + "\n")
        return digest

    def read(self, digest: str) -> bytes | None:
        p = self._root / digest
        if p.exists():
            return p.read_bytes()
        return None

    def metadata(self, digest: str | None = None) -> list[dict]:
        records: list[dict] = []
        if not self._meta_path.exists():
            return records
        with self._meta_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if digest is None or obj.get("artifact") == digest:
                    records.append(obj)
        return records

    def show(self, digest: str) -> dict:
        """Return provenance + content for an artifact."""
        metas = self.metadata(digest)
        if not metas:
            return {"error": f"no evidence for {digest}"}
        meta = metas[-1]
        content = self.read(digest)
        result: dict = {**meta}
        if content is not None:
            result["content_preview"] = content[:4096].decode(errors="replace")
            result["encrypted"] = meta.get("encrypted", False)
            if meta.get("encrypted"):
                result["content_preview"] = "[GPG-ENCRYPTED]"
        return result
