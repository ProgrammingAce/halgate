"""Per-engagement asset/service graph and diffs."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .store import EvidenceStore


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class InventoryStore:
    def __init__(self, root: Path, session_id: str):
        self._base = root / "inventory"
        self._session = session_id
        self._base.mkdir(parents=True, exist_ok=True)
        self._snapshots: list[str] = []

    def _graph_path(self, engagement_id: str) -> Path:
        return self._base / f"{engagement_id}.json"

    def _load(self, engagement_id: str) -> dict:
        p = self._graph_path(engagement_id)
        if p.exists():
            try:
                return json.loads(p.read_text())
            except json.JSONDecodeError:
                pass
        return {"engagement_id": engagement_id, "assets": {}, "updated": None}

    def _save(self, engagement_id: str, graph: dict) -> None:
        graph["updated"] = _now_iso()
        self._graph_path(engagement_id).write_text(
            json.dumps(graph, indent=2, sort_keys=True))

    def upsert_asset(self, engagement_id: str, asset_id: str,
                     addr: str | None = None, hostname: str | None = None,
                     services: list[str] | None = None,
                     software: list[str] | None = None,
                     evidence_ref: str | None = None) -> dict:
        graph = self._load(engagement_id)
        asset: dict = graph["assets"].get(asset_id, {"id": asset_id})
        if addr:
            asset["addr"] = addr
        if hostname:
            asset["hostname"] = hostname
        if services:
            asset.setdefault("services", []).extend(
                s for s in services if s not in asset.get("services", []))
        if software:
            asset.setdefault("software", []).extend(
                sw for sw in software if sw not in asset.get("software", []))
        if evidence_ref:
            asset.setdefault("evidence_refs", []).append(evidence_ref)
        graph["assets"][asset_id] = asset
        self._save(engagement_id, graph)
        return asset

    def snapshot(self, engagement_id: str) -> str:
        graph = self._load(engagement_id)
        snap_id = _now_iso().replace(":", "").replace("-", "").replace("+", "")
        self._snapshots.append(snap_id)
        snap_path = self._base / f"{engagement_id}.{snap_id}.snapshot.json"
        snap_path.write_text(json.dumps(graph, indent=2, sort_keys=True))
        return snap_id

    def diff(self, engagement_id: str, against: str | None = None) -> dict:
        current = self._load(engagement_id)
        cur_assets = set(current.get("assets", {}).keys())
        if against:
            snap_path = self._base / f"{engagement_id}.{against}.snapshot.json"
            if not snap_path.exists():
                return {"error": f"snapshot not found: {against}"}
            try:
                prior = json.loads(snap_path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                return {"error": f"snapshot is unreadable: {e}"}
            prior_assets = set(prior.get("assets", {}).keys())
            added = sorted(cur_assets - prior_assets)
            removed = sorted(prior_assets - cur_assets)
            changed = []
            for a in sorted(cur_assets & prior_assets):
                if current["assets"].get(a) != prior.get("assets", {}).get(a):
                    changed.append(a)
            return {"added": added, "removed": removed,
                    "changed": changed, "total": len(cur_assets)}
        return {"total": len(cur_assets), "assets": sorted(cur_assets)}
