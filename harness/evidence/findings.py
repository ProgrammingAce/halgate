"""Structured findings with evidence links and export formats."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .store import EvidenceStore

VALID_STATUSES = ("open", "confirmed", "mitigated", "rejected", "resolved")
VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class FindingStore:
    def __init__(self, evidence: EvidenceStore, session_id: str):
        self._evidence = evidence
        self._session = session_id
        self._path = Path(evidence._root.parent) / "findings.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        existing = 0
        if self._path.exists():
            with self._path.open() as f:
                existing = sum(1 for line in f if line.strip())
        self._seq = existing + 1

    def add(self, title: str, severity: str, description: str,
            evidence_refs: list[str], confidence: float = 0.5,
            affected_assets: list[str] | None = None,
            location: str = "", remediation: str = "",
            status: str = "open", engagement_id: str | None = None) -> dict:
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {severity}")
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        if not evidence_refs:
            raise ValueError("at least one evidence reference required")
        fid = f"find-{self._seq:04d}"
        finding = {
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": max(0.0, min(1.0, confidence)),
            "description": description,
            "evidence_refs": evidence_refs,
            "affected_assets": affected_assets or [],
            "location": location,
            "remediation": remediation,
            "status": status,
            "engagement_id": engagement_id,
            "created": _now_iso(),
            "updated": _now_iso(),
        }
        self._seq += 1
        with self._path.open("a") as f:
            f.write(json.dumps(finding, separators=(",", ":")) + "\n")
        return finding

    def update_status(self, fid: str, status: str) -> dict | None:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        entries = self.list_all()
        for i, e in enumerate(entries):
            if e.get("id") == fid:
                e["status"] = status
                e["updated"] = _now_iso()
                with self._path.open("w") as f:
                    for entry in entries:
                        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                return e
        return None

    def list_all(self, status: str | None = None) -> list[dict]:
        entries: list[dict] = []
        if not self._path.exists():
            return entries
        with self._path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if status is None or obj.get("status") == status:
                    entries.append(obj)
        return entries

    def export_markdown(self, status: str | None = None) -> str:
        findings = self.list_all(status)
        lines = ["# Security Findings", ""]
        lines.append(f"Session: {self._session}")
        lines.append(f"Generated: {_now_iso()}")
        lines.append(f"Total: {len(findings)}")
        lines.append("")
        for f in findings:
            lines.append(f"## {f['id']}: {f['title']}")
            lines.append(f"- **Severity**: {f['severity']}")
            lines.append(f"- **Status**: {f['status']}")
            lines.append(f"- **Confidence**: {f['confidence']:.0%}")
            lines.append(f"- **Location**: {f.get('location', 'n/a')}")
            lines.append(f"- **Evidence**: {', '.join(f['evidence_refs'])}")
            lines.append("")
            lines.append(f.get("description", ""))
            if f.get("remediation"):
                lines.append(f"\n**Remediation**: {f['remediation']}")
            lines.append("")
        return "\n".join(lines)

    def export_json(self, status: str | None = None) -> str:
        findings = self.list_all(status)
        return json.dumps({"session": self._session,
                           "generated": _now_iso(),
                           "findings": findings}, indent=2)

    def export_sarif(self, status: str | None = None) -> str:
        findings = self.list_all(status)
        results = []
        severity_map = {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "none",
        }
        for f in findings:
            results.append({
                "ruleId": f["id"],
                "level": severity_map.get(f["severity"], "warning"),
                "message": {"text": f["description"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("location", "unknown")
                        }
                    }
                }],
            })
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                       "master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "halgate-harness"}},
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)
