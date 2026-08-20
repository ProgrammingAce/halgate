"""Importers for external reports (Nmap XML, Nuclei, Burp, SARIF).

Imports are untrusted data: they create evidence records and derived
inventory/finding records but CANNOT execute commands or alter policy.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .store import EvidenceStore
from .inventory import InventoryStore
from .findings import FindingStore


def import_nmap_xml(evidence: EvidenceStore, inventory: InventoryStore,
                    findings: FindingStore, path: str,
                    engagement_id: str) -> dict:
    """Import an Nmap XML report."""
    p = Path(path)
    if not p.exists():
        return {"error": f"file not found: {path}"}
    raw = p.read_bytes()
    art_ref = evidence.store(raw, "nmap_import", path, engagement_id)
    hosts: list[dict] = []
    try:
        tree = ET.parse(str(p))
        root = tree.getroot()
        for host_elem in root.findall(".//host"):
            addr_elem = host_elem.find("address")
            hostaddr = addr_elem.get("addr", "") if addr_elem is not None else "unknown"
            state_elem = host_elem.find(".//state")
            status = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            ports = []
            for port in host_elem.findall(".//port"):
                ports.append(port.get("portid", "?"))
            inventory.upsert_asset(
                engagement_id, hostaddr,
                addr=hostaddr, services=ports,
                evidence_ref=art_ref)
            hosts.append({"addr": hostaddr, "status": status, "ports": ports})
    except ET.ParseError as e:
        return {"error": f"XML parse failed: {e}", "evidence_ref": art_ref}
    return {
        "imported": True,
        "evidence_ref": art_ref,
        "hosts": len(hosts),
        "hosts_detail": hosts,
    }


def import_nuclei_jsonl(evidence: EvidenceStore, inventory: InventoryStore,
                        findings: FindingStore, path: str,
                        engagement_id: str) -> dict:
    """Import a Nuclei JSONL report."""
    p = Path(path)
    if not p.exists():
        return {"error": f"file not found: {path}"}
    raw = p.read_bytes()
    art_ref = evidence.store(raw, "nuclei_import", path, engagement_id)
    entries: list[dict] = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append(obj)
    for obj in entries:
        host = obj.get("host", obj.get("input", ""))
        if host:
            inventory.upsert_asset(engagement_id, host, addr=host,
                                   evidence_ref=art_ref)
    return {
        "imported": True,
        "evidence_ref": art_ref,
        "entries": len(entries),
    }


def import_burp(evidence: EvidenceStore, inventory: InventoryStore,
                findings: FindingStore, path: str,
                engagement_id: str) -> dict:
    """Import a Burp Suite XML or JSON report."""
    p = Path(path)
    if not p.exists():
        return {"error": f"file not found: {path}"}
    raw = p.read_bytes()
    art_ref = evidence.store(raw, "burp_import", path, engagement_id)
    if p.suffix == ".json":
        try:
            data = json.loads(raw)
            issues = data if isinstance(data, list) else data.get("issues", [])
            for issue in issues:
                host = issue.get("host", issue.get("url", ""))
                if host:
                    inventory.upsert_asset(
                        engagement_id, host, addr=host,
                        evidence_ref=art_ref)
            return {"imported": True, "evidence_ref": art_ref,
                    "issues": len(issues)}
        except (json.JSONDecodeError, KeyError) as e:
            return {"error": f"JSON parse failed: {e}", "evidence_ref": art_ref}
    try:
        tree = ET.parse(str(p))
        root = tree.getroot()
        issues = root.findall(".//issue")
        for issue in issues:
            host = issue.findtext("host", "")
            if host:
                inventory.upsert_asset(engagement_id, host, addr=host,
                                       evidence_ref=art_ref)
        return {"imported": True, "evidence_ref": art_ref,
                "issues": len(issues)}
    except ET.ParseError as e:
        return {"error": f"XML parse failed: {e}", "evidence_ref": art_ref}


def import_sarif(evidence: EvidenceStore, inventory: InventoryStore,
                 findings: FindingStore, path: str,
                 engagement_id: str) -> dict:
    """Import a SARIF report."""
    p = Path(path)
    if not p.exists():
        return {"error": f"file not found: {path}"}
    raw = p.read_bytes()
    art_ref = evidence.store(raw, "sarif_import", path, engagement_id)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return {"error": f"SARIF parse failed: {e}", "evidence_ref": art_ref}
    results: list[dict] = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            results.append(r)
            loc = (r.get("locations") or [{}])[0]
            uri = (loc.get("physicalLocation", {})
                   .get("artifactLocation", {})
                   .get("uri", ""))
            if uri:
                inventory.upsert_asset(engagement_id, uri, addr=uri,
                                       evidence_ref=art_ref)
    return {
        "imported": True,
        "evidence_ref": art_ref,
        "results": len(results),
    }


IMPORTERS = {
    "nmap": import_nmap_xml,
    "nuclei": import_nuclei_jsonl,
    "burp": import_burp,
    "sarif": import_sarif,
}
