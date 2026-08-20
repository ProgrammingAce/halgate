"""Tests for EvidenceStore, FindingStore, and InventoryStore."""
import hashlib
import json

import pytest

from halgate.config import EvidenceConfig
from halgate.evidence.store import EvidenceStore
from halgate.evidence.findings import FindingStore
from halgate.evidence.inventory import InventoryStore


class TestEvidenceStore:
    @pytest.fixture
    def store(self, tmp_path):
        cfg = EvidenceConfig(dir=str(tmp_path / "evidence"), max_artifact_bytes=4096)
        return EvidenceStore(cfg, "sess1")

    def test_store_returns_sha256(self, store):
        content = b"hello world"
        digest = store.store(content, "read_file", "read:/x", "eng1")
        expected = hashlib.sha256(content).hexdigest()
        assert digest == expected

    def test_store_and_read_symmetric(self, store):
        content = b"evidence payload"
        digest = store.store(content, "grep", "grep:match", "eng1")
        assert store.read(digest) == content

    def test_metadata_records(self, store):
        content = b"data"
        digest = store.store(content, "tool_a", "event_a", "eng1")
        store.store(content, "tool_b", "event_b", "eng2")
        metas = store.metadata(digest)
        assert len(metas) == 2
        assert metas[0]["source_tool"] == "tool_a"
        assert metas[1]["source_tool"] == "tool_b"

    def test_read_missing_returns_none(self, store):
        assert store.read("deadbeef" * 8) is None

    def test_show_returns_provenance(self, store):
        digest = store.store(b"evidence data", "http", "req:GET", "eng1")
        result = store.show(digest)
        assert result["artifact"] == digest
        assert result["source_tool"] == "http"
        assert "evidence data" in result["content_preview"]

    def test_show_missing_returns_error(self, store):
        result = store.show("abcdef" * 8)
        assert "error" in result

    def test_encrypted_preview(self, store):
        digest = store.store(b"enc", "gpg", "enc", "eng1", encrypted=True)
        result = store.show(digest)
        assert result["content_preview"] == "[GPG-ENCRYPTED]"

    def test_max_size_enforced(self, tmp_path):
        cfg = EvidenceConfig(dir=str(tmp_path / "ev"), max_artifact_bytes=8)
        s = EvidenceStore(cfg, "s")
        with pytest.raises(ValueError, match="too large"):
            s.store(b"x" * 16, "tool", "event", "eng")


class TestFindingStore:
    @pytest.fixture
    def env(self, tmp_path):
        cfg = EvidenceConfig(dir=str(tmp_path / "evidence"))
        ev = EvidenceStore(cfg, "sess-1")
        fs = FindingStore(ev, "sess-1")
        return ev, fs

    def test_add_returns_finding(self, env):
        _, fs = env
        f = fs.add("SQLi in /login", "high", "desc", ["abc123"],
                   confidence=0.9, location="/login.php",
                   remediation="Parameterize")
        assert f["id"] == "find-0001"
        assert f["severity"] == "high"
        assert f["confidence"] == 0.9
        assert f["status"] == "open"

    def test_add_invalid_severity(self, env):
        _, fs = env
        with pytest.raises(ValueError, match="invalid severity"):
            fs.add("t", "extreme", "d", ["ref"])

    def test_add_requires_evidence_refs(self, env):
        _, fs = env
        with pytest.raises(ValueError, match="evidence reference"):
            fs.add("t", "high", "d", [])

    def test_confidence_clamped(self, env):
        _, fs = env
        f = fs.add("t", "low", "d", ["ref"], confidence=1.5)
        assert f["confidence"] == 1.0
        f2 = fs.add("t2", "low", "d", ["ref"], confidence=-1)
        assert f2["confidence"] == 0.0

    def test_sequence_increments(self, env):
        _, fs = env
        f1 = fs.add("a", "info", "d", ["r"])
        f2 = fs.add("b", "info", "d", ["r"])
        assert f1["id"] == "find-0001"
        assert f2["id"] == "find-0002"

    def test_list_all_filter(self, env):
        _, fs = env
        fs.add("a", "high", "d", ["r"], status="confirmed")
        fs.add("b", "low", "d", ["r"])
        assert len(fs.list_all(status="confirmed")) == 1
        assert len(fs.list_all(status="open")) == 1

    def test_export_markdown(self, env):
        _, fs = env
        fs.add("SQLi", "critical", "desc here", ["ref1"], confidence=0.95)
        md = fs.export_markdown()
        assert "# Security Findings" in md
        assert "find-0001" in md

    def test_export_json(self, env):
        _, fs = env
        fs.add("XSS", "medium", "d", ["r"])
        data = json.loads(fs.export_json())
        assert data["session"] == "sess-1"
        assert len(data["findings"]) == 1

    def test_export_sarif(self, env):
        _, fs = env
        fs.add("Vuln", "high", "desc", ["r"], location="/x.py")
        sarif = json.loads(fs.export_sarif())
        assert sarif["version"] == "2.1.0"
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert results[0]["message"]["text"] == "desc"


class TestInventoryStore:
    @pytest.fixture
    def inv(self, tmp_path):
        return InventoryStore(tmp_path, "sess1")

    def test_upsert_new_asset(self, inv):
        asset = inv.upsert_asset("eng1", "10.0.0.1", addr="10.0.0.1",
                                 hostname="web.local",
                                 services=["80/tcp", "443/tcp"],
                                 software=["nginx/1.24"])
        assert asset["id"] == "10.0.0.1"
        assert asset["hostname"] == "web.local"
        assert asset["services"] == ["80/tcp", "443/tcp"]

    def test_upsert_merges_services(self, inv):
        inv.upsert_asset("eng1", "h", services=["80/tcp"])
        a = inv.upsert_asset("eng1", "h", services=["443/tcp", "22/tcp"])
        assert len(a["services"]) == 3

    def test_snapshot_diff(self, inv):
        inv.upsert_asset("eng1", "a", addr="a", services=["80/tcp"])
        snap = inv.snapshot("eng1")
        inv.upsert_asset("eng1", "b", addr="b", services=["22/tcp"])
        inv.upsert_asset("eng1", "a", services=["80/tcp", "443/tcp"])
        d = inv.diff("eng1", against=snap)
        assert "a" in d["changed"]
        assert "b" in d["added"]
        assert d["removed"] == []

    def test_current_total(self, inv):
        inv.upsert_asset("eng1", "x", addr="x")
        assert inv.diff("eng1")["total"] == 1
