"""Tests for MemoryStore.edit (edit-as-replace)."""
import pytest

from harness.config import MemoryConfig
from harness.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path, instance_id):
    cfg = MemoryConfig(dir=str(tmp_path / "mem"))
    return MemoryStore(cfg, instance_id)


def test_edit_basic(store):
    store.remember("original text here", source="scanned")
    entries = store.read_long_term()
    mid = entries[0]["id"]
    r = store.edit(mid, "revised text here")
    assert r["success"]
    assert r["changed"] is True
    assert r["previous_id"] == mid
    assert r["id"] != mid
    entries = store.read_long_term()
    assert len(entries) == 1
    assert entries[0]["text"] == "revised text here"
    assert entries[0]["id"] == r["id"]


def test_edit_same_text_noop(store):
    store.remember("same text", source="scanned")
    entries = store.read_long_term()
    mid = entries[0]["id"]
    r = store.edit(mid, "same text")
    assert r["success"]
    assert r["changed"] is False
    assert r["id"] == mid


def test_edit_unknown_id(store):
    r = store.edit("nosuchid", "new text")
    assert not r["success"]
    assert "no memory" in r["error"]


def test_edit_collision(store):
    store.remember("text A", source="scanned")
    store.remember("text B", source="scanned")
    entries = store.read_long_term()
    a_id = next(e["id"] for e in entries if e["text"] == "text A")
    r = store.edit(a_id, "text B")
    assert not r["success"]
    assert "collision" in r["error"]


def test_edit_preserves_metadata(store):
    store.remember("original fact", source="scanned", category="vulnerability")
    entries = store.read_long_term()
    mid = entries[0]["id"]
    old_conf = entries[0]["confidence"]
    store.edit(mid, "updated fact")
    entries = store.read_long_term()
    new_entry = entries[0]
    assert new_entry["category"] == "vulnerability"
    assert new_entry["source"] == "scanned"
    assert new_entry["confidence"] == old_conf
    assert new_entry["first_seen"] == entries[0]["first_seen"]
    assert new_entry["related_ids"] == [mid]


def test_edit_empty_text_rejected(store):
    store.remember("some fact", source="scanned")
    store.read_long_term()
    r = store.edit("some_id", "")
    assert not r["success"]
    assert "empty" in r["error"]
