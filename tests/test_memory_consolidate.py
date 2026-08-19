"""Tests for memory consolidation."""
import pytest
from unittest.mock import AsyncMock, patch

from harness.config import ConsolidationConfig, EndpointConfig, MemoryConfig
from harness.llm.client import Completion, TokenUsage
from harness.memory.consolidate import extract_json, run_consolidation
from harness.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path, instance_id):
    cfg = MemoryConfig(dir=str(tmp_path / "mem"))
    return MemoryStore(cfg, instance_id)


def make_llm(response_json: str) -> AsyncMock:
    llm = AsyncMock()
    llm.complete = AsyncMock(return_value=Completion(
        content=response_json,
        tool_calls=[],
        usage=TokenUsage(100, 200, 300),
        finish_reason="stop",
    ))
    return llm


def test_extract_json_basic():
    data = extract_json('{"memories": [], "episode": "done"}')
    assert data == {"memories": [], "episode": "done"}


def test_extract_json_in_prose():
    text = 'Here are the results:\n```json\n{"memories": [{"text": "x"}]}\n```\nDone.'
    data = extract_json(text)
    assert "memories" in data


def test_extract_json_invalid():
    from harness.errors import HarnessError
    with pytest.raises(HarnessError, match="no valid JSON"):
        extract_json("not json at all")


@pytest.mark.asyncio
async def test_consolidation_pinned_survives(store):
    # Store a pinned fact
    store.remember("RULE: target is 192.168.1.0/24", source="stated",
                   category="scope")
    # Store ephemeral facts the LLM would consolidate
    store.remember("port 80 open running nginx", source="scanned")
    store.remember("nginx version 1.24.0 on port 80", source="scanned")

    pinned_entries = [e for e in store.read_long_term() if e.get("pinned")]
    assert len(pinned_entries) == 1

    # LLM response preserves pinned fact verbatim but merges the nginx facts
    import json as _json
    pinned_text = pinned_entries[0]["text"]
    llm_resp = _json.dumps({
        "memories": [
            {"text": pinned_text, "category": "scope",
             "subject": "target", "confidence": 0.95},
            {"text": "nginx 1.24.0 on port 80", "category": "target_arch",
             "subject": "target", "confidence": 0.7},
        ],
        "episode": "recon session",
    })
    llm = make_llm(llm_resp)
    cfg = store._cfg
    ok, new_count = await run_consolidation(store, llm, cfg)
    assert ok, "consolidation should succeed"

    entries = store.read_long_term()
    # Pinned fact must survive
    assert any(e.get("text") == pinned_text for e in entries)
    # New count should be reasonable
    assert new_count >= 2


@pytest.mark.asyncio
async def test_consolidation_reinjects_dropped_pinned(store):
    store.remember("PINNED RULE: no port scanning above 1024",
                   source="stated", category="scope")
    # LLM response drops the pinned fact entirely
    llm_resp = '{"memories": [{"text": "port 443 is open", ' \
               '"category": "target_arch", "subject": "target", ' \
               '"confidence": 0.7}], "episode": "scan"}'
    llm = make_llm(llm_resp)
    cfg = store._cfg
    ok, new_count = await run_consolidation(store, llm, cfg)
    assert ok
    entries = store.read_long_term()
    # Pinned fact must be re-injected
    assert any("PINNED RULE" in e.get("text", "") for e in entries)


@pytest.mark.asyncio
async def test_consolidation_confidence_cap(store):
    store.remember("a fact with scanned source", source="scanned")
    # LLM tries to raise confidence above cap for new reflected facts
    llm_resp = '{"memories": [{"text": "totally new insight", ' \
               '"category": "insight", "subject": "target", ' \
               '"confidence": 0.9}], "episode": ""}'
    llm = make_llm(llm_resp)
    cfg = store._cfg
    ok, _ = await run_consolidation(store, llm, cfg)
    assert ok
    entries = store.read_long_term()
    for e in entries:
        if e.get("source") in ("inferred", "reflected"):
            assert e["confidence"] <= 0.6, \
                f"confidence {e['confidence']} exceeds inferred cap"
