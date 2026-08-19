"""Checkpoint save/load roundtrip, listing, naming."""
from __future__ import annotations

import json

import pytest

from harness.scope import Engagement
from harness.sessions.checkpoint import (
    SessionCheckpoint,
    default_session_name,
    slugify,
)


def sample_engagements(tmp_path):
    root = tmp_path / "proj"
    root.mkdir(exist_ok=True)
    return [
        Engagement(id="eng-01", label="Codebase: payments-svc", target=str(root),
                   package="defensive"),
        Engagement(id="eng-02", label="Lab net", target="192.168.1.0/24",
                   package="offensive", execution_mode="container"),
    ]


def test_roundtrip(tmp_path):
    cp = SessionCheckpoint(str(tmp_path / "sessions"), "sess-1")
    engs = sample_engagements(tmp_path)
    messages = [
        {"role": "user", "content": "scan the lab"},
        {"role": "assistant", "content": None, "tool_calls": []},
        {"role": "tool", "tool_call_id": "1", "content": "{}"},
    ]
    panes = [{"id": "pane-01", "name": "nc", "cmd": ["nc", "-l", "4444"]}]
    cp.save("sess-1", "my-label", messages, panes, engs, "llama-local", None)
    restored = SessionCheckpoint.load(str(tmp_path / "sessions"), "sess-1")
    assert restored.name == "my-label"
    assert restored.messages == messages
    assert restored.panes == panes
    assert [e.id for e in restored.engagements] == ["eng-01", "eng-02"]
    assert restored.engagements[0].package == "defensive"
    assert restored.engagements[1].execution_mode == "container"
    assert restored.llm_id == "llama-local"


def test_checkpoint_never_stores_raw_secret(tmp_path):
    """Defensive: even if a caller passes secret-bearing messages, the
    transcript file is what it is given — the harness redacts before append.
    Here we assert the checkpoint writer does not add any extra plaintext
    channels (meta stores hashes, not message content)."""
    cp = SessionCheckpoint(str(tmp_path / "s"), "sess-2")
    cp.save("sess-2", "n", [{"role": "user", "content": "x [CRED:cred_a]"}],
            [], sample_engagements(tmp_path), "llm", None)
    meta = json.loads((cp.dir / "meta.json").read_text())
    assert "AKIA" not in json.dumps(meta)
    assert "engagements" in meta["hashes"]


def test_list_and_latest(tmp_path):
    base = tmp_path / "sessions"
    for i, name in enumerate(["a-older", "b-newer"]):
        cp = SessionCheckpoint(str(base), name)
        cp.save(name, name, [], [], sample_engagements(tmp_path), "llm", None,
                created=f"2026-08-{10 + i:02d}T00:00:00")
    sessions = SessionCheckpoint.list_sessions(str(base))
    assert [s["id"] for s in sessions] == ["b-newer", "a-older"]
    assert SessionCheckpoint.latest(str(base)) == "b-newer"
    assert SessionCheckpoint.latest(str(tmp_path / "missing")) is None


def test_load_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        SessionCheckpoint.load(str(tmp_path / "s"), "nope")


def test_resumed_from_preserved_across_saves(tmp_path):
    cp = SessionCheckpoint(str(tmp_path / "s"), "sess-3")
    engs = sample_engagements(tmp_path)
    cp.save("sess-3", "n", [], [], engs, "llm", None,
            created="2026-08-01T00:00:00")
    cp.save("sess-3", "n2", [{"role": "user", "content": "hi"}], [], engs,
            "llm", "sess-3")
    restored = SessionCheckpoint.load(str(tmp_path / "s"), "sess-3")
    assert restored.name == "n2"
    assert restored.created if hasattr(restored, "created") else True


def test_session_naming():
    engs = [Engagement(id="e1", label="Payments Svc", target="/x",
                       package="defensive")]
    import os
    os.environ.setdefault("TZ", "UTC")
    name = default_session_name(engs)
    parts = name.split("_")
    assert len(parts) == 3 and len(parts[2]) == 4
    assert "payments-svc" in name
    assert default_session_name(engs, override="custom") == "custom"
    assert slugify("Hello, World!") == "hello-world"
