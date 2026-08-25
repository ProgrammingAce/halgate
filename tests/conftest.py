import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from halgate.config import Config, load_config, load_packages  # noqa: E402

@pytest.fixture
def instance_id() -> str:
    return "testinstance.1"


@pytest.fixture
def packages():
    return load_packages(REPO_ROOT / "scope_packages.yaml")


@pytest.fixture
def config(tmp_path, instance_id, monkeypatch) -> Config:
    """Config pointing all state dirs at tmp_path with a native test key."""
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    cfg = load_config(REPO_ROOT / "config.example.yaml", REPO_ROOT / "scope_packages.yaml")
    cfg.memory.dir = str(tmp_path / "memory")
    cfg.shell.workdir = str(tmp_path)
    cfg.safety.dry_run = False
    cfg.audit.dir = str(tmp_path / "audit")
    cfg.audit.forensic_enabled = True
    cfg.audit.encryption_key_file = str(tmp_path / "native-key.json")
    from halgate.crypto import NativeCrypto
    NativeCrypto.initialize(cfg.audit.encryption_key_file)
    cfg.sessions.dir = str(tmp_path / "sessions")
    cfg.evidence.dir = str(tmp_path / "evidence")
    return cfg


@pytest.fixture
def broken_gpg_config(tmp_path, config) -> Config:
    """Same config with no key envelope (fail-closed tests)."""
    config.audit.encryption_key_file = str(tmp_path / "missing-key.json")
    return config


class FakeLLM:
    """Canned-response OpenAI-compatible client for tests."""

    def __init__(self, responses: list | None = None):
        self.responses = list(responses or [])
        self.calls: list[list[dict]] = []

    async def complete(self, messages: list[dict], tools: list[dict] | None = None):
        from halgate.llm.client import Completion, TokenUsage
        self.calls.append(messages)
        if not self.responses:
            return Completion(content="done", tool_calls=[],
                              usage=TokenUsage(10, 5), finish_reason="stop")
        resp = self.responses.pop(0)
        if isinstance(resp, Completion):
            return resp
        if isinstance(resp, Exception):
            raise resp
        tc = []
        for c in resp.get("tool_calls") or []:
            tc.append(
                type("TC", (), {"id": c[0], "name": c[1], "arguments": c[2]})())
        return Completion(content=resp.get("content", ""), tool_calls=tc,
                          usage=TokenUsage(resp.get("pt", 10), resp.get("ct", 5)),
                          finish_reason=resp.get("finish", "stop"))

    async def close(self):
        pass
