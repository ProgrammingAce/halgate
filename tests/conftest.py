import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from halgate.config import Config, load_config, load_packages  # noqa: E402

TEST_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
FAKE_GPG = REPO_ROOT / "tests" / "fixtures" / "fake_gpg.py"
BROKEN_GPG = REPO_ROOT / "tests" / "fixtures" / "broken_gpg.py"


@pytest.fixture(autouse=True, scope="session")
def _gpg_executables():
    FAKE_GPG.chmod(0o755)
    BROKEN_GPG.chmod(0o755)
    yield


@pytest.fixture
def instance_id() -> str:
    return "testinstance.1"


@pytest.fixture
def packages():
    return load_packages(REPO_ROOT / "scope_packages.yaml")


@pytest.fixture
def config(tmp_path, instance_id, monkeypatch) -> Config:
    """Config pointing all state dirs at tmp_path, fake gpg, test fingerprint."""
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    cfg = load_config(REPO_ROOT / "config.example.yaml", REPO_ROOT / "scope_packages.yaml")
    cfg.memory.dir = str(tmp_path / "memory")
    cfg.shell.workdir = str(tmp_path)
    cfg.safety.dry_run = False
    cfg.audit.dir = str(tmp_path / "audit")
    cfg.audit.forensic_enabled = True
    cfg.audit.gpg_recipient = TEST_FINGERPRINT
    cfg.audit.gpg_homedir = None
    cfg.audit.gpg_executable = str(FAKE_GPG)
    cfg.sessions.dir = str(tmp_path / "sessions")
    cfg.evidence.dir = str(tmp_path / "evidence")
    # fake gpg validates against FAKE_GPG_KEY
    os.environ["FAKE_GPG_KEY"] = TEST_FINGERPRINT
    return cfg


@pytest.fixture
def broken_gpg_config(tmp_path, config) -> Config:
    """Same config but the gpg executable always fails (fail-closed tests)."""
    config.audit.gpg_executable = str(BROKEN_GPG)
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
