"""TUI-safe native-key unlock coverage."""
from __future__ import annotations

import json

import pytest

from halgate.crypto import NativeCrypto
from halgate.errors import ForensicEncryptionError
from halgate.halgate import Halgate


class _Client:
    def __init__(self):
        self.calls = []

    async def stream_complete(self, messages, tools, on_delta):
        from halgate.llm.client import Completion, TokenUsage
        self.calls.append(messages)
        return Completion(content="done", tool_calls=[], usage=TokenUsage(1, 1))


@pytest.mark.asyncio
async def test_phrase_callback_unlocks_before_forensic_logging(config, monkeypatch, tmp_path):
    key_file = tmp_path / "callback-key.json"
    phrase = NativeCrypto.initialize(key_file)
    NativeCrypto._cache.clear()
    config.audit.encryption_key_file = str(key_file)

    async def provide_phrase():
        return phrase

    monkeypatch.setattr("getpass.getpass", lambda _: pytest.fail("prompted"))
    halgate = Halgate(config, [], phrase_callback=provide_phrase)
    client = _Client()
    halgate.router._clients[halgate.router.active_endpoint.id] = client

    assert await halgate.run("inspect") == "done"
    assert len(client.calls) == 1
    entries = [json.loads(line) for line in halgate.audit.path.read_text().splitlines()]
    user_input = next(entry for entry in entries if entry["event"] == "user_input")
    assert "_forensic" in user_input["payload"]


@pytest.mark.asyncio
async def test_cancelled_phrase_aborts_before_llm(config, tmp_path):
    key_file = tmp_path / "callback-key.json"
    NativeCrypto.initialize(key_file)
    NativeCrypto._cache.clear()
    config.audit.encryption_key_file = str(key_file)

    async def cancel():
        return None

    halgate = Halgate(config, [], phrase_callback=cancel)
    client = _Client()
    halgate.router._clients[halgate.router.active_endpoint.id] = client

    with pytest.raises(ForensicEncryptionError, match="cancelled"):
        await halgate.run("inspect")
    assert client.calls == []
