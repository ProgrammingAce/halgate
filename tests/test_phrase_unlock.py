"""TUI-safe native-key unlock coverage."""
from __future__ import annotations

import json

import pytest

from halgate.crypto import NativeCrypto
from halgate.errors import EncryptionError, ForensicEncryptionError
from halgate.halgate import Halgate
from halgate.memory.keystore import KeyStore


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


@pytest.mark.asyncio
async def test_missing_key_does_not_request_phrase_and_remains_fail_closed(
        config, tmp_path):
    config.audit.encryption_key_file = str(tmp_path / "missing-key.json")
    prompted = False

    async def provide_phrase():
        nonlocal prompted
        prompted = True
        return "should not be requested"

    halgate = Halgate(config, [], phrase_callback=provide_phrase)
    client = _Client()
    halgate.router._clients[halgate.router.active_endpoint.id] = client

    with pytest.raises(ForensicEncryptionError, match="native encryption unavailable"):
        await halgate.run("inspect")
    assert not prompted
    assert client.calls == []


@pytest.mark.asyncio
async def test_keystore_provider_unlocks_once_and_rechecks_after_cache_reset(
        config, instance_id, tmp_path):
    key_file = tmp_path / "keystore-key.json"
    phrase = NativeCrypto.initialize(key_file)
    NativeCrypto._cache.clear()
    config.audit.encryption_key_file = str(key_file)
    calls = 0

    async def provide_phrase():
        nonlocal calls
        calls += 1
        return phrase

    keystore = KeyStore(config.audit, instance_id, provide_phrase)
    first = await keystore.store("token", "top-secret", "test")
    assert await keystore.reveal(first) == "top-secret"
    assert calls == 1

    # Key rotation clears the shared cache. A ready keystore must still use
    # its TUI provider rather than letting a worker thread call getpass.
    NativeCrypto._cache.clear()
    await keystore.store("token", "second-secret", "test")
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["cancel", "wrong"])
async def test_keystore_unlock_provider_fails_closed(config, instance_id, tmp_path,
                                                      provider):
    key_file = tmp_path / "keystore-key.json"
    phrase = NativeCrypto.initialize(key_file)
    crypto = NativeCrypto(key_file, lambda: phrase)
    credential_id = "cred_test"
    ciphertext = crypto.encrypt_sync(
        b"top-secret", f"credential:{instance_id}:{credential_id}")
    NativeCrypto._cache.clear()
    config.audit.encryption_key_file = str(key_file)

    async def provide_phrase():
        return None if provider == "cancel" else "wrong phrase"

    keystore = KeyStore(config.audit, instance_id, provide_phrase)
    keystore._path.write_text(json.dumps({
        "id": credential_id, "type": "token", "ciphertext": ciphertext.decode(),
        "encryption_version": 1,
    }) + "\n")

    with pytest.raises(EncryptionError):
        await keystore.reveal(credential_id)
    assert not NativeCrypto._cache
