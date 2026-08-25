"""Redactor + keystore: secrets become [CRED:ids]; ciphertext-only storage."""
from __future__ import annotations

import json

import pytest

from halgate.errors import EncryptionError
from halgate.guardrails.redactor import Redactor, contains_secret
from halgate.memory.keystore import KeyStore

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def keystore(config, instance_id):
    ks = KeyStore(config.audit, instance_id)
    return ks


async def test_keystore_verifies_recipient(keystore, config):
    info = await keystore.verify()
    assert info["encryption_version"] == 1
    assert info["can_encrypt"]


async def test_store_encrypts_ciphertext_only(keystore, config):
    secret = "ghp_" + "A" * 36
    cid = await keystore.store("github_pat", secret, "tool:http", "eng-01")
    assert cid.startswith("cred_")
    raw = keystore._path.read_text()
    assert secret not in raw
    assert "[CRED" not in raw  # raw file is pure ciphertext records
    records = [json.loads(l) for l in raw.splitlines() if l]
    assert records[0]["encryption_version"] == 1
    assert records[0]["ciphertext"].startswith('{"version":1')
    assert records[0]["engagement"] == "eng-01"
    # reveal round-trips through native encryption
    revealed = await keystore.reveal(cid)
    assert revealed == secret


async def test_redact_replaces_all_patterns(keystore, config):
    redactor = Redactor(keystore)
    jwt = "eyJhbGciOiJIUzI1NiJ9.0123456789abcdef0123456789abcdef0123456789.sig23456789sig"
    text = (f"AWS: {AWS_KEY}\njwt={jwt}\npassword: hunter2secret\n")
    out = await redactor.redact(text, "test", "eng-01")
    assert AWS_KEY not in out and jwt not in out and "hunter2secret" not in out
    assert out.count("[CRED:") == 3
    # no secret material in the file
    stored = keystore._path.read_text()
    assert AWS_KEY not in stored and jwt not in stored


async def test_redact_object_recursive(keystore, config):
    redactor = Redactor(keystore)
    payload = {"a": f"key={AWS_KEY}", "b": [1, [f"{AWS_KEY}"]],
               "c": {"d": "clean"}}
    out = await redactor.redact_object(payload, "tool:shell", "eng-01")
    assert AWS_KEY not in json.dumps(out)
    assert "[CRED:" in out["a"] and "[CRED:" in out["b"][1][0]
    assert out["c"]["d"] == "clean"


async def test_native_key_failure_fails_closed(broken_gpg_config, instance_id):
    ks = KeyStore(broken_gpg_config.audit, instance_id)
    redactor = Redactor(ks)
    with pytest.raises(EncryptionError):
        await redactor.redact(f"key={AWS_KEY}", "test", "eng-01")
    # no plaintext secret persisted on disk
    if ks._path.exists():
        assert AWS_KEY not in ks._path.read_text()


def test_detect_helpers():
    assert contains_secret(f"token={AWS_KEY}")
    assert not contains_secret("a clean sentence without secrets")
