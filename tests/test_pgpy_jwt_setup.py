"""The generated PGPy setup must support decrypting JWT signing keys."""
from __future__ import annotations

import os

import pytest

from harness.harness import Harness
from harness.openpgp import generate_keypair
from harness.tools.jwt_sign import sign_hmac


@pytest.mark.asyncio
async def test_generated_pgpy_recipient_can_reveal_signing_secret(
        config, tmp_path, monkeypatch):
    pytest.importorskip("pgpy")
    pair = generate_keypair(tmp_path, "Test session", "correct horse battery staple")
    harness = Harness(config, [])
    harness.use_pgpy_recipient(
        pair.fingerprint, str(pair.public_key_path), str(pair.private_key_path),
        "correct horse battery staple")

    passphrase_env = harness.config.audit.pgpy_passphrase_env
    assert harness.config.audit.crypto_backend == "pgpy"
    assert harness.config.audit.pgpy_private_key == str(pair.private_key_path)
    assert passphrase_env and passphrase_env in os.environ
    try:
        credential = await harness._keystore.store(
            "jwt_signing_key", "test-hmac-signing-key", "test")
        secret = await harness._keystore.reveal(credential)
        token, _, _ = sign_hmac("HS256", secret.encode(), {"sub": "tester"}, 60)
        assert token.count(".") == 2
    finally:
        monkeypatch.delenv(passphrase_env, raising=False)
