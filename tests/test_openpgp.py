"""Python-native OpenPGP backend and generated-key coverage."""
from __future__ import annotations

import os
import stat

import pytest

from harness.config import AuditConfig
from harness.openpgp import backend_from_config, generate_keypair


def test_pgpy_generated_keypair_encrypts_and_decrypts(tmp_path, monkeypatch):
    pytest.importorskip("pgpy")
    pair = generate_keypair(tmp_path, "Test engagement", "correct horse battery staple")
    assert pair.public_key_path.exists()
    assert pair.private_key_path.exists()
    assert stat.S_IMODE(pair.private_key_path.stat().st_mode) == 0o600

    cfg = AuditConfig(
        crypto_backend="pgpy",
        gpg_recipient=pair.fingerprint,
        pgpy_public_key=str(pair.public_key_path),
        pgpy_private_key=str(pair.private_key_path),
        pgpy_passphrase_env="HALGATE_TEST_PGPY_PASSPHRASE",
    )
    monkeypatch.setenv("HALGATE_TEST_PGPY_PASSPHRASE", "correct horse battery staple")
    backend = backend_from_config(cfg)
    ciphertext = backend.encrypt_sync(b"secret evidence")
    assert b"BEGIN PGP MESSAGE" in ciphertext
    assert os.fsdecode(ciphertext).find("secret evidence") == -1

    import asyncio
    assert asyncio.run(backend.decrypt(ciphertext)) == b"secret evidence"


def test_gpg_backend_falls_back_to_pgpy_when_gpg_is_unavailable(
        tmp_path, monkeypatch):
    pytest.importorskip("pgpy")
    pair = generate_keypair(tmp_path, "Fallback", "correct horse battery staple")
    cfg = AuditConfig(
        crypto_backend="gpg",
        gpg_executable="missing-gpg-for-test",
        gpg_recipient=pair.fingerprint,
        pgpy_public_key=str(pair.public_key_path),
        pgpy_private_key=str(pair.private_key_path),
        pgpy_passphrase_env="HALGATE_TEST_PGPY_FALLBACK_PASSPHRASE",
    )
    monkeypatch.setenv("HALGATE_TEST_PGPY_FALLBACK_PASSPHRASE",
                       "correct horse battery staple")

    backend = backend_from_config(cfg)
    ciphertext = backend.encrypt_sync(b"fallback secret")

    assert b"BEGIN PGP MESSAGE" in ciphertext
    import asyncio
    assert asyncio.run(backend.decrypt(ciphertext)) == b"fallback secret"


def test_pgpy_rejects_short_generation_passphrase(tmp_path):
    pytest.importorskip("pgpy")
    with pytest.raises(Exception, match="passphrase"):
        generate_keypair(tmp_path, "Test", "too short")
