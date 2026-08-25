"""Native secret-storage coverage."""
from pathlib import Path

import pytest

from halgate.crypto import NativeCrypto
from halgate.errors import EncryptionError


def test_native_envelope_round_trip_and_context_binding(tmp_path):
    key_file = tmp_path / "key.json"
    phrase = NativeCrypto.initialize(key_file)
    NativeCrypto._cache.clear()
    crypto = NativeCrypto(key_file, lambda: phrase)
    ciphertext = crypto.encrypt_sync(b"secret evidence", "forensic:i:s:1")
    assert crypto.decrypt_sync(ciphertext, "forensic:i:s:1") == b"secret evidence"
    with pytest.raises(EncryptionError):
        crypto.decrypt_sync(ciphertext, "forensic:i:s:2")


def test_backup_and_restore_requires_phrase(tmp_path):
    source = tmp_path / "key.json"
    backup = tmp_path / "backup.halk"
    restored = tmp_path / "restored.json"
    phrase = NativeCrypto.initialize(source)
    NativeCrypto.backup(source, backup)
    with pytest.raises(EncryptionError):
        NativeCrypto.restore(backup, restored, "wrong phrase")
    NativeCrypto.restore(backup, restored, phrase)
    NativeCrypto._cache.clear()
    assert NativeCrypto(restored, lambda: phrase)._root_key()


def test_archive_and_replace_preserves_the_old_envelope(tmp_path):
    key_file = tmp_path / "key.json"
    old_phrase = NativeCrypto.initialize(key_file)
    old_envelope = key_file.read_bytes()
    new_phrase, archive = NativeCrypto.archive_and_replace(key_file)
    assert archive.read_bytes() == old_envelope
    assert archive.stat().st_mode & 0o777 == 0o600
    assert new_phrase != old_phrase
    NativeCrypto._cache.clear()
    assert NativeCrypto(key_file, lambda: new_phrase)._root_key()
    assert NativeCrypto(archive, lambda: old_phrase)._root_key()
