"""Crypto backends must not be required to start a non-forensic session."""
from __future__ import annotations

from halgate.audit.logger import AuditLogger
from halgate.memory.keystore import KeyStore


def test_disabled_forensics_does_not_unlock_native_key_at_startup(config, instance_id):
    config.audit.forensic_enabled = False
    config.audit.encryption_key_file = str(config.audit.dir) + "/missing-key.json"

    logger = AuditLogger(config.audit, "no-gpg", instance_id)
    keystore = KeyStore(config.audit, instance_id)

    logger.session_start([], "test", resumed=False)
    assert logger._crypto is None
    assert keystore._crypto is None
