"""Crypto backends must not be required to start a non-forensic session."""
from __future__ import annotations

from harness.audit.logger import AuditLogger
from harness.memory.keystore import KeyStore


def test_disabled_forensics_does_not_resolve_gpg_at_startup(config, instance_id):
    config.audit.forensic_enabled = False
    config.audit.gpg_executable = "gpg-not-installed-for-test"

    logger = AuditLogger(config.audit, "no-gpg", instance_id)
    keystore = KeyStore(config.audit, instance_id)

    logger.session_start([], "test", resumed=False)
    assert logger._gpg is None
    assert keystore._gpg is None
