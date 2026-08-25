"""Audit logger: hash chain, rotation, encrypted forensic payloads."""
from __future__ import annotations

import json

import pytest

from halgate.audit.logger import AuditLogger, verify_chain
from halgate.audit import replay
from halgate.errors import ForensicEncryptionError

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_TEXT = f"leaked password: {AWS_KEY} found here"


@pytest.fixture
def logger(config, instance_id):
    return AuditLogger(config.audit, "sess-audit-1", instance_id)


def test_chain_integrity_and_replay(logger, config):
    logger.session_start([], "llama-local", resumed=False)
    logger.user_input("hello " + AWS_KEY, raw="hello " + AWS_KEY)
    for i in range(3):
        logger.tool_call("read_file", {"path": f"/x/{i}"}, "eng-01")
        logger.tool_result("read_file", {"ok": i}, 1.5, False)
    logger.session_end("test")
    ok, broken, msg = verify_chain(logger.path)
    assert ok, msg
    assert broken is None
    events = replay.replay(logger.path)
    # session_start + user_input + 3*(tool_call+tool_result) + session_end
    assert len(events) == 9
    assert events[0]["event"] == "session_start"
    assert [e["seq"] for e in events] == list(range(1, 10))


def test_operational_log_redacts_secrets(logger):
    logger.user_input("clean text")
    raw_text = "key=" + AWS_KEY
    logger.user_input("redacted " + "[CRED:cred_x]", raw=raw_text)
    text = logger.path.read_text()
    assert AWS_KEY not in text
    assert "[CRED:cred_x]" in text


def test_forensic_payload_encrypted_and_linked(logger, config):
    raw_text = "token: " + AWS_KEY
    logger.user_input("redacted-only", raw=raw_text)
    entry = logger.last_entry()
    ref = entry["payload"]["_forensic"]
    assert ref["encryption_version"] == 1
    payload_path = logger.path.parent / ref["path"]
    blob = payload_path.read_bytes()
    assert AWS_KEY not in blob.decode(errors="replace")
    assert b'"version":1' in blob
    from halgate.crypto import NativeCrypto
    out = NativeCrypto(config.audit.encryption_key_file).decrypt_sync(
        blob, f"forensic:{logger._instance_id}:{logger.session_id}:{entry['seq']}").decode()
    assert AWS_KEY in out


def test_tamper_detection(logger, config):
    logger.session_start([], "llm", resumed=False)
    logger.tool_call("x", {}, "eng-01")
    with logger.path.open() as f:
        lines = f.readlines()
    entry = json.loads(lines[1])
    entry["payload"]["tool"] = "evil"
    lines[1] = json.dumps(entry) + "\n"
    logger.path.write_text("".join(lines))
    ok, broken, msg = verify_chain(logger.path)
    assert not ok and broken == 2


def test_reorder_detection(logger):
    logger.session_start([], "llm", resumed=False)
    logger.tool_call("a", {}, "e")
    logger.tool_call("b", {}, "e")
    with logger.path.open() as f:
        lines = f.readlines()
    lines[1], lines[2] = lines[2], lines[1]
    logger.path.write_text("".join(lines))
    ok, _, _ = verify_chain(logger.path)
    assert not ok


def test_no_forensic_for_clean_raw(logger):
    logger.tool_result("read_file", {"data": "clean"}, 1.0, False,
                       raw={"data": "clean"})
    entry = logger.last_entry()
    assert "_forensic" not in entry["payload"]


def test_rotation_keeps_chain(config, instance_id, tmp_path, monkeypatch):
    config.audit.rotate_bytes = 600  # force rotation quickly
    lg = AuditLogger(config.audit, "sess-rot", instance_id)
    for i in range(40):
        lg.tool_call("t", {"i": i, "pad": "x" * 60}, "eng-01")
    ok, broken, msg = verify_chain(lg.path)
    assert ok, msg
    events = replay.load_events(lg.path)
    assert len(events) >= 1
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))  # contiguous


def test_search_filters(logger):
    logger.tool_call("shell", {"command": "nmap x"}, "eng-01")
    logger.tool_call("grep", {"pattern": "x"}, "eng-02")
    found = replay.search(logger.path, event="tool_call", key="tool",
                          value="grep")
    assert len(found) == 1 and found[0]["payload"]["engagement_id"] == "eng-02"


def test_encrypt_failure_is_fail_closed(broken_gpg_config, instance_id):
    lg = AuditLogger(broken_gpg_config.audit, "sess-fc", instance_id)
    with pytest.raises(ForensicEncryptionError):
        lg.user_input("redacted", raw="key=" + AWS_KEY)
    # and nothing plaintext landed in the operational log afterwards
    content = lg.path.read_text() if lg.path.exists() else ""
    assert AWS_KEY not in content


def test_forensic_failure_does_not_consume_audit_sequence(logger, monkeypatch):
    original = logger._encrypt_forensic_payload

    def fail(*_args, **_kwargs):
        raise ForensicEncryptionError("test encryption failure")

    monkeypatch.setattr(logger, "_encrypt_forensic_payload", fail)
    with pytest.raises(ForensicEncryptionError):
        logger.user_input("redacted", raw="key=" + AWS_KEY)
    monkeypatch.setattr(logger, "_encrypt_forensic_payload", original)
    logger.user_input("clean")
    assert logger.last_entry()["seq"] == 1


def test_decrypt_payload_round_trip_and_audit_event(logger, config, instance_id):
    import asyncio
    from halgate.audit.replay import decrypt_payload
    logger.session_start([], "llm", resumed=False)
    raw_text = "token: " + AWS_KEY
    logger.user_input("redacted", raw=raw_text)  # forensic payload at seq 2
    out = asyncio.run(decrypt_payload(
        logger.path, config.audit, instance_id, "sess-audit-1", 2, logger))
    assert AWS_KEY in out
    # Decrypting is itself audited as a secret_reveal access event
    reveal = [e for e in replay.load_events(logger.path)
              if e["event"] == "secret_reveal"]
    assert len(reveal) == 1
    assert reveal[0]["payload"]["cred_id"] == "seq:2"
    ok, _, msg = verify_chain(logger.path)
    assert ok, msg


def test_decrypt_payload_missing_seq_raises(logger, config, instance_id):
    import asyncio
    from halgate.audit.replay import decrypt_payload
    from halgate.errors import EncryptionError
    logger.session_start([], "llm", resumed=False)
    with pytest.raises(EncryptionError):
        asyncio.run(decrypt_payload(
            logger.path, config.audit, instance_id, "sess-audit-1", 99, None))


def test_cli_audit_decrypt(config, instance_id, capsys):
    from types import SimpleNamespace
    from halgate.audit.logger import AuditLogger
    from halgate.cli import _handle_audit
    logger = AuditLogger(config.audit, "sess-cli-1", instance_id)
    logger.session_start([], "llm", resumed=False)
    logger.user_input("redacted", raw="token: " + AWS_KEY)
    args = SimpleNamespace(audit_cmd="decrypt", session_id="sess-cli-1",
                           seq=2, event=None, key=None)
    _handle_audit(args, config, instance_id)
    out = capsys.readouterr().out
    assert AWS_KEY in out
    reveal = [e for e in replay.load_events(logger.path)
              if e["event"] == "secret_reveal"]
    assert len(reveal) == 1
