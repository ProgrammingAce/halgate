"""Audit CLI helpers: replay, verify, search, forensic decrypt access."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import AuditConfig
from ..errors import GpgError
from ..openpgp import backend_from_config


def session_log_path(audit_dir: str, instance_id: str | None,
                     session_id: str) -> Path:
    """Resolve the session log; instance_id optional (searches all if None)."""
    base = Path(audit_dir)
    if instance_id:
        p = base / instance_id / f"{session_id}.jsonl"
        if not p.exists():
            raise FileNotFoundError(f"no audit log for session {session_id} "
                                    f"in instance {instance_id}")
        return p
    for instance_dir in sorted(base.iterdir()):
        candidate = instance_dir / f"{session_id}.jsonl"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"no audit log for session {session_id}")


def load_events(log_path: Path) -> list[dict]:
    g2, g1 = log_path.with_suffix(".jsonl.2"), log_path.with_suffix(".1")
    events: list[dict] = []
    for gen in (g2, g1, log_path):
        if not gen.exists():
            continue
        with gen.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        raise ValueError(
                            f"malformed audit event in {gen}: {e}") from e
    return events


def replay(log_path: Path, event_filter: str | None = None,
           tool_filter: str | None = None) -> list[dict]:
    """Redacted events in order, optionally filtered. No forensic decryption."""
    events = load_events(log_path)
    if event_filter:
        events = [e for e in events if e.get("event") == event_filter]
    if tool_filter:
        events = [e for e in events
                  if e.get("payload", {}).get("tool") == tool_filter]
    return events


def verify(log_path: Path) -> tuple[bool, int | None, str]:
    from .logger import verify_chain
    return verify_chain(log_path)


def search(log_path: Path, event: str = "", key: str = "",
           value: str = "") -> list[dict]:
    events = load_events(log_path)
    out = []
    for e in events:
        if event and e.get("event") != event:
            continue
        if key and str(e.get("payload", {}).get(key, "")) != value:
            continue
        out.append(e)
    return out


async def decrypt_payload(log_path: Path, audit_cfg: AuditConfig,
                          instance_id: str, session_id: str, seq: int,
                          logger) -> str:
    """Decrypt one forensic payload through the local GPG agent.

    Only the access event is logged (never plaintext to audit/LLM).
    """
    events = load_events(log_path)
    target = next((e for e in events if e.get("seq") == seq), None)
    if target is None:
        raise GpgError(f"no event with seq {seq}")
    ref = target.get("payload", {}).get("_forensic")
    if ref is None:
        raise GpgError(f"event {seq} has no forensic payload")
    base = log_path.parent
    payload_path = base / ref["path"]
    if not payload_path.exists():
        raise GpgError(f"forensic payload missing: {ref['path']}")
    gpg = backend_from_config(audit_cfg)
    blob = payload_path.read_bytes()
    plaintext = (await gpg.decrypt(blob)).decode(errors="replace")
    if logger is not None:
        logger.secret_reveal(f"seq:{seq}")
    return plaintext
