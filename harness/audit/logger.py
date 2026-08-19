"""Append-only, hash-chained operational audit log + encrypted forensics.

ALWAYS ON. Redacted data lives in the operational chain; full originals that
contain secrets are OpenPGP-encrypted to the configured full recipient
fingerprint in a separate forensic store. Plaintext secrets never enter the
operational log, LLM context, checkpoints, or UI.

Files:  <audit_dir>/<instance_id>/<session_id>.jsonl           (operations)
        <audit_dir>/<instance_id>/forensic/<session_id>/<seq>.gpg
Rotation at rotate_bytes: base -> .1 -> .2 (oldest dropped at max).

Hash chain: hash = SHA-256 of the canonical JSON of the entry without its own
`hash` field (including prev_hash). The chain spans generations, so rotated
files verify as one continuous chain.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import AuditConfig
from ..errors import ForensicEncryptionError
from ..openpgp import OpenPgpBackend, backend_from_config
from ..guardrails.redactor import scan_object


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class AuditLogger:
    def __init__(self, audit_cfg: AuditConfig, session_id: str,
                 instance_id: str, gpg: OpenPgpBackend | None = None):
        self._cfg = audit_cfg
        self._dir = Path(audit_cfg.dir) / instance_id
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / f"{session_id}.jsonl"
        self._forensic_dir = self._dir / "forensic" / session_id
        self._session = session_id
        self._seq = 0
        self._prev_hash = "0" * 64
        # Encryption is only needed when a raw payload is retained.  Do not
        # require a host GnuPG binary (or a configured PGPy key) merely to
        # start normal, redacted audit logging.
        self._gpg = gpg
        if self._path.exists():
            # Continue the chain after process restarts.
            last = self.last_entry()
            if last:
                self._prev_hash = last["hash"]
                self._seq = last["seq"]

    @property
    def path(self) -> Path:
        return self._path

    @property
    def session_id(self) -> str:
        return self._session

    # -- core ---------------------------------------------------------------

    def last_entry(self) -> dict | None:
        """Last entry across rotated generations (oldest -> newest)."""
        last = None
        g2 = self._path.with_suffix(".jsonl.2")
        g1 = self._path.with_suffix(".jsonl.1")
        for gen in (g2, g1, self._path):
            if not gen.exists():
                continue
            with gen.open() as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
        return last

    def last_seq(self) -> int:
        entry = self.last_entry()
        return int(entry["seq"]) if entry else 0

    def _encrypt_forensic_payload(self, event: str, raw: Any, seq: int) -> dict:
        """Encrypt the full event payload; return reference metadata only.

        Raises ForensicEncryptionError on any failure so the caller aborts
        before a raw secret can be retained or forwarded.
        """
        payload = {"event": event, "raw": raw, "ts": _now_iso()}
        blob = json.dumps(payload, separators=(",", ":")).encode()
        try:
            ciphertext = self._crypto_backend().encrypt_sync(blob)
        except Exception as e:
            raise ForensicEncryptionError(
                f"OpenPGP encryption unavailable; refusing to retain raw payload: {e}") from e
        target = self._forensic_dir / f"{seq:06d}.gpg"
        try:
            self._forensic_dir.mkdir(parents=True, exist_ok=True)
            target.write_bytes(ciphertext)
        except OSError as e:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise ForensicEncryptionError(
                f"unable to persist encrypted forensic payload: {e}") from e
        try:
            import os
            os.chmod(target, 0o600)
        except OSError:
            pass
        return {
            "path": str(target.relative_to(self._dir)),
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
            "recipient": self._crypto_backend().recipient,
        }

    def _crypto_backend(self) -> OpenPgpBackend:
        """Create crypto support only for an operation that requires it."""
        if self._gpg is None:
            self._gpg = backend_from_config(self._cfg)
        return self._gpg

    def _log(self, event: str, payload: dict, raw: Any = None) -> dict:
        seq = self._seq + 1
        entry = {
            "seq": seq,
            "ts": _now_iso(),
            "session": self._session,
            "event": event,
            "payload": payload,
            "prev_hash": self._prev_hash,
        }
        if raw is not None and self._cfg.forensic_enabled:
            payload["_forensic"] = self._encrypt_forensic_payload(
                event, raw, seq)
        elif raw is not None:
            payload["_forensic"] = {"skipped": True}
        raw_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(raw_json.encode()).hexdigest()
        entry["hash"] = digest
        with self._path.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True)
                    + "\n")
        self._seq = seq
        self._prev_hash = digest
        self._rotate_if_needed()
        return entry

    def _rotate_if_needed(self) -> None:
        limit = self._cfg.rotate_bytes
        if limit <= 0 or not self._path.exists():
            return
        if self._path.stat().st_size < limit:
            return
        g2, g1 = self._path.with_suffix(".jsonl.2"), self._path.with_suffix(".1")
        if g2.exists():
            g2.unlink()
        if g1.exists():
            g1.replace(g2)
        self._path.replace(g1)
        # Chain continues: new file's first prev_hash is last hash of old file.

    # -- event methods -------------------------------------------------------

    def session_start(self, engagements: list, llm_id: str, resumed: bool,
                      metadata: dict | None = None) -> None:
        self._log("session_start", {
            "engagements": engagements, "llm_id": llm_id, "resumed": resumed,
            "metadata": metadata or {},
        })

    def session_end(self, reason: str) -> None:
        self._log("session_end", {"reason": reason})

    def user_input(self, text: str, raw: str | None = None) -> None:
        self._log("user_input", {"text": text},
                  raw=raw if raw is not None else text)

    def llm_request(self, messages: list, model: str) -> None:
        self._log("llm_request", {"model": model,
                                  "messages": messages,
                                  "message_count": len(messages)})

    def llm_response(self, content: str, tool_calls: list,
                     tokens_in: int, tokens_out: int) -> None:
        self._log("llm_response", {
            "content": content,
            "tool_calls": [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                for tc in tool_calls
            ],
            "tokens_in": tokens_in, "tokens_out": tokens_out,
        })

    def tool_call(self, name: str, args: dict, engagement_id: str) -> None:
        self._log("tool_call", {"tool": name, "args": args,
                                "engagement_id": engagement_id})

    def tool_result(self, name: str, result: dict, elapsed_ms: float,
                    truncated: bool, raw: dict | None = None,
                    engagement_id: str | None = None) -> None:
        payload: dict = {"tool": name, "result": result,
                         "elapsed_ms": round(elapsed_ms, 1),
                         "truncated": truncated, "engagement_id": engagement_id}
        self._log("tool_result", payload,
                  raw=raw if raw is not None and scan_object(raw) else None)

    def guard_decision(self, tool: str, allowed: bool, reason: str,
                       engagement_id: str | None = None) -> None:
        self._log("guard_decision", {"tool": tool, "allowed": allowed,
                                     "reason": reason,
                                     "engagement_id": engagement_id})

    def budget_decision(self, engagement_id: str, allowed: bool, reason: str,
                        kind: str = "") -> None:
        self._log("budget_decision", {"engagement_id": engagement_id,
                                      "allowed": allowed, "reason": reason,
                                      "kind": kind})

    def pane_event(self, pane_id: str, action: str, detail: dict,
                   engagement_id: str | None = None) -> None:
        self._log("pane_event", {"pane_id": pane_id, "action": action,
                                 "detail": detail,
                                 "engagement_id": engagement_id})

    def memory_op(self, op: str, mem_id: str, detail: dict) -> None:
        self._log("memory_op", {"op": op, "id": mem_id, "detail": detail})

    def secret_reveal(self, cred_id: str) -> None:
        # Access event only; plaintext must never be recorded.
        self._log("secret_reveal", {"cred_id": cred_id})

    def secret_store(self, cred_id: str, cred_type: str,
                    engagement_id: str | None = None) -> None:
        """An operator stored a secret; record the id and type only."""
        self._log("secret_store", {"cred_id": cred_id, "type": cred_type,
                                   "engagement_id": engagement_id})

    def engagement_policy(self, engagement_id: str, action: str,
                          detail: dict, operator: str = "operator") -> None:
        """A per-engagement policy was changed (claim extensions, etc.)."""
        self._log("engagement_policy", {"engagement_id": engagement_id,
                                        "action": action,
                                        "detail": detail,
                                        "operator": operator})

    def jwt_signed(self, engagement_id: str, credential_id: str | None,
                   algorithm: str, claim_keys: list, ttl_seconds: int | None,
                   expires_at: int | None) -> None:
        """A JWT signing event: algorithm, claim keys, key reference,
        engagement, and expiry only — never the key or the token."""
        self._log("jwt_signed", {
            "engagement_id": engagement_id,
            "credential_id": credential_id,
            "algorithm": algorithm,
            "claim_keys": claim_keys,
            "ttl_seconds": ttl_seconds,
            "expires_at": expires_at,
        })

    def approval(self, tool: str, approved: bool, summarized: bool,
                 engagement_id: str | None = None) -> None:
        self._log("approval", {"tool": tool, "approved": approved,
                               "summarized": summarized,
                               "engagement_id": engagement_id})

    def error(self, exc: str) -> None:
        self._log("error", {"error": exc})

    def compact(self, turns: int, tokens_freed: int) -> None:
        self._log("compact", {"turns": turns, "tokens_freed": tokens_freed})

    def panic(self, outcome: dict) -> None:
        self._log("panic", outcome)

    def dry_run_plan(self, tool: str, plan: dict, engagement_id: str) -> None:
        self._log("dry_run_plan", {"tool": tool, "plan": plan,
                                   "engagement_id": engagement_id})

    def callback_endpoint_event(self, action: str, endpoint_id: str,
                                detail: dict,
                                engagement_id: str | None = None) -> None:
        """Lifecycle of an approved callback listener (bounded metadata only;
        captured callback payloads are recorded in tool result events)."""
        self._log("callback_endpoint", {"action": action,
                                        "endpoint_id": endpoint_id,
                                        "detail": detail,
                                        "engagement_id": engagement_id})

    def injection_warning(self, tool: str, patterns: list[str],
                          engagement_id: str | None = None) -> None:
        self._log("injection_warning", {"tool": tool, "patterns": patterns,
                                        "engagement_id": engagement_id})


def verify_chain(path: Path) -> tuple[bool, int | None, str]:
    """Verify the hash chain of one or more (rotated) generations.

    Returns (ok, broken_seq, message).
    """
    generations = []
    g2, g1 = path.with_suffix(".jsonl.2"), path.with_suffix(".1")
    for candidate in (g2, g1, path):
        if candidate.exists():
            generations.append(candidate)
    if not generations:
        return False, None, f"no audit file at {path}"
    seen = 0
    first = True
    prev_hash = "0" * 64
    expected_seq = None
    for gen in generations:
        with gen.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, None, f"malformed JSON: {e}"
                if first:
                    first = False
                    # The oldest surviving generation may begin mid-session
                    # (older generations rotated out). Tolerate a head link
                    # only when its own seq proves data preceded it.
                    expected_seq = int(entry["seq"])
                    if expected_seq == 1 and entry["prev_hash"] != "0" * 64:
                        return False, entry["seq"], "head prev_hash not zero"
                else:
                    if entry.get("seq") != expected_seq:
                        return False, entry.get("seq"), \
                            f"seq gap: expected {expected_seq}, " \
                            f"got {entry.get('seq')}"
                    if entry.get("prev_hash") != prev_hash:
                        return False, entry["seq"], "broken prev_hash link"
                own = entry.get("hash")
                check = {k: v for k, v in entry.items() if k != "hash"}
                digest = hashlib.sha256(
                    json.dumps(check, separators=(",", ":"),
                               sort_keys=True).encode()).hexdigest()
                if digest != own:
                    return False, entry["seq"], "entry hash mismatch (tampered)"
                prev_hash = own
                expected_seq += 1
                seen += 1
    return True, None, f"chain intact ({seen} entries)"
