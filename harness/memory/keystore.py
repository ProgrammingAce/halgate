"""Encrypted credential keystore (OpenPGP, fail-closed).

Stores detected credentials as GPG-encrypted records. Separate from memory
and never loaded into LLM context. The harness holds only the recipient's
public key; decryption happens via the local operator's GPG agent on
explicit reveal. Plaintext values are passed only through stdin and are never
written to any file, log, or audit record.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

from ..config import AuditConfig
from ..errors import GpgError
from ..openpgp import OpenPgpBackend, backend_from_config


class KeyStore:
    def __init__(self, cfg: AuditConfig, instance_id: str):
        self._path = Path(cfg.dir) / "secrets" / f"keystore.{instance_id}.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 without relying on process umask.
        fd = os.open(self._path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
        if os.access(self._path, os.F_OK):
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        # Do not start a crypto backend until a credential is actually stored
        # or revealed.  This keeps normal sessions usable when forensic
        # capture is disabled and no GnuPG executable is installed.
        self._cfg = cfg
        self._gpg: OpenPgpBackend | None = None
        self.recipient = cfg.gpg_recipient
        self._ready = False
        self._lock = asyncio.Lock()

    async def verify(self) -> dict:
        """Confirm the configured full fingerprint resolves to an
        encryption-capable public key. Returns no secret material."""
        result = await self._crypto_backend().verify_recipient()
        self._ready = True
        return result

    async def _ensure_ready(self) -> None:
        if self._ready:
            return
        await self.verify()

    def store_sync(self, cred_type: str, value: str, found_in: str,
                   engagement_id: str | None = None) -> str:
        """Synchronous entry point used by Redactor inside redaction passes.

        Runs gpg via a one-shot asyncio-free subprocess (small payload,
        bounded time). Fail-closed: any failure raises GpgError so the caller
        aborts instead of persisting/forwarding the raw secret.
        """
        existing = self._find(value)
        if existing:
            return existing
        ciphertext = self._crypto_backend().encrypt_sync(value.encode())
        short_id = "cred_" + uuid4().hex
        entry = {
            "id": short_id,
            "type": cred_type,
            "ciphertext": ciphertext.decode(),
            "ts": _now_iso(),
            "found_in": found_in,
            "engagement": engagement_id,
        }
        with self._path.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return short_id

    async def store(self, cred_type: str, value: str, found_in: str,
                    engagement_id: str | None = None) -> str:
        """Encrypt and store a credential. Returns opaque id (cred_<uuid>)."""
        async with self._lock:
            await self._ensure_ready()
            return await asyncio.to_thread(
                self.store_sync, cred_type, value, found_in, engagement_id)

    async def reveal(self, short_id: str) -> str | None:
        """Decrypt via local GPG agent. Caller audits access; plaintext never
        enters audit/LLM/memory."""
        entry = self._find_by_id(short_id)
        if entry is None:
            return None
        raw = entry["ciphertext"].encode()
        plaintext = await self._crypto_backend().decrypt(raw)
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as e:
            raise GpgError("decrypted credential is not valid UTF-8") from e

    def known_ids(self) -> list[dict]:
        """List stored credential ids with non-secret metadata only."""
        out: list[dict] = []
        if not self._path.exists():
            return out
        with self._path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                out.append({"id": obj.get("id"), "type": obj.get("type"),
                            "ts": obj.get("ts"),
                            "engagement": obj.get("engagement")})
        return out

    def _find_by_id(self, short_id: str) -> dict | None:
        if not self._path.exists():
            return None
        with self._path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("id") == short_id:
                    return obj
        return None

    def _find(self, value: str) -> str | None:
        """De-duplicate by content: locate the id of an already-stored value by
        decrypting candidates (keystores are small)."""
        if not self._path.exists():
            return None
        async def _match() -> str | None:
            with self._path.open() as f:
                lines = [l.strip() for l in f if l.strip()]
            for line in lines:
                obj = json.loads(line)
                try:
                    decrypted = (await self._crypto_backend().decrypt(
                        obj["ciphertext"].encode())).decode(errors="replace")
                except GpgError:
                    continue
                if decrypted == value:
                    return obj.get("id")
            return None
        # store_sync is synchronous; use a nested event-loop-safe check only
        # when no loop is running, otherwise skip de-dup (safe duplicate).
        try:
            asyncio.get_running_loop()
            return None  # inside a loop: skip dedup to avoid blocking
        except RuntimeError:
            return asyncio.run(_match())

    def _crypto_backend(self) -> OpenPgpBackend:
        """Create crypto support only at the point encryption is required."""
        if self._gpg is None:
            self._gpg = backend_from_config(self._cfg)
        return self._gpg

    def list(self) -> list[dict]:
        return self.known_ids()

    def rewrap(self, new_recipient: str) -> int:
        """Operator-only recipient rotation. Requires local decryption
        capability; audit counts/fingerprints only, never values."""
        raise NotImplementedError("rewrap requires interactive local agent; "
                                  "use `harness secret rotate-recipient`")


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().astimezone().isoformat(timespec="milliseconds")
