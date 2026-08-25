"""Encrypted credential keystore (native AEAD, fail-closed).

Stores detected credentials as encrypted records. Separate from memory and
never loaded into LLM context. Decryption requires the local operator's
recovery phrase on explicit reveal. Plaintext values are never
written to any file, log, or audit record.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

from ..config import AuditConfig
from ..crypto import NativeCrypto
from ..errors import EncryptionError


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
        # Do not request the recovery phrase until a credential is stored or
        # revealed, keeping normal sessions usable without secret access.
        self._cfg = cfg
        self._crypto: NativeCrypto | None = None
        self._instance_id = instance_id
        self._ready = False
        self._lock = asyncio.Lock()

    async def verify(self) -> dict:
        """Confirm the native key can be unlocked. Returns no secret material."""
        self._crypto_backend()._root_key()
        result = {"encryption_version": 1, "can_encrypt": True}
        self._ready = True
        return result

    async def _ensure_ready(self) -> None:
        if self._ready:
            return
        await self.verify()

    def store_sync(self, cred_type: str, value: str, found_in: str,
                   engagement_id: str | None = None) -> str:
        """Synchronous entry point used by Redactor inside redaction passes.

        Uses in-process AEAD for this small payload. Fail-closed: any failure raises EncryptionError so the caller
        aborts instead of persisting/forwarding the raw secret.
        """
        existing = self._find(value)
        if existing:
            return existing
        short_id = "cred_" + uuid4().hex
        ciphertext = self._crypto_backend().encrypt_sync(
            value.encode(), f"credential:{self._instance_id}:{short_id}")
        entry = {
            "id": short_id,
            "type": cred_type,
            "ciphertext": ciphertext.decode(),
            "encryption_version": 1,
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
        """Decrypt with the local recovery key. Caller audits access; plaintext never
        enters audit/LLM/memory."""
        entry = self._find_by_id(short_id)
        if entry is None:
            return None
        if entry.get("encryption_version") != 1:
            raise EncryptionError("legacy OpenPGP credentials are unsupported")
        raw = entry["ciphertext"].encode()
        plaintext = self._crypto_backend().decrypt_sync(
            raw, f"credential:{self._instance_id}:{short_id}")
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as e:
            raise EncryptionError("decrypted credential is not valid UTF-8") from e

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
                    decrypted = self._crypto_backend().decrypt_sync(
                        obj["ciphertext"].encode(),
                        f"credential:{self._instance_id}:{obj.get('id')}").decode(errors="replace")
                except EncryptionError:
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

    def _crypto_backend(self) -> NativeCrypto:
        """Create crypto support only at the point encryption is required."""
        if self._crypto is None:
            self._crypto = NativeCrypto(self._cfg.encryption_key_file)
        return self._crypto

    def list(self) -> list[dict]:
        return self.known_ids()


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().astimezone().isoformat(timespec="milliseconds")
