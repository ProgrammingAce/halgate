"""Async GnuPG wrapper. Fail-closed: every failure raises GpgError.

Plaintext is passed only via stdin; the plaintext, passphrases, and full
recipient arguments never appear in an argv string that audit/UI code might
log (recipient is a configured fingerprint, passed positionally to gpg).
"""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess

from .errors import GpgError

_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_GPG_TIMEOUT_SECONDS = 30
_MAX_GPG_IO_BYTES = 64 * 1024 * 1024


class Gpg:
    def __init__(self, recipient: str, homedir: str | None = None,
                 executable: str = "gpg"):
        if not _FINGERPRINT_RE.match(recipient or ""):
            raise GpgError("GPG recipient must be a full 40-hex fingerprint")
        self.recipient = recipient.upper()
        self.homedir = homedir
        self.executable = executable

    def _base_args(self) -> list[str]:
        args = [self.executable, "--batch", "--quiet", "--no-tty",
                "--pinentry-mode", "loopback",
                "--max-output", str(_MAX_GPG_IO_BYTES)]
        if self.homedir:
            args += ["--homedir", self.homedir]
        return args

    async def _run(self, args: list[str], stdin: bytes | None = None
                   ) -> tuple[int, bytes, bytes]:
        if shutil.which(self.executable) is None and "/" not in self.executable:
            raise GpgError(f"gpg executable not found: {self.executable}")
        if stdin is not None and len(stdin) > _MAX_GPG_IO_BYTES:
            raise GpgError("gpg input exceeds the 64 MiB safety limit")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(
                proc.communicate(stdin or b""), _GPG_TIMEOUT_SECONDS)
        except asyncio.TimeoutError as e:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            raise GpgError("gpg operation timed out") from e
        except OSError as e:
            raise GpgError(f"gpg invocation failed: {e}") from e
        if len(out) > _MAX_GPG_IO_BYTES or len(err) > _MAX_GPG_IO_BYTES:
            raise GpgError("gpg output exceeds the 64 MiB safety limit")
        return proc.returncode or 0, out, err

    async def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt to the configured recipient; armored ASCII output."""
        args = self._base_args() + ["--yes", "--trust-model", "always",
                                    "--armor", "--encrypt", "--recipient",
                                    self.recipient]
        rc, out, err = await self._run(args, plaintext)
        if rc != 0 or b"BEGIN PGP MESSAGE" not in out:
            raise GpgError(f"gpg encryption failed (rc={rc}): {err[:200]!r}")
        return out

    def encrypt_sync(self, plaintext: bytes) -> bytes:
        """Synchronous encryption for audit/redaction paths; fail closed."""
        if len(plaintext) > _MAX_GPG_IO_BYTES:
            raise GpgError("gpg input exceeds the 64 MiB safety limit")
        if shutil.which(self.executable) is None and "/" not in self.executable:
            raise GpgError(f"gpg executable not found: {self.executable}")
        try:
            proc = subprocess.run(
                self._base_args() + ["--yes", "--trust-model", "always",
                                     "--armor", "--encrypt", "--recipient",
                                     self.recipient],
                input=plaintext, capture_output=True,
                timeout=_GPG_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise GpgError(f"gpg encryption unavailable (fail-closed): {e}") from e
        if (len(proc.stdout) > _MAX_GPG_IO_BYTES
                or len(proc.stderr) > _MAX_GPG_IO_BYTES):
            raise GpgError("gpg output exceeds the 64 MiB safety limit")
        if proc.returncode != 0 or b"BEGIN PGP MESSAGE" not in proc.stdout:
            raise GpgError(f"gpg encryption failed (rc={proc.returncode})")
        return proc.stdout

    async def decrypt(self, armored: bytes | str) -> bytes:
        if isinstance(armored, str):
            armored = armored.encode()
        args = self._base_args() + ["--yes", "--decrypt"]
        rc, out, _ = await self._run(args, armored)
        if rc != 0:
            raise GpgError("gpg decryption failed (local agent required)")
        return out

    async def verify_recipient(self) -> dict:
        """Confirm the configured fingerprint resolves to an encryption-capable
        public key. Returns non-secret metadata only."""
        args = self._base_args() + ["--with-colons", "--fixed-list-mode",
                                    "--list-keys", self.recipient]
        rc, out, err = await self._run(args)
        if rc != 0:
            raise GpgError(
                f"recipient {self.recipient} not found in keyring "
                f"(rc={rc}): {err[:200]!r}")
        colon = out.decode(errors="replace")
        fingerprint = None
        can_encrypt = False
        uid = ""
        for line in colon.splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                can_encrypt = "e" in fields[12] if len(fields) > 12 else False
            elif fields[0] == "fpr" and fingerprint is None:
                fingerprint = fields[9] if len(fields) > 9 else None
            elif fields[0] == "uid" and not uid:
                uid = fields[9] if len(fields) > 9 else ""
        if fingerprint is None or fingerprint.upper() != self.recipient:
            raise GpgError("listed fingerprint does not match configured recipient")
        if not can_encrypt:
            raise GpgError("recipient key is not capable of encryption")
        return {"fingerprint": fingerprint.upper(), "uid": uid, "can_encrypt": True}
