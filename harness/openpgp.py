"""OpenPGP backends for forensic encryption.

The GnuPG backend retains existing behavior.  The PGPy backend uses only
Python dependencies and explicit armored key files, so it does not need a
machine-wide GnuPG installation or keyring.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import AuditConfig
from .errors import GpgError
from .gpg import Gpg


class OpenPgpBackend(Protocol):
    recipient: str

    def encrypt_sync(self, plaintext: bytes) -> bytes: ...
    async def encrypt(self, plaintext: bytes) -> bytes: ...
    async def decrypt(self, armored: bytes | str) -> bytes: ...
    async def verify_recipient(self) -> dict: ...


class GpgBackend:
    def __init__(self, cfg: AuditConfig):
        self._gpg = Gpg(cfg.gpg_recipient, cfg.gpg_homedir, cfg.gpg_executable)
        self.recipient = self._gpg.recipient

    def encrypt_sync(self, plaintext: bytes) -> bytes:
        return self._gpg.encrypt_sync(plaintext)

    async def encrypt(self, plaintext: bytes) -> bytes:
        return await self._gpg.encrypt(plaintext)

    async def decrypt(self, armored: bytes | str) -> bytes:
        return await self._gpg.decrypt(armored)

    async def verify_recipient(self) -> dict:
        return await self._gpg.verify_recipient()


class FallbackOpenPgpBackend:
    """Prefer GnuPG, with PGPy as a fail-closed local fallback."""
    def __init__(self, primary: OpenPgpBackend, fallback: OpenPgpBackend):
        self._primary = primary
        self._fallback = fallback
        self.recipient = primary.recipient

    def _error(self, operation: str, primary: GpgError,
               fallback: GpgError) -> GpgError:
        return GpgError(
            f"OpenPGP {operation} failed with GnuPG and PGPy "
            f"(gpg: {primary}; pgpy: {fallback})")

    def encrypt_sync(self, plaintext: bytes) -> bytes:
        try:
            return self._primary.encrypt_sync(plaintext)
        except GpgError as primary_error:
            try:
                return self._fallback.encrypt_sync(plaintext)
            except GpgError as fallback_error:
                raise self._error("encryption", primary_error,
                                  fallback_error) from fallback_error

    async def encrypt(self, plaintext: bytes) -> bytes:
        try:
            return await self._primary.encrypt(plaintext)
        except GpgError as primary_error:
            try:
                return await self._fallback.encrypt(plaintext)
            except GpgError as fallback_error:
                raise self._error("encryption", primary_error,
                                  fallback_error) from fallback_error

    async def decrypt(self, armored: bytes | str) -> bytes:
        try:
            return await self._primary.decrypt(armored)
        except GpgError as primary_error:
            try:
                return await self._fallback.decrypt(armored)
            except GpgError as fallback_error:
                raise self._error("decryption", primary_error,
                                  fallback_error) from fallback_error

    async def verify_recipient(self) -> dict:
        try:
            return await self._primary.verify_recipient()
        except GpgError as primary_error:
            try:
                return await self._fallback.verify_recipient()
            except GpgError as fallback_error:
                raise self._error("recipient verification", primary_error,
                                  fallback_error) from fallback_error


class PGPyBackend:
    def __init__(self, cfg: AuditConfig):
        if not cfg.pgpy_public_key:
            raise GpgError("PGPy backend requires audit.pgpy_public_key")
        self.recipient = cfg.gpg_recipient.upper()
        self._public_path = Path(cfg.pgpy_public_key)
        self._private_path = Path(cfg.pgpy_private_key) if cfg.pgpy_private_key else None
        self._passphrase_env = cfg.pgpy_passphrase_env

    @staticmethod
    def _module():
        try:
            import pgpy
        except ImportError as e:
            raise GpgError("PGPy backend unavailable; install the 'PGPy' package") from e
        return pgpy

    def _public_key(self):
        pgpy = self._module()
        try:
            key, _ = pgpy.PGPKey.from_file(str(self._public_path))
        except (OSError, ValueError) as e:
            raise GpgError(f"unable to load PGPy public key: {e}") from e
        if not key.is_public or str(key.fingerprint).upper() != self.recipient:
            raise GpgError("PGPy public key fingerprint does not match configured recipient")
        self._validate_recipient_key(key)
        return key

    @staticmethod
    def _validate_recipient_key(key) -> None:
        """Reject unusable recipient keys before encrypting any payload."""
        from pgpy.constants import KeyFlags
        if key.is_expired:
            raise GpgError("PGPy recipient key is expired")
        if list(key.revocation_signatures):
            raise GpgError("PGPy recipient key is revoked")
        flags = key._get_key_flags()
        if not flags.intersection({KeyFlags.EncryptCommunications,
                                   KeyFlags.EncryptStorage}):
            raise GpgError("PGPy recipient key is not encryption-capable")

    @staticmethod
    def _preferences(key):
        """Select supported algorithms from the recipient's self-signature."""
        uid = next(iter(key.userids), None)
        if uid is None or uid.selfsig is None:
            raise GpgError("PGPy recipient key has no usable self-signature")
        cipher = next((item for item in uid.selfsig.cipherprefs
                       if item.is_supported), None)
        # PGPy exposes support probing for symmetric ciphers but not for its
        # CompressionAlgorithm enum. Selecting the recipient's first stated
        # preference avoids forcing an incompatible compression choice.
        compression = next(iter(uid.selfsig.compprefs), None)
        if cipher is None or compression is None:
            raise GpgError("PGPy recipient key has no supported encryption preferences")
        return cipher, compression

    def encrypt_sync(self, plaintext: bytes) -> bytes:
        pgpy = self._module()
        try:
            key = self._public_key()
            cipher, compression = self._preferences(key)
            message = pgpy.PGPMessage.new(plaintext, file=False,
                                          compression=compression)
            armored = str(key.encrypt(message, cipher=cipher)).encode()
        except Exception as e:
            raise GpgError(f"PGPy encryption failed (fail-closed): {e}") from e
        if b"BEGIN PGP MESSAGE" not in armored:
            raise GpgError("PGPy encryption failed (fail-closed): invalid armored output")
        return armored

    async def encrypt(self, plaintext: bytes) -> bytes:
        return await asyncio.to_thread(self.encrypt_sync, plaintext)

    async def decrypt(self, armored: bytes | str) -> bytes:
        return await asyncio.to_thread(self._decrypt_sync, armored)

    def _decrypt_sync(self, armored: bytes | str) -> bytes:
        if not self._private_path:
            raise GpgError("PGPy decryption requires audit.pgpy_private_key")
        pgpy = self._module()
        try:
            key, _ = pgpy.PGPKey.from_file(str(self._private_path))
            message = pgpy.PGPMessage.from_blob(armored)
            if key.is_protected:
                if not self._passphrase_env:
                    raise GpgError("PGPy private key is protected; configure pgpy_passphrase_env")
                passphrase = os.environ.get(self._passphrase_env)
                if not passphrase:
                    raise GpgError(f"PGPy passphrase environment variable is not set: {self._passphrase_env}")
                with key.unlock(passphrase):
                    value = key.decrypt(message).message
            else:
                value = key.decrypt(message).message
        except GpgError:
            raise
        except Exception as e:
            raise GpgError("PGPy decryption failed") from e
        return value.encode() if isinstance(value, str) else bytes(value)

    async def verify_recipient(self) -> dict:
        key = await asyncio.to_thread(self._public_key)
        return {"fingerprint": str(key.fingerprint).upper(), "uid": "",
                "can_encrypt": True}


@dataclass(frozen=True)
class GeneratedKeyPair:
    fingerprint: str
    public_key_path: Path
    private_key_path: Path


def generate_keypair(downloads_dir: Path, label: str, passphrase: str) -> GeneratedKeyPair:
    """Generate a protected RSA OpenPGP pair and export it to Downloads."""
    if len(passphrase) < 12:
        raise GpgError("key passphrase must be at least 12 characters")
    pgpy = PGPyBackend._module()
    from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                                PubKeyAlgorithm, SymmetricKeyAlgorithm)
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(label or "Halgate forensic key")
    key.add_uid(uid, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB])
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA512)
    downloads_dir.mkdir(parents=True, exist_ok=True)
    fingerprint = str(key.fingerprint).upper()
    stem = f"halgate-{fingerprint[-16:].lower()}"
    public_path = downloads_dir / f"{stem}-public.asc"
    private_path = downloads_dir / f"{stem}-private.asc"
    if public_path.exists() or private_path.exists():
        raise GpgError(f"refusing to overwrite existing key export: {stem}")
    try:
        public_path.write_text(str(key.pubkey))
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as private_file:
            private_file.write(str(key))
        os.chmod(public_path, 0o644)
    except OSError as e:
        for path in (public_path, private_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise GpgError(f"could not export generated key pair: {e}") from e
    return GeneratedKeyPair(fingerprint, public_path, private_path)


def backend_from_config(cfg: AuditConfig) -> OpenPgpBackend:
    if cfg.crypto_backend == "pgpy":
        return PGPyBackend(cfg)
    gpg = GpgBackend(cfg)
    # A configured PGPy public key provides a safe fallback when GnuPG is
    # unavailable or cannot use the host keyring.
    return (FallbackOpenPgpBackend(gpg, PGPyBackend(cfg))
            if cfg.pgpy_public_key else gpg)
