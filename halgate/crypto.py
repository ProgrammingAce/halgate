"""Native, portable encryption for Halgate secret-bearing state.

The root key is random and stored only in an encrypted envelope.  Operators
retain the recovery phrase; plaintext keys live only in this process.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import EncryptionError

_AAD = b"halgate-root-key-v1"
_WORDS = """amber anchor apple apron arch arrow atlas autumn bamboo barrel beacon berry
birch blue boat breeze brook cactus candle canyon cedar cherry cloud coast comet
copper coral crane creek crystal dawn delta desert drift ember falcon fern field
flame forest fossil frost galaxy garden glacier harbor hawk hazel honey island
ivory jasmine juniper kestrel lagoon lantern leaf lemon lilac lotus marble meadow
mercury mist moon moss mountain nectar night north oak ocean olive onyx orchid
otter pebble pine plum prairie quartz quiet raven reef ridge river robin rose sable
saffron sage sand scarlet shadow shore silver sky solar sparrow spruce star stone
summit sun swift tide timber topaz trail valley velvet violet wave west willow wind
winter wren zephyr""".split()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def generate_recovery_phrase() -> str:
    """Return 24 random words; this is displayed only during key creation."""
    return " ".join(secrets.choice(_WORDS) for _ in range(24))


class NativeCrypto:
    _cache: dict[Path, bytes] = {}

    def __init__(self, key_file: str | Path, phrase_provider=None):
        self.path = Path(key_file).expanduser().resolve()
        self._phrase_provider = phrase_provider or self._prompt

    @staticmethod
    def _prompt() -> str:
        return getpass.getpass("Halgate recovery phrase: ")

    @staticmethod
    def _derive(phrase: str, salt: bytes) -> bytes:
        if not phrase or len(phrase.split()) < 12:
            raise EncryptionError("a valid Halgate recovery phrase is required")
        return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
            phrase.encode("utf-8"))

    @classmethod
    def initialize(cls, key_file: str | Path, phrase: str | None = None) -> str:
        path = Path(key_file).expanduser().resolve()
        if path.exists():
            raise EncryptionError(f"refusing to overwrite existing key file: {path}")
        phrase = phrase or generate_recovery_phrase()
        salt, nonce, root = os.urandom(16), os.urandom(12), os.urandom(32)
        wrapped = AESGCM(cls._derive(phrase, salt)).encrypt(nonce, root, _AAD)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"version": 1, "kdf": "scrypt", "salt": _b64(salt),
                       "nonce": _b64(nonce), "ciphertext": _b64(wrapped)}, f,
                      separators=(",", ":"))
        cls._cache[path] = root
        return phrase

    def _root_key(self) -> bytes:
        if self.path in self._cache:
            return self._cache[self.path]
        if not self.path.exists():
            raise EncryptionError("native encryption key is not initialized; run 'halgate key init'")
        try:
            obj = json.loads(self.path.read_text())
            if obj.get("version") != 1 or obj.get("kdf") != "scrypt":
                raise ValueError("unsupported key envelope")
            phrase = self._phrase_provider()
            root = AESGCM(self._derive(phrase, _unb64(obj["salt"]))).decrypt(
                _unb64(obj["nonce"]), _unb64(obj["ciphertext"]), _AAD)
            if len(root) != 32:
                raise ValueError("invalid root key")
        except EncryptionError:
            raise
        except Exception as e:
            raise EncryptionError("could not unlock native encryption key") from e
        self._cache[self.path] = root
        return root

    def encrypt_sync(self, plaintext: bytes, context: str) -> bytes:
        try:
            nonce = os.urandom(12)
            ciphertext = AESGCM(self._root_key()).encrypt(
                nonce, plaintext, context.encode("utf-8"))
            return json.dumps({"version": 1, "nonce": _b64(nonce),
                               "ciphertext": _b64(ciphertext)},
                              separators=(",", ":")).encode()
        except EncryptionError:
            raise
        except Exception as e:
            raise EncryptionError("native encryption failed") from e

    def decrypt_sync(self, envelope: bytes | str, context: str) -> bytes:
        try:
            obj = json.loads(envelope)
            if obj.get("version") != 1:
                raise ValueError("unsupported ciphertext version")
            return AESGCM(self._root_key()).decrypt(
                _unb64(obj["nonce"]), _unb64(obj["ciphertext"]),
                context.encode("utf-8"))
        except EncryptionError:
            raise
        except Exception as e:
            raise EncryptionError("native ciphertext is invalid, tampered with, or uses the wrong recovery phrase") from e

    @classmethod
    def backup(cls, source: str | Path, destination: str | Path) -> None:
        src, dest = Path(source).resolve(), Path(destination).resolve()
        if not src.exists():
            raise EncryptionError("native encryption key is not initialized")
        if dest.exists():
            raise EncryptionError(f"refusing to overwrite existing backup: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    @classmethod
    def archive_and_replace(cls, key_file: str | Path) -> tuple[str, Path]:
        """Archive an existing envelope, then create a replacement key.

        The archive stays beside the configured key so a recovered old phrase
        can still be used to access records written under the prior key.
        """
        path = Path(key_file).expanduser().resolve()
        if not path.is_file():
            raise EncryptionError("native encryption key does not exist")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive = path.with_name(f"{path.name}.{stamp}.bak")
        if archive.exists():
            raise EncryptionError(f"refusing to overwrite key archive: {archive}")
        try:
            os.replace(path, archive)
            os.chmod(archive, 0o600)
            cls._cache.pop(path, None)
            phrase = cls.initialize(path)
        except Exception as e:
            if archive.exists():
                if path.exists():
                    path.unlink()
                os.replace(archive, path)
            if isinstance(e, EncryptionError):
                raise
            raise EncryptionError("could not archive and replace native key") from e
        return phrase, archive

    @classmethod
    def restore(cls, source: str | Path, destination: str | Path, phrase: str,
                replace: bool = False) -> None:
        src, dest = Path(source).resolve(), Path(destination).resolve()
        if dest.exists() and not replace:
            raise EncryptionError(f"refusing to overwrite existing key file: {dest}")
        # Do not let an already-unlocked source key bypass recovery-phrase
        # verification during restore.
        cls._cache.pop(src, None)
        probe = cls(src, lambda: phrase)
        probe._root_key()  # authenticate before copying
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
        dest.write_bytes(src.read_bytes())
        os.chmod(dest, 0o600)
