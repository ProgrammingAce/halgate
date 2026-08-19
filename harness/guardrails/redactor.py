"""Credential pattern detection and replacement (fail-closed via keystore).

The Redactor runs recursively on all user input, tool arguments/results,
memory writes, UI output, checkpoints, errors, and LLM messages before they
enter any plaintext store. Discovered secret values are retained only in the
OpenPGP-encrypted keystore addressed to the configured full recipient
fingerprint; if encryption fails, the call raises (fail-closed) so no
plaintext is persisted or forwarded.
"""
from __future__ import annotations

import re
from typing import Any

from ..errors import GpgError
from ..memory.keystore import KeyStore

CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b[Aa][Kk][Ii][Aa][0-9A-Z]{16}\b"), "aws_key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github_pat"),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "github_token"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "hex_key_256"),
    (re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[=:]\s*['\"]?(\S{4,})['\"]?"),
     "kv_credential"),
]


def _secret_value(match: re.Match) -> str:
    return match.group(match.lastindex) if match.lastindex else match.group(0)


def detect_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(pattern_name, secret_value)] for all matches. Detection only."""
    found: list[tuple[str, str]] = []
    for pattern, cred_type in CREDENTIAL_PATTERNS:
        for m in pattern.finditer(text):
            found.append((cred_type, _secret_value(m)))
    return found


def contains_secret(text: str) -> bool:
    return bool(detect_secrets(text))


def scan_object(value: Any) -> bool:
    """Recursively report whether any string in a JSON-like payload has a secret."""
    if isinstance(value, str):
        return contains_secret(value)
    if isinstance(value, dict):
        return any(scan_object(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(scan_object(v) for v in value)
    return False


class Redactor:
    def __init__(self, keystore: KeyStore):
        self._keystore = keystore

    async def redact(self, text: str, found_in: str,
                     engagement_id: str | None = None) -> str:
        """Replace all credential patterns with [CRED:short_id] placeholders."""
        if not isinstance(text, str) or not text:
            return text if isinstance(text, str) else ""

        result = text
        for pattern, cred_type in CREDENTIAL_PATTERNS:
            matches = list(pattern.finditer(result))
            if not matches:
                continue
            pieces: list[str] = []
            cursor = 0
            for match in matches:
                pieces.append(result[cursor:match.start()])
                value = _secret_value(match)
                # Fail-closed: if the keystore cannot encrypt, raise; the caller
                # aborts instead of persisting/forwarding the raw secret.
                short_id = await self._keystore.store(
                    cred_type, value, found_in, engagement_id)
                pieces.append(f"[CRED:{short_id}]")
                cursor = match.end()
            pieces.append(result[cursor:])
            result = "".join(pieces)
        return result

    async def redact_object(self, value: Any, found_in: str,
                            engagement_id: str | None = None) -> Any:
        """Recursively redact every string in a JSON-like tool payload."""
        if isinstance(value, str):
            return await self.redact(value, found_in, engagement_id)
        if isinstance(value, dict):
            return {k: await self.redact_object(v, found_in, engagement_id)
                    for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [await self.redact_object(v, found_in, engagement_id)
                    for v in value]
        return value
