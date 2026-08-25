"""Shared error types."""


class HalgateError(Exception):
    """Base error for the halgate."""


class ConfigError(HalgateError):
    pass


class ScopeError(HalgateError):
    pass


class EncryptionError(HalgateError):
    """Native encryption is unavailable, invalid, or has been tampered with."""


class ForensicEncryptionError(HalgateError):
    """Raised when a secret-bearing payload cannot be encrypted (fail-closed)."""


class StoppedError(HalgateError):
    """Raised when the session is action-locked (panic stop)."""


class BudgetExhaustedError(HalgateError):
    pass
