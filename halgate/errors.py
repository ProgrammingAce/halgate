"""Shared error types."""


class HalgateError(Exception):
    """Base error for the halgate."""


class ConfigError(HalgateError):
    pass


class ScopeError(HalgateError):
    pass


class GpgError(HalgateError):
    pass


class ForensicEncryptionError(HalgateError):
    """Raised when a secret-bearing payload cannot be encrypted (fail-closed)."""


class StoppedError(HalgateError):
    """Raised when the session is action-locked (panic stop)."""


class BudgetExhaustedError(HalgateError):
    pass
