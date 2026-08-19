"""Shared error types."""


class HarnessError(Exception):
    """Base error for the harness."""


class ConfigError(HarnessError):
    pass


class ScopeError(HarnessError):
    pass


class GpgError(HarnessError):
    pass


class ForensicEncryptionError(HarnessError):
    """Raised when a secret-bearing payload cannot be encrypted (fail-closed)."""


class StoppedError(HarnessError):
    """Raised when the session is action-locked (panic stop)."""


class BudgetExhaustedError(HarnessError):
    pass
