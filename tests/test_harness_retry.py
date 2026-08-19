"""Transient endpoint failures should not abandon an in-progress tool turn."""

from types import SimpleNamespace

from harness.harness import Harness


def test_retryable_http_server_error() -> None:
    error = RuntimeError("provider failed")
    error.response = SimpleNamespace(status_code=500)  # type: ignore[attr-defined]
    assert Harness._is_retryable_endpoint_error(error) is True


def test_non_retryable_http_client_error() -> None:
    error = RuntimeError("bad request")
    error.response = SimpleNamespace(status_code=400)  # type: ignore[attr-defined]
    assert Harness._is_retryable_endpoint_error(error) is False
