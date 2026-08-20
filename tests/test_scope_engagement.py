"""Engagement matching semantics: path vs network targets, component safety."""
from __future__ import annotations

import pytest

from halgate.errors import ScopeError
from halgate.scope import Engagement


def test_invalid_execution_mode_rejected():
    with pytest.raises(ScopeError):
        Engagement(id="e", label="l", target="/x", package="defensive",
                   execution_mode="weird")


def test_invalid_status_rejected():
    with pytest.raises(ScopeError):
        Engagement(id="e", label="l", target="/x", package="defensive",
                   status="zombie")


def test_path_target_matches_subpaths(tmp_path):
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    e = Engagement(id="e", label="l", target=str(root), package="read-only")
    assert e.matches_target(str(root / "src" / "a.py"))
    assert not e.matches_target(str(tmp_path / "other"))


def test_path_prefix_confusion_on_engagement(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    sibling = tmp_path / "proj.evil"
    sibling.mkdir()
    e = Engagement(id="e", label="l", target=str(root), package="read-only")
    assert not e.matches_target(str(sibling / "file.txt"))


def test_network_target_matches():
    e = Engagement(id="e", label="l", target="10.20.0.0/16", package="offensive")
    assert e.matches_target("10.20.3.4")
    assert not e.matches_target("10.21.0.1")


def test_single_ip_target():
    e = Engagement(id="e", label="l", target="192.168.1.5", package="defensive")
    assert e.matches_target("192.168.1.5")
    assert not e.matches_target("192.168.1.6")


def test_hostname_exact_fallback():
    e = Engagement(id="e", label="l", target="host.example.corp", package="defensive")
    assert e.matches_target("host.example.corp")
    assert not e.matches_target("host.example.com")
