"""Safety boundaries for target-scoped session auto-approval."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from harness.dispatch import ApprovalResult
from harness.llm.client import ToolCall
from harness.scope import Engagement
from harness.tui import HarnessApp, _approval_requirement_reason, _exact_action_target


def _call(name: str, arguments: dict) -> ToolCall:
    return ToolCall(id="test", name=name, arguments=arguments)


def test_exact_host_is_eligible() -> None:
    assert _exact_action_target(_call(
        "scan", {"targets": ["192.168.4.132"]})) == "192.168.4.132"
    assert _exact_action_target(_call(
        "http", {"url": "https://Target.Example/api"})) == "target.example"
    assert _exact_action_target(_call(
        "shell", {"command": "nmap -Pn 192.168.4.132"})) == "192.168.4.132"
    assert _exact_action_target(_call(
        "jwt_sign", {"engagement_id": "eng-01"})) == "engagement-bound"


def test_ambiguous_or_network_targets_are_not_eligible() -> None:
    assert _exact_action_target(_call(
        "scan", {"targets": ["192.168.4.0/24"]})) is None
    assert _exact_action_target(_call(
        "scan", {"targets": ["192.168.4.132", "192.168.4.133"]})) is None
    assert _exact_action_target(_call(
        "shell", {"command": "nmap 192.168.4.132 192.168.4.133"})) is None


def test_non_network_tools_are_not_eligible_but_http_methods_are() -> None:
    assert _exact_action_target(_call(
        "write_file", {"path": "/tmp/out"})) is None
    assert _exact_action_target(_call(
        "http", {"method": "POST", "url": "http://192.168.4.132/api"})) == "192.168.4.132"


def test_approval_rationale_names_the_relevant_safety_boundary() -> None:
    assert "network probes" in _approval_requirement_reason(_call("scan", {}))
    assert "running process" in _approval_requirement_reason(
        _call("pane_write", {}))


@pytest.mark.asyncio
async def test_approve_all_covers_concurrent_endpoints_in_one_engagement() -> None:
    """One approval covers queued calls to any endpoint in its target scope."""
    app = object.__new__(HarnessApp)
    app._chat = None
    app._target_auto_approvals = set()
    app._approval_decision_lock = asyncio.Lock()
    app.h = SimpleNamespace(audit=MagicMock())
    callbacks = []
    app.push_screen = lambda screen, callback: callbacks.append(callback)

    engagement = Engagement("eng1", "target", "192.168.4.0/24", "pkg")
    calls = [
        _call("shell", {"command": "nmap -Pn 192.168.4.132"}),
        _call("shell", {"command": "nmap -Pn 192.168.4.133"}),
    ]
    first, second = [asyncio.create_task(app._approve_tool(call, engagement))
                     for call in calls]

    await asyncio.sleep(0)
    assert len(callbacks) == 1
    callbacks[0](ApprovalResult(
        approved=True, auto_approve_target="192.168.4.0/24"))

    decisions = await asyncio.gather(first, second)
    assert len(callbacks) == 1
    assert decisions[0].approved is True
    assert decisions[1].auto_approved is True
    assert decisions[1].auto_approve_target == "192.168.4.0/24"
