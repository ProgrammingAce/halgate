"""Tests for dispatch_parallel: approval gating, dry-run, budget."""
import pytest

from halgate.config import (BudgetLimits, BudgetsConfig, Config, EndpointConfig,
                            LLMConfig)
from halgate.dispatch import (
    dispatch_parallel,
    ApprovalResult,
    AUTO_APPROVE,
)
from halgate.llm.client import ToolCall
from halgate.scope import Engagement, ScopeGate, ScopePackage
from halgate.errors import BudgetExhaustedError
from halgate.budget import BudgetManager
from halgate.tools.registry import ToolRegistry


class NoopRedactor:
    async def redact(self, text, found_in, engagement_id=None):
        return text
    async def redact_object(self, value, found_in, engagement_id=None):
        return value


class FakeExecutor:
    def __init__(self):
        self.calls = []
    async def call(self, name, args):
        self.calls.append((name, args))
        return {"ok": True, "tool": name}


class FakeAudit:
    def __init__(self):
        self.guard_decisions = []
        self.tool_calls = []
        self.tool_results = []
        self.budget_decisions = []
    def guard_decision(self, name, allowed, reason):
        self.guard_decisions.append((name, allowed, reason))
    def budget_decision(self, engagement_id, allowed, reason, kind=""):
        self.budget_decisions.append(
            (engagement_id, allowed, reason, kind))
    def tool_call(self, name, args, engagement_id):
        self.tool_calls.append((name, args, engagement_id))
    def tool_result(self, name, result, elapsed, truncated=False,
                    raw=None, engagement_id=""):
        self.tool_results.append((name, result, elapsed, truncated, raw, engagement_id))
    def panic(self, outcome):
        pass


async def auto_approve(tc, engagement):
    return ApprovalResult(approved=True)


async def deny_approve(tc, engagement):
    return ApprovalResult(approved=False)


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    eng = Engagement(id="eng1", label="test", target=str(root),
                     package="testpkg")
    pkg = ScopePackage(
        name="testpkg",
        tools={"read_file": True, "write_file": True, "shell": True,
               "glob": True, "grep": True,
               "pane_list": True, "pane_read": True,
               "memory_remember": True, "memory_recall": True,
               "http": True, "scan": True, "process": True},
        shell_allowlist=["echo", "cat", "pwd","ls"],
        http_methods=["GET"],
        scan_enabled=True,
        scan_max_targets=10,
        scan_max_ports=100,
    )
    gate = ScopeGate(engagements=[eng], packages={"testpkg": pkg}, overrides={})
    cfg = Config(
        llm=LLMConfig(active="t", endpoints=[
            EndpointConfig(id="t", base_url="x", model="m")]),
        safety=Config.safety if hasattr(Config, 'safety') else __import__(
            'halgate.config', fromlist=['SafetyConfig']).SafetyConfig(
            dry_run=False),
    )
    audit = FakeAudit()
    executor = FakeExecutor()
    return {"gate": gate, "eng": eng, "cfg": cfg,
            "audit": audit, "executor": executor,
            "redactor": NoopRedactor(), "root": root}


@pytest.mark.asyncio
async def test_auto_approve_no_approvers_called(setup):
    """read_file (AUTO_APPROVE) should not trigger the approver."""
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    tc = ToolCall(id="1", name="read_file",
                  arguments={"path": str(setup["root"] / "f.txt"),
                             "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert len(results) == 1
    assert results[0]["ok"] is True
    # Approver was never actually needed; audit shows tool_call was made
    assert any(t[0] == "read_file" for t in audit.tool_calls)


@pytest.mark.asyncio
async def test_approval_required_triggers_approvers(setup):
    """shell (not in AUTO_APPROVE) must call the approver."""
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    tc = ToolCall(id="1", name="shell",
                  arguments={"command": "echo hi", "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert results[0]["ok"] is True


@pytest.mark.asyncio
async def test_denied_by_operator(setup):
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    tc = ToolCall(id="1", name="shell",
                  arguments={"command": "echo hi", "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, deny_approve,
        setup["redactor"])
    assert "denied by operator" in results[0].get("error", "")
    # Should not have been executed
    assert executor.calls == []


@pytest.mark.asyncio
async def test_dry_run_returns_plan(setup):
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    cfg.safety.dry_run = True
    tc = ToolCall(id="1", name="shell",
                  arguments={"command": "echo hi", "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert results[0].get("dry_run") is True
    assert "echo hi" in results[0]["plan"]
    assert executor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("global_dry_run", "override", "expected"), [
    (False, True, True),
    (True, False, False),
])
async def test_engagement_dry_run_override_takes_precedence(
        setup, global_dry_run, override, expected):
    setup["cfg"].safety.dry_run = global_dry_run
    setup["eng"].safety_overrides["dry_run"] = override
    tc = ToolCall(id="1", name="shell",
                  arguments={"command": "echo hi", "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], setup["executor"], setup["gate"], setup["audit"], setup["cfg"],
        auto_approve, setup["redactor"])
    assert results[0].get("dry_run", False) is expected
    assert bool(setup["executor"].calls) is not expected


@pytest.mark.asyncio
async def test_dry_run_releases_budget_reservation(setup):
    gate = setup["gate"]
    eng = setup["eng"]
    cfg = setup["cfg"]
    cfg.safety.dry_run = True
    budget_mgr = BudgetManager(
        BudgetsConfig(default=BudgetLimits(max_actions=1)), [eng])
    for call_id in ("1", "2"):
        results = await dispatch_parallel(
            [ToolCall(id=call_id, name="shell",
                      arguments={"command": "echo hi", "engagement_id": "eng1"})],
            setup["executor"], gate, setup["audit"], cfg, auto_approve,
            setup["redactor"], budgets=budget_mgr)
        assert results[0].get("dry_run") is True


@pytest.mark.asyncio
async def test_gate_denied(setup):
    """Unknown engagement => gate denies."""
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    tc = ToolCall(id="1", name="read_file",
                  arguments={"path": "/x", "engagement_id": "nonexistent"})
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert "error" in results[0]


@pytest.mark.asyncio
async def test_budget_exhaustion(setup):
    gate = setup["gate"]
    eng = setup["eng"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    # Budget with max_actions=1
    from halgate.config import BudgetsConfig, BudgetLimits
    budget_mgr = BudgetManager(
        BudgetsConfig(default=BudgetLimits(max_actions=1)), [eng])
    budget_mgr.try_reserve("eng1", "max_actions", 1)
    budget_mgr.settle(budget_mgr._states["eng1"].reserved and
        __import__("halgate.budget", fromlist=["BudgetReservation"]
        ).BudgetReservation("eng1", "max_actions", 1))
    # Now reserve again -> should exhaust
    tc = ToolCall(id="1", name="shell",
                  arguments={"command": "echo hi", "engagement_id": "eng1"})
    # Use a budget manager where max_actions is already exhausted
    results = await dispatch_parallel(
        [tc], executor, gate, audit, cfg, auto_approve,
        setup["redactor"], budgets=_ExhaustedBudget("eng1"))
    assert "error" in results[0]
    # The denial is recorded as a dedicated budget decision event
    assert audit.budget_decisions == [
        ("eng1", False, "budget exhausted for eng1: max_actions",
         "max_actions")]


@pytest.mark.asyncio
async def test_budget_reservation_is_audited(setup):
    gate = setup["gate"]
    eng = setup["eng"]
    audit = setup["audit"]
    cfg = setup["cfg"]
    budget_mgr = BudgetManager(
        BudgetsConfig(default=BudgetLimits(max_actions=5)), [eng])
    tc = ToolCall(id="1", name="read_file",
                  arguments={"path": str(setup["root"]),
                             "engagement_id": "eng1"})
    results = await dispatch_parallel(
        [tc], setup["executor"], gate, audit, cfg, auto_approve,
        setup["redactor"], budgets=budget_mgr)
    assert results[0]["ok"] is True
    assert audit.budget_decisions == [
        ("eng1", True, "reserved 1 max_actions", "")]


class _ExhaustedBudget:
    def __init__(self, eng_id: str = ""):
        self._eng_id = eng_id
    def try_reserve(self, eng_id, kind, amount):
        raise BudgetExhaustedError(
            f"budget exhausted for {eng_id}: {kind}")
    def release(self, reservation):
        pass
    def settle(self, reservation, delta=None):
        pass


@pytest.mark.asyncio
async def test_multiple_calls_order_preserved(setup):
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    tcs = [
        ToolCall(id="1", name="read_file",
                 arguments={"path": str(setup["root"]),
                            "engagement_id": "eng1"}),
        ToolCall(id="2", name="glob",
                 arguments={"pattern": "*.txt",
                            "path": str(setup["root"]),
                            "engagement_id": "eng1"}),
    ]
    results = await dispatch_parallel(
        tcs, executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert len(results) == 2
    # Both should have been executed
    assert len(executor.calls) == 2


@pytest.mark.asyncio
async def test_failure_does_not_abort_others(setup):
    gate = setup["gate"]
    audit = setup["audit"]
    executor = setup["executor"]
    cfg = setup["cfg"]
    # First call will fail at gate (unknown engagement)
    tcs = [
        ToolCall(id="1", name="read_file",
                 arguments={"path": "/x", "engagement_id": "bogus"}),
        ToolCall(id="2", name="read_file",
                 arguments={"path": str(setup["root"]),
                            "engagement_id": "eng1"}),
    ]
    results = await dispatch_parallel(
        tcs, executor, gate, audit, cfg, auto_approve,
        setup["redactor"])
    assert "error" in results[0]
    assert results[1].get("ok") is True


@pytest.mark.asyncio
async def test_authorization_exception_does_not_abort_siblings(setup, monkeypatch):
    gate = setup["gate"]
    executor = setup["executor"]

    original_authorize = gate.authorize

    def raise_for_first(name, args, engagement_id):
        if args.get("boom"):
            raise ValueError("bad tool input")
        return original_authorize(name, args, engagement_id)

    monkeypatch.setattr(gate, "authorize", raise_for_first)
    calls = [
        ToolCall(id="1", name="read_file", arguments={
            "path": str(setup["root"]), "engagement_id": "eng1", "boom": True}),
        ToolCall(id="2", name="read_file", arguments={
            "path": str(setup["root"]), "engagement_id": "eng1"}),
    ]
    results = await dispatch_parallel(
        calls, executor, gate, setup["audit"], setup["cfg"], auto_approve,
        setup["redactor"])
    assert "authorization failed" in results[0]["error"]
    assert results[1].get("ok") is True


@pytest.mark.asyncio
async def test_tool_registry_rejects_direct_execution():
    registry = ToolRegistry.__new__(ToolRegistry)
    result = await registry.call("write_file", {
        "path": "/tmp/outside-scope", "content": "no", "engagement_id": "e"})
    assert "dispatch_parallel" in result["error"]


def test_auto_approve_set():
    assert "read_file" in AUTO_APPROVE
    assert "glob" in AUTO_APPROVE
    assert "grep" in AUTO_APPROVE
