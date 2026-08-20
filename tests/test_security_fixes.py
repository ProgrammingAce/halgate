"""Tests for security-critical bug fixes: budget mapping, findings seq,
nmap portid extraction, confidence cap, process session isolation."""
import inspect
import os
import shutil
import subprocess
import pytest

from harness.config import (
    Config, SafetyConfig, ScopePackage,
    BudgetsConfig, BudgetLimits, EvidenceConfig,
    EndpointConfig, LLMConfig, MemoryConfig,
    ProcessConfig,
)
from harness.scope import Engagement, ScopeGate
from harness.dispatch import (
    dispatch_parallel, BUDGET_KIND_BY_TOOL, _DEFAULT_BUDGET_KIND,
    ApprovalResult,
)
from harness.llm.client import ToolCall
from harness.evidence.findings import FindingStore
from harness.evidence.store import EvidenceStore
from harness.evidence.importers import import_nmap_xml
from harness.evidence.inventory import InventoryStore
from harness.memory.store import MemoryStore
from harness.process import ProcessManager


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
    def guard_decision(self, name, allowed, reason):
        self.guard_decisions.append((name, allowed, reason))
    def tool_call(self, name, args, engagement_id):
        self.tool_calls.append((name, args, engagement_id))
    def tool_result(self, name, result, elapsed, truncated=False,
                    raw=None, engagement_id=""):
        self.tool_results.append((name, result, elapsed, truncated, raw, engagement_id))


class TrackingBudget:
    def __init__(self, eng_id="e1"):
        self._eng_id = eng_id
        self.reserved_kinds: list[str] = []

    def try_reserve(self, eng_id, kind, amount):
        self.reserved_kinds.append(kind)
        return type("R", (), {
            "engagement_id": eng_id, "kind": kind, "amount": amount,
            "key": f"{eng_id}:{kind}",
        })()

    def release(self, reservation):
        pass

    def settle(self, reservation, delta=None):
        pass

    def status(self, eng_id):
        return {}


async def auto_approve(tc, engagement):
    return ApprovalResult(approved=True)


def _net_setup(tmp_path):
    """Network-scoped engagement for http/scan tests."""
    eng = Engagement(id="e1", label="nettest", target="10.0.0.0/8",
                     package="testpkg")
    pkg = ScopePackage(
        name="testpkg",
        tools={"read_file": True, "http": True, "scan": True,
               "shell": True, "glob": True, "grep": True,
               "write_file": True, "pane_list": True, "pane_read": True,
               "memory_remember": True, "memory_recall": True},
        http_methods=["GET"],
        scan_enabled=True,
        scan_max_targets=10,
        scan_max_ports=100,
    )
    gate = ScopeGate(engagements=[eng], packages={"testpkg": pkg}, overrides={})
    cfg = Config(
        llm=LLMConfig(active="t", endpoints=[
            EndpointConfig(id="t", base_url="x", model="m")]),
        # Budget exhaustion is meaningful only for executed calls; dry runs
        # release their reservation by design.
        safety=SafetyConfig(dry_run=False),
    )
    return {"gate": gate, "eng": eng, "cfg": cfg}


def _path_setup(tmp_path):
    """Path-scoped engagement for read_file/shell tests."""
    root = tmp_path / "target"
    root.mkdir()
    eng = Engagement(id="e1", label="pathtest", target=str(root),
                     package="testpkg")
    pkg = ScopePackage(
        name="testpkg",
        tools={"read_file": True, "http": True, "scan": True,
               "shell": True, "glob": True, "grep": True,
               "write_file": True, "pane_list": True, "pane_read": True,
               "memory_remember": True, "memory_recall": True},
    )
    gate = ScopeGate(engagements=[eng], packages={"testpkg": pkg}, overrides={})
    cfg = Config(
        llm=LLMConfig(active="t", endpoints=[
            EndpointConfig(id="t", base_url="x", model="m")]),
        safety=SafetyConfig(dry_run=True),
    )
    return {"gate": gate, "eng": eng, "cfg": cfg, "root": root}


class TestBudgetKindMapping:
    """Bug 1: budget.try_reserve was called with tool name as kind.
    Now maps to valid budget kinds."""

    @pytest.mark.asyncio
    async def test_http_maps_to_max_requests(self, tmp_path):
        s = _net_setup(tmp_path)
        budget = TrackingBudget()
        tc = ToolCall(id="1", name="http",
                      arguments={"url": "http://10.0.0.1/",
                                 "engagement_id": "e1"})
        await dispatch_parallel(
            [tc], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=budget)
        assert budget.reserved_kinds == ["max_requests"]

    @pytest.mark.asyncio
    async def test_scan_maps_to_max_scan_targets(self, tmp_path):
        s = _net_setup(tmp_path)
        budget = TrackingBudget()
        tc = ToolCall(id="1", name="scan",
                      arguments={"targets": ["10.0.0.1"],
                                 "engagement_id": "e1"})
        await dispatch_parallel(
            [tc], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=budget)
        assert budget.reserved_kinds == ["max_scan_targets"]

    @pytest.mark.asyncio
    async def test_shell_maps_to_max_actions(self, tmp_path):
        s = _path_setup(tmp_path)
        budget = TrackingBudget()
        tc = ToolCall(id="1", name="shell",
                      arguments={"command": "ls",
                                 "engagement_id": "e1"})
        await dispatch_parallel(
            [tc], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=budget)
        assert budget.reserved_kinds == ["max_actions"]

    @pytest.mark.asyncio
    async def test_read_file_maps_to_max_actions(self, tmp_path):
        s = _path_setup(tmp_path)
        budget = TrackingBudget()
        tc = ToolCall(id="1", name="read_file",
                      arguments={"path": str(s["root"]),
                                 "engagement_id": "e1"})
        await dispatch_parallel(
            [tc], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=budget)
        assert budget.reserved_kinds == ["max_actions"]

    def test_mapping_constants(self):
        assert BUDGET_KIND_BY_TOOL["http"] == "max_requests"
        assert BUDGET_KIND_BY_TOOL["scan"] == "max_scan_targets"
        assert _DEFAULT_BUDGET_KIND == "max_actions"


class TestBudgetExhaustionWithMapping:
    """Integration: real BudgetManager with correct kind mapping."""

    @pytest.mark.asyncio
    async def test_http_exhausts_max_requests(self, tmp_path):
        from harness.budget import BudgetManager
        s = _net_setup(tmp_path)
        eng = s["eng"]
        bm = BudgetManager(
            BudgetsConfig(default=BudgetLimits(max_requests=1)), [eng])
        tc1 = ToolCall(id="1", name="http",
                       arguments={"url": "http://10.0.0.1/",
                                  "engagement_id": "e1"})
        await dispatch_parallel(
            [tc1], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=bm)
        tc2 = ToolCall(id="2", name="http",
                       arguments={"url": "http://10.0.0.2/",
                                  "engagement_id": "e1"})
        results = await dispatch_parallel(
            [tc2], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=bm)
        assert "error" in results[0]
        assert "max_requests" in results[0]["error"]

    @pytest.mark.asyncio
    async def test_scan_uses_max_scan_targets_not_max_actions(self, tmp_path):
        from harness.budget import BudgetManager
        s = _net_setup(tmp_path)
        eng = s["eng"]
        bm = BudgetManager(
            BudgetsConfig(default=BudgetLimits(
                max_actions=0, max_scan_targets=2)),
            [eng])
        tc = ToolCall(id="1", name="scan",
                      arguments={"targets": ["10.0.0.1"],
                                 "engagement_id": "e1"})
        results = await dispatch_parallel(
            [tc], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=bm)
        assert "error" not in results[0]

    @pytest.mark.asyncio
    async def test_scan_exhausts_max_scan_targets(self, tmp_path):
        from harness.budget import BudgetManager
        s = _net_setup(tmp_path)
        eng = s["eng"]
        bm = BudgetManager(
            BudgetsConfig(default=BudgetLimits(max_scan_targets=1,
                                                max_requests=100)),
            [eng])
        tc1 = ToolCall(id="1", name="scan",
                       arguments={"targets": ["10.0.0.1"],
                                  "engagement_id": "e1"})
        await dispatch_parallel(
            [tc1], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=bm)
        tc2 = ToolCall(id="2", name="scan",
                       arguments={"targets": ["10.0.0.2"],
                                  "engagement_id": "e1"})
        results = await dispatch_parallel(
            [tc2], FakeExecutor(), s["gate"], FakeAudit(), s["cfg"],
            auto_approve, NoopRedactor(), budgets=bm)
        assert "error" in results[0]
        assert "max_scan_targets" in results[0]["error"]


class TestFindingsSeqContinuity:
    """Bug 11: FindingStore always started at seq=1; IDs collide on restart."""

    @pytest.fixture
    def ev(self, tmp_path):
        cfg = EvidenceConfig(dir=str(tmp_path / "evidence"))
        return EvidenceStore(cfg, "sess1")

    def test_seq_continues_across_instances(self, ev):
        fs = FindingStore(ev, "sess1")
        f1 = fs.add("first", "info", "d", ["r1"])
        f2 = fs.add("second", "info", "d", ["r2"])
        assert f1["id"] == "find-0001"
        assert f2["id"] == "find-0002"
        # Simulate re-instantiation (new FindingStore on same path)
        fs2 = FindingStore(ev, "sess1")
        f3 = fs2.add("third", "info", "d", ["r3"])
        assert f3["id"] == "find-0003"

    def test_seq_starts_at_one_when_empty(self, ev):
        fs = FindingStore(ev, "sess1")
        f = fs.add("first", "info", "d", ["r"])
        assert f["id"] == "find-0001"


class TestNmapPortidExtraction:
    """Bug 10: Nmap XML portid is an attribute, not a child element.
    Old code used port.find('portid') which always returned None."""

    @pytest.fixture
    def env(self, tmp_path):
        cfg = EvidenceConfig(dir=str(tmp_path / "ev"))
        ev = EvidenceStore(cfg, "sess")
        inv = InventoryStore(tmp_path, "sess")
        fs = FindingStore(ev, "sess")
        return ev, inv, fs

    def test_portid_from_attribute(self, env, tmp_path):
        ev, inv, fs = env
        xml_str = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '<status state="up"/>'
            '<ports>'
            '<port portid="22" proto="tcp"><state state="open"/></port>'
            '<port portid="80" proto="tcp"><state state="open"/></port>'
            '<port portid="443" proto="tcp"><state state="closed"/></port>'
            '</ports></host></nmaprun>'
        )
        f = tmp_path / "scan.xml"
        f.write_text(xml_str)
        result = import_nmap_xml(ev, inv, fs, str(f), "eng1")
        assert result["imported"] is True
        ports = result["hosts_detail"][0]["ports"]
        assert ports == ["22", "80", "443"]

    def test_single_port_extracted(self, env, tmp_path):
        ev, inv, fs = env
        xml_str = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="192.168.1.1" addrtype="ipv4"/>'
            '<status state="up"/>'
            '<ports><port portid="8080" proto="tcp">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        f = tmp_path / "single.xml"
        f.write_text(xml_str)
        result = import_nmap_xml(ev, inv, fs, str(f), "eng1")
        assert result["hosts_detail"][0]["ports"] == ["8080"]

    def test_multiple_hosts_all_ports(self, env, tmp_path):
        ev, inv, fs = env
        xml_str = (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><address addr="10.0.0.1"/><status state="up"/>'
            '<ports><port portid="22" proto="tcp">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.2"/><status state="up"/>'
            '<ports><port portid="80" proto="tcp">'
            '<state state="open"/></port>'
            '<port portid="443" proto="tcp">'
            '<state state="open"/></port></ports></host>'
            '</nmaprun>'
        )
        f = tmp_path / "multi.xml"
        f.write_text(xml_str)
        result = import_nmap_xml(ev, inv, fs, str(f), "eng1")
        assert result["hosts"] == 2
        assert result["hosts_detail"][0]["ports"] == ["22"]
        assert result["hosts_detail"][1]["ports"] == ["80", "443"]


class TestConfidenceCap:
    """Bug 2: resolve_confidence clamp ignored the cap parameter.
    Old: clamp always used min(1.0, max(0, v)); new: min(cap, max(0, v))."""

    @pytest.fixture
    def store(self, tmp_path):
        cfg = MemoryConfig(dir=str(tmp_path / "mem"))
        return MemoryStore(cfg, "test")

    def test_stated_high_confidence(self, store):
        # stated: max(0.9, min(1.0, 0.99)) = 0.99
        assert store.resolve_confidence(0.99, "stated") == pytest.approx(0.99)

    def test_scanned_low_confidence(self, store):
        # scanned: min(0.7, min(0.5, 0.3)) = 0.3
        assert store.resolve_confidence(0.3, "scanned") == pytest.approx(0.3)

    def test_scanned_high_capped(self, store):
        # scanned: min(0.7, min(0.5, 0.9)) = 0.5
        assert store.resolve_confidence(0.9, "scanned") == pytest.approx(0.5)

    def test_inferred_high_capped(self, store):
        # inferred: min(0.6, min(0.5, 0.9)) = 0.5
        assert store.resolve_confidence(0.9, "inferred") == pytest.approx(0.5)

    def test_none_claimed(self, store):
        # None → default 0.5
        assert store.resolve_confidence(None, "scanned") == 0.5
        assert store.resolve_confidence(None, "inferred") == 0.5

    def test_scanned_never_exceeds_cap(self, store):
        for v in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0, 5.0]:
            assert store.resolve_confidence(v, "scanned") <= 0.7

    def test_inferred_never_exceeds_cap(self, store):
        for v in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0, 5.0]:
            assert store.resolve_confidence(v, "inferred") <= 0.6


class TestProcessSessionIsolation:
    """Bug 3: start_new_session was only set in host mode, leaking
    grandchild processes in container mode on kill."""

    @pytest.mark.asyncio
    async def test_container_mode_session_leader(self, tmp_path):
        import asyncio
        cfg = Config(
            llm=LLMConfig(active="t", endpoints=[
                EndpointConfig(id="t", base_url="x", model="m")]),
            safety=SafetyConfig(),
            process=ProcessConfig(max_panes=4),
        )
        runtime = shutil.which(cfg.process.container_runtime)
        if runtime is None:
            pytest.skip("podman not available")
        image_check = subprocess.run(
            [runtime, "image", "exists", cfg.process.container_image],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if image_check.returncode != 0:
            pytest.skip("podman runtime or configured container image is unavailable")
        pm = ProcessManager(cfg)
        pane = await pm.spawn("s", ["sleep", "0.3"],
                              execution_mode="container")
        await asyncio.sleep(0.15)
        pid = pane.proc.pid
        pgid = os.getpgid(pid)
        assert pgid == pid, (
            f"container pane pgid={pgid} != pid={pid}; "
            "process not a session leader; kill cannot reach children")
        await pm.kill(pane.id)
        assert pane.exit_code is not None

    @pytest.mark.asyncio
    async def test_host_mode_session_leader(self, tmp_path):
        import asyncio
        cfg = Config(
            llm=LLMConfig(active="t", endpoints=[
                EndpointConfig(id="t", base_url="x", model="m")]),
            safety=SafetyConfig(),
            process=ProcessConfig(max_panes=4),
        )
        pm = ProcessManager(cfg)
        pane = await pm.spawn("s", ["sleep", "0.3"],
                              execution_mode="host")
        await asyncio.sleep(0.15)
        pid = pane.proc.pid
        pgid = os.getpgid(pid)
        assert pgid == pid
        await pm.kill(pane.id)


class TestHttpNoRedirect:
    """Bug 9: follow_redirects=True allowed scope bypass via 302 redirect."""

    def test_redirects_disabled(self):
        from harness.tools.http import handle_http
        src = inspect.getsource(handle_http)
        assert "follow_redirects=False" in src
        assert "follow_redirects=True" not in src


class TestGpgDecryptArgs:
    """Bug 12: --passphrase-fd 0 conflicts with encrypted data on stdin."""

    def test_base_args_no_passphrase_fd(self):
        from harness.gpg import Gpg
        gpg = Gpg("0123456789ABCDEF0123456789ABCDEF01234567")
        assert "--passphrase-fd" not in gpg._base_args()

    def test_decrypt_args_no_passphrase_fd(self):
        from harness.gpg import Gpg
        gpg = Gpg("0123456789ABCDEF0123456789ABCDEF01234567")
        decrypt_args = gpg._base_args() + ["--yes", "--decrypt"]
        assert "--passphrase-fd" not in decrypt_args


class TestRestoredSessionShape:
    """Bug 7: CLI accessed r.engagement_ids but RestoredSession has
    r.engagements (list[Engagement])."""

    def test_has_engagements_list(self):
        from harness.sessions.checkpoint import RestoredSession
        rs = RestoredSession(session_id="s1", name="test")
        assert hasattr(rs, "engagements")
        assert isinstance(rs.engagements, list)

    def test_no_engagement_ids(self):
        from harness.sessions.checkpoint import RestoredSession
        rs = RestoredSession(session_id="s1", name="test")
        assert not hasattr(rs, "engagement_ids")


class TestScanAuthorizeReturns3Tuple:
    """Bug 14 (newly found): scan authorize returned 2-tuple (bool, str)
    from check_scan_targets instead of 3-tuple (bool, str, engagement)."""

    @pytest.mark.asyncio
    async def test_scan_authorize_returns_engagement(self, tmp_path):
        s = _net_setup(tmp_path)
        gate = s["gate"]
        args = {"targets": ["10.0.0.1"], "engagement_id": "e1"}
        result = gate.authorize("scan", args, "e1")
        assert len(result) == 3, (
            f"gate.authorize('scan') returned {len(result)}-tuple, expected 3")
        allowed, reason, engagement = result
        assert allowed is True
        assert engagement is not None
        assert engagement.id == "e1"

    @pytest.mark.asyncio
    async def test_scan_authorize_deny_returns_engagement(self, tmp_path):
        s = _net_setup(tmp_path)
        gate = s["gate"]
        # Target outside scope
        args = {"targets": ["192.168.99.99"], "engagement_id": "e1"}
        result = gate.authorize("scan", args, "e1")
        assert len(result) == 3
        allowed, reason, engagement = result
        assert allowed is False
        assert engagement is not None


class TestCliTuiDispatch:
    """Bug 8: 'harness tui' was excluded from TUI code path by
    args.command != 'tui' guard in the outer condition."""

    def test_tui_command_enters_tui_path(self):
        import harness.cli as cli
        src = inspect.getsource(cli)
        # The old buggy condition
        assert 'args.command != "tui"' not in src, (
            "cli.py still has the TUI-blocking condition "
            "`args.command != \"tui\"` — 'harness tui' will skip TUI mode")


class TestAwaitRedactor:
    """Bug 4: harness.py called self._redactor.redact() without await.
    redact is async → the coroutine was never awaited.
    Verify the source uses await."""

    def test_run_awaits_redact(self):
        from harness.harness import Harness
        src = inspect.getsource(Harness.run)
        # The fixed call includes await
        assert "await self._redactor.redact(" in src, (
            "harness.py run() does not await redactor.redact()")

    def test_completion_content_awaits_redact(self):
        from harness.harness import Harness
        src = inspect.getsource(Harness.run)
        # Find the completion.content redaction line
        lines = [l.strip() for l in src.splitlines()
                 if "completion.content" in l and "redact" in l]
        await_found = any(
            "await" in l for l in lines
            if "self" in l and "redactor" in l)
        assert await_found, (
            "completion.content redaction not awaited")


class TestAwaitSafetyPanic:
    """Bug 5: harness.py shutdown() called safety.panic() without await.
    panic is async → the coroutine was never awaited, panes not killed,
    checkpoint not written."""

    def test_shutdown_awaits_panic(self):
        from harness.harness import Harness
        src = inspect.getsource(Harness.shutdown)
        assert "await self.safety.panic(" in src, (
            "harness.py shutdown() does not await safety.panic()")

    def test_shutdown_passes_checkpoint_fn(self):
        from harness.harness import Harness
        src = inspect.getsource(Harness.shutdown)
        assert "checkpoint_fn=" in src, (
            "harness.py shutdown() should pass checkpoint_fn "
            "to safety.panic()")
