"""Tests for SafetyController: panic stop and resume."""
import pytest

from harness.config import SafetyConfig
from harness.safety import SafetyController
from harness.errors import StoppedError


class FakeProcessMgr:
    def __init__(self, panes=None):
        self._panes = panes or []
        self.kill_all_called = False
        self.killed = []
    def kill_all(self):
        self.kill_all_called = True
        killed = []
        for p in self._panes:
            killed.append(p)
        self.killed = killed
        self._panes.clear()
        return killed


class FakeAudit:
    def __init__(self):
        self.panics = []
    def panic(self, outcome):
        self.panics.append(outcome)


@pytest.fixture
def pmgr():
    pane1 = {"id": "p1"}
    pane2 = {"id": "p2"}
    return FakeProcessMgr(panes=[pane1, pane2])


@pytest.fixture
def audit():
    return FakeAudit()


@pytest.fixture
def cfg():
    return SafetyConfig(dry_run=False, panic_checkpoint_timeout=5.0)


class TestStopped:
    def test_initially_not_stopped(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety.raise_if_stopped()  # no exception

    def test_raise_if_stopped(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety._stopped = True
        with pytest.raises(StoppedError, match="action-locked"):
            safety.raise_if_stopped()

    def test_resume_actions(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety._stopped = True
        safety.resume_actions()
        # Should no longer raise
        safety.raise_if_stopped()  # no exception


class TestPanic:
    @pytest.mark.asyncio
    async def test_panic_locks_actions(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        outcome = await safety.panic()
        assert outcome["panicked"] is True
        with pytest.raises(StoppedError):
            safety.raise_if_stopped()

    @pytest.mark.asyncio
    async def test_panic_kills_panes(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        outcome = await safety.panic()
        assert outcome["panes_killed"] == 2
        assert pmgr.kill_all_called is True

    @pytest.mark.asyncio
    async def test_panic_writes_checkpoint(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        checkpoint_called = []
        async def fake_checkpoint():
            checkpoint_called.append(True)
        outcome = await safety.panic(checkpoint_fn=fake_checkpoint)
        assert outcome["checkpoint"] == "written"
        assert checkpoint_called

    @pytest.mark.asyncio
    async def test_panic_checkpoint_failure(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        async def bad_checkpoint():
            raise RuntimeError("disk full")
        outcome = await safety.panic(checkpoint_fn=bad_checkpoint)
        assert outcome["checkpoint"] == "failed"
        assert any("disk full" in e for e in outcome["errors"])

    @pytest.mark.asyncio
    async def test_panic_without_checkpoint(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        outcome = await safety.panic()
        assert outcome["checkpoint"] == "skipped"

    @pytest.mark.asyncio
    async def test_panic_audits(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        await safety.panic()
        assert len(audit.panics) == 1
        assert audit.panics[0]["panicked"] is True
