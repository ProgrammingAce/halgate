"""Tests for SafetyController: panic stop, task cancellation, resume."""
import asyncio
import asyncio
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
        assert not safety.stopped

    def test_raise_if_stopped(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety._stopped = True
        with pytest.raises(StoppedError, match="action-locked"):
            safety.raise_if_stopped()

    def test_resume_actions(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety._stopped = True
        safety.resume_actions()
        assert not safety.stopped
        # Should no longer raise
        safety.raise_if_stopped()  # no exception


class TestTrack:
    def test_track_and_untrack(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        async def _run():
            task = asyncio.create_task(asyncio.sleep(0.1))
            safety.track(task)
            assert task in safety._tasks
            safety.untrack(task)
            assert task not in safety._tasks
            await task
        import asyncio
        asyncio.run(_run())

    def test_done_callback_auto_removes(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        async def _run():
            async def quick():
                return 42
            task = safety.track(asyncio.create_task(quick()))
            result = await task
            assert result == 42
            # After done, task should be removed from _tasks
            assert task not in safety._tasks
        import asyncio
        asyncio.run(_run())


class TestPanic:
    @pytest.mark.asyncio
    async def test_panic_cancels_tasks(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        # Start a slow task
        task = asyncio.create_task(asyncio.sleep(10))
        safety.track(task)
        await asyncio.sleep(0.05)  # let it run
        outcome = await safety.panic()
        assert outcome["panicked"] is True
        assert safety.stopped
        # Task should have been cancelled
        assert task.cancelled() or task.done()

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

    @pytest.mark.asyncio
    async def test_panic_with_cancelled_tasks(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        async def slow():
            await asyncio.sleep(10)
        task = safety.track(asyncio.create_task(slow()))
        await asyncio.sleep(0.05)
        outcome = await safety.panic()
        assert outcome["cancelled_tasks"] >= 1

    @pytest.mark.asyncio
    async def test_require_not_stopped(self, cfg, pmgr, audit):
        safety = SafetyController(cfg, pmgr, audit)
        safety._stopped = True
        with pytest.raises(StoppedError):
            safety.require_not_stopped_for_action()
