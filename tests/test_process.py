"""Tests for ProcessManager (panes): spawn, read, write, kill."""
import asyncio
import pytest

from halgate.config import Config, ProcessConfig
from halgate.process import ProcessManager


@pytest.fixture
def pm(tmp_path):
    cfg = Config(
        llm=__import__("halgate.config", fromlist=["LLMConfig"]).LLMConfig(
            active="test",
            endpoints=[__import__("halgate.config", fromlist=["EndpointConfig"])
                       .EndpointConfig(id="test", base_url="http://x", model="m")],
        ),
        process=ProcessConfig(max_panes=4),
    )
    return ProcessManager(cfg)


@pytest.mark.asyncio
async def test_spawn_and_read(pm):
    pane = await pm.spawn("test", ["echo", "hello"])
    output = await pm.read(pane.id, timeout=5.0)
    assert "hello" in output
    # Process should exit
    await asyncio.sleep(0.1)
    assert pane.status == "exited"


@pytest.mark.asyncio
async def test_write_and_read(pm):
    pane = await pm.spawn("cat_test", ["cat"])
    await pm.write(pane.id, "test data\n")
    output = await pm.read(pane.id, timeout=3.0)
    assert "test data" in output
    await pm.kill(pane.id)


@pytest.mark.asyncio
async def test_kill(pm):
    pane = await pm.spawn("sleepy", ["sleep", "10"])
    await asyncio.sleep(0.1)
    assert pane.status == "running"
    await pm.kill(pane.id)
    assert pane.status == "exited"


@pytest.mark.asyncio
async def test_kill_all(pm):
    await pm.spawn("a", ["sleep", "10"])
    await pm.spawn("b", ["sleep", "10"])
    await asyncio.sleep(0.1)
    killed = pm.kill_all()
    assert len(killed) == 2


@pytest.mark.asyncio
async def test_max_panes(pm):
    for i in range(4):
        await pm.spawn(f"p{i}", ["sleep", "10"])
    with pytest.raises(ValueError, match="max panes"):
        await pm.spawn("overflow", ["echo", "hi"])


@pytest.mark.asyncio
async def test_exited_panes_do_not_consume_capacity(pm):
    for i in range(4):
        pane = await pm.spawn(f"short-{i}", ["echo", str(i)])
        await pm.read(pane.id, timeout=1.0)
    replacement = await pm.spawn("replacement", ["echo", "ok"])
    assert replacement.id == "pane-05"


@pytest.mark.asyncio
async def test_list(pm):
    pane = await pm.spawn("listed", ["echo", "test"])
    panes = pm.list()
    assert any(p["id"] == pane.id for p in panes)
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_read_timeout(pm):
    pane = await pm.spawn("silent", ["sleep", "10"])
    output = await pm.read(pane.id, timeout=0.5)
    assert output == ""  # timeout with no data
    await pm.kill(pane.id)


@pytest.mark.asyncio
async def test_require_unknown_pane(pm):
    with pytest.raises(KeyError, match="no pane"):
        await pm.read("nonexist", 0.1)


@pytest.mark.asyncio
async def test_active_count(pm):
    assert pm.active_count() == 0
    pane = await pm.spawn("x", ["sleep", "10"])
    await asyncio.sleep(0.1)
    assert pm.active_count() == 1
    await pm.kill(pane.id)


@pytest.mark.asyncio
async def test_stderr_is_discarded(pm):
    pane = await pm.spawn("errtest", ["/bin/sh", "-c",
                                      "echo err >&2; echo out"])
    output = await pm.read(pane.id, timeout=3.0)
    assert "out" in output
