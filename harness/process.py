"""Process manager for long-lived panes (detached process groups)."""
from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config import Config, ProcessConfig


@dataclass
class Pane:
    id: str
    name: str
    cmd: list[str]
    proc: asyncio.subprocess.Process
    stdout_buf: bytes = b""
    stderr_buf: bytes = b""
    started: str = ""
    exit_code: int | None = None
    truncated: bool = False
    engagement_id: str = ""
    workdir: str = ""
    execution_mode: str = "host"

    @property
    def status(self) -> str:
        if self.exit_code is not None:
            return "exited"
        return "running"


class ProcessManager:
    def __init__(self, config: Config):
        self._panes: dict[str, Pane] = {}
        self._seq = 0
        self._max: int = config.process.max_panes
        self._max_buf: int = config.process.pane_buffer_bytes
        self._config = config

    async def spawn(self, name: str, cmd: list[str],
                    workdir: str | None = None,
                    execution_mode: str = "host",
                    engagement_id: str = "") -> Pane:
        if self.active_count() >= self._max:
            raise ValueError(f"max panes ({self._max}) reached")
        # Pane titles are rendered in Textual tab controls. Keep the durable
        # process record within the same bounded, non-empty display contract.
        name = " ".join(str(name or "").split())[:80] or "Process pane"
        self._seq += 1
        pane_id = f"pane-{self._seq:02d}"
        original_cmd = list(cmd)
        cwd = workdir or self._config.shell.workdir
        if execution_mode == "container":
            try:
                mount = os.path.realpath(cwd)
            except OSError as e:
                raise ValueError(f"invalid pane workdir: {e}") from e
            cmd = [self._config.process.container_runtime, "run", "--rm",
                   "--interactive", "--workdir", "/work", "--volume",
                   f"{mount}:/work:Z", self._config.process.container_image,
                   *cmd]
        elif execution_mode != "host":
            raise ValueError(f"invalid execution mode: {execution_mode}")
        kwargs: dict[str, Any] = dict(
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
        )
        proc = await asyncio.create_subprocess_exec(*cmd, **kwargs)
        pane = Pane(id=pane_id, name=name, cmd=original_cmd, proc=proc,
                    started=datetime.now().isoformat(), engagement_id=engagement_id,
                    workdir=cwd, execution_mode=execution_mode)
        self._panes[pane_id] = pane
        asyncio.create_task(self._reader(pane, proc.stdout))
        asyncio.create_task(self._reader_stderr(pane, proc.stderr))
        return pane

    async def write(self, pane_id: str, data: str | bytes) -> None:
        pane = self._require(pane_id)
        if pane.proc.stdin is None:
            raise ValueError(f"pane {pane_id} has no stdin")
        if isinstance(data, str):
            data = data.encode()
        pane.proc.stdin.write(data)
        await pane.proc.stdin.drain()

    async def read(self, pane_id: str, timeout: float | None = None) -> str:
        pane = self._require(pane_id)
        t = timeout or self._config.process.default_read_timeout
        if not pane.stdout_buf:
            try:
                await asyncio.wait_for(self._wait_for_data(pane), timeout=t)
            except asyncio.TimeoutError:
                pass
        data, pane.stdout_buf = pane.stdout_buf, b""
        return data.decode(errors="replace")

    def drain_output(self, pane_id: str) -> str:
        """Return buffered stdout immediately; intended for UI polling."""
        pane = self._require(pane_id)
        data, pane.stdout_buf = pane.stdout_buf, b""
        return data.decode(errors="replace")

    async def read_stderr(self, pane_id: str, timeout: float | None = None) -> str:
        pane = self._require(pane_id)
        t = timeout or self._config.process.default_read_timeout
        if not pane.stderr_buf:
            try:
                await asyncio.wait_for(self._wait_for_data_err(pane), timeout=t)
            except asyncio.TimeoutError:
                pass
        data, pane.stderr_buf = pane.stderr_buf, b""
        return data.decode(errors="replace")

    async def kill(self, pane_id: str) -> Pane:
        pane = self._require(pane_id)
        if pane.exit_code is not None:
            return pane
        pid = pane.proc.pid
        # Try group kill first (only works when proc is a session leader);
        # fall back to killing just the process.
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            try:
                pane.proc.terminate()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(pane.proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    pane.proc.kill()
                except ProcessLookupError:
                    pass
            await pane.proc.wait()
        pane.exit_code = pane.proc.returncode
        return pane

    def kill_all(self) -> list[Pane]:
        """Kill all running panes. Returns list of terminated panes."""
        to_kill = [p for p in self._panes.values() if p.exit_code is None]
        for p in to_kill:
            try:
                os.killpg(p.proc.pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                try:
                    p.proc.terminate()
                except ProcessLookupError:
                    p.exit_code = -1
        return to_kill

    def list(self) -> list[dict]:
        return [
            {"id": p.id, "name": p.name, "cmd": " ".join(p.cmd), "argv": p.cmd,
             "status": p.status, "started": p.started,
             "exit_code": p.exit_code, "truncated": p.truncated,
             "engagement_id": p.engagement_id, "workdir": p.workdir,
             "execution_mode": p.execution_mode}
            for p in self._panes.values()
        ]

    def get(self, pane_id: str) -> Pane | None:
        return self._panes.get(pane_id)

    async def _reader(self, pane: Pane, stream: asyncio.StreamReader):
        try:
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                pane.stdout_buf = self._append_bounded(pane, chunk)
        finally:
            if pane.exit_code is None:
                pane.exit_code = await pane.proc.wait()

    async def _reader_stderr(self, pane: Pane, stream: asyncio.StreamReader):
        try:
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                pane.stderr_buf = self._append_bounded(pane, chunk, stderr=True)
        finally:
            if pane.exit_code is None:
                pane.exit_code = await pane.proc.wait()

    def _append_bounded(self, pane: Pane, chunk: bytes,
                        stderr: bool = False) -> bytes:
        buf = pane.stderr_buf if stderr else pane.stdout_buf
        combined = buf + chunk
        if len(combined) > self._max_buf:
            combined = combined[-self._max_buf:]
            pane.truncated = True
        return combined

    async def _wait_for_data(self, pane: Pane) -> None:
        while pane.exit_code is None and not pane.stdout_buf:
            await asyncio.sleep(0.01)

    async def _wait_for_data_err(self, pane: Pane) -> None:
        while pane.exit_code is None and not pane.stderr_buf:
            await asyncio.sleep(0.01)

    def _require(self, pane_id: str) -> Pane:
        if pane_id not in self._panes:
            raise KeyError(f"no pane '{pane_id}'")
        return self._panes[pane_id]

    def active_count(self) -> int:
        return sum(1 for p in self._panes.values() if p.exit_code is None)
