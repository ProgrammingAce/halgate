"""Global panic stop and safe checkpointing."""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from .config import SafetyConfig
from .errors import StoppedError

CheckpointFn = Callable[[], Awaitable[None]]


class SafetyController:
    """Operator-initiated panic stop.

    panic() atomically: locks the session for new actions, terminates every
    pane process group, writes a checkpoint, and records a `panic` audit
    event with the outcome. It must remain usable when the LLM is
    unavailable (no LLM calls are made here).
    """

    def __init__(self, safety_cfg: SafetyConfig, process_mgr, audit):
        self._cfg = safety_cfg
        self._process_mgr = process_mgr
        self._audit = audit
        self._stopped = False

    @property
    def dry_run(self) -> bool:
        return self._cfg.dry_run

    def raise_if_stopped(self) -> None:
        if self._stopped:
            raise StoppedError("session is action-locked after panic stop; "
                                "use /resume-actions to unlock")

    async def panic(self, checkpoint_fn: CheckpointFn | None = None) -> dict:
        outcome: dict = {"panicked": True, "cancelled_tasks": 0,
                          "panes_killed": 0, "checkpoint": "failed",
                          "errors": []}
        self._stopped = True
        # 1. Terminate all pane process groups.
        try:
            killed = self._process_mgr.kill_all()
            outcome["panes_killed"] = len(killed)
        except Exception as e:  # noqa: BLE001 - panic must not raise
            outcome["errors"].append(f"kill_all: {e!r}")
        # 2. Write checkpoint (best-effort, bounded).
        if checkpoint_fn is not None:
            try:
                await asyncio.wait_for(checkpoint_fn(),
                                       timeout=self._cfg.panic_checkpoint_timeout)
                outcome["checkpoint"] = "written"
            except Exception as e:  # noqa: BLE001
                outcome["checkpoint"] = "failed"
                outcome["errors"].append(f"checkpoint: {e!r}")
        else:
            outcome["checkpoint"] = "skipped"
        # 3. Audit the panic event (audit is never cancelled).
        try:
            self._audit.panic(outcome)
        except Exception as e:  # noqa: BLE001
            outcome["errors"].append(f"audit: {e!r}")
        return outcome

    def resume_actions(self) -> None:
        """Explicit operator unlock. Does not revive killed processes."""
        self._stopped = False
