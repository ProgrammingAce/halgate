"""Progress-aware guard for multi-step agent tool workflows.

This is deliberately separate from authorization and budgets.  Those controls
decide *whether* an action is allowed; this controller decides whether the
current model turn is still making useful forward progress.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ProgressDecision:
    """The outcome after one completed batch of tool calls."""

    continue_running: bool
    reason: str = ""
    checkpoint_due: bool = False
    actions_completed: int = 0


class ProgressController:
    """Allow long workflows while detecting loops from their observable work.

    A batch is considered productive when it produces a result not observed
    earlier in this turn.  Repeating an exact action is tolerated briefly (it
    is useful for polling a live pane) but repeated identical work or several
    batches with no new result stops automatically with an operator-facing
    explanation instead of an unnecessary approval prompt.
    """

    _VOLATILE_RESULT_KEYS = frozenset({"headers", "date", "timestamp", "time"})
    _LARGE_RESULT_KEYS = frozenset({
        "raw", "body", "stdout", "stderr", "output", "partial_output",
    })
    _NON_IDENTITY_ARGUMENTS = frozenset({"reason"})
    _TRANSIENT_ERROR_MARKERS = frozenset({
        "timeout", "timed out", "connection failed", "temporar", "rate limit",
        "too many requests", "dns resolution failed",
    })

    def __init__(
        self,
        *,
        max_runtime_seconds: float,
        emergency_iteration_limit: int,
        max_stalled_batches: int,
        max_repeated_calls: int,
        checkpoint_every_actions: int,
        max_unchanged_pane_reads: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_runtime_seconds = max_runtime_seconds
        self.emergency_iteration_limit = emergency_iteration_limit
        self.max_stalled_batches = max_stalled_batches
        self.max_repeated_calls = max_repeated_calls
        self.max_unchanged_pane_reads = max_unchanged_pane_reads
        self.checkpoint_every_actions = checkpoint_every_actions
        self._clock = clock
        self._started_at = clock()
        self._action_counts: Counter[str] = Counter()
        self._result_fingerprints: set[str] = set()
        self._stalled_batches = 0
        self._unchanged_pane_reads = 0
        self.actions_completed = 0
        self._last_checkpoint_at = 0

    def before_next_batch(self, batches_completed: int) -> ProgressDecision:
        """Check independent wall-clock and emergency limits before an LLM call."""
        elapsed = self._clock() - self._started_at
        if elapsed >= self.max_runtime_seconds:
            return ProgressDecision(
                False,
                f"the per-request runtime limit ({self.max_runtime_seconds:.0f}s) was reached",
                actions_completed=self.actions_completed,
            )
        if batches_completed >= self.emergency_iteration_limit:
            return ProgressDecision(
                False,
                "the emergency tool-batch ceiling was reached",
                actions_completed=self.actions_completed,
            )
        return ProgressDecision(True, actions_completed=self.actions_completed)

    def record_batch(self, calls: list[Any], results: list[Any]) -> ProgressDecision:
        """Record completed work and decide whether the next batch is justified."""
        self.actions_completed += len(calls)
        signatures = [self._call_signature(call) for call in calls]

        novel_result = False
        for call, result in zip(calls, results):
            # An empty pane read is a poll with no observable work. It must
            # not be considered novel merely because it is the first empty
            # response seen in this turn.
            if (getattr(call, "name", "") == "pane_read"
                    and isinstance(result, dict)
                    and not result.get("output")):
                continue
            fingerprint = self._result_fingerprint(result)
            if fingerprint not in self._result_fingerprints:
                self._result_fingerprints.add(fingerprint)
                novel_result = True

        transient_failure = any(self._is_transient_result(result) for result in results)
        pane_read_poll = bool(calls) and all(
            getattr(call, "name", "") == "pane_read" for call in calls)

        if novel_result:
            self._stalled_batches = 0
            self._action_counts.clear()
            self._action_counts.update(signatures)
        elif transient_failure:
            # Network and service failures are retryable conditions, not loop
            # evidence. Wall-clock and emergency batch ceilings still apply.
            self._stalled_batches = 0
            self._action_counts.clear()
            self._action_counts.update(signatures)
        else:
            self._stalled_batches += 1
            self._action_counts.update(signatures)

        if pane_read_poll and not novel_result and not transient_failure:
            self._unchanged_pane_reads += 1
        else:
            self._unchanged_pane_reads = 0

        checkpoint_due = (
            self.checkpoint_every_actions > 0
            and self.actions_completed - self._last_checkpoint_at
            >= self.checkpoint_every_actions
        )
        if checkpoint_due:
            self._last_checkpoint_at = self.actions_completed

        if self._unchanged_pane_reads >= self.max_unchanged_pane_reads:
            return ProgressDecision(
                False,
                f"{self._unchanged_pane_reads} consecutive pane reads had no new output",
                checkpoint_due,
                self.actions_completed,
            )

        # Do not reject a mixed batch merely because one action is a retry.
        # A batch composed entirely of calls beyond the retry allowance is a
        # loop. Counts reset after a novel or transient result, so this is a
        # consecutive retry limit rather than a whole-turn quota.
        if not novel_result and signatures and all(
            self._action_counts[signature] > self.max_repeated_calls
            for signature in signatures
        ):
            return ProgressDecision(
                False,
                "the agent repeated the same tool action without a new outcome",
                checkpoint_due,
                self.actions_completed,
            )
        if self._stalled_batches >= self.max_stalled_batches:
            return ProgressDecision(
                False,
                f"{self._stalled_batches} consecutive tool batches produced no new result",
                checkpoint_due,
                self.actions_completed,
            )
        return ProgressDecision(True, checkpoint_due=checkpoint_due,
                                actions_completed=self.actions_completed)

    @classmethod
    def _is_transient_result(cls, result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        status = result.get("status")
        if isinstance(status, int) and (status in {408, 425, 429} or status >= 500):
            return True
        error = str(result.get("error", "")).lower()
        return any(marker in error for marker in cls._TRANSIENT_ERROR_MARKERS)

    @classmethod
    def _call_signature(cls, call: Any) -> str:
        arguments = getattr(call, "arguments", {}) or {}
        identity_args = {
            key: value for key, value in arguments.items()
            if key not in cls._NON_IDENTITY_ARGUMENTS
        }
        return cls._digest({"name": getattr(call, "name", ""),
                            "arguments": identity_args})

    @classmethod
    def _result_fingerprint(cls, result: Any) -> str:
        return cls._digest(cls._normalise_result(result))

    @classmethod
    def _normalise_result(cls, value: Any) -> Any:
        """Retain result meaning while removing volatile and unbounded fields."""
        if isinstance(value, dict):
            normalised: dict[str, Any] = {}
            for key, child in value.items():
                if key.lower() in cls._VOLATILE_RESULT_KEYS:
                    continue
                if key.lower() in cls._LARGE_RESULT_KEYS:
                    normalised[key] = cls._digest(child)
                else:
                    normalised[key] = cls._normalise_result(child)
            return normalised
        if isinstance(value, list):
            return [cls._normalise_result(child) for child in value]
        if isinstance(value, tuple):
            return [cls._normalise_result(child) for child in value]
        if isinstance(value, str) and len(value) > 4096:
            return {"text_sha256": cls._digest(value), "length": len(value)}
        return value

    @staticmethod
    def _digest(value: Any) -> str:
        try:
            encoded = json.dumps(value, sort_keys=True, default=str,
                                 separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            encoded = repr(value).encode("utf-8", "replace")
        return hashlib.sha256(encoded).hexdigest()
