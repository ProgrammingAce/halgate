"""ContextTracker: token accounting for display and pressure warnings."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ContextTracker:
    def __init__(self, model_context: int, output_reserve: int):
        self.model_context = model_context
        self.output_reserve = output_reserve
        self.budget = model_context - output_reserve  # usable for input
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.turn_count = 0
        self._current_window = 0  # estimated tokens in current message history

    def record(self, usage: TokenUsage) -> None:
        self.total_prompt_tokens += usage.prompt_tokens
        self.total_completion_tokens += usage.completion_tokens
        self.turn_count += 1
        self._current_window = usage.prompt_tokens

    def current_pct(self) -> float:
        return (self._current_window / self.budget) * 100.0 if self.budget else 0.0

    @property
    def total_tokens(self) -> int:
        """All tokens sent to and received from the model this session."""
        return self.total_prompt_tokens + self.total_completion_tokens

    def status_line(self) -> str:
        pct = self.current_pct()
        return (f"ctx: {self._current_window:,}/{self.budget:,} ({pct:.0f}%) "
                f"| {self.turn_count} turns "
                f"| {self.total_prompt_tokens:,} in / "
                f"{self.total_completion_tokens:,} out")

    def reset_current_window(self) -> None:
        """A compaction invalidates the previous prompt-window measurement."""
        self._current_window = 0


class LifetimeTokenCounter:
    """Durable aggregate usage, intentionally separate from session context."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self.sent = 0
        self.received = 0
        self._load()

    @property
    def total(self) -> int:
        return self.sent + self.received

    def record(self, usage: TokenUsage) -> None:
        self.sent += max(0, usage.prompt_tokens)
        self.received += max(0, usage.completion_tokens)
        self._save()

    def status_line(self) -> str:
        return (f"Lifetime usage: {self.total:,} tokens "
                f"({self.sent:,} sent / {self.received:,} received)")

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text())
            self.sent = max(0, int(data.get("sent", 0)))
            self.received = max(0, int(data.get("received", 0)))
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(".tmp")
            temporary.write_text(json.dumps({
                "sent": self.sent,
                "received": self.received,
            }))
            temporary.replace(self._path)
        except OSError:
            # Usage display must never interrupt a completed model response.
            pass
