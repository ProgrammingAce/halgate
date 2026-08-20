"""ContextTracker accounting."""
from __future__ import annotations

from harness.tracker import ContextTracker, LifetimeTokenCounter, TokenUsage


def test_record_and_pct():
    t = ContextTracker(model_context=10000, output_reserve=2000)
    assert t.budget == 8000
    t.record(TokenUsage(400, 50))
    assert t.current_pct() == 5.0  # 400 / 8000 usable budget
    assert t.turn_count == 1
    t.record(TokenUsage(600, 60))
    assert t.current_pct() == 7.5
    assert t.total_prompt_tokens == 1000
    assert t.total_completion_tokens == 110


def test_status_line():
    t = ContextTracker(10000, 2000)
    t.record(TokenUsage(4000, 100))
    line = t.status_line()
    assert "ctx: 4,000/8,000 (50%)" in line
    assert "1 turns" in line
    assert "4,000 in / 100 out" in line


def test_lifetime_counter_persists_outside_the_session_context(tmp_path):
    path = tmp_path / "lifetime_tokens.json"
    counter = LifetimeTokenCounter(path)
    counter.record(TokenUsage(4000, 100))
    counter.record(TokenUsage(600, 60))

    restored = LifetimeTokenCounter(path)
    assert restored.total == 4760
    assert restored.status_line() == (
        "Lifetime usage: 4,760 tokens (4,600 sent / 160 received)")


def test_zero_budget_safe():
    t = ContextTracker(0, 0)
    assert t.current_pct() == 0.0
