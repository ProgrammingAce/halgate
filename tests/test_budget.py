"""Budgets: atomic reservations, hard denies, release/settle, runtime."""
from __future__ import annotations

import pytest

from harness.budget import BudgetManager
from harness.config import BudgetLimits, BudgetsConfig
from harness.errors import BudgetExhaustedError
from harness.scope import Engagement


def make_manager(limits, overrides=None):
    engs = [Engagement(id="e1", label="l", target="10.0.0.0/24",
                       package="offensive",
                       budget_overrides=overrides or {})]
    return BudgetManager(BudgetsConfig(default=limits), engs)


def test_reservation_and_settle():
    bm = make_manager(BudgetLimits(max_actions=3))
    r1 = bm.try_reserve("e1", "max_actions")
    r2 = bm.try_reserve("e1", "max_actions")
    s = bm.status("e1")
    assert s["max_actions"]["reserved"] == 2
    bm.settle(r1)  # completed
    s = bm.status("e1")
    assert s["max_actions"]["used"] == 1
    assert s["max_actions"]["reserved"] == 1
    bm.settle(r2)
    r3 = bm.try_reserve("e1", "max_actions")  # 2 used + 1 reserved = limit
    with pytest.raises(BudgetExhaustedError):
        bm.try_reserve("e1", "max_actions")
    bm.settle(r3)


def test_hard_deny_on_exhaustion_is_deterministic():
    bm = make_manager(BudgetLimits(max_requests=2))
    r = bm.try_reserve("e1", "max_requests")
    bm.try_reserve("e1", "max_requests")
    with pytest.raises(BudgetExhaustedError, match="max_requests"):
        bm.try_reserve("e1", "max_requests")
    bm.release(r)
    # after release the slot is available again
    r3 = bm.try_reserve("e1", "max_requests")
    bm.settle(r3)


def test_release_on_denial():
    bm = make_manager(BudgetLimits(max_actions=1))
    r = bm.try_reserve("e1", "max_actions")
    bm.release(r)  # operator denied
    r2 = bm.try_reserve("e1", "max_actions")
    bm.settle(r2)


def test_settle_delta_accounts_actual_usage():
    bm = make_manager(BudgetLimits(max_actions=10))
    reservation = bm.try_reserve("e1", "max_actions", 4)
    bm.settle(reservation, delta=2)
    status = bm.status("e1")["max_actions"]
    assert status["used"] == 2
    assert status["reserved"] == 0


def test_scan_targets_counted():
    bm = make_manager(BudgetLimits(max_scan_targets=5))
    r = bm.try_reserve("e1", "max_scan_targets", 4)
    with pytest.raises(BudgetExhaustedError):
        bm.try_reserve("e1", "max_scan_targets", 2)
    bm.settle(r)
    r2 = bm.try_reserve("e1", "max_scan_targets", 1)
    assert r2.amount == 1


def test_budget_overrides_per_engagement():
    limits = BudgetLimits(max_actions=10)
    bm = make_manager(limits, overrides={"max_actions": 2})
    bm.try_reserve("e1", "max_actions")
    bm.try_reserve("e1", "max_actions")
    with pytest.raises(BudgetExhaustedError):
        bm.try_reserve("e1", "max_actions")


def test_runtime_budget():
    bm = make_manager(BudgetLimits(max_runtime_seconds=0))
    state = bm._state("e1")
    state.started -= 5  # pretend 5s elapsed
    with pytest.raises(BudgetExhaustedError, match="runtime"):
        bm.try_reserve("e1", "runtime")


def test_unknown_engagement_rejected():
    bm = make_manager(BudgetLimits())
    with pytest.raises(BudgetExhaustedError):
        bm.try_reserve("ghost", "max_actions")


def test_late_registered_engagement_is_budgetable():
    bm = BudgetManager(BudgetsConfig(default=BudgetLimits()), [])
    eng = Engagement(id="late", label="Added after startup",
                     target="10.0.0.1", package="defensive")
    bm.register(eng)
    reservation = bm.try_reserve("late", "max_actions")
    bm.settle(reservation)
    assert bm.status("late")["max_actions"]["used"] == 1


def test_byte_accounting_is_enforced():
    bm = make_manager(BudgetLimits(max_bytes_in=5))
    bm.account("e1", "max_bytes_in", 3)
    with pytest.raises(BudgetExhaustedError, match="max_bytes_in"):
        bm.account("e1", "max_bytes_in", 3)
    assert bm.status("e1")["max_bytes_in"]["used"] == 3
