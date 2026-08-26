"""Per-engagement action, rate, byte, and time budgets.

Budgets apply BEFORE approval and execution: a reservation is taken before
the operator is prompted. Denials, cancellations, and errors release the
reservation; completed actions settle it. Exhaustion is a hard deny.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .config import BudgetLimits, BudgetsConfig
from .errors import BudgetExhaustedError
from .scope import Engagement

KINDS = ("max_actions", "max_requests", "max_scan_targets",
         "max_bytes_in", "max_bytes_out")


@dataclass
class BudgetReservation:
    engagement_id: str
    kind: str
    amount: int

    @property
    def key(self) -> str:
        return f"{self.engagement_id}:{self.kind}"


@dataclass
class BudgetState:
    limits: BudgetLimits
    taken: dict[str, int] = field(default_factory=dict)
    reserved: dict[str, int] = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)

    def current(self, kind: str) -> int:
        return self.taken.get(kind, 0) + self.reserved.get(kind, 0)


class BudgetManager:
    def __init__(self, budgets: BudgetsConfig, engagements: list[Engagement]):
        self._states: dict[str, BudgetState] = {}
        self._engagements = {e.id: e for e in engagements}
        self._defaults = budgets.default

    def register(self, engagement: Engagement) -> None:
        """Make an engagement added after session startup budgetable."""
        self._engagements[engagement.id] = engagement

    def replace_engagements(self, engagements: list[Engagement]) -> None:
        """Reset budget state when switching to another saved session."""
        self._engagements = {e.id: e for e in engagements}
        self._states.clear()

    def update_limits(self, engagement: Engagement) -> None:
        """Apply changed per-engagement limits without resetting usage."""
        self._engagements[engagement.id] = engagement
        state = self._states.get(engagement.id)
        if state is not None:
            state.limits = self.limits(engagement.id)

    def limits(self, engagement_id: str) -> BudgetLimits:
        limits = self._defaults.model_copy(deep=True)
        eng = self._engagements.get(engagement_id)
        if eng and eng.budget_overrides:
            for key, value in eng.budget_overrides.items():
                if hasattr(limits, key) and isinstance(value, int):
                    setattr(limits, key, value)
        return limits

    def disabled(self, engagement_id: str) -> bool:
        engagement = self._engagements.get(engagement_id)
        return bool(engagement and engagement.budgets_disabled)

    def _state(self, engagement_id: str) -> BudgetState:
        if engagement_id not in self._engagements:
            raise BudgetExhaustedError(f"unknown engagement: {engagement_id}")
        if engagement_id not in self._states:
            self._states[engagement_id] = BudgetState(self.limits(engagement_id))
        return self._states[engagement_id]

    def try_reserve(self, engagement_id: str, kind: str,
                    amount: int = 1) -> BudgetReservation:
        """Atomically reserve budget; raise BudgetExhaustedError on exhaustion.

        Single-threaded event loop => plain check-and-reserve is atomic.
        """
        if self.disabled(engagement_id):
            # Keep dispatch's reserve/release/settle flow intact while making
            # the operator's explicit per-engagement disablement a no-op.
            return BudgetReservation(engagement_id, kind, 0)
        if kind == "runtime":
            state = self._state(engagement_id)
            if time.monotonic() - state.started > state.limits.max_runtime_seconds:
                raise BudgetExhaustedError("max runtime exceeded")
            return BudgetReservation(engagement_id, "runtime", 0)
        if kind not in KINDS:
            raise ValueError(f"unknown budget kind: {kind}")
        state = self._state(engagement_id)
        limit = getattr(state.limits, kind)
        if state.current(kind) + amount > limit:
            raise BudgetExhaustedError(
                f"budget exhausted for {engagement_id}: {kind} "
                f"({state.current(kind)} used/{limit} max), denied {amount}")
        state.reserved[kind] = state.reserved.get(kind, 0) + amount
        return BudgetReservation(engagement_id, kind, amount)

    def release(self, reservation: BudgetReservation) -> None:
        """Return a reservation (denied/cancelled/failed action)."""
        state = self._states.get(reservation.engagement_id)
        if state is None or reservation.kind not in state.reserved:
            return
        state.reserved[reservation.kind] = max(
            0, state.reserved[reservation.kind] - reservation.amount)

    def settle(self, reservation: BudgetReservation,
               delta: int | None = None) -> None:
        """Keep a reservation counted as consumed (action completed)."""
        state = self._states.get(reservation.engagement_id)
        if state is None or reservation.kind not in state.reserved:
            return
        consumed = reservation.amount if delta is None else delta
        if consumed < 0 or consumed > reservation.amount:
            raise ValueError("settlement delta must be within the reservation")
        state.taken[reservation.kind] = (state.taken.get(reservation.kind, 0)
                                         + consumed)
        state.reserved[reservation.kind] = max(
            0, state.reserved[reservation.kind] - reservation.amount)

    def account(self, engagement_id: str, kind: str, amount: int) -> None:
        """Atomically charge measured usage against a bounded budget."""
        if amount < 0:
            raise ValueError("accounting amount must not be negative")
        reservation = self.try_reserve(engagement_id, kind, amount)
        self.settle(reservation)

    def status(self, engagement_id: str) -> dict:
        if self.disabled(engagement_id):
            return {"engagement": engagement_id, "disabled": True}
        state = self._state(engagement_id)
        out: dict = {"engagement": engagement_id}
        for kind in KINDS + ("max_runtime_seconds",):
            out[kind] = {
                "used": state.taken.get(kind, 0),
                "reserved": state.reserved.get(kind, 0),
                "limit": getattr(state.limits, kind),
            }
        out["runtime_elapsed_s"] = int(time.monotonic() - state.started)
        return out

    def all_status(self) -> list[dict]:
        return [self.status(e) for e in
                [s for s in list(self._states)] or
                [e.id for e in self._engagements]]
