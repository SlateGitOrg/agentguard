"""Rate limits (sliding window) and spend budgets.

Both are split into a side-effect-free *check* used while deciding and a *commit* applied only
after a tool actually executed, so a denied or refused call never consumes quota. All time
comes from an injectable :class:`Clock` so tests are deterministic.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal

from agentguard.policy import Budget, RateSpec

Clock = Callable[[], float]


def monotonic_clock() -> float:
    return time.monotonic()


@dataclass
class ManualClock:
    """A clock that only moves when told to (tests, simulations)."""

    now: float = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("clocks do not run backwards")
        self.now += seconds


@dataclass
class SlidingWindowLimiter:
    """Per-key sliding-window counter. ``check`` is O(k) amortized in expired entries."""

    clock: Clock = monotonic_clock
    _events: dict[str, deque[float]] = field(default_factory=dict)

    def _prune(self, key: str, window: float) -> deque[float]:
        events = self._events.setdefault(key, deque())
        cutoff = self.clock() - window
        while events and events[0] <= cutoff:
            events.popleft()
        return events

    def check(self, key: str, spec: RateSpec) -> str | None:
        """``None`` if one more call fits in the window, else the reason it does not."""
        events = self._prune(key, spec.per_seconds)
        if len(events) >= spec.calls:
            retry = events[0] + spec.per_seconds - self.clock()
            return (
                f"rate limit {spec.calls}/{spec.per_seconds:g}s reached for {key} "
                f"(retry in {retry:.1f}s)"
            )
        return None

    def commit(self, key: str) -> None:
        self._events.setdefault(key, deque()).append(self.clock())

    def count(self, key: str, spec: RateSpec) -> int:
        return len(self._prune(key, spec.per_seconds))


@dataclass
class BudgetLedger:
    """Cumulative spend per budget id for one session."""

    spent: dict[str, Decimal] = field(default_factory=dict)

    def check(self, budget: Budget, currency: str, amount: Decimal) -> str | None:
        if currency.upper() != budget.currency:
            return (
                f"budget {budget.id} is in {budget.currency}; "
                f"a {currency.upper()} payment cannot be accounted against it"
            )
        if amount < 0:
            return "negative amounts are not accepted"
        already = self.spent.get(budget.id, Decimal(0))
        if already + amount > budget.limit:
            return (
                f"budget {budget.id}: {already} + {amount} would exceed limit "
                f"{budget.limit} {budget.currency}"
            )
        return None

    def commit(self, budget: Budget, amount: Decimal) -> None:
        self.spent[budget.id] = self.spent.get(budget.id, Decimal(0)) + amount

    def remaining(self, budget: Budget) -> Decimal:
        return budget.limit - self.spent.get(budget.id, Decimal(0))
