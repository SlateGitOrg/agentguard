"""Sliding-window rate limiter and budget ledger."""

from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentguard.limits import BudgetLedger, ManualClock, SlidingWindowLimiter, monotonic_clock
from agentguard.policy import Budget, RateSpec


def test_window_allows_n_then_blocks_until_expiry() -> None:
    clock = ManualClock()
    limiter = SlidingWindowLimiter(clock)
    spec = RateSpec(calls=2, per_seconds=10)
    for _ in range(2):
        assert limiter.check("k", spec) is None
        limiter.commit("k")
        clock.advance(1)
    reason = limiter.check("k", spec)
    assert reason is not None
    assert "retry in 8.0s" in reason
    clock.advance(8)  # first event (t=0) leaves the window at t=10
    assert limiter.check("k", spec) is None
    assert limiter.count("k", spec) == 1
    assert limiter.check("other", spec) is None


def test_check_does_not_consume() -> None:
    limiter = SlidingWindowLimiter(ManualClock())
    spec = RateSpec(1, 5)
    for _ in range(5):
        assert limiter.check("k", spec) is None


def test_manual_clock_rejects_negative_steps() -> None:
    with pytest.raises(ValueError, match="backwards"):
        ManualClock().advance(-1)
    assert monotonic_clock() > 0


@given(
    st.lists(st.floats(min_value=0, max_value=5, allow_nan=False), min_size=1, max_size=60),
    st.integers(1, 5),
    st.floats(min_value=0.5, max_value=20),
)
def test_never_more_than_n_commits_in_any_window(
    gaps: list[float], calls: int, window: float
) -> None:
    clock = ManualClock()
    limiter = SlidingWindowLimiter(clock)
    spec = RateSpec(calls, window)
    times: list[float] = []
    for gap in gaps:
        clock.advance(gap)
        if limiter.check("k", spec) is None:
            limiter.commit("k")
            times.append(clock.now)
    for i, t in enumerate(times):
        in_window = [u for u in times[: i + 1] if u > t - window]
        assert len(in_window) <= calls


def test_budget_ledger() -> None:
    budget = Budget("b", "money.pay", "USD", Decimal(100))
    ledger = BudgetLedger()
    assert ledger.check(budget, "usd", Decimal(60)) is None
    ledger.commit(budget, Decimal(60))
    assert ledger.remaining(budget) == Decimal(40)
    assert ledger.check(budget, "USD", Decimal(40)) is None
    assert "would exceed" in str(ledger.check(budget, "USD", Decimal("40.01")))
    assert "cannot be accounted" in str(ledger.check(budget, "EUR", Decimal(1)))
    assert "negative" in str(ledger.check(budget, "USD", Decimal(-5)))


@given(st.lists(st.decimals(min_value=0, max_value=500, places=2), max_size=40))
def test_ledger_never_exceeds_limit(amounts: list[Decimal]) -> None:
    budget = Budget("b", "money.pay", "USD", Decimal(1000))
    ledger = BudgetLedger()
    for amount in amounts:
        if ledger.check(budget, "USD", amount) is None:
            ledger.commit(budget, amount)
        assert ledger.spent.get("b", Decimal(0)) <= budget.limit
