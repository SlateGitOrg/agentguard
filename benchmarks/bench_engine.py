"""Micro-benchmark: cost of one policy decision and of one fully mediated, audited call.

Prints median and p99 latency over many calls for a representative mix (allowed read,
constraint-checked payment, tainted high-impact call, URL allow-list denial). Numbers depend
on the machine; the README quotes one run and the command that produced it.
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path

from agentguard.approval import deny_all
from agentguard.audit import AuditLog
from agentguard.engine import PolicyEngine, SessionState, ToolCall
from agentguard.labels import Label
from agentguard.policy import load_policy
from agentguard.session import GuardedSession
from agentguard.tools import load_world, sandbox_registry

ROOT = Path(__file__).resolve().parent.parent
N = 20_000


def measure(fn: Callable[[], object], n: int = N) -> tuple[float, float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return statistics.median(samples) / 1000, samples[int(n * 0.99)] / 1000


def main() -> None:
    world = load_world(ROOT / "scenarios" / "worlds" / "office.yaml")
    registry = sandbox_registry(world)
    policy = load_policy(ROOT / "policies" / "assistant.yaml", registry)
    book = PolicyEngine(policy, registry, "bookkeeper")
    research = PolicyEngine(policy, registry, "research-assistant")
    state = SessionState()
    clean, tainted = Label(), Label.parse("untrusted/internal")
    cases: list[tuple[str, Callable[[], object]]] = [
        (
            "decide: allowed read (glob)",
            lambda: book.decide(ToolCall("read_file", {"path": "invoices/a.txt"}), clean, state),
        ),
        (
            "decide: payment (decimal bounds, budget)",
            lambda: book.decide(
                ToolCall("pay", {"payee_id": "acme", "amount": 120, "currency": "USD"}),
                clean,
                state,
            ),
        ),
        (
            "decide: tainted high-impact -> approval",
            lambda: book.decide(
                ToolCall("pay", {"payee_id": "acme", "amount": 120, "currency": "USD"}),
                tainted,
                state,
            ),
        ),
        (
            "decide: URL allow-list denial",
            lambda: research.decide(
                ToolCall("fetch_url", {"url": "https://evil.test/c?d=x"}), clean, state
            ),
        ),
    ]
    print(f"python {platform.python_version()} on {platform.machine()} ({sys.platform}), N={N}")
    print(f"{'case':<44} {'median us':>10} {'p99 us':>10}")
    for name, fn in cases:
        med, p99 = measure(fn)
        print(f"{name:<44} {med:>10.1f} {p99:>10.1f}")

    session = GuardedSession(book, audit=AuditLog(), approver=deny_all)
    call = ToolCall("get_balance", {"currency": "USD"})
    med, p99 = measure(lambda: session.call(call), n=5_000)
    print(f"{'session.call: decide+execute+2 audit records':<44} {med:>10.1f} {p99:>10.1f}")


if __name__ == "__main__":
    main()
