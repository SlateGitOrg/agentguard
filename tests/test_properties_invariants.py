"""Property tests for the core safety invariants of a guarded session.

Random call sequences over a tool set that includes taint sources, with a random approver,
must never (1) run a high-impact handler from a tainted context without an approval that
said yes, (2) run anything the engine denied, (3) lower the context label, or (4) produce an
audit log that fails verification or the auditor's invariant check.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from agentguard.approval import ApprovalRequest, ApprovalResponse
from agentguard.audit import AuditLog, verify_records
from agentguard.engine import PolicyEngine, ToolCall, Verdict
from agentguard.labels import Label
from agentguard.limits import ManualClock
from agentguard.policy import parse_policy
from agentguard.session import GuardedSession, Mode, Status, check_taint_invariant
from agentguard.tooling import CallContext, Impact, Tool, ToolOutput, ToolRegistry
from tests.helpers import mini_registry, policy_doc

POLICY = """
version: 1
name: prop
taint: {medium: allow, high: require_approval}
egress: {internal: allow, secret: require_approval}
tasks:
  main:
    grants:
      - id: r
        capability: fs.read
        constraints: {path: {glob: ["notes/**", "secret/**"]}}
      - id: w
        capability: fs.write
        constraints: {path: {glob: ["out/**"]}}
      - id: s
        capability: net.send
        constraints: {to: {email: {domains: [example.com]}}}
        rate: {calls: 3, per_seconds: 50}
      - id: p
        capability: money.pay
        constraints: {amount: {max: 100}, currency: {one_of: [USD]}}
        approve_above: {amount: 40}
      - {id: f, capability: net.fetch}
    budgets:
      - {id: b, capability: money.pay, currency: USD, limit: 150}
"""

paths = st.sampled_from(["notes/a", "notes/x/y", "secret/k", "out/r", "../etc", "src/z"])
calls = st.one_of(
    st.builds(lambda p: ToolCall("read", {"path": p}), paths),
    st.builds(lambda p: ToolCall("write", {"path": p, "text": "t"}), paths),
    st.builds(
        lambda to: ToolCall("send", {"to": to, "body": "b"}),
        st.sampled_from(["a@example.com", "x@evil.test", "nope"]),
    ),
    st.builds(
        lambda a, c: ToolCall("pay", {"to": "acme", "amount": a, "currency": c}),
        st.sampled_from([1, 39.99, 40, 41, 100, 101, -5, "12", True]),
        st.sampled_from(["USD", "EUR"]),
    ),
    st.builds(lambda u: ToolCall("fetch", {"url": u}), st.sampled_from(["u1", "u2"])),
    st.builds(lambda n: ToolCall(n, {}), st.sampled_from(["nope", "read"])),
)


def build(approvals: list[bool], mode: Mode) -> tuple[GuardedSession, list[tuple[str, Label]]]:
    """Session over the mini registry; ``fetch`` taints, reading ``secret/`` raises secrecy.
    ``ran`` records (tool, context label at call time) for every handler that executed."""
    ran: list[tuple[str, Label]] = []

    def wrap(tool: Tool) -> Tool:
        def handler(args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
            ran.append((tool.spec.name, ctx.label))
            out = tool.handler(args, ctx)
            if tool.spec.name == "read" and str(args.get("path", "")).startswith("secret/"):
                return ToolOutput(out.content, Label.parse("secret"))
            return out

        return Tool(tool.spec, handler)

    registry = ToolRegistry([wrap(t) for t in mini_registry()])
    answers = iter(approvals)

    def approver(request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(next(answers, False), "random")

    clock = ManualClock()
    engine = PolicyEngine(parse_policy(policy_doc(POLICY)), registry, "main")
    session = GuardedSession(
        engine, audit=AuditLog(clock=clock), approver=approver, mode=mode, clock=clock
    )
    return session, ran


@given(st.lists(calls, max_size=25), st.lists(st.booleans(), max_size=25), st.data())
def test_enforce_mode_invariants(
    sequence: list[ToolCall], approvals: list[bool], data: st.DataObject
) -> None:
    session, ran = build(approvals, Mode.ENFORCE)
    clock = session.state.limiter.clock
    previous = session.context.current
    for call in sequence:
        if isinstance(clock, ManualClock):
            clock.advance(data.draw(st.sampled_from([0, 1, 30])))
        before_runs = len(ran)
        result = session.call(call)
        executed_now = len(ran) > before_runs
        # (2) deny/refuse means the handler did not run
        if result.status in (Status.DENIED, Status.REFUSED):
            assert not executed_now
        if result.decision.verdict is Verdict.DENY:
            assert not executed_now
        # (1) high-impact from taint only with a yes
        spec_impact = result.decision.impact
        if executed_now and spec_impact is Impact.HIGH and result.decision.context.tainted:
            assert result.approval is not None
            assert result.approval.approved
        # (3) monotone label
        assert previous.flows_to(session.context.current)
        previous = session.context.current
    # handler-side view: every high-impact handler that ran from a tainted context was approved
    high = {"send", "pay"}
    tainted_high_runs = [name for name, label in ran if name in high and label.tainted]
    approved = sum(
        1
        for r in session.audit.records
        if r["event"] == "approval" and r["approved"] and r["tool"] in high
    )
    assert len(tainted_high_runs) <= approved
    # (4) the audit trail verifies and the auditor finds no violation
    session.close()
    assert verify_records(session.audit.records).ok
    assert check_taint_invariant(session.audit.records) == []
    # budgets are never exceeded
    assert sum(session.state.ledger.spent.values()) <= 150


@given(st.lists(calls, max_size=20))
def test_monitor_mode_auditor_catches_every_unapproved_tainted_high_call(
    sequence: list[ToolCall],
) -> None:
    session, ran = build([], Mode.MONITOR)
    for call in sequence:
        session.call(call)
    session.close()
    tainted_high = [n for n, label in ran if n in ("send", "pay") and label.tainted]
    assert len(check_taint_invariant(session.audit.records)) == len(tainted_high)
