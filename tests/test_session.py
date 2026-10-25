"""GuardedSession: execution, approvals, labels, monitor mode and the audit trail."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from agentguard.approval import ApprovalRequest, ApprovalResponse, approve_all, deny_all
from agentguard.audit import AuditLog, verify_records
from agentguard.engine import PolicyEngine, ToolCall, Verdict
from agentguard.errors import SandboxError
from agentguard.labels import Label
from agentguard.limits import ManualClock
from agentguard.policy import parse_policy
from agentguard.session import GuardedSession, Mode, Status, check_taint_invariant
from agentguard.tooling import CallContext, Tool, ToolOutput, ToolRegistry
from tests.helpers import mini_registry, policy_doc

POLICY = """
version: 1
name: session-test
tasks:
  main:
    max_tool_calls: 6
    grants:
      - {id: r, capability: fs.read}
      - {id: w, capability: fs.write}
      - id: s
        capability: net.send
        rate: {calls: 1, per_seconds: 100}
      - id: p
        capability: money.pay
        approve_above: {amount: 10}
      - {id: f, capability: net.fetch}
    budgets:
      - {id: b, capability: money.pay, currency: USD, limit: 30}
"""


def make(
    approver: Any = deny_all, mode: Mode = Mode.ENFORCE, registry: ToolRegistry | None = None
) -> GuardedSession:
    reg = registry or mini_registry()
    engine = PolicyEngine(parse_policy(policy_doc(POLICY)), reg, "main")
    clock = ManualClock(100.0)
    return GuardedSession(
        engine,
        audit=AuditLog(clock=clock),
        approver=approver,
        mode=mode,
        clock=clock,
        session_id="s1",
    )


def pay(amount: float) -> ToolCall:
    return ToolCall("pay", {"to": "acme", "amount": amount, "currency": "USD"})


def events(session: GuardedSession) -> list[str]:
    return [r["event"] for r in session.audit.records]


def test_allowed_call_executes_and_is_audited() -> None:
    s = make()
    result = s.call(ToolCall("read", {"path": "a"}, "c1"))
    assert result.status is Status.EXECUTED
    assert result.executed
    assert result.message.startswith("ok")
    assert events(s) == ["session_start", "decision", "execution"]
    decision = s.audit.records[1]
    assert decision["verdict"] == "allow"
    assert decision["call_id"] == "c1"
    assert decision["grants"] == ["r"]
    assert s.stats.allowed == 1
    assert s.stats.by_tool["read"] == {"allowed": 1, "executed": 1}


def test_denied_call_does_not_execute() -> None:
    s = make()
    result = s.call(ToolCall("pay", {"to": "acme", "amount": 5, "currency": "EUR"}))
    assert result.status is Status.DENIED
    assert result.message.startswith("[agentguard] DENIED pay: budget b is in USD")
    assert events(s) == ["session_start", "decision"]
    assert s.stats.denied == 1


def test_fetch_taints_context_then_high_impact_needs_approval() -> None:
    s = make(approver=deny_all)
    s.call(ToolCall("fetch", {"url": "u"}))
    assert s.context.tainted
    assert "context_label" in events(s)
    result = s.call(ToolCall("send", {"to": "x", "body": "secret body"}))
    assert result.status is Status.REFUSED
    assert "needs human approval" in result.message
    assert result.approval is not None
    assert result.approval.approved is False
    approval = next(r for r in s.audit.records if r["event"] == "approval")
    assert approval["approved"] is False
    # sensitive argument is redacted in the decision record
    decision = [r for r in s.audit.records if r["event"] == "decision"][-1]
    assert decision["args"]["body"].startswith("sha256:")
    assert check_taint_invariant(s.audit.records) == []


def test_approved_call_runs_and_satisfies_invariant() -> None:
    seen: list[ApprovalRequest] = []

    def approver(req: ApprovalRequest) -> ApprovalResponse:
        seen.append(req)
        return approve_all(req)

    s = make(approver=approver)
    s.call(ToolCall("fetch", {"url": "u"}))
    result = s.call(ToolCall("send", {"to": "x", "body": "b"}))
    assert result.status is Status.EXECUTED
    assert s.stats.approved == 1
    assert "step 1: fetch" in seen[0].taint_trace
    assert seen[0].args["body"].startswith("sha256:")
    assert check_taint_invariant(s.audit.records) == []


def test_rate_and_budget_commit_only_after_execution() -> None:
    s = make(approver=deny_all)
    assert s.call(pay(20)).status is Status.REFUSED  # above approve_above, refused
    assert s.state.ledger.spent == {}
    assert s.call(pay(10)).status is Status.EXECUTED
    assert s.call(pay(10)).status is Status.EXECUTED
    assert s.call(pay(10)).status is Status.EXECUTED
    result = s.call(pay(1))
    assert result.status is Status.DENIED
    assert "would exceed limit 30" in result.message
    assert s.call(ToolCall("send", {"to": "x", "body": "b"})).status is Status.EXECUTED
    assert "rate limit" in s.call(ToolCall("send", {"to": "x", "body": "b"})).message


def test_tool_call_cap_counts_executions() -> None:
    s = make()
    for _ in range(6):
        assert s.call(ToolCall("read", {"path": "a"})).status is Status.EXECUTED
    assert "tool-call limit 6" in s.call(ToolCall("read", {"path": "a"})).message


def _registry_with(handler: Any, label: Label | None = None) -> ToolRegistry:
    reg = mini_registry()
    tools = [t if t.spec.name != "read" else Tool(t.spec, handler) for t in reg]
    out = ToolRegistry(tools)
    if label is not None:
        spec = out.get("read").spec
        object.__setattr__(spec, "output_label", label)
    return out


def test_tool_errors_are_contained_and_still_label() -> None:
    def failing(args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        raise SandboxError("no such file")

    s = make(registry=_registry_with(failing))
    result = s.call(ToolCall("read", {"path": "a"}))
    assert result.status is Status.ERROR
    assert result.executed
    assert result.message == "[tool error] no such file"
    assert s.stats.errors == 1

    def crashing(args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        raise ZeroDivisionError

    s = make(registry=_registry_with(crashing, Label.parse("untrusted")))
    result = s.call(ToolCall("read", {"path": "a"}))
    assert result.message == "[tool error] internal tool error (ZeroDivisionError)"
    assert s.context.tainted  # an error page from an untrusted source still taints


def test_handler_sees_context_label() -> None:
    labels: list[Label] = []

    def spy(args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        labels.append(ctx.label)
        return ToolOutput("x")

    s = make(registry=_registry_with(spy))
    s.call(ToolCall("read", {"path": "a"}))
    s.call(ToolCall("fetch", {"url": "u"}))
    s.call(ToolCall("read", {"path": "a"}))
    assert [label.tainted for label in labels] == [False, True]


def test_observe_external_content() -> None:
    s = make()
    s.observe(Label.parse("untrusted"), "pasted document")
    assert s.context.tainted
    assert s.context.explain().endswith("pasted document -> untrusted/public")


def test_monitor_mode_executes_but_records_overrides() -> None:
    s = make(mode=Mode.MONITOR)
    s.call(ToolCall("fetch", {"url": "u"}))
    result = s.call(ToolCall("send", {"to": "x", "body": "b"}))
    assert result.status is Status.EXECUTED
    assert result.decision.verdict is Verdict.REQUIRE_APPROVAL
    assert "monitor_override" in events(s)
    assert s.stats.would_block == 1
    violations = check_taint_invariant(s.audit.records)
    assert [(v.tool, v.detail) for v in violations] == [("send", "high-impact from taint")]
    # structurally broken calls are never executed, even in monitor mode
    assert s.call(ToolCall("nope", {})).status is Status.DENIED
    assert s.call(ToolCall("read", {"path": 3})).status is Status.DENIED


def test_close_and_audit_verifies() -> None:
    s = make()
    s.call(ToolCall("read", {"path": "a"}))
    s.close("done")
    assert s.audit.records[-1]["event"] == "session_end"
    assert s.audit.records[-1]["outcome"] == "done"
    assert verify_records(s.audit.records).ok


def test_default_session_id_and_audit() -> None:
    engine = PolicyEngine(parse_policy(policy_doc(POLICY)), mini_registry(), "main")
    s = GuardedSession(engine)
    assert len(s.session_id) == 12
    assert s.audit.records[0]["policy_digest"] == engine.policy.digest


@pytest.mark.parametrize("mode", [Mode.ENFORCE, Mode.MONITOR])
def test_non_mapping_args_are_denied(mode: Mode) -> None:
    s = make(mode=mode)
    result = s.call(ToolCall("read", "path=a"))
    assert result.status is Status.DENIED
    decision = [r for r in s.audit.records if r["event"] == "decision"][-1]
    assert decision["args"] == "path=a"
