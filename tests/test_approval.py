"""Approval hooks are fail-closed."""

from __future__ import annotations

import io

from agentguard.approval import (
    ApprovalRequest,
    ApprovalResponse,
    ConsoleApprover,
    PredicateApprover,
    RecordingApprover,
    approve_all,
    ask,
    deny_all,
)

REQ = ApprovalRequest(
    task="t",
    tool="pay",
    args={"amount": 5},
    reasons=("context is tainted",),
    context="untrusted/public",
    taint_trace="step 1: fetch -> untrusted/public",
    step=2,
)


def test_render_contains_everything_a_human_needs() -> None:
    text = REQ.render()
    for fragment in ("tool:    pay", "{'amount': 5}", "untrusted/public", "step 1: fetch"):
        assert fragment in text


def test_basic_approvers() -> None:
    assert ask(deny_all, REQ).approved is False
    assert ask(approve_all, REQ).approved is True
    rec = RecordingApprover(approve_all, [])
    assert ask(rec, REQ).approved
    assert rec.seen == [REQ]
    pred = PredicateApprover(lambda r: r.tool != "pay", "careful")
    resp = ask(pred, REQ)
    assert (resp.approved, resp.approver, resp.note) == (False, "careful", "rejected by rule")


def test_hook_exceptions_and_garbage_are_refusals() -> None:
    def boom(request: ApprovalRequest) -> ApprovalResponse:
        raise RuntimeError("hook crashed")

    def garbage(request: ApprovalRequest) -> ApprovalResponse:
        return True  # type: ignore[return-value]

    assert ask(boom, REQ) == ApprovalResponse(False, "error", "approval hook raised RuntimeError")
    assert ask(garbage, REQ).approved is False


def test_console_approver_requires_explicit_yes() -> None:
    for answer, expected in (("y\n", True), ("YES\n", True), ("\n", False), ("sure\n", False)):
        out = io.StringIO()
        resp = ConsoleApprover(io.StringIO(answer), out)(REQ)
        assert resp.approved is expected
        assert "approve? [y/N]" in out.getvalue()
