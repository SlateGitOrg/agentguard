"""Guarded sessions: decide, ask, execute, label and audit every tool call.

:class:`GuardedSession` is the single choke point between an agent and its tools. It owns the
monotone context label, the rate/budget state and the audit trail for one task run. The only
way a tool handler is invoked is through :meth:`GuardedSession.call`.

``Mode.MONITOR`` executes everything and only *records* what enforcement would have done; it
exists to roll a policy out safely and to measure the unprotected baseline in evaluations.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from agentguard.approval import ApprovalRequest, ApprovalResponse, Approver, ask, deny_all
from agentguard.audit import AuditLog, digest_value, redact
from agentguard.engine import Decision, PolicyEngine, SessionState, ToolCall, Verdict
from agentguard.errors import SandboxError
from agentguard.labels import ContextLabel, Label
from agentguard.limits import BudgetLedger, Clock, SlidingWindowLimiter, monotonic_clock
from agentguard.tooling import CallContext, Impact, ToolOutput

log = logging.getLogger(__name__)


class Mode(StrEnum):
    ENFORCE = "enforce"
    MONITOR = "monitor"


class Status(StrEnum):
    EXECUTED = "executed"
    DENIED = "denied"
    REFUSED = "refused"  # approval was required and not given
    ERROR = "error"  # the tool ran and failed


@dataclass(frozen=True)
class CallResult:
    status: Status
    decision: Decision
    step: int
    message: str
    output: ToolOutput | None = None
    approval: ApprovalResponse | None = None

    @property
    def executed(self) -> bool:
        return self.status in (Status.EXECUTED, Status.ERROR)


@dataclass
class SessionStats:
    allowed: int = 0
    approval_requested: int = 0
    approved: int = 0
    denied: int = 0
    executed: int = 0
    errors: int = 0
    would_block: int = 0  # monitor mode: calls enforcement would have denied or held
    by_tool: dict[str, dict[str, int]] = field(default_factory=dict)

    def bump(self, tool: str, key: str) -> None:
        self.by_tool.setdefault(tool, {}).setdefault(key, 0)
        self.by_tool[tool][key] += 1


class GuardedSession:
    def __init__(
        self,
        engine: PolicyEngine,
        *,
        audit: AuditLog | None = None,
        approver: Approver = deny_all,
        mode: Mode = Mode.ENFORCE,
        clock: Clock = monotonic_clock,
        session_id: str | None = None,
    ) -> None:
        self.engine = engine
        self.audit = audit if audit is not None else AuditLog()
        self.approver = approver
        self.mode = mode
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.context = ContextLabel()
        self.state = SessionState(limiter=SlidingWindowLimiter(clock), ledger=BudgetLedger())
        self.stats = SessionStats()
        self.step = 0
        self.audit.append(
            "session_start",
            session=self.session_id,
            policy=engine.policy.name,
            policy_digest=engine.policy.digest,
            task=engine.task.name,
            mode=mode.value,
        )

    # ---------------------------------------------------------------------------------------

    def observe(self, label: Label, origin: str) -> None:
        """Account for content entering the context from outside a tool (e.g. a pasted file)."""
        self._absorb(label, origin)

    def _absorb(self, label: Label, origin: str) -> None:
        before = self.context.current
        if self.context.absorb(label, step=self.step, origin=origin):
            self.audit.append(
                "context_label",
                session=self.session_id,
                step=self.step,
                origin=origin,
                before=before.describe(),
                after=self.context.current.describe(),
            )

    def _audit_decision(self, call: ToolCall, decision: Decision) -> None:
        spec = (
            self.engine.registry.get(call.name).spec if call.name in self.engine.registry else None
        )
        sensitive = spec.sensitive_args if spec else frozenset()
        args = redact(call.args, sensitive) if isinstance(call.args, Mapping) else call.args
        self.audit.append(
            "decision",
            session=self.session_id,
            step=self.step,
            tool=call.name,
            call_id=call.call_id,
            args=args,
            verdict=decision.verdict.value,
            reasons=list(decision.reasons),
            approval_reasons=list(decision.approval_reasons),
            grants=list(decision.grants),
            impact=decision.impact.name.lower() if decision.impact is not None else None,
            context=decision.context.describe(),
        )

    def _request(self, call: ToolCall, decision: Decision) -> ApprovalResponse:
        spec = self.engine.registry.get(call.name).spec
        request = ApprovalRequest(
            task=self.engine.task.name,
            tool=call.name,
            args=redact(call.args, spec.sensitive_args),
            reasons=decision.approval_reasons,
            context=decision.context.describe(),
            taint_trace=self.context.explain(),
            step=self.step,
        )
        response = ask(self.approver, request)
        self.audit.append(
            "approval",
            session=self.session_id,
            step=self.step,
            tool=call.name,
            approved=response.approved,
            approver=response.approver,
            note=response.note,
        )
        return response

    # ---------------------------------------------------------------------------------------

    def call(self, call: ToolCall) -> CallResult:
        """Mediate one tool call end to end. Never raises for policy or tool failures."""
        self.step += 1
        decision = self.engine.decide(call, self.context.current, self.state)
        self._audit_decision(call, decision)
        approval: ApprovalResponse | None = None

        if self.mode is Mode.MONITOR:
            if decision.verdict is not Verdict.ALLOW:
                self.audit.append(
                    "monitor_override",
                    session=self.session_id,
                    step=self.step,
                    tool=call.name,
                    would_be=decision.verdict.value,
                )
            if not decision.executable:
                return self._finish_denied(call, decision)
            self.stats.allowed += 1
            self.stats.bump(call.name, "allowed")
            if decision.verdict is not Verdict.ALLOW:
                self.stats.would_block += 1
            return self._execute(call, decision, approval)

        if decision.verdict is Verdict.DENY:
            return self._finish_denied(call, decision)
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            self.stats.approval_requested += 1
            self.stats.bump(call.name, "approval_requested")
            approval = self._request(call, decision)
            if not approval.approved:
                self.stats.bump(call.name, "refused")
                reasons = "; ".join(decision.approval_reasons)
                return CallResult(
                    Status.REFUSED,
                    decision,
                    self.step,
                    f"[agentguard] {call.name} needs human approval ({reasons}) and it was "
                    f"not given ({approval.note}). Do not retry; continue without it.",
                    approval=approval,
                )
            self.stats.approved += 1
        else:
            self.stats.allowed += 1
            self.stats.bump(call.name, "allowed")
        return self._execute(call, decision, approval)

    def _finish_denied(self, call: ToolCall, decision: Decision) -> CallResult:
        self.stats.denied += 1
        self.stats.bump(call.name, "denied")
        return CallResult(
            Status.DENIED,
            decision,
            self.step,
            f"[agentguard] DENIED {call.name}: {'; '.join(decision.reasons)}",
        )

    def _execute(
        self, call: ToolCall, decision: Decision, approval: ApprovalResponse | None
    ) -> CallResult:
        tool = self.engine.registry.get(call.name)
        args = dict(call.args)
        status = Status.EXECUTED
        output: ToolOutput | None = None
        error = ""
        try:
            output = tool.handler(
                args, CallContext(self.context.current, self.step, self.session_id)
            )
        except SandboxError as exc:
            status, error = Status.ERROR, str(exc)
        except Exception as exc:  # a crashing tool must not crash the guard
            log.exception("tool %s crashed", call.name)
            status, error = Status.ERROR, f"internal tool error ({type(exc).__name__})"

        self.state.calls_executed += 1
        for key, _spec in decision.rate_keys:
            self.state.limiter.commit(key)
        if status is Status.EXECUTED:
            for intent in decision.spend:
                self.state.ledger.commit(intent.budget, intent.amount)
        self.stats.executed += 1
        self.stats.bump(call.name, "executed")

        out_label = tool.spec.output_label
        if output is not None:
            out_label = out_label.join(output.label)
        self.audit.append(
            "execution",
            session=self.session_id,
            step=self.step,
            tool=call.name,
            status=status.value,
            impact=tool.spec.impact.name.lower(),
            context=self.context.current.describe(),
            approved=approval.approved if approval else None,
            output_label=out_label.describe(),
            output_digest=digest_value(output.content) if output else None,
            error=error or None,
        )
        if status is Status.ERROR:
            self.stats.errors += 1
            # Even a failed call may have read attacker-controlled data (e.g. an error page).
            self._absorb(tool.spec.output_label, f"{call.name} (error)")
            return CallResult(status, decision, self.step, f"[tool error] {error}", None, approval)
        assert output is not None
        self._absorb(out_label, call.name)
        return CallResult(status, decision, self.step, output.content, output, approval)

    def close(self, outcome: str = "") -> None:
        self.audit.append(
            "session_end",
            session=self.session_id,
            steps=self.step,
            context=self.context.current.describe(),
            outcome=outcome,
        )


# ------------------------------------------------------------------------------------------
# Invariant checking over audit records
# ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class InvariantViolation:
    session: str
    step: int
    tool: str
    detail: str


def check_taint_invariant(records: list[dict[str, Any]]) -> list[InvariantViolation]:
    """Every *executed* high-impact call made from a tainted context has an approval.

    Works purely from the audit log, so it can be run by an auditor who does not trust the
    process that produced the log (after :func:`agentguard.audit.verify_log`).
    """
    approved: set[tuple[str, int]] = set()
    violations: list[InvariantViolation] = []
    for record in records:
        key = (str(record.get("session")), int(record.get("step", -1)))
        if record.get("event") == "approval" and record.get("approved") is True:
            approved.add(key)
        elif record.get("event") == "execution":
            tainted = str(record.get("context", "")).startswith("untrusted")
            high = record.get("impact") == Impact.HIGH.name.lower()
            if high and tainted and key not in approved:
                violations.append(
                    InvariantViolation(
                        key[0], key[1], str(record.get("tool")), "high-impact from taint"
                    )
                )
    return violations
