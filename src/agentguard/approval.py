"""Human-approval hooks.

When the engine returns ``REQUIRE_APPROVAL`` the session asks an :class:`Approver`. Approvers
are fail-closed: any exception, or any return value that is not an :class:`ApprovalResponse`,
counts as a refusal. The request shows the human the *redacted* arguments, every reason the
call needs approval and where the context's taint came from -- the information needed to spot
"send_email to an address that only appeared inside an inbound message".
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApprovalRequest:
    task: str
    tool: str
    args: Mapping[str, Any]
    reasons: tuple[str, ...]
    context: str
    taint_trace: str
    step: int

    def render(self) -> str:
        lines = [
            f"[agentguard] approval needed (task {self.task}, step {self.step})",
            f"  tool:    {self.tool}",
            f"  args:    {dict(self.args)}",
            f"  context: {self.context}",
            f"  taint:   {self.taint_trace}",
        ]
        lines.extend(f"  reason:  {r}" for r in self.reasons)
        return "\n".join(lines)


@dataclass(frozen=True)
class ApprovalResponse:
    approved: bool
    approver: str
    note: str = ""


class Approver(Protocol):
    def __call__(self, request: ApprovalRequest) -> ApprovalResponse: ...


def deny_all(request: ApprovalRequest) -> ApprovalResponse:
    """Unattended operation: nobody is there to approve, so nothing needing approval runs."""
    return ApprovalResponse(False, "auto-deny", "no human available")


def approve_all(request: ApprovalRequest) -> ApprovalResponse:
    """A rubber-stamping human. Useful to measure the *approval burden* of a policy."""
    return ApprovalResponse(True, "auto-approve", "approve-all hook")


@dataclass
class RecordingApprover:
    """Wraps another approver and keeps every request it saw (tests, evaluations)."""

    inner: Approver
    seen: list[ApprovalRequest]

    def __call__(self, request: ApprovalRequest) -> ApprovalResponse:
        self.seen.append(request)
        return self.inner(request)


@dataclass
class PredicateApprover:
    """Approve exactly the requests ``predicate`` accepts (a scripted, careful human)."""

    predicate: Callable[[ApprovalRequest], bool]
    name: str = "predicate"

    def __call__(self, request: ApprovalRequest) -> ApprovalResponse:
        ok = bool(self.predicate(request))
        return ApprovalResponse(ok, self.name, "approved" if ok else "rejected by rule")


@dataclass
class ConsoleApprover:
    """Interactive y/N prompt. Anything other than an explicit ``y``/``yes`` is a refusal."""

    stdin: TextIO
    stdout: TextIO

    def __call__(self, request: ApprovalRequest) -> ApprovalResponse:
        self.stdout.write(request.render() + "\n  approve? [y/N] ")
        self.stdout.flush()
        answer = self.stdin.readline().strip().lower()
        return ApprovalResponse(answer in ("y", "yes"), "console", f"answered {answer!r}")


def ask(approver: Approver, request: ApprovalRequest) -> ApprovalResponse:
    """Call ``approver`` fail-closed."""
    try:
        response = approver(request)
    except Exception as exc:  # an approval hook must never be able to fail open
        log.warning("approval hook raised %s; treating as refusal", exc)
        return ApprovalResponse(False, "error", f"approval hook raised {type(exc).__name__}")
    if not isinstance(response, ApprovalResponse):
        return ApprovalResponse(False, "error", "approval hook returned an invalid response")
    return response
