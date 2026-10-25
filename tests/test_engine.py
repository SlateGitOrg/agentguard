"""Decision procedure: every stage of PolicyEngine.decide."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard.engine import PolicyEngine, SessionState, ToolCall, Verdict
from agentguard.labels import BOTTOM, Integrity, Label, Secrecy
from agentguard.limits import ManualClock, SlidingWindowLimiter
from agentguard.policy import parse_policy
from tests.helpers import mini_registry, policy_doc

POLICY = """
version: 1
name: engine-test
egress: {internal: allow, secret: require_approval}
tasks:
  main:
    max_tool_calls: 10
    grants:
      - id: read-notes
        capability: fs.read
        constraints: {path: {glob: ["notes/**"]}}
      - id: read-docs
        capability: fs.read
        constraints: {path: {glob: ["docs/**"]}}
      - id: write-out
        capability: fs.write
        constraints: {path: {glob: ["out/**"]}}
      - id: send-team
        capability: net.send
        constraints: {to: {email: {domains: [example.com]}}}
        rate: {calls: 2, per_seconds: 60}
      - id: pay
        capability: money.pay
        constraints: {amount: {max: 500}, currency: {one_of: [USD]}}
        approve_above: {amount: 100}
      - id: fetch
        capability: net.fetch
        approval: when_tainted
    deny:
      - capability: fs.*
        constraints: {path: {glob: ["**/secret*"]}}
        reason: no secrets
    budgets:
      - {id: spend, capability: money.pay, currency: USD, limit: 300}
  locked:
    grants:
      - capability: fs.read
    taint: {low: deny, medium: deny, high: deny}
  strict-egress:
    grants:
      - capability: net.send
      - capability: fs.read
"""

TAINTED = Label(Integrity.UNTRUSTED, Secrecy.PUBLIC)
SECRET = Label(Integrity.TRUSTED, Secrecy.SECRET)
INTERNAL = Label(Integrity.TRUSTED, Secrecy.INTERNAL)


def engine(task: str = "main", policy_text: str = POLICY) -> PolicyEngine:
    return PolicyEngine(parse_policy(policy_doc(policy_text)), mini_registry(), task)


def decide(
    name: str,
    args: Any,
    context: Label = BOTTOM,
    state: SessionState | None = None,
    task: str = "main",
) -> Any:
    return engine(task).decide(ToolCall(name, args), context, state or SessionState())


def test_allow_with_matching_grant() -> None:
    d = decide("read", {"path": "docs/a.md"})
    assert d.verdict is Verdict.ALLOW
    assert d.allowed
    assert d.grants == ("read-docs",)  # first grant failed, second accepted
    assert d.explain() == "allow read | via read-docs"


@pytest.mark.parametrize(
    ("name", "args", "fragment"),
    [
        ("nope", {}, "unknown tool 'nope'"),
        ("read", "path=notes/a", "must be a JSON object"),
        ("read", {"path": 5}, "schema: path: expected string"),
        ("read", {"path": "notes/a", "x": 1}, "x: unexpected argument"),
        ("read", {"path": "notes/secret.txt"}, "deny rule on fs.*: no secrets"),
        ("read", {"path": "src/a.py"}, "no grant for 'fs.read' accepts"),
        ("read", {"path": "notes/../../etc/passwd"}, "not a valid sandbox-relative path"),
        ("send", {"to": "x@evil.test", "body": "hi"}, "not in allowed domains"),
        ("pay", {"to": "acme", "amount": 501, "currency": "USD"}, "exceeds max 500"),
        ("pay", {"to": "acme", "amount": 50, "currency": "EUR"}, "not one of"),
        ("copy", {"path": "notes/a", "dest": "notes/b"}, "path 'notes/b' matches none of"),
        ("copy", {"path": "out/a", "dest": "out/b"}, "no grant for 'fs.read'"),
        ("copy", {"path": "notes/a", "dest": "out/secret"}, "deny rule on fs.*"),
    ],
)
def test_denials(name: str, args: Any, fragment: str) -> None:
    d = decide(name, args)
    assert d.verdict is Verdict.DENY
    assert fragment in d.explain()


def test_structural_denials_are_not_executable() -> None:
    assert decide("nope", {}).executable is False
    assert decide("read", "x").executable is False
    assert decide("read", {"path": 1}).executable is False
    assert decide("read", {"path": "notes/secret"}).executable is True


def test_aliases_route_write_constraints_to_dest() -> None:
    d = decide("copy", {"path": "notes/a", "dest": "out/b"})
    assert d.verdict is Verdict.ALLOW
    assert d.grants == ("read-notes", "write-out")


def test_multi_capability_tool_needs_every_capability() -> None:
    text = POLICY.replace(
        "      - id: write-out\n        capability: fs.write\n        constraints: "
        '{path: {glob: ["out/**"]}}\n',
        "",
    )
    d = engine(policy_text=text).decide(
        ToolCall("copy", {"path": "notes/a", "dest": "out/b"}), BOTTOM, SessionState()
    )
    assert d.verdict is Verdict.DENY
    assert "capability 'fs.write' not granted" in d.reasons[0]


def test_tool_call_cap() -> None:
    state = SessionState(calls_executed=10)
    assert "tool-call limit 10" in decide("read", {"path": "notes/a"}, state=state).explain()


def test_rate_limit_and_keys() -> None:
    clock = ManualClock()
    state = SessionState(limiter=SlidingWindowLimiter(clock))
    args = {"to": "a@example.com", "body": "x"}
    d = decide("send", args, state=state)
    assert d.rate_keys
    assert d.rate_keys[0][0] == "main/send-team"
    for _ in range(2):
        state.limiter.commit("main/send-team")
    assert "rate limit 2/60s" in decide("send", args, state=state).explain()
    clock.advance(61)
    assert decide("send", args, state=state).verdict is Verdict.ALLOW


def test_budget_and_thresholds() -> None:
    state = SessionState()
    small = {"to": "acme", "amount": 80, "currency": "usd"}
    assert decide("pay", small, state=state).verdict is Verdict.DENY  # one_of is case-sensitive
    small["currency"] = "USD"
    d = decide("pay", small, state=state)
    assert d.verdict is Verdict.ALLOW
    assert d.spend[0].amount == 80
    big = {"to": "acme", "amount": 250, "currency": "USD"}
    d = decide("pay", big, state=state)
    assert d.verdict is Verdict.REQUIRE_APPROVAL
    assert d.approval_reasons == ("amount=250 above approval threshold 100 (grant pay)",)
    state.ledger.commit(d.spend[0].budget, d.spend[0].amount)
    d = decide("pay", {"to": "acme", "amount": 60, "currency": "USD"}, state=state)
    assert "would exceed limit 300" in d.explain()


def test_taint_rules_by_impact() -> None:
    assert decide("read", {"path": "notes/a"}, TAINTED).verdict is Verdict.ALLOW
    assert decide("write", {"path": "out/a", "text": "t"}, TAINTED).verdict is Verdict.ALLOW
    d = decide("pay", {"to": "acme", "amount": 5, "currency": "USD"}, TAINTED)
    assert d.verdict is Verdict.REQUIRE_APPROVAL
    assert "context is tainted and pay is high-impact" in d.approval_reasons[0]
    locked = decide("read", {"path": "x"}, TAINTED, task="locked")
    assert locked.verdict is Verdict.DENY
    assert "tainted" in locked.reasons[0]


def test_when_tainted_grant_approval() -> None:
    assert decide("fetch", {"url": "u"}).verdict is Verdict.ALLOW
    d = decide("fetch", {"url": "u"}, TAINTED)
    assert d.approval_reasons == ("grant fetch requires approval in a tainted context",)


def test_egress_by_secrecy() -> None:
    args = {"to": "a@example.com", "body": "x"}
    assert decide("send", args, INTERNAL).verdict is Verdict.ALLOW
    d = decide("send", args, SECRET)
    assert d.verdict is Verdict.REQUIRE_APPROVAL
    assert "holds secret data" in d.approval_reasons[0]
    deny_egress = POLICY.replace(
        "egress: {internal: allow, secret: require_approval}",
        "egress: {internal: deny, secret: deny}",
    )
    d = engine("strict-egress", deny_egress).decide(
        ToolCall("send", args), INTERNAL, SessionState()
    )
    assert d.verdict is Verdict.DENY


def test_tainted_and_secret_accumulate_reasons() -> None:
    d = decide(
        "send", {"to": "a@example.com", "body": "x"}, Label(Integrity.UNTRUSTED, Secrecy.SECRET)
    )
    assert d.verdict is Verdict.REQUIRE_APPROVAL
    assert len(d.approval_reasons) == 2
    assert "needs approval" in d.explain()


def test_always_approval_mode() -> None:
    text = POLICY.replace("        approval: when_tainted", "        approval: always")
    d = engine(policy_text=text).decide(ToolCall("fetch", {"url": "u"}), BOTTOM, SessionState())
    assert d.approval_reasons == ("grant fetch always requires approval",)


def test_visible_tools_hide_ungranted() -> None:
    names = [s.name for s in engine().visible_tools()]
    assert names == ["read", "write", "send", "pay", "fetch", "copy"]
    assert [s.name for s in engine("locked").visible_tools()] == ["read"]


def test_decide_is_pure() -> None:
    state = SessionState()
    eng = engine()
    for _ in range(5):
        eng.decide(ToolCall("send", {"to": "a@example.com", "body": "x"}), BOTTOM, state)
        eng.decide(ToolCall("pay", {"to": "a", "amount": 90, "currency": "USD"}), BOTTOM, state)
    assert state.calls_executed == 0
    assert state.ledger.spent == {}
    assert state.limiter.count("main/send-team", engine().task.grants[3].rate) == 0  # type: ignore[arg-type]
