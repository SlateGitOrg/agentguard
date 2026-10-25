"""Tests for the YAML policy language: parsing, strictness and binding to a registry."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentguard.errors import PolicyError
from agentguard.policy import Action, ApprovalMode, load_policy, parse_policy
from agentguard.tooling import Impact
from agentguard.tools import World, sandbox_registry
from tests.helpers import mini_registry, policy_doc

GOOD = """
version: 1
name: test
taint: {medium: require_approval}
egress: {internal: require_approval, secret: deny}
tasks:
  t:
    description: demo
    max_tool_calls: 5
    grants:
      - id: r
        capability: fs.read
        constraints: {path: {glob: ["notes/**"]}}
      - capability: fs.write
      - id: p
        capability: money.*
        constraints: {amount: {max: 100}, currency: {one_of: [USD]}}
        approve_above: {amount: 50}
        approval: when_tainted
        rate: {calls: 2, per_seconds: 60}
    deny:
      - capability: fs.read
        constraints: {path: {glob: ["notes/secret*"]}}
        reason: private
    budgets:
      - {id: b, capability: money.pay, currency: usd, limit: 150}
    taint: {low: allow, high: deny}
"""


def test_parse_good_policy() -> None:
    policy = parse_policy(policy_doc(GOOD)).bind(mini_registry())
    task = policy.task("t")
    assert policy.taint.medium is Action.REQUIRE_APPROVAL
    assert policy.egress.secret is Action.DENY
    assert task.max_tool_calls == 5
    assert [g.id for g in task.grants] == ["r", "grant-1", "p"]
    pay = task.grants[2]
    assert pay.approval is ApprovalMode.WHEN_TAINTED
    assert pay.approve_above == {"amount": Decimal(50)}
    assert pay.rate is not None
    assert pay.rate.calls == 2
    assert task.budgets[0].currency == "USD"
    # task-level taint inherits unspecified levels from the policy-level rules
    rules = policy.taint_rules(task)
    assert rules.medium is Action.REQUIRE_APPROVAL
    assert rules.high is Action.DENY
    assert rules.for_impact(Impact.LOW) is Action.ALLOW
    assert task.grants_for("money.pay") == [pay]
    assert pay.thresholds_exceeded({"amount": 60}) == [
        "amount=60 above approval threshold 50 (grant p)"
    ]
    assert pay.thresholds_exceeded({"amount": "junk"}) == []
    assert len(policy.digest) == 64
    with pytest.raises(PolicyError, match="no task 'missing'"):
        policy.task("missing")


def test_digest_is_stable_and_content_sensitive() -> None:
    a = parse_policy(policy_doc(GOOD))
    b = parse_policy(policy_doc(GOOD))
    c = parse_policy(policy_doc(GOOD.replace("max: 100", "max: 101")))
    assert a.digest == b.digest != c.digest


def test_deny_rule_matching() -> None:
    task = parse_policy(policy_doc(GOOD)).task("t")
    rule = task.denies[0]
    assert rule.matches("fs.read", {"path": "notes/secret.md"})
    assert not rule.matches("fs.read", {"path": "notes/public.md"})
    assert not rule.matches("fs.write", {"path": "notes/secret.md"})
    assert not rule.matches("fs.read", {})


def _mutate(old: str, new: str) -> Any:
    assert old in GOOD, old
    return policy_doc(GOOD.replace(old, new, 1))


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ("version: 1", "version: 2", "unsupported policy version"),
        ("name: test", "name: ''", "non-empty 'name'"),
        ("name: test", "name: test\nextra: 1", "unknown key(s) ['extra']"),
        ("taint: {medium: require_approval}", "taint: {high: allow}", "may not be allowed"),
        ("taint: {low: allow, high: deny}", "taint: {high: allow}", "may not be allowed"),
        ("taint: {medium: require_approval}", "taint: {medium: maybe}", "expected one of"),
        ("taint: {medium: require_approval}", "taint: {extreme: deny}", "unknown key"),
        ("egress: {internal: require_approval, secret: deny}", "egress: {public: deny}", "unknown"),
        ("max_tool_calls: 5", "max_tool_calls: 0", "positive integer"),
        ("max_tool_calls: 5", "max_tool_calls: true", "positive integer"),
        ("      - id: r\n", "      - id: r\n        bogus: 1\n", "unknown key"),
        ("capability: fs.write", "capability: FS.Write", "invalid capability pattern"),
        ("capability: fs.write", "constraints: {}", "needs a 'capability'"),
        ("- id: p", "- id: r", "duplicate grant ids"),
        ("- id: p", "- id: ''", "non-empty string"),
        ("approval: when_tainted", "approval: sometimes", "approval must be one of"),
        ("approve_above: {amount: 50}", "approve_above: {amount: lots}", "must be a number"),
        ("per_seconds: 60", "per_seconds: 0", "positive number"),
        ("calls: 2,", "calls: -1,", "positive integer"),
        ('{path: {glob: ["notes/**"]}}', "{path: {}}", "no constraints given"),
        ('{path: {glob: ["notes/**"]}}', '{path: {glob: ["/abs"]}}', "invalid glob"),
        ('{path: {glob: ["notes/**"]}}', "{path: [notes]}", "expected a mapping"),
        ("        reason: private", "        reason: 5", "reason must be a string"),
        (
            '      - capability: fs.read\n        constraints: {path: {glob: ["notes/secret*"]}}',
            '      - constraints: {path: {glob: ["notes/secret*"]}}',
            "needs a 'capability'",
        ),
        ("currency: usd, limit: 150", "currency: usd", "budget needs 'limit'"),
        ("limit: 150", "limit: -1", "non-negative"),
        ("currency: usd", "currency: '$$'", "alphabetic"),
        ("    grants:\n", "    grants: {}\n    old_grants:\n", "unknown key"),
        ("    budgets:\n", "    budgets: {}\n    old_budgets:\n", "unknown key"),
    ],
)
def test_parse_errors(old: str, new: str, fragment: str) -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy(_mutate(old, new))
    assert fragment in str(info.value)


def test_structural_errors() -> None:
    with pytest.raises(PolicyError, match="expected a mapping"):
        parse_policy(["not", "a", "policy"])
    with pytest.raises(PolicyError, match="defines no tasks"):
        parse_policy({"version": 1, "name": "x", "tasks": {}})
    with pytest.raises(PolicyError, match="grants must be a list"):
        parse_policy({"version": 1, "name": "x", "tasks": {"t": {"grants": {}}}})
    with pytest.raises(PolicyError, match="deny and budgets must be lists"):
        parse_policy({"version": 1, "name": "x", "tasks": {"t": {"deny": {}}}})


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ("capability: fs.write", "capability: db.write", "covers no tool"),
        (
            'constraints: {path: {glob: ["notes/**"]}}',
            'constraints: {file: {glob: ["notes/**"]}}',
            "has no such argument",
        ),
        (
            "constraints: {amount: {max: 100}, currency: {one_of: [USD]}}",
            "constraints: {memo: {max_length: 10}}",
            "optional in tool 'pay'",
        ),
        ("approve_above: {amount: 50}", "approve_above: {currency: 50}", "not a numeric argument"),
        ("    deny:\n      - capability: fs.read", "    deny:\n      - capability: db.x", "covers"),
        ('{path: {glob: ["notes/secret*"]}}', "{file: {glob: [x]}}", "has no such argument"),
        ("capability: money.pay, currency", "capability: db.x, currency", "covers no tool"),
        ("capability: money.pay, currency", "capability: fs.read, currency", "no spend arguments"),
    ],
)
def test_bind_errors(old: str, new: str, fragment: str) -> None:
    policy = parse_policy(_mutate(old, new))
    with pytest.raises(PolicyError) as info:
        policy.bind(mini_registry())
    assert fragment in str(info.value)


def test_bind_resolves_aliases_for_multi_capability_tools() -> None:
    # 'copy' declares fs.write with path->dest; dest is required, so binding succeeds and an
    # optional alias target would be rejected exactly like an optional plain argument.
    parse_policy(policy_doc(GOOD)).bind(mini_registry())
    doc = policy_doc(
        GOOD.replace(
            "- capability: fs.write",
            "- capability: fs.write\n        constraints: {path: {glob: [out/**]}}",
        )
    )
    parse_policy(doc).bind(mini_registry())


def test_load_policy_file_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read policy file"):
        load_policy(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [1\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(bad)


def test_shipped_policy_binds_to_sandbox_tools(root: Path) -> None:
    policy = load_policy(root / "policies" / "assistant.yaml", sandbox_registry(World()))
    assert set(policy.tasks) == {
        "inbox-assistant",
        "research-assistant",
        "bookkeeper",
        "file-organizer",
    }
    assert policy.taint.high is Action.REQUIRE_APPROVAL
