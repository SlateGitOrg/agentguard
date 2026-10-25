"""Deny rules over list-valued arguments use existential semantics: one matching element
is enough for the deny rule to fire, so benign elements cannot dilute a forbidden one."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from agentguard.constraints import ArgumentConstraints, build_constraint
from agentguard.engine import PolicyEngine, SessionState, ToolCall, Verdict
from agentguard.labels import BOTTOM
from agentguard.policy import parse_policy
from agentguard.tooling import Impact, Tool, ToolRegistry, ToolSpec
from tests.helpers import echo, obj, policy_doc

POLICY = """
version: 1
name: deny-lists
tasks:
  main:
    grants:
      - id: g
        capability: fs.read
        constraints: {paths: {glob: ["**"]}}
    deny:
      - capability: fs.read
        constraints: {paths: {glob: ["**/.env"]}}
        reason: no credentials
"""


def registry() -> ToolRegistry:
    spec = ToolSpec(
        "read_many",
        "read several files",
        ("fs.read",),
        obj({"paths": {"type": "array", "items": {"type": "string"}}}),
        Impact.LOW,
    )
    return ToolRegistry([Tool(spec, echo())])


ENGINE = PolicyEngine(parse_policy(policy_doc(POLICY)), registry(), "main")


def decide(paths: list[str]) -> Verdict:
    return ENGINE.decide(ToolCall("read_many", {"paths": paths}), BOTTOM, SessionState()).verdict


def test_single_forbidden_element_is_denied() -> None:
    assert decide([".env"]) is Verdict.DENY


def test_benign_element_does_not_dilute_deny() -> None:
    d = ENGINE.decide(ToolCall("read_many", {"paths": ["a.txt", ".env"]}), BOTTOM, SessionState())
    assert d.verdict is Verdict.DENY
    assert "deny rule on fs.read: no credentials" in d.explain()


def test_all_benign_elements_allowed() -> None:
    assert decide(["a.txt", "b/c.md"]) is Verdict.ALLOW


def test_empty_list_does_not_trigger_deny() -> None:
    assert decide([]) is Verdict.ALLOW


def test_any_element_must_satisfy_every_constraint_of_the_argument() -> None:
    ac = ArgumentConstraints(
        "paths",
        (build_constraint("glob", ["secret/**"], "t"), build_constraint("max_length", 10, "t")),
    )
    # one element matches the glob, another the length bound, none matches both
    assert not ac.satisfied_by_some({"paths": ["secret/very-long-name", "x"]})
    assert ac.satisfied_by_some({"paths": ["x", "secret/k"]})
    assert ac.satisfied_by_some({"paths": "secret/k"})
    assert not ac.satisfied_by_some({"other": "secret/k"})


SAFE = st.sampled_from(["a.txt", "docs/r.md", "notes/x/y", "src/env.py", ".envrc"])
FORBIDDEN = st.sampled_from([".env", "app/.env", "a/b/.env"])


@given(st.lists(SAFE, max_size=5), FORBIDDEN, st.data())
def test_any_forbidden_element_denies_whatever_else_is_in_the_list(
    safe: list[str], bad: str, data: st.DataObject
) -> None:
    position = data.draw(st.integers(min_value=0, max_value=len(safe)))
    paths = [*safe[:position], bad, *safe[position:]]
    assert decide(paths) is Verdict.DENY


@given(st.lists(SAFE, max_size=6))
def test_lists_without_forbidden_elements_are_allowed(safe: list[str]) -> None:
    assert decide(safe) is Verdict.ALLOW
