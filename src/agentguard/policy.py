"""The YAML policy language: parsing, validation and binding to a tool registry.

A policy grants *capabilities* to *tasks*. An agent session runs under exactly one task and may
only call tools whose every declared capability is covered by one of the task's grants, with
the call's arguments satisfying the grant's constraints. Anything not granted is denied.

Example (see ``policies/assistant.yaml`` for the full shipped policy)::

    version: 1
    name: assistant
    taint:                       # what a *tainted* context may do, by tool impact
      medium: allow
      high: require_approval     # 'allow' is rejected here: see THREAT_MODEL.md
    egress:                      # what a context holding secret data may send out
      secret: require_approval
    tasks:
      inbox-assistant:
        max_tool_calls: 30
        grants:
          - id: read-notes
            capability: fs.read
            constraints:
              path: {glob: ["notes/**"], deny_glob: ["**/.env"]}
          - id: pay-vendors
            capability: payments.transfer
            constraints: {currency: {one_of: [USD]}, amount: {max: 500}}
            approve_above: {amount: 100}
            rate: {calls: 3, per_seconds: 3600}
        deny:
          - capability: fs.write
            constraints: {path: {glob: ["**/*.sh"]}}
            reason: no executable scripts
        budgets:
          - {id: daily-spend, capability: payments.transfer, currency: USD, limit: 400}

Validation is strict and fail-closed: unknown keys, unknown constraint kinds, constraints on
arguments a covered tool does not have (or does not *require*), and grants that cover no
registered tool are all :class:`~agentguard.errors.PolicyError` at load/bind time, because
each of those silently widens what a policy author believed they granted.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from agentguard.constraints import ArgumentConstraints, build_constraint, to_decimal
from agentguard.errors import PolicyError
from agentguard.tooling import (
    CAPABILITY_PATTERN_RE,
    Impact,
    ToolRegistry,
    ToolSpec,
    capability_matches,
)

SUPPORTED_VERSION = 1


class Action(StrEnum):
    """What a rule tells the engine to do with a call it applies to."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ApprovalMode(StrEnum):
    """When a grant itself demands human approval."""

    NEVER = "never"
    ALWAYS = "always"
    WHEN_TAINTED = "when_tainted"


@dataclass(frozen=True)
class TaintRules:
    """Action for calls made while the context is tainted (untrusted), keyed by tool impact.

    ``high`` can never be ``allow``: that is the core safety invariant of the engine.
    """

    low: Action = Action.ALLOW
    medium: Action = Action.ALLOW
    high: Action = Action.REQUIRE_APPROVAL

    def for_impact(self, impact: Impact) -> Action:
        return {Impact.LOW: self.low, Impact.MEDIUM: self.medium, Impact.HIGH: self.high}[impact]


@dataclass(frozen=True)
class EgressRules:
    """Action for egress-capable tools, keyed by the secrecy of the context."""

    internal: Action = Action.ALLOW
    secret: Action = Action.REQUIRE_APPROVAL


@dataclass(frozen=True)
class RateSpec:
    """At most ``calls`` executions in any sliding window of ``per_seconds`` seconds."""

    calls: int
    per_seconds: float


@dataclass(frozen=True)
class Grant:
    """One capability granted to a task, with argument constraints and approval settings."""

    id: str
    capability: str
    constraints: tuple[ArgumentConstraints, ...] = ()
    approval: ApprovalMode = ApprovalMode.NEVER
    approve_above: Mapping[str, Decimal] = field(default_factory=dict)
    rate: RateSpec | None = None

    def covers(self, capability: str) -> bool:
        return capability_matches(self.capability, capability)

    def check(self, args: Mapping[str, Any]) -> list[str]:
        """Constraint failures for ``args`` (empty list = satisfied)."""
        failures: list[str] = []
        for arg_constraints in self.constraints:
            failures.extend(arg_constraints.check(args))
        return failures

    def thresholds_exceeded(self, args: Mapping[str, Any]) -> list[str]:
        """Human-readable reasons for every ``approve_above`` threshold the call exceeds."""
        out: list[str] = []
        for arg, limit in self.approve_above.items():
            value = to_decimal(args.get(arg))
            if value is not None and value > limit:
                out.append(f"{arg}={value} above approval threshold {limit} (grant {self.id})")
        return out


@dataclass(frozen=True)
class DenyRule:
    """Explicit deny: matches when the capability matches and every constrained argument is
    present with at least one value satisfying all of its constraints (for a list argument,
    any single element suffices). Deny rules win over grants."""

    capability: str
    constraints: tuple[ArgumentConstraints, ...]
    reason: str

    def matches(self, capability: str, args: Mapping[str, Any]) -> bool:
        if not capability_matches(self.capability, capability):
            return False
        return all(ac.satisfied_by_some(args) for ac in self.constraints)


@dataclass(frozen=True)
class Budget:
    """Cumulative spend limit per session, in one currency, over calls to matching tools."""

    id: str
    capability: str
    currency: str
    limit: Decimal


@dataclass(frozen=True)
class TaskPolicy:
    name: str
    description: str
    grants: tuple[Grant, ...]
    denies: tuple[DenyRule, ...] = ()
    budgets: tuple[Budget, ...] = ()
    max_tool_calls: int | None = None
    taint: TaintRules | None = None

    def grants_for(self, capability: str) -> list[Grant]:
        return [g for g in self.grants if g.covers(capability)]


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    tasks: Mapping[str, TaskPolicy]
    taint: TaintRules = field(default_factory=TaintRules)
    egress: EgressRules = field(default_factory=EgressRules)
    digest: str = ""

    def task(self, name: str) -> TaskPolicy:
        try:
            return self.tasks[name]
        except KeyError:
            raise PolicyError(f"policy {self.name!r} has no task {name!r}") from None

    def taint_rules(self, task: TaskPolicy) -> TaintRules:
        return task.taint if task.taint is not None else self.taint

    def bind(self, registry: ToolRegistry) -> Policy:
        """Check the policy against ``registry`` and return it; raise on any mismatch."""
        for task in self.tasks.values():
            _bind_task(task, registry)
        return self


# --------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------


def _expect_keys(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"unknown key(s) {sorted(unknown)}", where=where)


def _mapping(data: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise PolicyError(f"expected a mapping, got {type(data).__name__}", where=where)
    return data


def _action(value: Any, where: str) -> Action:
    try:
        return Action(value)
    except ValueError:
        raise PolicyError(
            f"expected one of {[a.value for a in Action]}, got {value!r}", where=where
        ) from None


def _capability_pattern(value: Any, where: str) -> str:
    if not isinstance(value, str) or not CAPABILITY_PATTERN_RE.match(value):
        raise PolicyError(f"invalid capability pattern {value!r}", where=where)
    return value


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PolicyError(f"expected a positive integer, got {value!r}", where=where)
    return value


def _parse_taint(data: Any, where: str, base: TaintRules) -> TaintRules:
    data = _mapping(data, where)
    _expect_keys(data, {"low", "medium", "high"}, where)
    rules = TaintRules(
        low=_action(data.get("low", base.low), f"{where}.low"),
        medium=_action(data.get("medium", base.medium), f"{where}.medium"),
        high=_action(data.get("high", base.high), f"{where}.high"),
    )
    if rules.high is Action.ALLOW:
        raise PolicyError(
            "high-impact tools may not be allowed from a tainted context "
            "(use require_approval or deny)",
            where=f"{where}.high",
        )
    return rules


def _parse_egress(data: Any, where: str) -> EgressRules:
    data = _mapping(data, where)
    _expect_keys(data, {"internal", "secret"}, where)
    base = EgressRules()
    return EgressRules(
        internal=_action(data.get("internal", base.internal), f"{where}.internal"),
        secret=_action(data.get("secret", base.secret), f"{where}.secret"),
    )


def _parse_constraints(data: Any, where: str) -> tuple[ArgumentConstraints, ...]:
    if data is None:
        return ()
    data = _mapping(data, where)
    out: list[ArgumentConstraints] = []
    for arg, spec in data.items():
        arg_where = f"{where}.{arg}"
        kinds = _mapping(spec, arg_where)
        if not kinds:
            raise PolicyError("no constraints given", where=arg_where)
        built = tuple(build_constraint(kind, value, arg_where) for kind, value in kinds.items())
        out.append(ArgumentConstraints(str(arg), built))
    return tuple(out)


def _parse_grant(data: Any, where: str, index: int) -> Grant:
    data = _mapping(data, where)
    _expect_keys(
        data, {"id", "capability", "constraints", "approval", "approve_above", "rate"}, where
    )
    if "capability" not in data:
        raise PolicyError("grant needs a 'capability'", where=where)
    capability = _capability_pattern(data["capability"], f"{where}.capability")
    grant_id = data.get("id", f"grant-{index}")
    if not isinstance(grant_id, str) or not grant_id:
        raise PolicyError("grant id must be a non-empty string", where=f"{where}.id")
    try:
        approval = ApprovalMode(data.get("approval", "never"))
    except ValueError:
        raise PolicyError(
            f"approval must be one of {[m.value for m in ApprovalMode]}", where=f"{where}.approval"
        ) from None
    thresholds: dict[str, Decimal] = {}
    for arg, raw in _mapping(data.get("approve_above", {}), f"{where}.approve_above").items():
        value = to_decimal(raw)
        if value is None:
            raise PolicyError(f"threshold for {arg!r} must be a number", where=where)
        thresholds[str(arg)] = value
    rate: RateSpec | None = None
    if "rate" in data:
        rate_data = _mapping(data["rate"], f"{where}.rate")
        _expect_keys(rate_data, {"calls", "per_seconds"}, f"{where}.rate")
        per = to_decimal(rate_data.get("per_seconds"))
        if per is None or per <= 0:
            raise PolicyError("per_seconds must be a positive number", where=f"{where}.rate")
        rate = RateSpec(_positive_int(rate_data.get("calls"), f"{where}.rate.calls"), float(per))
    return Grant(
        id=grant_id,
        capability=capability,
        constraints=_parse_constraints(data.get("constraints"), f"{where}.constraints"),
        approval=approval,
        approve_above=thresholds,
        rate=rate,
    )


def _parse_deny(data: Any, where: str) -> DenyRule:
    data = _mapping(data, where)
    _expect_keys(data, {"capability", "constraints", "reason"}, where)
    if "capability" not in data:
        raise PolicyError("deny rule needs a 'capability'", where=where)
    reason = data.get("reason", "explicitly denied by policy")
    if not isinstance(reason, str):
        raise PolicyError("reason must be a string", where=f"{where}.reason")
    return DenyRule(
        capability=_capability_pattern(data["capability"], f"{where}.capability"),
        constraints=_parse_constraints(data.get("constraints"), f"{where}.constraints"),
        reason=reason,
    )


def _parse_budget(data: Any, where: str) -> Budget:
    data = _mapping(data, where)
    _expect_keys(data, {"id", "capability", "currency", "limit"}, where)
    for key in ("id", "capability", "currency", "limit"):
        if key not in data:
            raise PolicyError(f"budget needs {key!r}", where=where)
    limit = to_decimal(data["limit"])
    if limit is None or limit < 0:
        raise PolicyError("limit must be a non-negative number", where=f"{where}.limit")
    currency = data["currency"]
    if not isinstance(currency, str) or not currency.isalpha():
        raise PolicyError("currency must be an alphabetic code", where=f"{where}.currency")
    return Budget(
        id=str(data["id"]),
        capability=_capability_pattern(data["capability"], f"{where}.capability"),
        currency=currency.upper(),
        limit=limit,
    )


def _parse_task(name: str, data: Any, where: str, base_taint: TaintRules) -> TaskPolicy:
    data = _mapping(data, where)
    _expect_keys(
        data, {"description", "grants", "deny", "budgets", "max_tool_calls", "taint"}, where
    )
    grants_raw = data.get("grants", [])
    if not isinstance(grants_raw, list):
        raise PolicyError("grants must be a list", where=f"{where}.grants")
    grants = tuple(_parse_grant(g, f"{where}.grants[{i}]", i) for i, g in enumerate(grants_raw))
    ids = [g.id for g in grants]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise PolicyError(f"duplicate grant ids {dupes}", where=f"{where}.grants")
    denies_raw = data.get("deny", [])
    budgets_raw = data.get("budgets", [])
    if not isinstance(denies_raw, list) or not isinstance(budgets_raw, list):
        raise PolicyError("deny and budgets must be lists", where=where)
    max_calls = data.get("max_tool_calls")
    return TaskPolicy(
        name=name,
        description=str(data.get("description", "")),
        grants=grants,
        denies=tuple(_parse_deny(d, f"{where}.deny[{i}]") for i, d in enumerate(denies_raw)),
        budgets=tuple(_parse_budget(b, f"{where}.budgets[{i}]") for i, b in enumerate(budgets_raw)),
        max_tool_calls=None
        if max_calls is None
        else _positive_int(max_calls, f"{where}.max_tool_calls"),
        taint=(
            _parse_taint(data["taint"], f"{where}.taint", base_taint) if "taint" in data else None
        ),
    )


def policy_digest(data: Any) -> str:
    """SHA-256 over the canonical JSON form of the parsed policy document."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def parse_policy(data: Any) -> Policy:
    """Build a :class:`Policy` from an already-parsed YAML/JSON document."""
    data = _mapping(data, "policy")
    _expect_keys(data, {"version", "name", "taint", "egress", "tasks"}, "policy")
    version = data.get("version")
    if version != SUPPORTED_VERSION:
        raise PolicyError(f"unsupported policy version {version!r} (expected 1)", where="policy")
    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyError("policy needs a non-empty 'name'", where="policy")
    taint = _parse_taint(data.get("taint", {}), "policy.taint", TaintRules())
    egress = _parse_egress(data.get("egress", {}), "policy.egress")
    tasks_raw = _mapping(data.get("tasks"), "policy.tasks")
    if not tasks_raw:
        raise PolicyError("policy defines no tasks", where="policy.tasks")
    tasks = {
        str(task_name): _parse_task(str(task_name), body, f"tasks.{task_name}", taint)
        for task_name, body in tasks_raw.items()
    }
    return Policy(
        name=name,
        version=version,
        tasks=tasks,
        taint=taint,
        egress=egress,
        digest=policy_digest(data),
    )


def load_policy(path: str | Path, registry: ToolRegistry | None = None) -> Policy:
    """Load a policy YAML file, optionally binding (cross-checking) it against ``registry``."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file: {exc}", where=str(path)) from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}", where=str(path)) from exc
    policy = parse_policy(data)
    return policy.bind(registry) if registry is not None else policy


# --------------------------------------------------------------------------------------------
# Binding
# --------------------------------------------------------------------------------------------


def _covered_tools(pattern: str, specs: list[ToolSpec]) -> list[ToolSpec]:
    return [s for s in specs if any(capability_matches(pattern, c) for c in s.capabilities)]


def _check_constrained_args(
    pattern: str,
    constraints: tuple[ArgumentConstraints, ...],
    tools: list[ToolSpec],
    where: str,
    *,
    require: bool,
) -> None:
    """Every constrained argument must exist in every covered tool (after per-capability
    aliasing) and, for grants, be *required* -- else omitting it would skip the check."""
    for spec in tools:
        required = set(spec.args_schema.get("required", []))
        caps = [c for c in spec.capabilities if capability_matches(pattern, c)]
        for arg_constraints in constraints:
            for cap in caps:
                arg = spec.resolve_arg(cap, arg_constraints.arg)
                if arg not in spec.argument_names:
                    raise PolicyError(
                        f"constraint on {arg_constraints.arg!r} but covered tool "
                        f"{spec.name!r} has no such argument",
                        where=where,
                    )
                if require and arg not in required:
                    raise PolicyError(
                        f"constraint on {arg!r} but it is optional in tool {spec.name!r}; "
                        "an omitted argument would bypass the constraint",
                        where=where,
                    )


def _bind_task(task: TaskPolicy, registry: ToolRegistry) -> None:
    specs = registry.specs()
    for grant in task.grants:
        where = f"tasks.{task.name}.grants[{grant.id}]"
        tools = _covered_tools(grant.capability, specs)
        if not tools:
            raise PolicyError(f"capability {grant.capability!r} covers no tool", where=where)
        _check_constrained_args(grant.capability, grant.constraints, tools, where, require=True)
        for arg in grant.approve_above:
            for spec in tools:
                arg_schema = spec.args_schema.get("properties", {}).get(arg)
                if arg_schema is None or arg_schema.get("type") not in ("integer", "number"):
                    raise PolicyError(
                        f"approve_above names {arg!r}, not a numeric argument of {spec.name!r}",
                        where=where,
                    )
    for index, rule in enumerate(task.denies):
        where = f"tasks.{task.name}.deny[{index}]"
        tools = _covered_tools(rule.capability, specs)
        if not tools:
            raise PolicyError(f"capability {rule.capability!r} covers no tool", where=where)
        _check_constrained_args(rule.capability, rule.constraints, tools, where, require=False)
    for budget in task.budgets:
        where = f"tasks.{task.name}.budgets[{budget.id}]"
        tools = _covered_tools(budget.capability, specs)
        if not tools:
            raise PolicyError(f"capability {budget.capability!r} covers no tool", where=where)
        for spec in tools:
            if spec.spend is None:
                raise PolicyError(
                    f"budget covers {spec.name!r}, which declares no spend arguments",
                    where=where,
                )
