"""The decision procedure: one tool call in, one :class:`Decision` out.

Evaluation order (the first DENY wins; approval reasons accumulate)::

    1. tool exists in the registry                       -> else DENY
    2. arguments validate against the tool's schema       -> else DENY
    3. no explicit deny rule matches                      -> else DENY
    4. every declared capability has a satisfied grant    -> else DENY
    5. session tool-call cap not reached                  -> else DENY
    6. rate limits of the matched grants have room        -> else DENY
    7. spend fits every budget covering the tool          -> else DENY
    8. taint rule for the tool's impact (context tainted) -> DENY / approval
    9. egress rule for the context's secrecy (egress tool) -> DENY / approval
   10. grant approval mode and approve_above thresholds   -> approval
   => REQUIRE_APPROVAL if any approval reason, else ALLOW

``decide`` never mutates state: rate-limit and budget consumption is committed by the session
only after the tool actually ran. Cost is O(G*C + A) for G grants, C declared capabilities
and A argument values (plus constraint evaluation, linear in argument length).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Any

from agentguard.constraints import to_decimal
from agentguard.errors import RegistryError
from agentguard.labels import Label, Secrecy
from agentguard.limits import BudgetLedger, SlidingWindowLimiter
from agentguard.policy import Action, ApprovalMode, Budget, Grant, Policy, RateSpec, TaskPolicy
from agentguard.schema import validate
from agentguard.tooling import Impact, ToolRegistry, ToolSpec, capability_matches

log = logging.getLogger(__name__)


class Verdict(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation proposed by the model."""

    name: str
    args: Any  # normally a mapping; anything else is denied by the engine
    call_id: str = ""


@dataclass(frozen=True)
class SpendIntent:
    budget: Budget
    currency: str
    amount: Decimal


@dataclass(frozen=True)
class Decision:
    """The engine's verdict plus everything needed to explain and commit it."""

    verdict: Verdict
    tool: str
    reasons: tuple[str, ...] = ()
    approval_reasons: tuple[str, ...] = ()
    grants: tuple[str, ...] = ()
    impact: Impact | None = None
    context: Label = field(default_factory=Label)
    rate_keys: tuple[tuple[str, RateSpec], ...] = ()
    spend: tuple[SpendIntent, ...] = ()
    executable: bool = True  # False when the call cannot run at all (unknown tool, bad args)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def explain(self) -> str:
        parts = [f"{self.verdict.value} {self.tool}"]
        if self.grants:
            parts.append(f"via {', '.join(self.grants)}")
        if self.reasons:
            parts.append("; ".join(self.reasons))
        if self.approval_reasons:
            parts.append("needs approval: " + "; ".join(self.approval_reasons))
        return " | ".join(parts)


@dataclass
class SessionState:
    """Mutable per-session counters the engine reads (and the session commits to)."""

    limiter: SlidingWindowLimiter = field(default_factory=SlidingWindowLimiter)
    ledger: BudgetLedger = field(default_factory=BudgetLedger)
    calls_executed: int = 0


def _deny(tool: str, reason: str, **extra: Any) -> Decision:
    return Decision(Verdict.DENY, tool, reasons=(reason,), **extra)


class PolicyEngine:
    """Evaluates tool calls for one task of a bound policy."""

    def __init__(self, policy: Policy, registry: ToolRegistry, task: str) -> None:
        policy.bind(registry)
        self.policy = policy
        self.registry = registry
        self.task: TaskPolicy = policy.task(task)
        self.taint_rules = policy.taint_rules(self.task)

    def visible_tools(self) -> list[ToolSpec]:
        """Tools whose every capability is covered by some grant: what the model is shown.

        Hiding ungranted tools is a usability measure only; :meth:`decide` re-checks anyway.
        """
        return [
            spec
            for spec in self.registry.specs()
            if all(self.task.grants_for(cap) for cap in spec.capabilities)
        ]

    def decide(self, call: ToolCall, context: Label, state: SessionState) -> Decision:
        """Evaluate ``call`` made from a context labelled ``context``. Pure w.r.t. ``state``."""
        try:
            spec = self.registry.get(call.name).spec
        except RegistryError:
            return _deny(
                call.name, f"unknown tool {call.name!r}", context=context, executable=False
            )
        base: dict[str, Any] = {"impact": spec.impact, "context": context}

        if not isinstance(call.args, Mapping):
            return _deny(spec.name, "arguments must be a JSON object", executable=False, **base)
        violations = validate(spec.args_schema, dict(call.args))
        if violations:
            detail = "; ".join(str(v) for v in violations)
            return _deny(spec.name, f"schema: {detail}", executable=False, **base)
        args = dict(call.args)

        denied = self._explicit_deny(spec, args)
        if denied is not None:
            return _deny(spec.name, denied, **base)
        matched, failure = self._match_grants(spec, args)
        if failure is not None:
            return _deny(spec.name, failure, **base)
        base["grants"] = tuple(g.id for g in matched)

        cap_limit = self.task.max_tool_calls
        if cap_limit is not None and state.calls_executed >= cap_limit:
            return _deny(spec.name, f"session tool-call limit {cap_limit} reached", **base)
        rate_keys, failure = self._check_rates(matched, state)
        if failure is not None:
            return _deny(spec.name, failure, **base)
        base["rate_keys"] = rate_keys
        spend, failure = self._check_budgets(spec, args, state)
        if failure is not None:
            return _deny(spec.name, failure, **base)
        base["spend"] = spend

        approval: list[str] = []
        for action, why in self._flow_rules(spec, context):
            if action is Action.DENY:
                return _deny(spec.name, why, **base)
            if action is Action.REQUIRE_APPROVAL:
                approval.append(why)
        for grant in matched:
            if grant.approval is ApprovalMode.ALWAYS:
                approval.append(f"grant {grant.id} always requires approval")
            elif grant.approval is ApprovalMode.WHEN_TAINTED and context.tainted:
                approval.append(f"grant {grant.id} requires approval in a tainted context")
            approval.extend(grant.thresholds_exceeded(args))

        verdict = Verdict.REQUIRE_APPROVAL if approval else Verdict.ALLOW
        decision = Decision(verdict, spec.name, approval_reasons=tuple(approval), **base)
        log.debug("decision %s", decision.explain())
        return decision

    # -- stages --------------------------------------------------------------------------------

    def _explicit_deny(self, spec: ToolSpec, args: Mapping[str, Any]) -> str | None:
        for cap in spec.capabilities:
            view = spec.args_for(cap, args)
            for rule in self.task.denies:
                if rule.matches(cap, view):
                    return f"deny rule on {rule.capability}: {rule.reason}"
        return None

    def _match_grants(
        self, spec: ToolSpec, args: Mapping[str, Any]
    ) -> tuple[list[Grant], str | None]:
        """For every declared capability pick the first grant whose constraints accept
        ``args``. A tool with several capabilities needs all of them (conjunction)."""
        matched: list[Grant] = []
        for cap in spec.capabilities:
            candidates = self.task.grants_for(cap)
            if not candidates:
                return [], f"capability {cap!r} not granted to task {self.task.name!r}"
            failures: list[str] = []
            chosen: Grant | None = None
            view = spec.args_for(cap, args)
            for grant in candidates:
                problems = grant.check(view)
                if not problems:
                    chosen = grant
                    break
                failures.extend(f"[{grant.id}] {p}" for p in problems)
            if chosen is None:
                return [], f"no grant for {cap!r} accepts these arguments: " + "; ".join(failures)
            if all(g.id != chosen.id for g in matched):  # one grant may cover several caps
                matched.append(chosen)
        return matched, None

    def _check_rates(
        self, matched: list[Grant], state: SessionState
    ) -> tuple[tuple[tuple[str, RateSpec], ...], str | None]:
        keys: list[tuple[str, RateSpec]] = []
        for grant in matched:
            if grant.rate is not None:
                key = f"{self.task.name}/{grant.id}"
                reason = state.limiter.check(key, grant.rate)
                if reason:
                    return (), reason
                keys.append((key, grant.rate))
        return tuple(keys), None

    def _check_budgets(
        self, spec: ToolSpec, args: Mapping[str, Any], state: SessionState
    ) -> tuple[tuple[SpendIntent, ...], str | None]:
        if spec.spend is None:
            return (), None
        amount = to_decimal(args.get(spec.spend.amount_arg))
        currency = str(args.get(spec.spend.currency_arg, ""))
        if amount is None:  # pragma: no cover - the schema already requires a number
            return (), "spend amount is not a number"
        intents: list[SpendIntent] = []
        for budget in self.task.budgets:
            if any(capability_matches(budget.capability, c) for c in spec.capabilities):
                reason = state.ledger.check(budget, currency, amount)
                if reason:
                    return (), reason
                intents.append(SpendIntent(budget, currency.upper(), amount))
        return tuple(intents), None

    def _flow_rules(self, spec: ToolSpec, context: Label) -> list[tuple[Action, str]]:
        """Information-flow checks: integrity (taint -> impact) and secrecy (-> egress)."""
        out: list[tuple[Action, str]] = []
        if context.tainted:
            why = f"context is tainted and {spec.name} is {spec.impact.name.lower()}-impact"
            out.append((self.taint_rules.for_impact(spec.impact), why))
        if spec.egress and context.secrecy >= Secrecy.INTERNAL:
            rules = self.policy.egress
            action = rules.secret if context.secrecy is Secrecy.SECRET else rules.internal
            level = context.secrecy.name.lower()
            out.append((action, f"context holds {level} data and {spec.name} sends data out"))
        return out
