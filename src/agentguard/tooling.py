"""Tool declarations: capabilities, impact, argument schemas and the tool registry.

A tool is *declared* (:class:`ToolSpec`) separately from its *implementation* (a handler
callable). The policy engine only ever looks at specs, so the same policy can mediate the
sandboxed fake tools used in tests and real tools in an embedding application.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from agentguard.errors import RegistryError, SchemaError
from agentguard.labels import BOTTOM, Label
from agentguard.schema import JsonSchema, check_schema, sensitive_fields

CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
CAPABILITY_PATTERN_RE = re.compile(r"^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?)$")
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class Impact(IntEnum):
    """How much damage a single call can do if it was induced by an attacker."""

    LOW = 0  # read-only, no side effects
    MEDIUM = 1  # reversible or contained side effects (write a workspace file)
    HIGH = 2  # irreversible or externally visible (pay, send, delete)


def capability_matches(pattern: str, capability: str) -> bool:
    """Match a capability against a grant pattern.

    ``*`` matches everything; ``fs.*`` matches ``fs.read`` and ``fs.read.meta`` but not ``fs``
    itself or ``fsx.read`` (matching is on dot-separated segments, never raw prefixes).
    """
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return capability.startswith(prefix + ".")
    return pattern == capability


@dataclass(frozen=True)
class SpendSpec:
    """Which arguments of a tool carry a monetary amount and its currency (for budgets)."""

    amount_arg: str
    currency_arg: str


@dataclass(frozen=True)
class ToolSpec:
    """Static declaration of a tool, as seen by the policy engine and by the model."""

    name: str
    description: str
    capabilities: tuple[str, ...]
    args_schema: JsonSchema
    impact: Impact
    output_label: Label = BOTTOM
    egress: bool = False
    spend: SpendSpec | None = None
    # Per-capability argument aliases for multi-capability tools. ``{"fs.write": {"path":
    # "dest"}}`` means: when an fs.write grant (or deny rule) constrains ``path``, check this
    # tool's ``dest`` argument instead. Without it, a ``copy(path, dest)`` tool would have its
    # write target unconstrained by grants written for ``write_file(path, ...)``.
    arg_aliases: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not TOOL_NAME_RE.match(self.name):
            raise SchemaError(f"invalid tool name {self.name!r}")
        if not self.capabilities:
            raise SchemaError(f"tool {self.name} must declare at least one capability")
        for cap in self.capabilities:
            if not CAPABILITY_RE.match(cap):
                raise SchemaError(f"tool {self.name}: invalid capability {cap!r}")
        if self.args_schema.get("type") != "object":
            raise SchemaError(f"tool {self.name}: argument schema must be an object schema")
        check_schema(self.args_schema, f"{self.name}.args")
        props = self.args_schema.get("properties", {})
        for cap, aliases in self.arg_aliases.items():
            if cap not in self.capabilities:
                raise SchemaError(f"tool {self.name}: alias for undeclared capability {cap!r}")
            for target in aliases.values():
                if target not in props:
                    raise SchemaError(f"tool {self.name}: alias target {target!r} not in schema")
        if self.spend is not None:
            for arg in (self.spend.amount_arg, self.spend.currency_arg):
                if arg not in props:
                    raise SchemaError(f"tool {self.name}: spend argument {arg!r} not in schema")

    @property
    def argument_names(self) -> frozenset[str]:
        return frozenset(self.args_schema.get("properties", {}))

    def resolve_arg(self, capability: str, arg: str) -> str:
        """The tool argument that policy argument ``arg`` refers to for ``capability``."""
        return self.arg_aliases.get(capability, {}).get(arg, arg)

    def args_for(self, capability: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
        """View of ``args`` as seen by grants for ``capability`` (aliases applied)."""
        aliases = self.arg_aliases.get(capability)
        if not aliases:
            return args
        view = dict(args)
        for policy_arg, tool_arg in aliases.items():
            if tool_arg in args:
                view[policy_arg] = args[tool_arg]
            else:
                view.pop(policy_arg, None)
        return view

    @property
    def sensitive_args(self) -> frozenset[str]:
        return sensitive_fields(self.args_schema)

    def openai_schema(self) -> dict[str, Any]:
        """Render as an OpenAI-compatible ``tools`` entry (agentguard extensions stripped)."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": _strip_extensions(self.args_schema),
            },
        }


def _strip_extensions(schema: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "sensitive":
            continue
        if key == "properties":
            out[key] = {k: _strip_extensions(v) for k, v in value.items()}
        elif key == "items":
            out[key] = _strip_extensions(value)
        else:
            out[key] = value
    return out


@dataclass(frozen=True)
class ToolOutput:
    """What a tool handler returns: text for the model plus a data-flow label."""

    content: str
    label: Label = BOTTOM
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CallContext:
    """What a handler may know about the call: the context label at call time (so data the
    tool *stores* keeps the label of the context that produced it), the step and session."""

    label: Label = BOTTOM
    step: int = 0
    session: str = ""


Handler = Callable[[Mapping[str, Any], CallContext], ToolOutput]


@dataclass(frozen=True)
class Tool:
    spec: ToolSpec
    handler: Handler


class ToolRegistry:
    """Name -> :class:`Tool` mapping; duplicate names are rejected."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        if tool.spec.name in self._tools:
            raise RegistryError(f"tool {tool.spec.name!r} registered twice")
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise RegistryError(f"unknown tool {name!r}") from None

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

    def specs(self) -> list[ToolSpec]:
        return [t.spec for t in self._tools.values()]

    def subset(self, names: list[str]) -> ToolRegistry:
        return ToolRegistry([self.get(n) for n in names])
