"""Small builders shared by the unit tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml

from agentguard.labels import BOTTOM, Label
from agentguard.tooling import (
    CallContext,
    Impact,
    SpendSpec,
    Tool,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)


def obj(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": list(props) if required is None else required,
    }


def echo(label: Label = BOTTOM) -> Any:
    def handler(args: Mapping[str, Any], ctx: CallContext) -> ToolOutput:
        return ToolOutput(f"ok {dict(args)}", label)

    return handler


def mini_registry() -> ToolRegistry:
    """read (low), write (medium), send (high, egress), pay (high, spend), fetch (untrusted)."""
    s = {"type": "string"}
    specs = [
        (ToolSpec("read", "read", ("fs.read",), obj({"path": s}), Impact.LOW), BOTTOM),
        (
            ToolSpec("write", "write", ("fs.write",), obj({"path": s, "text": s}), Impact.MEDIUM),
            BOTTOM,
        ),
        (
            ToolSpec(
                "send",
                "send",
                ("net.send",),
                obj({"to": s, "body": {"type": "string", "sensitive": True}}),
                Impact.HIGH,
                egress=True,
            ),
            BOTTOM,
        ),
        (
            ToolSpec(
                "pay",
                "pay",
                ("money.pay",),
                obj(
                    {"to": s, "amount": {"type": "number"}, "currency": s, "memo": s},
                    required=["to", "amount", "currency"],
                ),
                Impact.HIGH,
                spend=SpendSpec("amount", "currency"),
            ),
            BOTTOM,
        ),
        (
            ToolSpec(
                "fetch",
                "fetch",
                ("net.fetch",),
                obj({"url": s}),
                Impact.LOW,
                output_label=Label.parse("untrusted"),
            ),
            Label.parse("untrusted"),
        ),
        (
            ToolSpec(
                "copy",
                "copy",
                ("fs.read", "fs.write"),
                obj({"path": s, "dest": s}),
                Impact.MEDIUM,
                arg_aliases={"fs.write": {"path": "dest"}},
            ),
            BOTTOM,
        ),
    ]
    return ToolRegistry([Tool(spec, echo(label)) for spec, label in specs])


def policy_doc(text: str) -> Any:
    return yaml.safe_load(text)
