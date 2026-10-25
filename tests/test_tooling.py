"""Tests for tool declarations, capability matching and the registry."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard.errors import RegistryError, SchemaError
from agentguard.tooling import Impact, SpendSpec, Tool, ToolRegistry, ToolSpec, capability_matches
from tests.helpers import echo, mini_registry, obj


@pytest.mark.parametrize(
    ("pattern", "cap", "ok"),
    [
        ("*", "anything.at.all", True),
        ("fs.*", "fs.read", True),
        ("fs.*", "fs.read.meta", True),
        ("fs.*", "fs", False),
        ("fs.*", "fsx.read", False),
        ("fs.read", "fs.read", True),
        ("fs.read", "fs.readx", False),
        ("fs", "fs.read", False),
    ],
)
def test_capability_matches(pattern: str, cap: str, ok: bool) -> None:
    assert capability_matches(pattern, cap) is ok


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"name": "Bad Name"}, "invalid tool name"),
        ({"capabilities": ()}, "at least one capability"),
        ({"capabilities": ("FS.read",)}, "invalid capability"),
        ({"capabilities": ("fs.*",)}, "invalid capability"),
        ({"args_schema": {"type": "string"}}, "must be an object schema"),
        ({"args_schema": {"type": "object", "properties": {"x": {"type": "date"}}}}, "type"),
        ({"spend": SpendSpec("amount", "currency")}, "spend argument 'amount'"),
        ({"arg_aliases": {"fs.write": {"path": "dest"}}}, "undeclared capability"),
        ({"arg_aliases": {"x.y": {"path": "dest"}}}, "alias target 'dest'"),
    ],
)
def test_toolspec_validation(kwargs: dict[str, Any], fragment: str) -> None:
    base: dict[str, Any] = {
        "name": "t",
        "description": "d",
        "capabilities": ("x.y",),
        "args_schema": obj({}),
        "impact": Impact.LOW,
    }
    base.update(kwargs)
    with pytest.raises(SchemaError, match=fragment):
        ToolSpec(**base)


def test_openai_schema_strips_extensions() -> None:
    spec = mini_registry().get("send").spec
    rendered = spec.openai_schema()
    assert rendered["function"]["name"] == "send"
    params = rendered["function"]["parameters"]
    assert "sensitive" not in params["properties"]["body"]
    assert spec.sensitive_args == frozenset({"body"})
    assert spec.argument_names == frozenset({"to", "body"})
    arr = ToolSpec(
        "arr",
        "d",
        ("x.y",),
        obj({"xs": {"type": "array", "items": {"type": "string", "sensitive": True}}}),
        Impact.LOW,
    )
    assert (
        "sensitive"
        not in arr.openai_schema()["function"]["parameters"]["properties"]["xs"]["items"]
    )


def test_arg_aliases_view() -> None:
    spec = mini_registry().get("copy").spec
    args = {"path": "a", "dest": "b"}
    assert spec.args_for("fs.read", args) == args
    assert spec.args_for("fs.write", args) == {"path": "b", "dest": "b"}
    assert spec.args_for("fs.write", {"path": "a"}) == {}
    assert spec.resolve_arg("fs.write", "path") == "dest"
    assert spec.resolve_arg("fs.read", "path") == "path"


def test_registry_operations() -> None:
    reg = mini_registry()
    assert len(reg) == 6
    assert "read" in reg
    assert "nope" not in reg
    assert [t.spec.name for t in reg][:2] == ["read", "write"]
    with pytest.raises(RegistryError, match="unknown tool"):
        reg.get("nope")
    with pytest.raises(RegistryError, match="registered twice"):
        reg.register(Tool(reg.get("read").spec, echo()))
    sub = reg.subset(["read", "pay"])
    assert [s.name for s in sub.specs()] == ["read", "pay"]
    assert len(ToolRegistry()) == 0
