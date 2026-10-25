"""Tests for the closed JSON-Schema subset used for tool arguments."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard.errors import SchemaError
from agentguard.schema import check_schema, sensitive_fields, validate

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 8, "pattern": "[a-z/]+"},
        "amount": {"type": "number", "minimum": 0, "maximum": 10},
        "count": {"type": "integer"},
        "flag": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["a", "b"]},
        "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 2},
        "secret": {"type": "string", "sensitive": True},
    },
    "required": ["path"],
}


def test_valid_document_has_no_violations() -> None:
    check_schema(SCHEMA)
    args = {"path": "a/b", "amount": 2.5, "count": 3, "flag": True, "mode": "a", "tags": ["x"]}
    assert validate(SCHEMA, args) == []


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        ({}, "path: required argument missing"),
        ({"path": "a", "extra": 1}, "extra: unexpected argument"),
        ({"path": ""}, "shorter than 1"),
        ({"path": "abcdefghi"}, "longer than 8"),
        ({"path": "A"}, "does not match pattern"),
        ({"path": "a", "amount": -1}, "< minimum 0"),
        ({"path": "a", "amount": 11}, "> maximum 10"),
        ({"path": "a", "amount": float("nan")}, "expected number"),
        ({"path": "a", "amount": True}, "expected number"),
        ({"path": "a", "count": True}, "expected integer"),
        ({"path": "a", "count": 1.5}, "expected integer"),
        ({"path": "a", "flag": 1}, "expected boolean"),
        ({"path": "a", "mode": "c"}, "not in ['a', 'b']"),
        ({"path": "a", "tags": []}, "fewer than 1 items"),
        ({"path": "a", "tags": ["x", "y", "z"]}, "more than 2 items"),
        ({"path": "a", "tags": [1]}, "tags[0]: expected string"),
        ({"path": "a", "tags": "x"}, "expected array"),
    ],
)
def test_violations(args: dict[str, Any], fragment: str) -> None:
    messages = [str(v) for v in validate(SCHEMA, args)]
    assert any(fragment in m for m in messages), messages


def test_root_type_mismatch_is_reported_at_root() -> None:
    assert str(validate(SCHEMA, ["not", "an", "object"])[0]) == "$: expected object, got list"


def test_additional_properties_can_be_enabled() -> None:
    schema = {"type": "object", "properties": {}, "additionalProperties": True}
    assert validate(schema, {"anything": 1}) == []


@pytest.mark.parametrize(
    ("schema", "fragment"),
    [
        ({"type": "object", "format": "x"}, "unsupported schema keyword"),
        ({"type": "tuple"}, "'type' must be one of"),
        ({"type": "string", "pattern": "("}, "invalid pattern"),
        ({"type": "object", "additionalProperties": {}}, "must be a boolean"),
        ({"type": "object", "properties": []}, "properties must be a mapping"),
        ({"type": "object", "properties": {}, "required": ["x"]}, "unknown properties"),
        ({"type": "array"}, "must declare 'items'"),
        ({"type": "array", "items": {"type": "nope"}}, "$[]"),
        ("not a mapping", "must be a mapping"),
    ],
)
def test_check_schema_rejects(schema: Any, fragment: str) -> None:
    with pytest.raises(SchemaError) as info:
        check_schema(schema)
    assert fragment in str(info.value)


def test_sensitive_fields() -> None:
    assert sensitive_fields(SCHEMA) == frozenset({"secret"})
