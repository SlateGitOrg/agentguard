"""A small, strict JSON-Schema subset used for tool argument schemas.

Why not the ``jsonschema`` package? The guard sits on the security boundary, so the schema
dialect is intentionally tiny and closed: unknown keywords are a :class:`SchemaError` at tool
registration time rather than being silently ignored (a classic source of "validated" input
that was never actually checked). Supported keywords:

``type`` (object/string/integer/number/boolean/array), ``properties``, ``required``,
``additionalProperties`` (bool only, default **false**), ``enum``, ``minimum``, ``maximum``,
``minLength``, ``maxLength``, ``pattern`` (full match), ``items``, ``minItems``, ``maxItems``,
``description`` and the agentguard extension ``sensitive`` (value is hashed in the audit log).

Note the default for ``additionalProperties`` is the opposite of JSON Schema: unexpected
arguments are rejected unless explicitly allowed.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentguard.errors import SchemaError

JsonSchema = Mapping[str, Any]

_TYPES = {"object", "string", "integer", "number", "boolean", "array"}
_KEYWORDS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "items",
    "minItems",
    "maxItems",
    "description",
    "sensitive",
}


@dataclass(frozen=True)
class SchemaViolation:
    """One validation failure, located by a JSON-pointer-like path."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '$'}: {self.message}"


def check_schema(schema: JsonSchema, path: str = "$") -> None:
    """Raise :class:`SchemaError` if ``schema`` uses anything outside the supported subset."""
    if not isinstance(schema, Mapping):
        raise SchemaError(f"{path}: schema must be a mapping")
    unknown = set(schema) - _KEYWORDS
    if unknown:
        raise SchemaError(f"{path}: unsupported schema keyword(s) {sorted(unknown)}")
    typ = schema.get("type")
    if typ not in _TYPES:
        raise SchemaError(f"{path}: 'type' must be one of {sorted(_TYPES)}, got {typ!r}")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise SchemaError(f"{path}: invalid pattern: {exc}") from exc
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        raise SchemaError(f"{path}: additionalProperties must be a boolean")
    if typ == "object":
        props = schema.get("properties", {})
        if not isinstance(props, Mapping):
            raise SchemaError(f"{path}: properties must be a mapping")
        for name, sub in props.items():
            check_schema(sub, f"{path}.{name}")
        required = schema.get("required", [])
        missing = [r for r in required if r not in props]
        if missing:
            raise SchemaError(f"{path}: required names unknown properties {missing}")
    if typ == "array":
        if "items" not in schema:
            raise SchemaError(f"{path}: array schemas must declare 'items'")
        check_schema(schema["items"], f"{path}[]")


def _type_ok(typ: str, value: Any) -> bool:
    # bool is a subclass of int in Python; never let True pass as an integer amount.
    if typ == "object":
        return isinstance(value, Mapping)
    if typ == "string":
        return isinstance(value, str)
    if typ == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if typ == "number":
        return (
            isinstance(value, int | float)
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        )
    if typ == "boolean":
        return isinstance(value, bool)
    if typ == "array":
        return isinstance(value, list)
    return False  # pragma: no cover - check_schema rejects unknown types


def validate(schema: JsonSchema, value: Any, path: str = "") -> list[SchemaViolation]:
    """Validate ``value`` against ``schema``; return every violation found (empty = valid)."""
    typ = schema["type"]
    if not _type_ok(typ, value):
        return [SchemaViolation(path, f"expected {typ}, got {type(value).__name__}")]
    out: list[SchemaViolation] = []
    if "enum" in schema and value not in schema["enum"]:
        out.append(SchemaViolation(path, f"{value!r} not in {list(schema['enum'])}"))
    if typ in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            out.append(SchemaViolation(path, f"{value} < minimum {schema['minimum']}"))
        if "maximum" in schema and value > schema["maximum"]:
            out.append(SchemaViolation(path, f"{value} > maximum {schema['maximum']}"))
    elif typ == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(SchemaViolation(path, f"shorter than {schema['minLength']}"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(SchemaViolation(path, f"longer than {schema['maxLength']}"))
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            out.append(SchemaViolation(path, f"does not match pattern {schema['pattern']!r}"))
    elif typ == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(SchemaViolation(path, f"fewer than {schema['minItems']} items"))
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(SchemaViolation(path, f"more than {schema['maxItems']} items"))
        for i, item in enumerate(value):
            out.extend(validate(schema["items"], item, f"{path}[{i}]"))
    elif typ == "object":
        props: Mapping[str, Any] = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                out.append(SchemaViolation(_join(path, name), "required argument missing"))
        if not schema.get("additionalProperties", False):
            for name in value:
                if name not in props:
                    out.append(SchemaViolation(_join(path, str(name)), "unexpected argument"))
        for name, sub in props.items():
            if name in value:
                out.extend(validate(sub, value[name], _join(path, name)))
    return out


def sensitive_fields(schema: JsonSchema) -> frozenset[str]:
    """Top-level argument names marked ``sensitive: true``."""
    props: Mapping[str, Any] = schema.get("properties", {})
    return frozenset(name for name, sub in props.items() if sub.get("sensitive", False))


def _join(path: str, name: str) -> str:
    return f"{path}.{name}" if path else name
