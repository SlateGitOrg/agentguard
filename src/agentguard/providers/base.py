"""Provider-neutral chat types (OpenAI wire format for messages and tool schemas)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

Message = dict[str, Any]


@dataclass(frozen=True)
class ModelToolCall:
    """A tool call as emitted by the model. ``arguments`` is the parsed JSON value, or the raw
    string when the model produced something that is not JSON (the engine then denies it)."""

    id: str
    name: str
    arguments: Any

    def to_message(self) -> dict[str, Any]:
        raw = self.arguments if isinstance(self.arguments, str) else json.dumps(self.arguments)
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": raw},
        }


@dataclass(frozen=True)
class ModelResponse:
    content: str = ""
    tool_calls: tuple[ModelToolCall, ...] = ()
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def final(self) -> bool:
        return not self.tool_calls


class ChatProvider(Protocol):
    name: str

    def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
        """Return the model's next turn given the conversation and the visible tools."""
        ...


def parse_arguments(raw: Any) -> Any:
    """Decode tool-call arguments; leave undecodable strings as-is (fail closed downstream)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return raw
    return raw
