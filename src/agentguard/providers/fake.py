"""Deterministic scripted provider used by tests, the demo and the scenario suite.

It plays a fixed sequence of turns regardless of what the tools return. In attack scenarios
the script deliberately *obeys* the injected instructions: it models the worst case, a model
that is fully hijacked by untrusted content, so the guard -- not the model -- must stop it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentguard.errors import ProviderError
from agentguard.providers.base import ChatProvider, Message, ModelResponse, ModelToolCall


@dataclass(frozen=True)
class ScriptStep:
    """One model turn: either some tool calls or a final answer."""

    calls: tuple[tuple[str, Any], ...] = ()
    final: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScriptStep:
        if "final" in data:
            return cls(final=str(data["final"]))
        if "call" in data:
            items: Sequence[Any] = [data]
        elif "calls" in data and isinstance(data["calls"], list):
            items = data["calls"]
        else:
            raise ProviderError(f"script step needs 'call', 'calls' or 'final': {dict(data)}")
        calls = []
        for item in items:
            if not isinstance(item, Mapping) or "call" not in item:
                raise ProviderError(f"bad scripted call {item!r}")
            calls.append((str(item["call"]), item.get("args", {})))
        return cls(calls=tuple(calls))


@dataclass
class ScriptedProvider:
    steps: Sequence[ScriptStep]
    name: str = "scripted"
    seen: list[list[Message]] = field(default_factory=list)
    _index: int = 0

    def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
        self.seen.append([dict(m) for m in messages])
        if self._index >= len(self.steps):
            return ModelResponse(content="(script finished)")
        step = self.steps[self._index]
        self._index += 1
        if step.final is not None:
            return ModelResponse(content=step.final)
        calls = tuple(
            ModelToolCall(id=f"call_{self._index}_{i}", name=name, arguments=args)
            for i, (name, args) in enumerate(step.calls)
        )
        return ModelResponse(tool_calls=calls)

    @classmethod
    def from_script(cls, script: Sequence[Mapping[str, Any]]) -> ScriptedProvider:
        return cls([ScriptStep.from_dict(s) for s in script])


@dataclass
class PrefixedProvider:
    """Plays the first scripted steps, then hands the conversation to a real provider.

    Used by the real-model evaluation to *force* the step that brings content into the
    context (open the injected e-mail, fetch the page, read the invoice) so that every run
    actually exercises the decision the scenario is about; everything after that is the real
    model's own choice.
    """

    prefix: ScriptedProvider
    inner: ChatProvider
    steps: int
    name: str = "prefixed"
    _played: int = 0

    def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
        if self._played < self.steps:
            self._played += 1
            return self.prefix.complete(messages, tools)
        return self.inner.complete(messages, tools)
