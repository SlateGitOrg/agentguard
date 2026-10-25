"""Scripted fake provider and the OpenAI-compatible client (with an in-process transport)."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from agentguard.errors import ProviderError
from agentguard.providers import OpenAICompatProvider, ScriptedProvider, ScriptStep
from agentguard.providers.base import ModelToolCall, parse_arguments
from agentguard.providers.openai_compat import salvage_text_tool_call

TOOLS = [{"type": "function", "function": {"name": "read_file", "parameters": {}}}]


def test_scripted_provider_plays_steps_then_finishes() -> None:
    p = ScriptedProvider.from_script(
        [
            {"call": "read_file", "args": {"path": "a"}},
            {"calls": [{"call": "a"}, {"call": "b", "args": {"x": 1}}]},
            {"final": "done"},
        ]
    )
    r1 = p.complete([{"role": "user", "content": "hi"}], TOOLS)
    assert [(c.name, c.arguments) for c in r1.tool_calls] == [("read_file", {"path": "a"})]
    assert not r1.final
    r2 = p.complete([], TOOLS)
    assert [c.name for c in r2.tool_calls] == ["a", "b"]
    assert r2.tool_calls[1].id == "call_2_1"
    r3 = p.complete([], TOOLS)
    assert r3.final
    assert r3.content == "done"
    assert p.complete([], TOOLS).content == "(script finished)"
    assert len(p.seen) == 4


@pytest.mark.parametrize("bad", [{}, {"calls": "x"}, {"calls": [1]}, {"calls": [{"args": {}}]}])
def test_bad_script_steps(bad: dict[str, Any]) -> None:
    with pytest.raises(ProviderError):
        ScriptStep.from_dict(bad)


def test_tool_call_message_and_argument_parsing() -> None:
    call = ModelToolCall("c1", "f", {"a": 1})
    assert call.to_message()["function"]["arguments"] == '{"a": 1}'
    assert ModelToolCall("c1", "f", "{bad").to_message()["function"]["arguments"] == "{bad"
    assert parse_arguments('{"a": 1}') == {"a": 1}
    assert parse_arguments("") == {}
    assert parse_arguments("{oops") == "{oops"
    assert parse_arguments({"a": 2}) == {"a": 2}
    assert parse_arguments(None) is None


def completion(message: dict[str, Any], usage: dict[str, Any] | None = None) -> bytes:
    return json.dumps({"choices": [{"message": message}], "usage": usage or {}}).encode()


class FakeTransport:
    def __init__(self, *responses: bytes | Exception) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
        self.requests.append({"url": url, "body": json.loads(body), "headers": headers})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def provider(transport: FakeTransport, **kw: Any) -> OpenAICompatProvider:
    return OpenAICompatProvider(
        base_url="http://localhost:11434/v1", model="m", transport=transport, **kw
    )


def test_openai_tool_calls_are_parsed() -> None:
    t = FakeTransport(
        completion(
            {
                "content": None,
                "tool_calls": [
                    {"id": "x1", "function": {"name": "read_file", "arguments": '{"path": "a"}'}},
                    {"function": {"name": "read_file", "arguments": "not json"}},
                ],
            },
            {"prompt_tokens": 10, "completion_tokens": 3, "note": "x"},
        )
    )
    r = provider(t).complete([{"role": "user", "content": "hi"}], TOOLS)
    assert [(c.id, c.arguments) for c in r.tool_calls] == [
        ("x1", {"path": "a"}),
        ("call_1", "not json"),
    ]
    assert r.usage == {"prompt_tokens": 10, "completion_tokens": 3}
    sent = t.requests[0]
    assert sent["url"] == "http://localhost:11434/v1/chat/completions"
    assert sent["body"]["tools"] == TOOLS
    assert sent["body"]["temperature"] == 0.0
    assert sent["headers"]["Authorization"].startswith("Bearer ")


def test_final_text_and_no_tools() -> None:
    t = FakeTransport(completion({"content": "all done"}))
    r = provider(t).complete([], [])
    assert r.final
    assert r.content == "all done"
    assert "tools" not in t.requests[0]["body"]


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('{"name": "read_file", "parameters": {"path": "a"}}', ("read_file", {"path": "a"})),
        (
            '```json\n{"name": "read_file", "arguments": "{\\"path\\": \\"b\\"}"}\n```',
            ("read_file", {"path": "b"}),
        ),
        ('{"name": "rm_rf", "parameters": {}}', None),
        ("I will read the file now.", None),
        ("{not json}", None),
        ("[1, 2]", None),
    ],
)
def test_salvage_text_tool_calls(content: str, expected: tuple[str, Any] | None) -> None:
    got = salvage_text_tool_call(content, {"read_file"})
    if expected is None:
        assert got is None
    else:
        assert got is not None
        assert (got.name, got.arguments) == expected


def test_salvage_is_applied_by_the_client() -> None:
    t = FakeTransport(completion({"content": '{"name": "read_file", "parameters": {"path": "a"}}'}))
    r = provider(t).complete([], TOOLS)
    assert r.tool_calls[0].name == "read_file"
    assert r.content == ""


def test_retries_then_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentguard.providers.openai_compat.time.sleep", lambda _s: None)
    t = FakeTransport(urllib.error.URLError("refused"), completion({"content": "ok"}))
    assert provider(t, retries=1).complete([], []).content == "ok"
    t = FakeTransport(TimeoutError("slow"), ConnectionError("reset"))
    with pytest.raises(ProviderError, match="after 2 attempts"):
        provider(t, retries=1).complete([], [])


@pytest.mark.parametrize("raw", [b"not json", b"{}", b'{"choices": []}', b'{"choices": [1]}'])
def test_malformed_responses(raw: bytes) -> None:
    with pytest.raises(ProviderError, match="malformed"):
        provider(FakeTransport(raw)).complete([], [])


def test_rejects_non_http_base_url() -> None:
    with pytest.raises(ProviderError, match="http"):
        OpenAICompatProvider(base_url="file:///etc/passwd").complete([], [])


def test_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_MODEL", "llama3.1:8b")
    monkeypatch.setenv("AGENTGUARD_BASE_URL", "http://127.0.0.1:9/v1")
    p = OpenAICompatProvider()
    assert (p.model, p.base_url) == ("llama3.1:8b", "http://127.0.0.1:9/v1")


def test_prefixed_provider_forces_then_delegates() -> None:
    from agentguard.providers import PrefixedProvider

    prefix = ScriptedProvider.from_script([{"call": "read_file", "args": {"path": "a"}}])
    inner = ScriptedProvider.from_script([{"final": "inner speaking"}])
    p = PrefixedProvider(prefix, inner, steps=1)
    assert p.complete([], TOOLS).tool_calls[0].name == "read_file"
    assert p.complete([], TOOLS).content == "inner speaking"
    assert len(inner.seen) == 1
