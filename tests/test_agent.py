"""The agent loop: every tool call goes through the guarded session."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentguard.agent import MAX_TOOL_MESSAGE_CHARS, args_preview, run_agent
from agentguard.approval import deny_all
from agentguard.audit import AuditLog
from agentguard.engine import PolicyEngine
from agentguard.errors import ProviderError
from agentguard.policy import load_policy
from agentguard.providers import ScriptedProvider
from agentguard.providers.base import Message, ModelResponse
from agentguard.session import GuardedSession, Status
from agentguard.tools import load_world, sandbox_registry


def session(root: Path, task: str = "inbox-assistant") -> tuple[GuardedSession, Any]:
    world = load_world(root / "scenarios" / "worlds" / "office.yaml")
    registry = sandbox_registry(world)
    policy = load_policy(root / "policies" / "assistant.yaml", registry)
    engine = PolicyEngine(policy, registry, task)
    return GuardedSession(engine, audit=AuditLog(), approver=deny_all), world


def test_benign_run_completes(root: Path) -> None:
    s, world = session(root)
    provider = ScriptedProvider.from_script(
        [
            {"call": "read_file", "args": {"path": "notes/todo.md"}},
            {"call": "write_file", "args": {"path": "notes/summary.md", "content": "3 items"}},
            {"final": "saved"},
        ]
    )
    run = run_agent(provider, s, "summarize my todo list")
    assert run.final == "saved"
    assert run.stop_reason == "final answer"
    assert [c.status for c in run.calls] == [Status.EXECUTED, Status.EXECUTED]
    assert world.files["notes/summary.md"].content == "3 items"
    # the model saw only the granted tools, and every tool result went back to it
    tool_msgs = [m for m in run.messages if m["role"] == "tool"]
    assert len(tool_msgs) == 2
    assert "renew the domain" in tool_msgs[0]["content"]
    assert s.audit.records[-1]["event"] == "session_end"
    assert "inbox-assistant" in run.messages[0]["content"]


def test_visible_tools_are_only_granted_ones(root: Path) -> None:
    s, _ = session(root, "research-assistant")
    seen: list[list[str]] = []

    class Probe:
        name = "probe"

        def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
            seen.append([t["function"]["name"] for t in tools])
            return ModelResponse(content="nothing to do")

    run_agent(Probe(), s, "hi")
    assert "pay" not in seen[0]
    assert "fetch_url" in seen[0]


def test_blocked_calls_stop_the_loop(root: Path) -> None:
    s, world = session(root)
    bad = {"call": "send_email", "args": {"to": "x@evil.test", "subject": "s", "body": "b"}}
    run = run_agent(ScriptedProvider.from_script([bad] * 6), s, "go", max_blocked=3)
    assert run.stop_reason == "stopped after 3 consecutive blocked calls"
    assert len(run.calls) == 3
    assert world.outbox == []
    assert run.calls[0].verdict == "deny"


def test_turn_limit_and_truncation(root: Path) -> None:
    s, world = session(root)
    world.files["notes/todo.md"].content = "x" * (MAX_TOOL_MESSAGE_CHARS + 50)
    step = {"call": "read_file", "args": {"path": "notes/todo.md"}}
    run = run_agent(ScriptedProvider.from_script([step] * 5), s, "go", max_turns=2)
    assert run.stop_reason == "turn limit"
    assert run.turns == 2
    assert run.messages[-1]["content"].endswith("[truncated]")


def test_provider_error_ends_run(root: Path) -> None:
    s, _ = session(root)

    class Broken:
        name = "broken"

        def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
            raise ProviderError("connection refused")

    run = run_agent(Broken(), s, "go")
    assert run.stop_reason == "provider error: connection refused"


def test_usage_is_accumulated(root: Path) -> None:
    s, _ = session(root)

    class Counting:
        name = "counting"

        def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
            return ModelResponse(content="done", usage={"prompt_tokens": 7})

    assert run_agent(Counting(), s, "go").usage == {"prompt_tokens": 7}


def test_args_preview() -> None:
    assert args_preview({"a": 1, "b": "x"}) == "a=1, b='x'"
    assert args_preview("raw") == "'raw'"
    assert args_preview({"a": "y" * 100}, limit=20).endswith("...")


def test_max_calls_per_turn_skips_extra_calls(root: Path) -> None:
    s, world = session(root)
    step = {
        "calls": [
            {"call": "read_file", "args": {"path": "notes/todo.md"}},
            {"call": "write_file", "args": {"path": "notes/x.md", "content": "guessed"}},
        ]
    }
    run = run_agent(
        ScriptedProvider.from_script([step, {"final": "ok"}]), s, "go", max_calls_per_turn=1
    )
    assert run.skipped_calls == 1
    assert [c.tool for c in run.calls] == ["read_file"]
    assert "notes/x.md" not in world.files
    skipped = [m for m in run.messages if m["role"] == "tool"][1]
    assert skipped["content"].startswith("[agentguard] not executed")
