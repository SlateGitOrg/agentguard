"""Minimal OpenAI-compatible chat-completions client (stdlib only), aimed at Ollama.

Defaults come from the environment: ``AGENTGUARD_BASE_URL`` (``http://localhost:11434/v1``),
``AGENTGUARD_MODEL`` (``llama3.1:8b``) and ``AGENTGUARD_API_KEY`` (unused by Ollama).

Small local models sometimes print a tool call as JSON *text* instead of using the
``tool_calls`` field; :func:`salvage_text_tool_call` recovers the common
``{"name": ..., "parameters": {...}}`` shape so those turns are still mediated by the guard
rather than silently dropped.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentguard.errors import ProviderError
from agentguard.providers.base import Message, ModelResponse, ModelToolCall, parse_arguments

log = logging.getLogger(__name__)

Transport = Callable[[str, bytes, dict[str, str], float], bytes]


def urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # scheme checked by caller
        data: bytes = response.read()
        return data


def salvage_text_tool_call(content: str, tool_names: set[str]) -> ModelToolCall | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :] if "{" in text else text
    if not (text.startswith("{") and text.rstrip().endswith("}")):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("name") not in tool_names:
        return None
    args = data.get("parameters", data.get("arguments", {}))
    return ModelToolCall(id="text_call_0", name=str(data["name"]), arguments=parse_arguments(args))


@dataclass
class OpenAICompatProvider:
    base_url: str = field(
        default_factory=lambda: os.environ.get("AGENTGUARD_BASE_URL", "http://localhost:11434/v1")
    )
    model: str = field(default_factory=lambda: os.environ.get("AGENTGUARD_MODEL", "llama3.1:8b"))
    api_key: str = field(default_factory=lambda: os.environ.get("AGENTGUARD_API_KEY", "ollama"))
    temperature: float = 0.0
    seed: int = 7
    timeout: float = 300.0
    retries: int = 2
    transport: Transport = urllib_transport
    name: str = "openai-compat"

    def complete(self, messages: list[Message], tools: list[dict[str, Any]]) -> ModelResponse:
        if not self.base_url.startswith(("http://", "https://")):
            raise ProviderError(f"base_url must be http(s): {self.base_url!r}")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "seed": self.seed,
        }
        if tools:
            payload["tools"] = tools
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        url = self.base_url.rstrip("/") + "/chat/completions"
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                raw = self.transport(url, body, headers, self.timeout)
                return self._parse(raw, {t["function"]["name"] for t in tools})
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = exc
                log.warning("provider attempt %d failed: %s", attempt + 1, exc)
                time.sleep(min(2.0**attempt, 8.0))
        raise ProviderError(f"model request failed after {self.retries + 1} attempts: {last}")

    @staticmethod
    def _parse(raw: bytes, tool_names: set[str]) -> ModelResponse:
        try:
            data = json.loads(raw)
            message = data["choices"][0]["message"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"malformed chat completion: {exc}") from exc
        content = message.get("content") or ""
        calls = []
        for i, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function", {}) if isinstance(call, dict) else {}
            calls.append(
                ModelToolCall(
                    id=str(call.get("id") or f"call_{i}"),
                    name=str(function.get("name", "")),
                    arguments=parse_arguments(function.get("arguments", {})),
                )
            )
        if not calls and content:
            salvaged = salvage_text_tool_call(content, tool_names)
            if salvaged is not None:
                calls.append(salvaged)
                content = ""
        usage = {k: int(v) for k, v in (data.get("usage") or {}).items() if isinstance(v, int)}
        return ModelResponse(content=content, tool_calls=tuple(calls), usage=usage)
