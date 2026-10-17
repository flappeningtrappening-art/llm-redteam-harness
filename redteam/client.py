"""Minimal OpenAI-compatible chat client built on urllib.

No third-party dependencies: the harness must run on an air-gapped box with
nothing but CPython. Handles tool_calls, usage accounting and latency so the
scorer and reporter can reason about cost.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    name: str
    arguments: dict
    raw_arguments: str = ""

    def arg_text(self) -> str:
        """Flatten argument values so a matcher can inspect them."""
        parts = []
        for value in self.arguments.values():
            if isinstance(value, str):
                parts.append(value)
            else:
                parts.append(json.dumps(value, sort_keys=True))
        return " ".join(parts)


@dataclass
class Response:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency: float = 0.0
    error: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def dump(self) -> str:
        """Everything a human might need to reproduce or triage this call."""
        if self.tool_calls:
            lines = [
                "tool_call name=%s args=%s" % (c.name, c.raw_arguments or c.arguments)
                for c in self.tool_calls
            ]
            return "\n".join(lines)
        return self.text


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    # ---------------------------------------------------------------- models
    def list_models(self) -> list:
        """Model ids advertised by the endpoint. Empty list if unsupported."""
        req = urllib.request.Request(self.base_url + "/models", method="GET")
        req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return []
        return [item.get("id") for item in payload.get("data", []) if item.get("id")]

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        models = self.list_models()
        if not models:
            raise RuntimeError(
                "no model specified and %s/models returned nothing; "
                "set REDTEAM_MODEL" % self.base_url
            )
        self.model = models[0]
        return self.model

    # ------------------------------------------------------------------ chat
    def chat(self, messages, tools=None, max_tokens=512, temperature=0.7) -> Response:
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base_url + "/chat/completions", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + self.api_key)

        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            return Response(error="HTTP %s: %s" % (exc.code, detail), latency=time.time() - started)
        except Exception as exc:
            return Response(error="%s: %s" % (type(exc).__name__, exc), latency=time.time() - started)

        latency = time.time() - started
        return self._parse(raw, latency)

    def _parse(self, raw: dict, latency: float) -> Response:
        choices = raw.get("choices") or []
        if not choices:
            return Response(error="no choices in response", latency=latency, raw=raw)

        message = choices[0].get("message") or {}
        calls = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            raw_args = fn.get("arguments") or ""
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except (ValueError, TypeError):
                args = {}
            calls.append(ToolCall(name=fn.get("name", ""), arguments=args, raw_arguments=str(raw_args)))

        usage = raw.get("usage") or {}
        return Response(
            text=message.get("content") or "",
            tool_calls=calls,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            latency=latency,
            raw=raw,
        )