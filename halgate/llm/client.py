"""Async OpenAI-compatible Chat Completions client (httpx)."""
from __future__ import annotations

import json
import inspect
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx

from ..config import EndpointConfig
from ..errors import ConfigError

_MAX_ERROR_BODY_BYTES = 8_192


def _auth_headers(cfg: EndpointConfig) -> dict[str, str]:
    """Build a safe optional bearer-auth header for an endpoint."""
    key = cfg.api_key
    if any(ord(char) < 0x20 or ord(char) == 0x7f or ord(char) > 0x7f
           for char in key):
        raise ConfigError("LLM endpoint api_key must contain only printable ASCII characters")
    key = key.strip()
    if not key:
        return {}
    return {"Authorization": f"Bearer {key}"}


class EndpointHTTPError(httpx.HTTPStatusError):
    """HTTP endpoint error retaining only a bounded diagnostic response body."""

    def __init__(self, message: str, *, request: httpx.Request,
                 response: httpx.Response, body: str) -> None:
        super().__init__(message, request=request, response=response)
        self.body = body


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class Completion:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str = "stop"  # "stop" | "tool_calls" | "length"


class OpenAIClient:
    def __init__(self, cfg: EndpointConfig, transport: httpx.AsyncBaseTransport | None = None):
        # transport injection point (tests use httpx.MockTransport)
        self._http = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            headers=_auth_headers(cfg),
            timeout=httpx.Timeout(cfg.timeout, connect=10),
            follow_redirects=False,
            transport=transport,
        )
        self.cfg = cfg

    async def complete(self, messages: list[dict],
                       tools: list[dict] | None = None) -> Completion:
        body: dict = {
            "model": self.cfg.model,
            "messages": messages,
            "max_tokens": self.cfg.max_tokens,
            "temperature": self.cfg.temperature,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        resp = await self._http.post("/chat/completions", json=body)
        await _raise_endpoint_error(resp)
        data = resp.json()
        return self._parse(data)

    async def stream_complete(
            self, messages: list[dict], tools: list[dict] | None = None,
            on_delta: Callable[[str], None | Awaitable[None]] | None = None) -> Completion:
        """Stream a Chat Completions response and reassemble its final form."""
        body: dict = {
            "model": self.cfg.model,
            "messages": messages,
            "max_tokens": self.cfg.max_tokens,
            "temperature": self.cfg.temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        content_parts: list[str] = []
        raw_calls: dict[int, dict] = {}
        usage = TokenUsage()
        finish_reason = "stop"
        async with self._http.stream("POST", "/chat/completions", json=body) as resp:
            await _raise_endpoint_error(resp)
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                usage_data = chunk.get("usage") or {}
                if usage_data:
                    usage = TokenUsage(
                        prompt_tokens=int(usage_data.get("prompt_tokens", 0)),
                        completion_tokens=int(usage_data.get("completion_tokens", 0)),
                    )
                for choice in chunk.get("choices") or []:
                    delta = choice.get("delta") or {}
                    text = delta.get("content") or ""
                    if text:
                        content_parts.append(text)
                        if on_delta:
                            callback_result = on_delta(text)
                            if inspect.isawaitable(callback_result):
                                await callback_result
                    for call in delta.get("tool_calls") or []:
                        index = int(call.get("index", 0))
                        assembled = raw_calls.setdefault(
                            index, {"id": "", "name": "", "arguments": ""})
                        assembled["id"] = call.get("id") or assembled["id"]
                        function = call.get("function") or {}
                        assembled["name"] = function.get("name") or assembled["name"]
                        assembled["arguments"] += function.get("arguments") or ""
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]

        tool_calls: list[ToolCall] = []
        for _, call in sorted(raw_calls.items()):
            try:
                arguments = json.loads(call["arguments"] or "{}")
            except json.JSONDecodeError:
                arguments = {"_raw": call["arguments"]}
            tool_calls.append(ToolCall(id=call["id"], name=call["name"],
                                       arguments=arguments))
        return Completion(content="".join(content_parts), tool_calls=tool_calls,
                          usage=usage, finish_reason=finish_reason)

    def _parse(self, data: dict) -> Completion:
        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            raw_args = tc["function"]["arguments"]
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) \
                    else dict(raw_args or {})
            except json.JSONDecodeError:
                args = {"_raw": raw_args}
            tool_calls.append(ToolCall(id=tc["id"],
                                       name=tc["function"]["name"],
                                       arguments=args))
        usage_data = data.get("usage") or {}
        usage = TokenUsage(
            prompt_tokens=int(usage_data.get("prompt_tokens", 0)),
            completion_tokens=int(usage_data.get("completion_tokens", 0)),
        )
        return Completion(
            content=msg.get("content") or "",
            tool_calls=tool_calls,
            usage=usage,
            finish_reason=choice.get("finish_reason", "stop"),
        )

    async def close(self) -> None:
        await self._http.aclose()


async def _raise_endpoint_error(response: httpx.Response) -> None:
    """Raise status errors with a bounded body available for safe audit logging."""
    if not response.is_error:
        return
    if response.is_stream_consumed:
        raw = response.content[:_MAX_ERROR_BODY_BYTES]
    else:
        chunks: list[bytes] = []
        remaining = _MAX_ERROR_BODY_BYTES
        async for chunk in response.aiter_bytes():
            chunks.append(chunk[:remaining])
            remaining -= len(chunk)
            if remaining <= 0:
                break
        raw = b"".join(chunks)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise EndpointHTTPError(
            str(error), request=response.request, response=response,
            body=raw.decode(errors="replace"),
        ) from error
