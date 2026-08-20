"""Tests for LLM client (httpx-based) and router."""
import json

import httpx
import pytest

from harness.config import Config, EndpointConfig, LLMConfig
from harness.llm.client import EndpointHTTPError, OpenAIClient
from harness.llm.router import LLMRouter


def make_endpoint(**kw) -> EndpointConfig:
    defaults = dict(id="test", base_url="http://localhost:9999/v1",
                    api_key="k", model="m")
    defaults.update(kw)
    return EndpointConfig(**defaults)


def httpx_client(resp_data: dict | None = None, status: int = 200) -> OpenAIClient:
    endpoint = make_endpoint()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=resp_data or {})

    transport = httpx.MockTransport(handler)
    return OpenAIClient(endpoint, transport=transport)


@pytest.mark.asyncio
async def test_complete_content():
    client = httpx_client({
        "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    })
    c = await client.complete([{"role": "user", "content": "hi"}])
    assert c.content == "hello"
    assert c.tool_calls == []
    assert c.usage.prompt_tokens == 5
    assert c.usage.completion_tokens == 3
    assert c.finish_reason == "stop"
    await client.close()


@pytest.mark.asyncio
async def test_complete_tool_calls():
    client = httpx_client({
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [{
                    "id": "call_1",
                    "function": {
                        "name": "shell",
                        "arguments": json.dumps({"command": "ls"}),
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    })
    c = await client.complete([{"role": "user", "content": "ls"}],
                              tools=[{"type": "function", "function": {}}])
    assert c.content == ""
    assert len(c.tool_calls) == 1
    assert c.tool_calls[0].id == "call_1"
    assert c.tool_calls[0].name == "shell"
    assert c.tool_calls[0].arguments == {"command": "ls"}
    assert c.finish_reason == "tool_calls"
    assert c.usage.total_tokens == 30
    await client.close()


@pytest.mark.asyncio
async def test_complete_error_status():
    client = httpx_client({"error": "bad request"}, status=400)
    with pytest.raises(EndpointHTTPError) as raised:
        await client.complete([{"role": "user", "content": "hi"}])
    assert '"error":"bad request"' in raised.value.body
    await client.close()


@pytest.mark.asyncio
async def test_complete_dict_arguments():
    """Some endpoints send arguments as a dict instead of a JSON string."""
    client = httpx_client({
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [{
                    "id": "call_x",
                    "function": {"name": "read_file",
                                 "arguments": {"path": "/tmp/x"}},
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {},
    })
    c = await client.complete([], tools=[])
    assert c.tool_calls[0].arguments == {"path": "/tmp/x"}
    assert c.usage.total_tokens == 0
    await client.close()


def make_config(endpoints: list[EndpointConfig] | None = None,
                active: str = "ep1") -> Config:
    eps = endpoints or [
        make_endpoint(id="ep1", base_url="http://a:1/v1", api_key="k1"),
        make_endpoint(id="ep2", base_url="http://b:2/v1", api_key="k2"),
    ]
    llm = LLMConfig(active=active, endpoints=eps)
    return Config(llm=llm)


def test_router_active():
    cfg = make_config()
    r = LLMRouter(cfg)
    assert r.active_id == "ep1"
    assert r.active_endpoint.id == "ep1"
    assert r.active_endpoint.base_url == "http://a:1/v1"


def test_router_switch():
    cfg = make_config()
    r = LLMRouter(cfg)
    r.switch("ep2")
    assert r.active_id == "ep2"
    assert r.active_endpoint.model == "m"
    assert r.active_endpoint.api_key == "k2"


def test_router_unknown_switch_raises():
    cfg = make_config()
    r = LLMRouter(cfg)
    with pytest.raises(ValueError, match="unknown endpoint"):
        r.switch("nope")


def test_router_lazy_client():
    cfg = make_config()
    r = LLMRouter(cfg)
    assert not r._clients
    _ = r.active
    assert "ep1" in r._clients
    assert "ep2" not in r._clients
