"""LLMRouter: endpoint selection and hot-swap (clients are lazily created)."""
from __future__ import annotations

from ..config import Config, EndpointConfig
from ..errors import ConfigError
from .client import OpenAIClient


class LLMRouter:
    def __init__(self, config: Config):
        self._config = config
        self._clients: dict[str, OpenAIClient] = {}
        self._active_id: str = config.llm.active
        cfg_endpoint = config.llm.get_endpoint(self._active_id)
        if cfg_endpoint.id not in config.llm.endpoints_by_id:
            raise ConfigError(f"unknown endpoint: {cfg_endpoint.id}")

    def _client_for(self, endpoint_id: str) -> OpenAIClient:
        if endpoint_id not in self._clients:
            spec = self._config.llm.get_endpoint(endpoint_id)
            self._clients[endpoint_id] = OpenAIClient(spec)
        return self._clients[endpoint_id]

    @property
    def active(self) -> OpenAIClient:
        return self._client_for(self._active_id)

    @property
    def active_endpoint(self) -> EndpointConfig:
        return self._config.llm.get_endpoint(self._active_id)

    @property
    def active_id(self) -> str:
        return self._active_id

    def switch(self, endpoint_id: str) -> None:
        if endpoint_id not in self._config.llm.endpoints_by_id:
            raise ValueError(f"unknown endpoint: {endpoint_id}")
        self._active_id = endpoint_id

    async def reload(self, endpoint_id: str | None = None) -> None:
        """Discard a cached client after its endpoint settings change."""
        endpoint_id = endpoint_id or self._active_id
        client = self._clients.pop(endpoint_id, None)
        if client is not None:
            await client.close()

    async def close_all(self) -> None:
        for c in self._clients.values():
            await c.close()
        self._clients.clear()
