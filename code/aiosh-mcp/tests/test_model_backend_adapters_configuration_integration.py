"""Integration Tests for Model Backend Adapters Configuration with Service & Registry (T-03208)."""

import asyncio
import pytest
from aiosh_mcp.model_backend_adapters_configuration import load_config_from_dict
from aiosh_mcp.model_backend_adapters_service import ModelBackendService
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointRegistry,
    ModelRequest,
    ModelMessage,
)


def test_integration_config_with_model_service():
    async def _test():
        config_dict = {
            "version": "1.0",
            "default_provider": "mock",
            "endpoints": {
                "mock-prod": {
                    "backend_id": "mock-prod",
                    "provider": "mock",
                    "model_name": "mock-prod-v1",
                    "timeout_ms": 5000,
                }
            }
        }
        cfg = load_config_from_dict(config_dict)
        registry = ModelEndpointRegistry()
        for bid, ep in cfg.endpoints.items():
            registry.register(ep)

        service = ModelBackendService(registry=registry)
        assert registry.get("mock-prod") is not None

        req = ModelRequest(
            model_id="mock-prod",
            messages=[ModelMessage(role="user", content="ping configuration")]
        )
        resp = await service.complete(req)
        assert resp.model == "mock-prod-v1"
        assert resp.content is not None

    asyncio.run(_test())
