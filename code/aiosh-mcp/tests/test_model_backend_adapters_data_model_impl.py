"""Implementation tests for Model Backend Adapters Data Model (T-03166)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointRegistry,
    ModelEndpointConfig,
    ModelProviderType,
    ModelCapabilities,
    build_default_model_registry,
    get_model_registry,
    model_message_from_dict,
    model_endpoint_from_dict,
    MODADAPT_ERR_BOUNDS,
    MAX_ENDPOINTS,
)


def test_default_model_registry():
    registry = build_default_model_registry()
    endpoints = registry.list_endpoints()
    assert len(endpoints) >= 5
    ids = {e.backend_id for e in endpoints}
    assert "mock-default" in ids
    assert "openai-primary" in ids
    assert "anthropic-primary" in ids
    assert "gemini-primary" in ids
    assert "ollama-local" in ids

    mock_ep = registry.get("mock-default")
    assert mock_ep.provider == ModelProviderType.MOCK
    assert mock_ep.model_name == "mock-model-v1"


def test_custom_endpoint_registration_and_removal():
    registry = ModelEndpointRegistry()
    custom = ModelEndpointConfig(
        backend_id="custom-vllm",
        provider=ModelProviderType.OPENAI_COMPATIBLE,
        model_name="mistral-7b",
        base_url="http://localhost:8000/v1",
    )
    registry.register(custom)
    assert len(registry.list_endpoints()) == 1

    fetched = registry.get("custom-vllm")
    assert fetched.model_name == "mistral-7b"

    assert registry.remove("custom-vllm") is True
    assert registry.remove("nonexistent") is False
    with pytest.raises(KeyError):
        registry.get("custom-vllm")


def test_endpoint_capacity_ceiling():
    registry = ModelEndpointRegistry()
    for i in range(MAX_ENDPOINTS):
        registry.register(
            ModelEndpointConfig(
                backend_id=f"ep-{i}",
                provider=ModelProviderType.MOCK,
                model_name=f"mock-{i}",
            )
        )
    assert len(registry.list_endpoints()) == MAX_ENDPOINTS

    # Exceeding capacity
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        registry.register(
            ModelEndpointConfig(
                backend_id="ep-overflow",
                provider=ModelProviderType.MOCK,
                model_name="overflow",
            )
        )


def test_deserialization_helpers():
    msg_dict = {"role": "assistant", "content": "hello world"}
    msg = model_message_from_dict(msg_dict)
    assert msg.role == "assistant"
    assert msg.content == "hello world"

    ep_dict = {
        "backend_id": "test-ep",
        "provider": "anthropic",
        "model_name": "claude-3-haiku",
        "api_key_env": "CUSTOM_ANTHROPIC_KEY",
        "timeout_ms": 15000,
        "max_retries": 2,
        "capabilities": {"streaming": True, "tool_calling": False},
        "is_active": True,
    }
    ep = model_endpoint_from_dict(ep_dict)
    assert ep.backend_id == "test-ep"
    assert ep.provider == ModelProviderType.ANTHROPIC
    assert ep.capabilities.tool_calling is False
    assert ep.timeout_ms == 15000
