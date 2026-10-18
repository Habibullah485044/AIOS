"""Scaffold tests for AI Control Plane Model Backend Adapters Data Model (T-03165)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelProviderType,
    ModelCapabilities,
    ModelEndpointConfig,
    ModelMessage,
    ModelUsage,
    ModelRequest,
    ModelResponse,
    validate_role,
    validate_temperature,
    MODADAPT_ERR_INVALID_ROLE,
    MODADAPT_ERR_BOUNDS,
    MODADAPT_ERR_SECRET_LEAK,
)


def test_provider_enum_members():
    assert ModelProviderType.OPENAI_COMPATIBLE == "openai_compatible"
    assert ModelProviderType.ANTHROPIC == "anthropic"
    assert ModelProviderType.GEMINI == "gemini"
    assert ModelProviderType.OLLAMA == "ollama"
    assert ModelProviderType.MOCK == "mock"


def test_capabilities_defaults():
    caps = ModelCapabilities()
    assert caps.streaming is True
    assert caps.tool_calling is True
    assert caps.vision is False
    assert caps.json_mode is True
    assert caps.max_context_window == 128000
    assert caps.max_output_tokens == 4096


def test_endpoint_config_validation():
    config = ModelEndpointConfig(
        backend_id="test-mock",
        provider=ModelProviderType.MOCK,
        model_name="mock-model-v1",
        api_key_env="MOCK_API_KEY",
    )
    config.validate()
    d = config.to_dict()
    assert d["backend_id"] == "test-mock"
    assert d["provider"] == "mock"

    # Test secret leak prevention (MODADAPT-INV3)
    bad_config = ModelEndpointConfig(
        backend_id="bad",
        provider=ModelProviderType.OPENAI_COMPATIBLE,
        model_name="gpt-4o",
        api_key_env="sk-proj-1234567890abcdef",
    )
    with pytest.raises(ValueError, match=MODADAPT_ERR_SECRET_LEAK):
        bad_config.validate()


def test_message_role_validation():
    msg = ModelMessage(role="user", content="hello")
    assert msg.role == "user"
    assert msg.content == "hello"

    with pytest.raises(ValueError, match=MODADAPT_ERR_INVALID_ROLE):
        ModelMessage(role="unauthorized_role", content="hi")


def test_usage_invariants():
    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    usage.validate_invariants()
    d = usage.to_dict()
    assert d["total_tokens"] == 15

    # Sum invariant violation (MODADAPT-INV2)
    bad_usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=20)
    with pytest.raises(AssertionError, match="MODADAPT-INV2"):
        bad_usage.validate_invariants()


def test_request_and_response_structures():
    req = ModelRequest(
        model_id="test-mock",
        messages=[ModelMessage(role="user", content="ping")],
        temperature=0.5,
    )
    req.validate()
    assert req.temperature == 0.5

    resp = ModelResponse(
        id="resp-001",
        model="mock-model-v1",
        content="pong",
        usage=ModelUsage(prompt_tokens=2, completion_tokens=1, total_tokens=3),
    )
    d = resp.to_dict()
    assert d["id"] == "resp-001"
    assert d["content"] == "pong"
