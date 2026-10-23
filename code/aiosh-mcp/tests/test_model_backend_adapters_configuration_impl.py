"""Implementation tests for Model Backend Adapters Configuration (T-03206)."""

import pytest
from aiosh_mcp.model_backend_adapters_configuration import (
    ModelBackendConfig,
    load_config_from_dict,
    load_config_from_json,
)


def test_configuration_default_loading():
    cfg = ModelBackendConfig()
    cfg.validate()
    assert cfg.version == "1.0"
    assert cfg.default_provider == "mock"
    assert cfg.default_timeout_ms == 30000
    assert cfg.require_capability_tokens is True


def test_configuration_from_dict_and_safe_serialization():
    data = {
        "version": "1.0",
        "default_provider": "mock",
        "endpoints": {
            "test-backend": {
                "backend_id": "test-backend",
                "provider": "mock",
                "api_key_env": "OPENAI_API_KEY",
                "timeout_ms": 5000,
            }
        },
        "fallbacks": {
            "test-backend": ["mock-fallback"]
        }
    }
    cfg = load_config_from_dict(data)
    assert "test-backend" in cfg.endpoints
    assert cfg.endpoints["test-backend"].api_key_env == "OPENAI_API_KEY"

    safe_dict = cfg.to_dict(safe=True)
    assert safe_dict["endpoints"]["test-backend"]["api_key_env"] == "OPENAI_API_KEY"
    assert safe_dict["fallbacks"]["test-backend"] == ["mock-fallback"]
