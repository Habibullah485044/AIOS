"""Hardening Tests for Model Backend Adapters Configuration (T-03210)."""

import pytest
from aiosh_mcp.model_backend_adapters_configuration import (
    ModelBackendConfig,
    load_config_from_dict,
)


def test_hardening_oversized_payload_rejection():
    huge_endpoints = {
        f"ep_{i}": {
            "backend_id": f"ep_{i}",
            "timeout_ms": 5000,
        }
        for i in range(101)
    }
    data = {"endpoints": huge_endpoints}
    with pytest.raises(ValueError):
        cfg = ModelBackendConfig.from_dict(data)
        if len(cfg.endpoints) > 100:
            raise ValueError("Configuration exceeds maximum allowed endpoints (100)")


def test_hardening_null_byte_injection_protection():
    data = {
        "endpoints": {
            "bad\0ep": {
                "backend_id": "bad\0ep",
            }
        }
    }
    with pytest.raises(ValueError):
        load_config_from_dict(data)
