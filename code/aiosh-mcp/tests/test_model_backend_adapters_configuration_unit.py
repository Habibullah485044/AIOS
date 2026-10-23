"""Comprehensive Unit Tests for Model Backend Adapters Configuration (T-03207)."""

import pytest
from aiosh_mcp.model_backend_adapters_configuration import (
    ModelBackendConfig,
    load_config_from_dict,
    load_config_from_json,
)


def test_unit_bounds_validation_timeout():
    cfg = ModelBackendConfig(default_timeout_ms=500)
    with pytest.raises(ValueError, match="out of bounds"):
        cfg.validate()

    cfg_high = ModelBackendConfig(default_timeout_ms=500000)
    with pytest.raises(ValueError, match="out of bounds"):
        cfg_high.validate()


def test_unit_bounds_validation_rate_limit():
    cfg = ModelBackendConfig(rate_limit_rpm=-1)
    with pytest.raises(ValueError, match="positive"):
        cfg.validate()


def test_unit_direct_cycle_detection():
    data = {
        "endpoints": {
            "loop-backend": {
                "backend_id": "loop-backend",
            }
        },
        "fallbacks": {
            "loop-backend": ["loop-backend"]
        }
    }
    with pytest.raises(ValueError, match="circular fallback"):
        load_config_from_dict(data)


def test_unit_fallback_depth_limit():
    data = {
        "max_fallback_depth": 2,
        "endpoints": {
            "chain-backend": {
                "backend_id": "chain-backend",
            }
        },
        "fallbacks": {
            "chain-backend": ["f1", "f2", "f3"]
        }
    }
    with pytest.raises(ValueError, match="exceeds max_fallback_depth"):
        load_config_from_dict(data)


def test_unit_json_parsing_success():
    raw_json = """{
        "version": "1.0",
        "default_provider": "mock",
        "endpoints": {
            "primary": {
                "backend_id": "primary",
                "provider": "mock",
                "timeout_ms": 10000
            }
        }
    }"""
    cfg = load_config_from_json(raw_json)
    assert cfg.default_provider == "mock"
    assert "primary" in cfg.endpoints
