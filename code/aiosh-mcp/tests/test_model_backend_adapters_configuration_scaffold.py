"""Scaffold tests for Model Backend Adapters Configuration (T-03205)."""

import pytest
from aiosh_mcp import model_backend_adapters_configuration as modconf


def test_configuration_module_exports():
    assert hasattr(modconf, "ModelBackendConfig")
    assert hasattr(modconf, "load_config_from_dict")
    assert hasattr(modconf, "load_config_from_json")


def test_configuration_scaffold_structure():
    cfg = modconf.ModelBackendConfig()
    assert hasattr(cfg, "to_dict")
    assert callable(modconf.load_config_from_dict)
    assert callable(modconf.load_config_from_json)
