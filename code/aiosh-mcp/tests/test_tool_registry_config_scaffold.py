"""Scaffold tests for the tool registry configuration (T-03405; spec T-03404)."""

import pytest

from aiosh_mcp import tool_registry_config as cfg


def test_keys_bounds_and_env_names_match_spec():
    assert {k: (f.default, f.lo, f.hi, f.env) for k, f in cfg.FIELDS.items()} == {
        "report_max_lines": (32, 0, 1000, "AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES"),
        "unregistered_samples": (50, 0, 200, "AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES")}
    assert cfg.MODES == ("shadow", "strict") and cfg.ENV_MODE == "AIOSH_TOOL_REGISTRY_MODE"
    assert cfg.MAX_CONFIG_FILE_BYTES == 64 * 1024 and cfg.ENV_CONFIG == "AIOSH_TOOL_REGISTRY_CONFIG"


def test_locked_keys_and_codes():
    assert "catalog" in cfg.LOCKED_KEYS and "grant_params" in cfg.LOCKED_KEYS
    assert not set(cfg.LOCKED_KEYS) & set(cfg.FIELDS)
    codes = sorted(v for k, v in vars(cfg).items() if k.startswith("TOOLREGCONF_ERR_"))
    assert len(codes) == 7


def test_defaults_match_the_service_constants():
    from aiosh_mcp import tool_registry_service as trs
    assert cfg.FIELDS["report_max_lines"].default == trs.MAX_REPORT_LINES
    assert cfg.FIELDS["unregistered_samples"].default == trs.MAX_UNREGISTERED_SAMPLES


def test_scaffold_stubs_are_implemented():
    """The T-03405 stubs raised NotImplementedError; T-03406 implemented them."""
    assert set(cfg.resolve()["config"]) == {"mode", *cfg.FIELDS}
