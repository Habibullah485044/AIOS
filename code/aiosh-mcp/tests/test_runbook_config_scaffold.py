"""Scaffold tests for Incident Response Runbooks configuration (T-03005)."""

import pytest

from aiosh_mcp.runbook_config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_CATALOG_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
    DEFAULT_MAX_CATALOG_FILE_BYTES,
    DEFAULT_STEP_TIMEOUT_SECONDS,
    MAX_CONFIG_FILE_BYTES,
    RunbookConfig,
    resolve_runbook_config,
    validate_config_path,
    RUNBOOKCONF_ERR_PATH_TRAVERSAL,
)


def test_constants_and_default_config():
    assert MAX_CONFIG_FILE_BYTES == 64 * 1024
    assert DEFAULT_CONFIG_PATH == "docs/runbook_config.json"
    assert DEFAULT_CATALOG_PATH == "docs/runbook_catalog.json"

    cfg = RunbookConfig()
    assert cfg.max_active_sessions == DEFAULT_MAX_ACTIVE_SESSIONS
    assert cfg.max_catalog_file_bytes == DEFAULT_MAX_CATALOG_FILE_BYTES
    assert cfg.default_step_timeout_seconds == DEFAULT_STEP_TIMEOUT_SECONDS
    assert cfg.require_operator_confirmation is True


def test_validate_config_path():
    assert validate_config_path("docs/runbook_catalog.json") == "docs/runbook_catalog.json"

    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_PATH_TRAVERSAL):
        validate_config_path("../evil/path.json")


def test_resolve_scaffold_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="resolve_runbook_config scaffold"):
        resolve_runbook_config()
