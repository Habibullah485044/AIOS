"""Implementation tests for Runbook configuration (T-03006)."""

import pytest
from aiosh_mcp.runbook_config import (
    DEFAULT_CATALOG_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
    DEFAULT_MAX_CATALOG_FILE_BYTES,
    DEFAULT_STEP_TIMEOUT_SECONDS,
    resolve_runbook_config,
)


def test_resolve_default():
    resolved = resolve_runbook_config()
    assert resolved.catalog_path == DEFAULT_CATALOG_PATH
    assert resolved.max_active_sessions == DEFAULT_MAX_ACTIVE_SESSIONS
    assert resolved.max_catalog_file_bytes == DEFAULT_MAX_CATALOG_FILE_BYTES
    assert resolved.default_step_timeout_seconds == DEFAULT_STEP_TIMEOUT_SECONDS
    assert resolved.require_operator_confirmation is True
    assert resolved.sources["catalog_path"] == "default"
    assert resolved.sources["max_active_sessions"] == "default"


def test_resolve_with_argument_overrides():
    resolved = resolve_runbook_config(
        catalog_path="docs/custom_catalog.json",
        max_active_sessions=500,
        max_catalog_file_bytes=2048 * 1024,
        default_step_timeout_seconds=1800,
        require_operator_confirmation=False,
    )
    assert resolved.catalog_path == "docs/custom_catalog.json"
    assert resolved.max_active_sessions == 500
    assert resolved.max_catalog_file_bytes == 2048 * 1024
    assert resolved.default_step_timeout_seconds == 1800
    assert resolved.require_operator_confirmation is False
    assert resolved.sources["catalog_path"] == "argument"
    assert resolved.sources["max_active_sessions"] == "argument"
