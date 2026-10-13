"""Comprehensive unit tests for Incident Response Runbooks configuration (T-03007)."""

import json
import os
import tempfile
import pytest

from aiosh_mcp.runbook_config import (
    DEFAULT_CATALOG_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
    DEFAULT_MAX_CATALOG_FILE_BYTES,
    DEFAULT_STEP_TIMEOUT_SECONDS,
    MAX_CONFIG_FILE_BYTES,
    MIN_MAX_ACTIVE_SESSIONS,
    MAX_MAX_ACTIVE_SESSIONS,
    MIN_MAX_CATALOG_FILE_BYTES,
    MAX_MAX_CATALOG_FILE_BYTES,
    MIN_STEP_TIMEOUT_SECONDS,
    MAX_STEP_TIMEOUT_SECONDS,
    RUNBOOKCONF_ERR_BOUNDS,
    RUNBOOKCONF_ERR_FILE_SIZE,
    RUNBOOKCONF_ERR_PARSE,
    RUNBOOKCONF_ERR_PATH_TRAVERSAL,
    RUNBOOKCONF_ERR_VALIDATION,
    hygiene_ok,
    resolve_runbook_config,
    validate_config_path,
)


def test_unit_validate_config_path_boundaries():
    assert validate_config_path("docs/runbook_catalog.json") == "docs/runbook_catalog.json"

    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_VALIDATION):
        validate_config_path("")

    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_VALIDATION):
        validate_config_path("   ")

    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_PATH_TRAVERSAL):
        validate_config_path("../evil/path.json")

    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_PATH_TRAVERSAL):
        validate_config_path("foo/bar/../../baz")

    long_path = "a" * 1025
    with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_BOUNDS):
        validate_config_path(long_path)


def test_unit_hygiene_predicate():
    assert hygiene_ok("valid/path/config.json") is True
    assert hygiene_ok("") is False
    assert hygiene_ok("   ") is False
    assert hygiene_ok("../traversal") is False
    assert hygiene_ok("bad\x00character") is False
    assert hygiene_ok("bad\x1fcharacter") is False


def test_unit_clamping_boundaries():
    # Min bound clamping
    res_low = resolve_runbook_config(
        max_active_sessions=0,
        max_catalog_file_bytes=10,
        default_step_timeout_seconds=0,
    )
    assert res_low.max_active_sessions == MIN_MAX_ACTIVE_SESSIONS
    assert res_low.max_catalog_file_bytes == MIN_MAX_CATALOG_FILE_BYTES
    assert res_low.default_step_timeout_seconds == MIN_STEP_TIMEOUT_SECONDS

    # Max bound clamping
    res_high = resolve_runbook_config(
        max_active_sessions=50000,
        max_catalog_file_bytes=50 * 1024 * 1024,
        default_step_timeout_seconds=200000,
    )
    assert res_high.max_active_sessions == MAX_MAX_ACTIVE_SESSIONS
    assert res_high.max_catalog_file_bytes == MAX_MAX_CATALOG_FILE_BYTES
    assert res_high.default_step_timeout_seconds == MAX_STEP_TIMEOUT_SECONDS


def test_unit_file_resolution_and_oversize_error():
    with tempfile.TemporaryDirectory() as td:
        valid_cfg_path = os.path.join(td, "valid_config.json")
        with open(valid_cfg_path, "w", encoding="utf-8") as f:
            json.dump({
                "max_active_sessions": 250,
                "default_step_timeout_seconds": 600,
                "require_operator_confirmation": False,
            }, f)

        res = resolve_runbook_config(config_path=valid_cfg_path)
        assert res.max_active_sessions == 250
        assert res.default_step_timeout_seconds == 600
        assert res.require_operator_confirmation is False
        assert res.sources["max_active_sessions"] == "file"
        assert res.sources["require_operator_confirmation"] == "file"

        # Oversized config file (> 64 KiB)
        huge_cfg_path = os.path.join(td, "huge_config.json")
        with open(huge_cfg_path, "wb") as f:
            f.write(b" " * (MAX_CONFIG_FILE_BYTES + 10))

        with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_FILE_SIZE):
            resolve_runbook_config(config_path=huge_cfg_path)


def test_unit_corrupted_json_fails_closed():
    with tempfile.TemporaryDirectory() as td:
        corrupt_path = os.path.join(td, "corrupt.json")
        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write("{ malformed json: true, ")

        with pytest.raises(ValueError, match=RUNBOOKCONF_ERR_PARSE):
            resolve_runbook_config(config_path=corrupt_path)
