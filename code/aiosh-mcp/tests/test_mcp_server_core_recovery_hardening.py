"""Hardening tests for MCP Server Core Recovery & Validation Subsystem (T-03160)."""

import pytest
from pathlib import Path
from aiosh_mcp.mcp_server_core_recovery import (
    validate_store_path,
    sanitize_error_message,
    MCPRECV_ERR_INVALID_PATH,
)


def test_validate_store_path_traversal():
    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("../secret/store.json")

    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("nested/../../store.json")


def test_validate_store_path_nul_byte():
    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("store.json\0evil")


def test_validate_store_path_bounds():
    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("")

    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("   ")

    with pytest.raises(ValueError, match=MCPRECV_ERR_INVALID_PATH):
        validate_store_path("a" * 1025)


def test_validate_store_path_reserved_devices():
    for dev in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]:
        with pytest.raises(ValueError, match="reserved device name detected"):
            validate_store_path(f"{dev}.json")
        with pytest.raises(ValueError, match="reserved device name detected"):
            validate_store_path(f"folder/{dev}")


def test_validate_store_path_ads():
    with pytest.raises(ValueError, match="alternate data stream"):
        validate_store_path("store.json:stream")


def test_sanitize_error_message():
    err1 = "Failed to open c:\\Users\\Secret\\mcp_store.json: file not found"
    clean1 = sanitize_error_message(err1)
    assert "c:\\Users" not in clean1
    assert "[REDACTED_PATH]" in clean1

    err2 = "Permission denied: /var/log/private/store.json"
    clean2 = sanitize_error_message(err2)
    assert "/var/log/private" not in clean2
    assert "[REDACTED_PATH]" in clean2
