"""Unit tests for MCP Server Core configuration subsystem (T-03107).

Standard 4-case testing battery:
1. Valid input (defaults, custom config, JSON roundtrip)
2. Invalid input (empty path, NUL bytes, traversal, invalid types)
3. Boundary values (min/max clamps across sessions, timeouts, payload limits)
4. Primary failure modes (missing file, oversized config > 64 KiB, precedence resolution)
"""

import os
import json
import tempfile
import pytest

from aiosh_mcp.mcp_server_core_config import (
    McpServerCoreConfig,
    McpConfigError,
    DEFAULT_STORE_PATH,
    MIN_ACTIVE_SESSIONS,
    MAX_ALLOWED_ACTIVE_SESSIONS,
    MIN_IDLE_TIMEOUT,
    MAX_ALLOWED_IDLE_TIMEOUT,
    MIN_EXECUTION_TIMEOUT,
    MAX_ALLOWED_EXECUTION_TIMEOUT,
    MIN_ARGUMENTS_SIZE,
    MAX_ALLOWED_ARGUMENTS_SIZE,
    MIN_TOOLS_COUNT,
    MAX_ALLOWED_TOOLS_COUNT,
    MAX_CONFIG_FILE_BYTES,
)


def test_unit_case1_valid_config():
    # 1. Default config
    cfg = McpServerCoreConfig()
    cfg.validate()
    assert cfg.store_path == DEFAULT_STORE_PATH

    # 2. Custom valid config
    custom = McpServerCoreConfig(
        store_path=".aios/custom_store.json",
        max_active_sessions=128,
        session_idle_timeout_seconds=7200,
        default_execution_timeout_seconds=60,
        max_arguments_size_bytes=2 * 1024 * 1024,
        max_tools_count=512,
        require_admin_grant=True,
        auto_prune_terminated=False,
    )
    custom.validate()
    assert custom.max_active_sessions == 128

    # 3. Round-trip serialization
    d = custom.to_dict()
    restored = McpServerCoreConfig.from_dict(d)
    assert restored == custom


def test_unit_case2_invalid_config():
    # Empty store path
    with pytest.raises(McpConfigError) as exc:
        McpServerCoreConfig(store_path="").validate()
    assert "MCPCFG-INV1" in str(exc.value)

    # NUL byte in store path
    with pytest.raises(McpConfigError) as exc:
        McpServerCoreConfig(store_path="bad\0path").validate()
    assert "MCPCFG-INV1" in str(exc.value)

    # Directory traversal in store path
    with pytest.raises(McpConfigError) as exc:
        McpServerCoreConfig(store_path="../../etc/passwd").validate()
    assert "MCPCFG-INV1" in str(exc.value)

    # Out of bounds active sessions
    with pytest.raises(McpConfigError) as exc:
        McpServerCoreConfig(max_active_sessions=0).validate()
    assert "MCPCFG-INV2" in str(exc.value)


def test_unit_case3_boundary_values():
    # Min bounds
    min_cfg = McpServerCoreConfig(
        max_active_sessions=MIN_ACTIVE_SESSIONS,
        session_idle_timeout_seconds=MIN_IDLE_TIMEOUT,
        default_execution_timeout_seconds=MIN_EXECUTION_TIMEOUT,
        max_arguments_size_bytes=MIN_ARGUMENTS_SIZE,
        max_tools_count=MIN_TOOLS_COUNT,
    )
    min_cfg.validate()

    # Max bounds
    max_cfg = McpServerCoreConfig(
        max_active_sessions=MAX_ALLOWED_ACTIVE_SESSIONS,
        session_idle_timeout_seconds=MAX_ALLOWED_IDLE_TIMEOUT,
        default_execution_timeout_seconds=MAX_ALLOWED_EXECUTION_TIMEOUT,
        max_arguments_size_bytes=MAX_ALLOWED_ARGUMENTS_SIZE,
        max_tools_count=MAX_ALLOWED_TOOLS_COUNT,
    )
    max_cfg.validate()

    # Beyond max bounds
    with pytest.raises(McpConfigError):
        McpServerCoreConfig(max_active_sessions=MAX_ALLOWED_ACTIVE_SESSIONS + 1).validate()


def test_unit_case4_primary_failure_modes():
    # 1. Missing file throws FileNotFoundError
    with pytest.raises(FileNotFoundError):
        McpServerCoreConfig.load_from_file("nonexistent_config_file_12345.json")

    # 2. Oversized config file throws McpConfigError
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(" " * (MAX_CONFIG_FILE_BYTES + 10))
        tmp_path = f.name
    try:
        with pytest.raises(McpConfigError) as exc:
            McpServerCoreConfig.load_from_file(tmp_path)
        assert "exceeds" in str(exc.value)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # 3. Resolution precedence: CLI overrides Env
    os.environ["AIOS_MCP_MAX_SESSIONS"] = "30"
    try:
        resolved = McpServerCoreConfig.resolve(cli_opts={"max_active_sessions": 50})
        assert resolved.max_active_sessions == 50
    finally:
        del os.environ["AIOS_MCP_MAX_SESSIONS"]
