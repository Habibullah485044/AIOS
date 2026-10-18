"""Scaffold test for MCP Server Core configuration subsystem (T-03105)."""

from aiosh_mcp.mcp_server_core_config import (
    McpServerCoreConfig,
    DEFAULT_STORE_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
)


def test_mcp_config_scaffold_default_and_validation():
    cfg = McpServerCoreConfig()
    assert cfg.store_path == DEFAULT_STORE_PATH
    assert cfg.max_active_sessions == DEFAULT_MAX_ACTIVE_SESSIONS
    cfg.validate()

    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert d["max_active_sessions"] == DEFAULT_MAX_ACTIVE_SESSIONS
