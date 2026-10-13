"""Scaffold tests for Incident Response Runbooks & RustSec MCP surface (T-02995)."""

import pytest

from aiosh_mcp.incident_runbook_mcp import (
    execute_runbook_action,
    execute_scan_action,
    register_runbook_tools,
)
from aiosh_mcp.server import mcp


def test_mcp_tools_registered():
    tools = mcp._tool_manager._tools
    assert "aios_runbook" in tools
    assert "aios_scan" in tools


def test_scaffold_tools_callable():
    res = execute_runbook_action(action="list")
    assert res["ok"] is True
    assert "runbooks" in res

    res_scan = execute_scan_action(action="net", target="127.0.0.1", ports="80,443")
    assert res_scan["ok"] is True
    assert res_scan["target"] == "127.0.0.1"
