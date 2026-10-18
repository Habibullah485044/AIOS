"""Integration tests for MCP Server Core Security Policy Subsystem (T-03128)."""

import pytest
from aiosh_mcp.server import mcp


def test_mcp_policy_evaluate_tool_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_policy_evaluate" in tool_names
    assert "aios_mcp_policy_status" in tool_names


@pytest.mark.anyio
async def test_mcp_policy_evaluate_read_only():
    res = await mcp.call_tool(
        "aios_mcp_policy_evaluate",
        {
            "subject_role": "agent:operator",
            "tool_name": "aios_mcp_config_get",
            "action_category": "read_only",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "ALLOW" in data or '"allowed": true' in data.lower()


@pytest.mark.anyio
async def test_mcp_policy_evaluate_state_changing_no_token():
    res = await mcp.call_tool(
        "aios_mcp_policy_evaluate",
        {
            "subject_role": "agent:operator",
            "tool_name": "aios_mcp_config_set",
            "action_category": "state_changing",
            "capability_token": "",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"allowed": false' in data.lower()


@pytest.mark.anyio
async def test_mcp_policy_status_tool():
    res = await mcp.call_tool("aios_mcp_policy_status", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "rules_count" in data
