"""Integration tests for MCP Server Core Recovery & Validation Subsystem (T-03158)."""

import json
import pytest
from aiosh_mcp.server import mcp


def test_mcp_recovery_tools_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_recovery_check" in tool_names
    assert "aios_mcp_recovery_repair" in tool_names


@pytest.mark.anyio
async def test_mcp_recovery_check_integration(tmp_path):
    store = tmp_path / "valid_store.json"
    store.write_text(json.dumps({"k1": "v1", "k2": "v2"}), encoding="utf-8")

    res = await mcp.call_tool("aios_mcp_recovery_check", {"path": str(store)})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert '"is_healthy": true' in data.lower()
    assert '"total_records": 2' in data.lower()


@pytest.mark.anyio
async def test_mcp_recovery_repair_gating(tmp_path):
    store = tmp_path / "corrupt_store.json"
    store.write_text("{corrupt-json", encoding="utf-8")

    # Call repair without capability token -> fails closed (PoR Invariant I-2)
    res = await mcp.call_tool("aios_mcp_recovery_repair", {"path": str(store), "capability_token": ""})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": false' in data.lower()
    assert "capability token required" in data.lower() or "unauthorized" in data.lower()


@pytest.mark.anyio
async def test_mcp_recovery_repair_success(tmp_path):
    store = tmp_path / "corrupt_store.json"
    store.write_text("{broken-json", encoding="utf-8")

    # Call repair with valid capability token
    res = await mcp.call_tool(
        "aios_mcp_recovery_repair",
        {"path": str(store), "capability_token": "por_cap_grant_repair_001"},
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "quarantine_and_reset" in data.lower()
    assert ".bak." in data.lower()
    assert '"is_healthy": true' in data.lower()
