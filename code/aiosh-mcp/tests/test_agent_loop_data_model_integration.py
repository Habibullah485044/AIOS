"""Integration tests for Agent Loop Hardening Data Model (T-03268).

Verifies FastMCP tool registration, PoR capability token gating (Invariant I-2),
read-only query dispatch, and FSM initialization.
"""

import json
import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.agent_loop_data_model import (
    LOOPDATA_ERR_NOT_FOUND,
    LOOPDATA_ERR_UNAUTHORIZED,
    LoopState,
    _GLOBAL_LOOP_REGISTRY,
)


@pytest.fixture(autouse=True)
def clean_registry():
    _GLOBAL_LOOP_REGISTRY.clear()
    yield
    _GLOBAL_LOOP_REGISTRY.clear()


def _extract_payload(res) -> dict:
    if isinstance(res, dict):
        return res
    if isinstance(res, list) and len(res) > 0:
        if hasattr(res[0], "text"):
            try:
                return json.loads(res[0].text)
            except Exception:
                return {"text": res[0].text}
        return res[0]
    return {"raw": str(res)}


def test_integration_agent_loop_tools_registered():
    """Verify agent loop data model tools are registered on the FastMCP server."""
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_agent_loop_status" in tool_names
    assert "aios_agent_loop_init" in tool_names


@pytest.mark.anyio
async def test_integration_agent_loop_status_not_found():
    """Verify querying an uninitialized loop returns LOOPDATA_ERR_NOT_FOUND."""
    res = await mcp._tool_manager.call_tool(
        "aios_agent_loop_status",
        {"loop_id": "nonexistent-loop-id"},
    )
    assert res is not None
    data = _extract_payload(res)
    assert data.get("ok") is False
    assert LOOPDATA_ERR_NOT_FOUND in data.get("error", "")


@pytest.mark.anyio
async def test_integration_agent_loop_init_por_gating():
    """PoR Invariant I-2: Mutating agent loop initialization requires capability token."""
    # Attempt without capability token
    res = await mcp._tool_manager.call_tool(
        "aios_agent_loop_init",
        {
            "loop_id": "loop-integ-test-01",
            "max_iterations": 20,
            "max_total_tokens": 16000,
            "capability_token": "",
        },
    )
    data = _extract_payload(res)
    assert data.get("ok") is False
    assert LOOPDATA_ERR_UNAUTHORIZED in data.get("error", "")

    # Attempt with valid capability token
    res_ok = await mcp._tool_manager.call_tool(
        "aios_agent_loop_init",
        {
            "loop_id": "loop-integ-test-01",
            "max_iterations": 20,
            "max_total_tokens": 16000,
            "capability_token": "por-cap-token-integ-valid",
        },
    )
    data_ok = _extract_payload(res_ok)
    assert data_ok.get("ok") is True
    assert data_ok.get("loop_id") == "loop-integ-test-01"
    assert data_ok["snapshot"]["current_state"] == LoopState.INIT.value

    # Now verify status query returns the loop
    res_status = await mcp._tool_manager.call_tool(
        "aios_agent_loop_status",
        {"loop_id": "loop-integ-test-01"},
    )
    status_data = _extract_payload(res_status)
    assert status_data.get("ok") is True
    assert status_data["snapshot"]["loop_id"] == "loop-integ-test-01"
    assert status_data["snapshot"]["current_state"] == "INIT"
