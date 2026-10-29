"""Integration tests for Model Backend Adapters Observability Subsystem (T-03238)."""

import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.model_backend_adapters_observability import (
    get_global_observability_service,
    HealthStatus,
)


@pytest.mark.anyio
async def test_integration_mcp_observability_snapshot_tool():
    # 1. Verify tool registration on FastMCP server
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    assert "aios_model_observability_snapshot" in tool_names

    # 2. Record simulated activity on global service
    service = get_global_observability_service()
    service.reset()
    service.record_completion(provider="gemini", duration_ms=250.0, prompt_tokens=150, completion_tokens=50)

    # 3. Call tool through FastMCP tool invocation
    result = await mcp.call_tool("aios_model_observability_snapshot", {})
    assert result is not None

    # Inspect snapshot data
    snap = service.get_snapshot()
    assert snap.total_requests == 1
    assert snap.successful_requests == 1
    assert snap.total_prompt_tokens == 150
    assert snap.total_completion_tokens == 50
    assert snap.total_tokens == 200
    assert snap.average_latency_ms == 250.0
    assert snap.health_status == HealthStatus.HEALTHY
    assert snap.provider_breakdown["gemini"] == 1
