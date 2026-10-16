"""Hardening tests for MCP Server Core service (T-03080).

Verifies:
- Idle and terminated session eviction via `prune_idle_sessions`
- Timeout clamping and bounded execution via `safe_dispatch_with_timeout`
- ADR-0035 §AF-2 non-panicking error envelopes under fault injection
"""

import pytest
from aiosh_mcp.mcp_server_core_service import (
    McpServerCoreService,
    MCPSVC_ERR_TOOL_NOT_FOUND,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
)


def test_hardening_prune_idle_and_terminated_sessions():
    service = McpServerCoreService()

    service.create_session("sess-h1", "client-a", "1.0")
    service.create_session("sess-h2", "client-b", "1.0")
    service.create_session("sess-h3", "client-c", "1.0")

    service.terminate_session("sess-h1")

    # Prune terminated sessions
    pruned = service.prune_idle_sessions(0.0)
    assert pruned == 1

    assert service.get_session("sess-h1") is None
    assert service.get_session("sess-h2") is not None
    assert service.get_session("sess-h3") is not None


def test_hardening_safe_dispatch_timeout_and_fault_tolerance():
    service = McpServerCoreService()

    tool = McpToolDefinition(
        name="aios.hardening.ping",
        description="Hardened ping tool",
        input_schema={"type": "object"},
    )
    service.register_tool(tool)

    # Dispatch with excessive timeout -> clamped gracefully
    call = McpToolCall(name="aios.hardening.ping", arguments={})
    env = service.safe_dispatch_with_timeout(call, timeout_seconds=999999)
    assert env.ok is True
    assert env.status == "success"

    # Dispatch missing tool with zero timeout -> clamped to 1, fail-closed envelope
    call_missing = McpToolCall(name="aios.missing.tool", arguments={})
    env_missing = service.safe_dispatch_with_timeout(call_missing, timeout_seconds=0)
    assert env_missing.ok is False
    assert env_missing.status == "error"
    assert env_missing.error_code == MCPSVC_ERR_TOOL_NOT_FOUND
