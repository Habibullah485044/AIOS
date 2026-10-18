"""Scaffold test for MCP Server Core MCP/API surface (T-03095)."""

from aiosh_mcp.mcp_server_core_api import (
    McpApiHandler,
    PROTOCOL_VERSION,
    SERVER_NAME,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_mcp_api_scaffold_ping_and_initialize():
    service = McpServerCoreService()
    handler = McpApiHandler(service)

    # Test ping
    ping_resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping"
    })
    assert ping_resp["jsonrpc"] == "2.0"
    assert ping_resp["id"] == 1
    assert ping_resp["result"]["status"] == "ok"

    # Test initialize
    init_resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        }
    })
    assert init_resp["id"] == 2
    assert init_resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init_resp["result"]["serverInfo"]["name"] == SERVER_NAME
    assert "sessionId" in init_resp["result"]
