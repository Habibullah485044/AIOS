"""Scaffold test for MCP Server Core CLI surface (T-03085)."""

from aiosh_mcp.mcp_server_core_cli import (
    parse_mcp_cli_args,
    execute_mcp_cli,
    EXIT_SUCCESS,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_mcp_cli_scaffold_types_and_ping():
    service = McpServerCoreService()

    subcmd, options = parse_mcp_cli_args(["ping", "--json"])
    assert subcmd == "ping"
    assert options["json"] is True

    output = execute_mcp_cli(subcmd, options, service)
    assert output.exit_code == EXIT_SUCCESS
    assert output.json_payload is not None
    assert output.json_payload["status"] == "ok"
