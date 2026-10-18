"""Integration tests for MCP Server Core CLI surface (T-03088).

Validates end-to-end execution of CLI commands against active services
and verifies PoR Invariant I-2 compliance.
"""

from aiosh_mcp.mcp_server_core_cli import (
    parse_mcp_cli_args,
    execute_mcp_cli,
    EXIT_SUCCESS,
)
from aiosh_mcp.mcp_server_core_data_model import McpToolDefinition
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_integration_mcp_cli_end_to_end():
    service = McpServerCoreService()

    # 1. Tool registration & query
    tool = McpToolDefinition(
        name="aios.system.telemetry",
        description="System telemetry probe",
        input_schema={"type": "object", "properties": {"metric": {"type": "string"}}},
    )
    service.register_tool(tool)

    subcmd, opts = parse_mcp_cli_args(["list", "--json"])
    list_out = execute_mcp_cli(subcmd, opts, service)
    assert list_out.exit_code == EXIT_SUCCESS
    assert list_out.json_payload is not None
    assert any(t["name"] == "aios.system.telemetry" for t in list_out.json_payload["tools"])

    subcmd, opts = parse_mcp_cli_args(["show", "aios.system.telemetry", "--json"])
    show_out = execute_mcp_cli(subcmd, opts, service)
    assert show_out.exit_code == EXIT_SUCCESS

    # 2. Dispatch with payload
    subcmd, opts = parse_mcp_cli_args([
        "dispatch",
        "aios.system.telemetry",
        "--args",
        '{"metric":"cpu_load"}',
        "--timeout",
        "15",
        "--json",
    ])
    disp_out = execute_mcp_cli(subcmd, opts, service)
    assert disp_out.exit_code == EXIT_SUCCESS
    assert disp_out.json_payload["ok"] is True

    # 3. Sessions lifecycle and pruning
    service.create_session("sess-integ-1", "desktop-worker", "1.0.0")
    service.terminate_session("sess-integ-1")

    subcmd, opts = parse_mcp_cli_args(["sessions", "--prune", "0", "--json"])
    prune_out = execute_mcp_cli(subcmd, opts, service)
    assert prune_out.exit_code == EXIT_SUCCESS
    assert prune_out.json_payload["pruned"] == 1
