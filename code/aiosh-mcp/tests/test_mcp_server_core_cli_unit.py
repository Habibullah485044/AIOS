"""Unit tests for MCP Server Core CLI surface (T-03087).

Standard 4-case testing battery:
1. Valid input (ping, list, show, safe dispatch, sessions prune)
2. Invalid input (unknown subcommands, unknown flags, missing args)
3. Boundary values (MAX_ARGUMENTS_SIZE 1 MiB, timeout clamp 1..300)
4. Primary failure modes (tool not found, privileged unauthorized tool)
"""

import pytest
from aiosh_mcp.mcp_server_core_cli import (
    parse_mcp_cli_args,
    execute_mcp_cli,
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_USAGE,
    EXIT_UNAUTHORIZED,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    MAX_ARGUMENTS_SIZE,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_unit_case1_valid_cli_commands():
    service = McpServerCoreService()
    tool = McpToolDefinition("aios.fs.read", "Read file", {"type": "object"})
    service.register_tool(tool)

    # 1. Ping
    subcmd, opts = parse_mcp_cli_args(["ping", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS

    # 2. List
    subcmd, opts = parse_mcp_cli_args(["list", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS

    # 3. Show
    subcmd, opts = parse_mcp_cli_args(["show", "aios.fs.read", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS

    # 4. Dispatch valid
    subcmd, opts = parse_mcp_cli_args(["dispatch", "aios.fs.read", "--args", '{"path":"/tmp/test"}'])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS

    # 5. Sessions prune
    subcmd, opts = parse_mcp_cli_args(["sessions", "--prune", "0", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS


def test_unit_case2_invalid_cli_inputs():
    with pytest.raises(ValueError):
        parse_mcp_cli_args([])

    with pytest.raises(ValueError):
        parse_mcp_cli_args(["list", "--bogus-flag"])

    subcmd, opts = parse_mcp_cli_args(["show"])
    out = execute_mcp_cli(subcmd, opts, McpServerCoreService())
    assert out.exit_code == EXIT_USAGE

    subcmd, opts = parse_mcp_cli_args(["dispatch"])
    out = execute_mcp_cli(subcmd, opts, McpServerCoreService())
    assert out.exit_code == EXIT_USAGE


def test_unit_case3_boundary_values():
    service = McpServerCoreService()
    tool = McpToolDefinition("aios.test.bound", "Boundary tool", {})
    service.register_tool(tool)

    # Max arguments limit violation (> 1 MiB)
    huge_args = '{"pad":"' + ("x" * (MAX_ARGUMENTS_SIZE + 1024)) + '"}'
    subcmd, opts = parse_mcp_cli_args(["dispatch", "aios.test.bound", "--args", huge_args])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_USAGE

    # Timeout boundary clamping
    subcmd, opts = parse_mcp_cli_args(["dispatch", "aios.test.bound", "--timeout", "999999", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_SUCCESS


def test_unit_case4_primary_failure_modes():
    service = McpServerCoreService()

    # 1. Tool not found
    subcmd, opts = parse_mcp_cli_args(["show", "nonexistent.tool"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_FAILURE

    # 2. Dispatch missing tool
    subcmd, opts = parse_mcp_cli_args(["dispatch", "nonexistent.tool"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_FAILURE

    # 3. Privileged tool missing grant token (fail closed with EXIT_UNAUTHORIZED = 3)
    subcmd, opts = parse_mcp_cli_args(["dispatch", "aios.admin.shutdown"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_UNAUTHORIZED
