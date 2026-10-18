"""Hardening tests for MCP Server Core CLI surface (T-03090).

Verifies:
- NUL byte rejection across all argument positions
- Structured JSON error envelopes when `--json` is supplied on failure
- Clamping and non-panicking execution under adversarial arguments
"""

import pytest
from aiosh_mcp.mcp_server_core_cli import (
    parse_mcp_cli_args,
    execute_mcp_cli,
    EXIT_FAILURE,
    EXIT_UNAUTHORIZED,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_hardening_nul_byte_rejection():
    with pytest.raises(ValueError) as exc:
        parse_mcp_cli_args(["ping\0evil"])
    assert "NUL byte" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        parse_mcp_cli_args(["list", "--filter", "tool\0bad"])
    assert "NUL byte" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        parse_mcp_cli_args(["dispatch", "aios.safe.tool\0"])
    assert "NUL byte" in str(exc.value)


def test_hardening_json_error_envelopes():
    service = McpServerCoreService()

    # 1. Tool not found in JSON mode
    subcmd, opts = parse_mcp_cli_args(["show", "missing.tool", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_FAILURE
    assert out.json_payload is not None
    assert out.json_payload["status"] == "error"
    assert out.json_payload["ok"] is False

    # 2. Privileged tool missing grant in JSON mode
    subcmd, opts = parse_mcp_cli_args(["dispatch", "aios.admin.reboot", "--json"])
    out = execute_mcp_cli(subcmd, opts, service)
    assert out.exit_code == EXIT_UNAUTHORIZED
    assert out.json_payload is not None
    assert out.json_payload["status"] == "error"
    assert out.json_payload["ok"] is False
