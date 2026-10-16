"""Hardening tests for MCP Server Core data model (T-03070).

Verifies:
- ADR-0035 §AF-2 envelope compliance on failure and success
- Exception-free behavior on malformed strings and payload overruns
- Proper error code preservation
"""

import pytest
from aiosh_mcp.mcp_server_core_data_model import (
    safe_parse_request_envelope,
    safe_validate_tool_envelope,
    MAX_PAYLOAD_SIZE,
    ERR_PARSE_ERROR,
    ERR_BOUNDS_EXCEEDED,
    ERR_INVALID_PARAMS,
)


def test_hardening_safe_parse_envelope():
    # 1. Success case
    valid_raw = '{"jsonrpc": "2.0", "id": 99, "method": "ping"}'
    env = safe_parse_request_envelope(valid_raw)
    assert env.ok is True
    assert env.status == "success"
    assert env.data["id"] == 99

    # 2. Syntax parse error (must not raise uncaught exception)
    bad_raw = "{not valid json at all}"
    env_bad = safe_parse_request_envelope(bad_raw)
    assert env_bad.ok is False
    assert env_bad.status == "error"
    assert env_bad.error_code == ERR_PARSE_ERROR

    # 3. Payload overrun (must reject without memory blowup)
    huge = "x" * (MAX_PAYLOAD_SIZE + 1024)
    env_huge = safe_parse_request_envelope(huge)
    assert env_huge.ok is False
    assert env_huge.error_code == ERR_BOUNDS_EXCEEDED


def test_hardening_safe_validate_tool_envelope():
    # 1. Valid tool
    env = safe_validate_tool_envelope(
        name="aios.safe.tool",
        description="A hardened tool",
        schema={"type": "object"},
    )
    assert env.ok is True
    assert env.data["name"] == "aios.safe.tool"

    # 2. Malformed tool with control chars
    env_bad = safe_validate_tool_envelope(
        name="aios.tool\x00null",
        description="description",
        schema={},
    )
    assert env_bad.ok is False
    assert env_bad.error_code == ERR_INVALID_PARAMS
