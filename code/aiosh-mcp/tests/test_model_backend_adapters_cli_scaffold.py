"""Scaffold tests for Model Backend Adapters CLI surface (T-03185)."""

import json
import pytest

from aiosh_mcp.model_backend_adapters_cli import (
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_USAGE,
    EXIT_UNAUTHORIZED,
    EXIT_TIMEOUT,
    ModelCliOutput,
    parse_model_cli_args,
    dispatch_model_cli,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


def test_exit_codes_contract():
    assert EXIT_SUCCESS == 0
    assert EXIT_FAILURE == 1
    assert EXIT_USAGE == 2
    assert EXIT_UNAUTHORIZED == 3
    assert EXIT_TIMEOUT == 4


def test_model_cli_output_constructors():
    out_succ = ModelCliOutput.success("ok", {"k": "v"})
    assert out_succ.exit_code == EXIT_SUCCESS
    assert out_succ.message == "ok"
    assert out_succ.json_payload == {"k": "v"}

    out_fail = ModelCliOutput.failure(EXIT_FAILURE, "failed Bearer secret-tok")
    assert out_fail.exit_code == EXIT_FAILURE
    assert "[REDACTED_SECRET]" in out_fail.message

    out_json = ModelCliOutput.failure_with_json(EXIT_UNAUTHORIZED, "unauthorized sk-1234567890abcdef", json_mode=True)
    assert out_json.exit_code == EXIT_UNAUTHORIZED
    assert out_json.json_payload is not None
    assert out_json.json_payload["ok"] is False
    assert "[REDACTED_SECRET]" in out_json.json_payload["error_message"]


def test_parse_model_cli_args_validation():
    with pytest.raises(ValueError, match="Missing model subcommand"):
        parse_model_cli_args([])

    with pytest.raises(ValueError, match="prohibited NUL byte"):
        parse_model_cli_args(["list", "arg\0bad"])

    with pytest.raises(ValueError, match="Unknown subcommand"):
        parse_model_cli_args(["invalid_subcmd"])

    subcmd, opts = parse_model_cli_args(["list", "--provider", "mock", "--active-only", "--json"])
    assert subcmd == "list"
    assert opts["provider"] == "mock"
    assert opts["active_only"] is True
    assert opts["json"] is True


def test_dispatch_por_token_gating():
    # Read-only requires no token
    svc = ModelBackendService()
    out = dispatch_model_cli(["list"], service=svc)
    assert out.exit_code == EXIT_SUCCESS

    # State-mutating requires token (PoR Invariant I-2)
    out_complete = dispatch_model_cli(["complete", "mock-default", "--prompt", "hello"], service=svc)
    assert out_complete.exit_code == EXIT_UNAUTHORIZED
    assert "capability token" in out_complete.message

    out_reg = dispatch_model_cli(["register", "custom-1", "--provider", "mock", "--model", "custom"], service=svc)
    assert out_reg.exit_code == EXIT_UNAUTHORIZED
    assert "capability token" in out_reg.message
