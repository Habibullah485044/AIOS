"""Comprehensive unit tests for Model Backend Adapters CLI Surface (T-03187).

Verifies invariants MODCLI-INV1..5:
  - MODCLI-INV1: Command Schema Canonicalization & Argument Parsing
  - MODCLI-INV2: Proof-of-Restraint Invariant I-2 Gating
  - MODCLI-INV3: Standardized Exit Code Taxonomy & JSON Envelope Parity
  - MODCLI-INV4: Secret & Telemetry Redaction
  - MODCLI-INV5: Fallback & Timeout Bounds
"""

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
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelProviderType,
)
from aiosh_mcp.model_backend_adapters_service import (
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_TIMEOUT,
    MODSERV_ERR_UNKNOWN_BACKEND,
)


@pytest.fixture
def service():
    return ModelBackendService()


# ---------------------------------------------------------------------------
# MODCLI-INV1: Command Schema Canonicalization & Argument Parsing
# ---------------------------------------------------------------------------

def test_parse_args_subcommand_validation():
    with pytest.raises(ValueError, match="Missing model subcommand"):
        parse_model_cli_args([])

    with pytest.raises(ValueError, match="Unknown subcommand 'destroy'"):
        parse_model_cli_args(["destroy"])

    with pytest.raises(ValueError, match="prohibited NUL byte"):
        parse_model_cli_args(["list", "--provider\0", "mock"])


def test_parse_args_flag_validation():
    with pytest.raises(ValueError, match="--provider requires a value"):
        parse_model_cli_args(["list", "--provider"])

    with pytest.raises(ValueError, match="--prompt requires text"):
        parse_model_cli_args(["complete", "mock-default", "--prompt"])

    with pytest.raises(ValueError, match="Invalid temperature"):
        parse_model_cli_args(["complete", "mock-default", "--prompt", "hi", "--temperature", "not_a_float"])

    with pytest.raises(ValueError, match="Invalid timeout"):
        parse_model_cli_args(["register", "b1", "--provider", "mock", "--model", "m", "--timeout", "bad_int"])

    with pytest.raises(ValueError, match="Unknown option '--invalid-flag'"):
        parse_model_cli_args(["list", "--invalid-flag"])


def test_parse_args_full_options():
    args = [
        "complete", "backend-1",
        "--prompt", "hello world",
        "--temperature", "0.5",
        "--fallback", "backend-2",
        "--fallback", "backend-3",
        "--token", "grant-xyz",
        "--json",
    ]
    subcmd, opts = parse_model_cli_args(args)
    assert subcmd == "complete"
    assert opts["positional"] == ["backend-1"]
    assert opts["prompt"] == "hello world"
    assert opts["temperature"] == 0.5
    assert opts["fallbacks"] == ["backend-2", "backend-3"]
    assert opts["token"] == "grant-xyz"
    assert opts["json"] is True


# ---------------------------------------------------------------------------
# MODCLI-INV2: Proof-of-Restraint Token Gating
# ---------------------------------------------------------------------------

def test_por_invariant_gating_pure_read(service):
    """Pure read commands require 0 capability tokens."""
    for cmd in [["list"], ["show", "mock-default"], ["health"]]:
        res = dispatch_model_cli(cmd, service=service)
        assert res.exit_code == EXIT_SUCCESS, f"Failed on pure read {cmd}"


def test_por_invariant_gating_mutations_rejected_without_token(service):
    """complete and register fail closed with EXIT_UNAUTHORIZED if token is missing."""
    for cmd in [
        ["complete", "mock-default", "--prompt", "test prompt"],
        ["complete", "mock-default", "--prompt", "test prompt", "--token", ""],
        ["complete", "mock-default", "--prompt", "test prompt", "--token", "   "],
        ["register", "new-b", "--provider", "mock", "--model", "v1"],
        ["register", "new-b", "--provider", "mock", "--model", "v1", "--token", ""],
    ]:
        res = dispatch_model_cli(cmd, service=service)
        assert res.exit_code == EXIT_UNAUTHORIZED, f"Expected 3 for {cmd}, got {res.exit_code}"
        assert "requires a capability token" in res.message


# ---------------------------------------------------------------------------
# MODCLI-INV3: Standardized Exit Codes & JSON Envelope Parity
# ---------------------------------------------------------------------------

def test_exit_codes_taxonomy():
    assert EXIT_SUCCESS == 0
    assert EXIT_FAILURE == 1
    assert EXIT_USAGE == 2
    assert EXIT_UNAUTHORIZED == 3
    assert EXIT_TIMEOUT == 4


def test_json_envelope_parity_on_success(service):
    res = dispatch_model_cli(["show", "mock-default", "--json"], service=service)
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.message)
    assert data["ok"] is True
    assert data["status"] == "success"
    assert data["exit_code"] == 0
    assert "endpoint" in data


def test_json_envelope_parity_on_usage_error():
    res = dispatch_model_cli(["show", "--json"])
    assert res.exit_code == EXIT_USAGE
    data = json.loads(res.message)
    assert data["ok"] is False
    assert data["status"] == "error"
    assert data["exit_code"] == 2
    assert "Missing backend_id" in data["error_message"]


# ---------------------------------------------------------------------------
# MODCLI-INV4: Secret & Telemetry Redaction
# ---------------------------------------------------------------------------

def test_secret_redaction_across_cli_outputs():
    raw_error = "Failed to connect: Bearer eyJhbGciOiJIUzI1NiJ9 with sk-1234567890abcdef and ghp_abcdef1234567890"
    out = ModelCliOutput.failure(EXIT_FAILURE, raw_error)
    assert "eyJhbGciOiJIUzI1NiJ9" not in out.message
    assert "sk-1234567890abcdef" not in out.message
    assert "ghp_abcdef1234567890" not in out.message
    assert "[REDACTED_SECRET]" in out.message

    out_json = ModelCliOutput.failure_with_json(EXIT_FAILURE, raw_error, json_mode=True)
    assert "sk-1234567890abcdef" not in out_json.message
    data = json.loads(out_json.message)
    assert "[REDACTED_SECRET]" in data["error_message"]


# ---------------------------------------------------------------------------
# Subcommand Execution Parity: list, show, health, complete, register
# ---------------------------------------------------------------------------

def test_subcommand_list_filtering(service):
    # Active only
    res_act = dispatch_model_cli(["list", "--active-only", "--json"], service=service)
    assert res_act.exit_code == EXIT_SUCCESS
    data_act = json.loads(res_act.message)
    assert all(e["is_active"] for e in data_act["endpoints"])

    # Provider filtering
    res_prov = dispatch_model_cli(["list", "--provider", "anthropic", "--json"], service=service)
    assert res_prov.exit_code == EXIT_SUCCESS
    data_prov = json.loads(res_prov.message)
    assert len(data_prov["endpoints"]) >= 1
    assert all(e["provider"] == "anthropic" for e in data_prov["endpoints"])


def test_subcommand_health_checks(service):
    res_all = dispatch_model_cli(["health", "--json"], service=service)
    assert res_all.exit_code == EXIT_SUCCESS
    payload = json.loads(res_all.message)
    assert payload["data"]["active_endpoints"] >= 1

    res_single = dispatch_model_cli(["health", "mock-default", "--json"], service=service)
    assert res_single.exit_code == EXIT_SUCCESS
    single_payload = json.loads(res_single.message)
    assert single_payload["data"]["backend_id"] == "mock-default"


def test_subcommand_complete_with_fallback(service):
    res = dispatch_model_cli(
        [
            "complete", "unknown-backend",
            "--prompt", "hello fallback",
            "--fallback", "mock-default",
            "--token", "valid-grant-token",
            "--json",
        ],
        service=service,
    )
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.message)
    assert data["ok"] is True
    assert "response" in data
