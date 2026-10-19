"""Hardening tests for Model Backend Adapters CLI surface (T-03190).

Validates defenses against:
  - Positional identifier traversal and length overflows (> 64 chars, '..', '/', '\\')
  - Out-of-bounds temperature values (< 0.0 or > 2.0)
  - Excessive fallback depth (> 5 endpoints)
  - Out-of-bounds timeout values (< 1000 or > 300000 ms)
  - Invariant I-2 fail-closed gating under adversarial inputs
"""

import json
import pytest

from aiosh_mcp.model_backend_adapters_cli import (
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_USAGE,
    EXIT_UNAUTHORIZED,
    EXIT_TIMEOUT,
    dispatch_model_cli,
    parse_model_cli_args,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def service():
    return ModelBackendService()


def test_hardening_temperature_bounds():
    # Negative temperature
    with pytest.raises(ValueError, match="must be within"):
        parse_model_cli_args(["complete", "mock-default", "--prompt", "hi", "--temperature", "-0.1"])

    # Overly high temperature
    with pytest.raises(ValueError, match="must be within"):
        parse_model_cli_args(["complete", "mock-default", "--prompt", "hi", "--temperature", "2.1"])

    # Valid boundaries
    _, opts0 = parse_model_cli_args(["complete", "mock-default", "--prompt", "hi", "--temperature", "0.0"])
    assert opts0["temperature"] == 0.0

    _, opts2 = parse_model_cli_args(["complete", "mock-default", "--prompt", "hi", "--temperature", "2.0"])
    assert opts2["temperature"] == 2.0


def test_hardening_positional_identifier_defenses():
    # Length overflow (> 64 chars)
    long_id = "a" * 65
    with pytest.raises(ValueError, match="exceeds max length"):
        parse_model_cli_args(["show", long_id])

    # Traversal patterns
    for bad_id in ["../secret", "dir/target", "dir\\target", ".."]:
        with pytest.raises(ValueError, match="Path traversal characters forbidden"):
            parse_model_cli_args(["show", bad_id])


def test_hardening_fallback_depth_ceiling():
    # Exceeding max fallback depth of 5
    args = [
        "complete", "primary-b", "--prompt", "test", "--token", "tok",
        "--fallback", "f1",
        "--fallback", "f2",
        "--fallback", "f3",
        "--fallback", "f4",
        "--fallback", "f5",
        "--fallback", "f6",
    ]
    with pytest.raises(ValueError, match="Fallback list exceeds max depth"):
        parse_model_cli_args(args)


def test_hardening_timeout_clamping():
    # Too small (< 1000 ms)
    with pytest.raises(ValueError, match="out of bounds"):
        parse_model_cli_args(["register", "b1", "--provider", "mock", "--model", "m", "--timeout", "999"])

    # Too large (> 300000 ms)
    with pytest.raises(ValueError, match="out of bounds"):
        parse_model_cli_args(["register", "b1", "--provider", "mock", "--model", "m", "--timeout", "300001"])


def test_hardening_dispatch_defense_integration(service):
    # Attempt traversal in dispatch returns EXIT_USAGE in JSON mode
    res = dispatch_model_cli(["show", "../../etc/passwd", "--json"], service=service)
    assert res.exit_code == EXIT_USAGE
    data = json.loads(res.message)
    assert data["ok"] is False
    assert "Path traversal" in data["error_message"]
