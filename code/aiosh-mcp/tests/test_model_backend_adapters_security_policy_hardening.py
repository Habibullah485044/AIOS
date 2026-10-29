"""Hardening tests for Model Backend Adapters Security Policy (T-03230)."""

import pytest
from aiosh_mcp.model_backend_adapters_security_policy import (
    ModelSecurityPolicy,
    PolicyVerdict,
    MAX_PAYLOAD_BYTES,
    MAX_TOKEN_LEN,
    MAX_ACTION_LEN,
)


def test_hardening_token_bounds_and_nul_bytes():
    policy = ModelSecurityPolicy()

    # NUL byte in capability token
    v = policy.evaluate("complete", token="grant\0malicious", payload="hello")
    assert not v.allowed
    assert "NUL byte injection detected in capability token" in v.reason
    assert v.audit_record["verdict"] == "refuse"

    # Oversized token
    long_token = "g" * (MAX_TOKEN_LEN + 1)
    v = policy.evaluate("complete", token=long_token, payload="hello")
    assert not v.allowed
    assert "exceeds maximum allowed size" in v.reason


def test_hardening_action_bounds_and_nul_bytes():
    policy = ModelSecurityPolicy()

    # NUL byte in action
    v = policy.evaluate("comp\0lete", token="valid_token")
    assert not v.allowed
    assert "NUL byte in action name" in v.reason

    # Oversized action
    long_action = "a" * (MAX_ACTION_LEN + 1)
    v = policy.evaluate(long_action, token="valid_token")
    assert not v.allowed
    assert "Action name must be 1.." in v.reason


def test_hardening_envelope_and_fail_closed():
    policy = ModelSecurityPolicy()

    # Allowed verdict envelope
    v_allow = policy.evaluate("list")
    env = v_allow.to_envelope()
    assert env["status"] == "success"
    assert env["ok"] is True
    assert "timestamp" in env

    # Rejected verdict envelope
    v_reject = policy.evaluate("complete", token="")
    env_rej = v_reject.to_envelope()
    assert env_rej["status"] == "rejected"
    assert env_rej["ok"] is False
    assert "POLICY_UNAUTHORIZED" in env_rej["reason"]
    assert env_rej["audit"]["verdict"] == "refuse"


def test_hardening_payload_bounds():
    policy = ModelSecurityPolicy()

    # 1 MiB boundary
    oversized = "x" * (MAX_PAYLOAD_BYTES + 10)
    v = policy.evaluate("list", payload=oversized)
    assert not v.allowed
    assert "Payload exceeds maximum allowed size" in v.reason
