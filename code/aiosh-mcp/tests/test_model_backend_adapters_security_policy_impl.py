"""Implementation tests for Model Backend Adapters Security Policy (T-03226)."""

import pytest
from aiosh_mcp.model_backend_adapters_security_policy import (
    ModelSecurityPolicy,
)


def test_secpol_read_action_allows_zero_token():
    policy = ModelSecurityPolicy(require_tokens=True)
    verdict = policy.evaluate("list", token=None)
    assert verdict.allowed is True
    assert verdict.audit_record["verdict"] == "allow"


def test_secpol_mutating_action_requires_token():
    policy = ModelSecurityPolicy(require_tokens=True)
    verdict_fail = policy.evaluate("complete", token=None)
    assert verdict_fail.allowed is False
    assert "Missing mandatory capability token" in verdict_fail.reason

    verdict_ok = policy.evaluate("complete", token="cap_token_123")
    assert verdict_ok.allowed is True


def test_secpol_nul_byte_rejection():
    policy = ModelSecurityPolicy()
    verdict = policy.evaluate("complete", token="valid_tok", payload="malicious" + chr(0) + "payload")
    assert verdict.allowed is False
    assert "NUL byte injection" in verdict.reason
