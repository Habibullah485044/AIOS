"""Unit Tests for Model Backend Adapters Security Policy (T-03227)."""

import pytest
from aiosh_mcp.model_backend_adapters_security_policy import (
    ModelSecurityPolicy,
    MAX_PAYLOAD_BYTES,
)


def test_unit_oversized_payload_rejection():
    policy = ModelSecurityPolicy()
    oversized = "A" * (MAX_PAYLOAD_BYTES + 10)
    verdict = policy.evaluate("complete", token="tok", payload=oversized)
    assert verdict.allowed is False
    assert "Payload exceeds maximum" in verdict.reason


def test_unit_exempt_read_actions():
    policy = ModelSecurityPolicy()
    for act in ["list", "show", "health", "ping"]:
        verdict = policy.evaluate(act)
        assert verdict.allowed is True
