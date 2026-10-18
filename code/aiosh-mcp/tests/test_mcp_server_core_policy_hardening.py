"""Hardening tests for MCP Server Core Security Policy Subsystem (T-03130)."""

import pytest
from aiosh_mcp.mcp_server_core_policy import (
    PolicyActionCategory,
    PolicyDecision,
    PolicyEffect,
    PolicyEvaluationRequest,
    PolicyRule,
    McpServerCorePolicyEngine,
)


def test_hardening_nul_bytes_rejection_in_rule():
    with pytest.raises(ValueError, match="cannot contain NUL bytes"):
        PolicyRule(
            rule_id="rule\x00malicious",
            role="agent",
            tool_pattern="*",
            action_category=PolicyActionCategory.READ_ONLY,
            effect=PolicyEffect.ALLOW,
        )


def test_hardening_nul_bytes_rejection_in_request():
    with pytest.raises(ValueError, match="cannot contain NUL bytes"):
        PolicyEvaluationRequest(
            subject_role="agent\x00bad",
            tool_name="aios_mcp_config_get",
            action_category=PolicyActionCategory.READ_ONLY,
        )

    with pytest.raises(ValueError, match="cannot contain NUL bytes"):
        PolicyEvaluationRequest(
            subject_role="agent",
            tool_name="aios_mcp_config_get\x00injection",
            action_category=PolicyActionCategory.READ_ONLY,
        )

    with pytest.raises(ValueError, match="cannot contain NUL bytes"):
        PolicyEvaluationRequest(
            subject_role="agent",
            tool_name="aios_mcp_config_get",
            action_category=PolicyActionCategory.READ_ONLY,
            capability_token="token\x00bad",
        )


def test_hardening_reason_truncation():
    long_reason = "E" * 500
    decision = PolicyDecision(
        effect=PolicyEffect.DENY,
        rule_id="rule:test",
        reason=long_reason,
        allowed=False,
    )
    assert len(decision.reason) == 256
    assert decision.reason == "E" * 256
