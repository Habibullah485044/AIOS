"""Implementation tests for MCP Server Core Security Policy Subsystem (T-03126)."""

import pytest
from aiosh_mcp.mcp_server_core_policy import (
    PolicyEffect,
    PolicyActionCategory,
    PolicyRule,
    PolicyEvaluationRequest,
    PolicyDecision,
    McpServerCorePolicyEngine,
)


def test_default_policy_evaluation():
    engine = McpServerCorePolicyEngine()
    engine.load_default_policy()
    assert engine.rules_count == 5

    # 1. Read-only allowed without token
    req_ro = PolicyEvaluationRequest(
        subject_role="agent:reader",
        tool_name="aios_mcp_config_get",
        action_category=PolicyActionCategory.READ_ONLY,
    )
    dec_ro = engine.evaluate(req_ro)
    assert dec_ro.allowed is True
    assert dec_ro.effect == PolicyEffect.ALLOW

    # 2. State-changing requires token (denied when missing)
    req_sc_no_token = PolicyEvaluationRequest(
        subject_role="agent:writer",
        tool_name="aios_mcp_config_set",
        action_category=PolicyActionCategory.STATE_CHANGING,
    )
    dec_sc_no = engine.evaluate(req_sc_no_token)
    assert dec_sc_no.allowed is False
    assert dec_sc_no.effect == PolicyEffect.REQUIRE_CAPABILITY

    # 3. State-changing with token is permitted
    req_sc_token = PolicyEvaluationRequest(
        subject_role="agent:writer",
        tool_name="aios_mcp_config_set",
        action_category=PolicyActionCategory.STATE_CHANGING,
        capability_token="cap:valid-token-123",
    )
    dec_sc_yes = engine.evaluate(req_sc_token)
    assert dec_sc_yes.allowed is True
    assert dec_sc_yes.effect == PolicyEffect.REQUIRE_CAPABILITY

    # 4. Anonymous calling admin is explicitly DENIED
    req_anon_admin = PolicyEvaluationRequest(
        subject_role="anonymous",
        tool_name="aios.admin.shutdown",
        action_category=PolicyActionCategory.ADMINISTRATIVE,
        capability_token="cap:attempted-bypass",
    )
    dec_anon_admin = engine.evaluate(req_anon_admin)
    assert dec_anon_admin.allowed is False
    assert dec_anon_admin.effect == PolicyEffect.DENY
