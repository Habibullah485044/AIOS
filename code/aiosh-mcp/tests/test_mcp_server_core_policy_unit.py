"""Focused Unit Tests for MCP Server Core Security Policy Subsystem (T-03127).

Covers:
- Valid policy evaluation across roles and actions
- Priority resolution and DENY tie-breaking
- Invariant I-2 mandatory capability token gating
- Boundary limits (MAX_RULES, length constraints)
- Negative failure modes
"""

import pytest
from aiosh_mcp.mcp_server_core_policy import (
    PolicyEffect,
    PolicyActionCategory,
    PolicyRule,
    PolicyEvaluationRequest,
    PolicyDecision,
    McpServerCorePolicyEngine,
    MAX_RULES,
    MAX_RULE_ID_LEN,
    MAX_ROLE_LEN,
    MAX_PATTERN_LEN,
)


def test_unit_rule_bounds_validation():
    # 1. Invalid empty rule_id
    with pytest.raises(ValueError, match="rule_id must be between 1 and"):
        PolicyRule(
            rule_id="",
            role="agent",
            tool_pattern="*",
            action_category=PolicyActionCategory.READ_ONLY,
            effect=PolicyEffect.ALLOW,
        )

    # 2. Oversized rule_id
    with pytest.raises(ValueError, match="rule_id must be between 1 and"):
        PolicyRule(
            rule_id="x" * (MAX_RULE_ID_LEN + 1),
            role="agent",
            tool_pattern="*",
            action_category=PolicyActionCategory.READ_ONLY,
            effect=PolicyEffect.ALLOW,
        )

    # 3. Oversized role
    with pytest.raises(ValueError, match="role must be between 1 and"):
        PolicyRule(
            rule_id="r1",
            role="r" * (MAX_ROLE_LEN + 1),
            tool_pattern="*",
            action_category=PolicyActionCategory.READ_ONLY,
            effect=PolicyEffect.ALLOW,
        )

    # 4. Oversized tool_pattern
    with pytest.raises(ValueError, match="tool_pattern must be between 1 and"):
        PolicyRule(
            rule_id="r1",
            role="agent",
            tool_pattern="p" * (MAX_PATTERN_LEN + 1),
            action_category=PolicyActionCategory.READ_ONLY,
            effect=PolicyEffect.ALLOW,
        )


def test_unit_priority_and_tie_breaking():
    engine = McpServerCorePolicyEngine()

    # Rule A: Allow with priority 100
    engine.add_rule(
        PolicyRule(
            rule_id="rule:allow-low",
            role="agent:*",
            tool_pattern="aios.test.*",
            action_category=PolicyActionCategory.DIAGNOSTICS,
            effect=PolicyEffect.ALLOW,
            priority=100,
        )
    )

    # Rule B: Deny with priority 200
    engine.add_rule(
        PolicyRule(
            rule_id="rule:deny-high",
            role="agent:*",
            tool_pattern="aios.test.*",
            action_category=PolicyActionCategory.DIAGNOSTICS,
            effect=PolicyEffect.DENY,
            priority=200,
        )
    )

    req = PolicyEvaluationRequest(
        subject_role="agent:qa",
        tool_name="aios.test.run",
        action_category=PolicyActionCategory.DIAGNOSTICS,
    )
    decision = engine.evaluate(req)
    # Higher priority (200) DENY must win
    assert decision.allowed is False
    assert decision.effect == PolicyEffect.DENY
    assert decision.rule_id == "rule:deny-high"


def test_unit_capacity_exhaustion():
    engine = McpServerCorePolicyEngine()
    for i in range(MAX_RULES):
        engine.add_rule(
            PolicyRule(
                rule_id=f"rule:{i:03d}",
                role="agent",
                tool_pattern="tool",
                action_category=PolicyActionCategory.READ_ONLY,
                effect=PolicyEffect.ALLOW,
            )
        )
    assert engine.rules_count == MAX_RULES

    # Exceeding limit raises ValueError
    with pytest.raises(ValueError, match="Maximum rules limit"):
        engine.add_rule(
            PolicyRule(
                rule_id="rule:overflow",
                role="agent",
                tool_pattern="tool",
                action_category=PolicyActionCategory.READ_ONLY,
                effect=PolicyEffect.ALLOW,
            )
        )


def test_unit_invariant_i2_enforcement():
    engine = McpServerCorePolicyEngine()
    engine.load_default_policy()

    # 1. Consequential tool without token -> denied under Invariant I-2
    req_sc = PolicyEvaluationRequest(
        subject_role="operator",
        tool_name="aios_mcp_config_set",
        action_category=PolicyActionCategory.STATE_CHANGING,
        capability_token=None,
    )
    dec_sc = engine.evaluate(req_sc)
    assert dec_sc.allowed is False
    assert dec_sc.effect == PolicyEffect.REQUIRE_CAPABILITY

    # 2. Consequential tool with whitespace token -> denied under Invariant I-2
    req_ws = PolicyEvaluationRequest(
        subject_role="operator",
        tool_name="aios_mcp_config_set",
        action_category=PolicyActionCategory.STATE_CHANGING,
        capability_token="   ",
    )
    dec_ws = engine.evaluate(req_ws)
    assert dec_ws.allowed is False

    # 3. Consequential tool with genuine token -> allowed
    req_ok = PolicyEvaluationRequest(
        subject_role="operator",
        tool_name="aios_mcp_config_set",
        action_category=PolicyActionCategory.STATE_CHANGING,
        capability_token="token:genuine-12345",
    )
    dec_ok = engine.evaluate(req_ok)
    assert dec_ok.allowed is True
    assert dec_ok.effect == PolicyEffect.REQUIRE_CAPABILITY
