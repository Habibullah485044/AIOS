"""Scaffold tests for MCP Server Core Security Policy Subsystem (T-03125)."""

import pytest
from aiosh_mcp.mcp_server_core_policy import (
    PolicyEffect,
    PolicyActionCategory,
    PolicyRule,
    PolicyEvaluationRequest,
    PolicyDecision,
    McpServerCorePolicyEngine,
    MAX_RULES,
)


def test_policy_scaffold_types():
    assert PolicyEffect.ALLOW.value == "ALLOW"
    assert PolicyEffect.DENY.value == "DENY"
    assert PolicyEffect.REQUIRE_CAPABILITY.value == "REQUIRE_CAPABILITY"

    assert PolicyActionCategory.READ_ONLY.value == "read_only"
    assert PolicyActionCategory.STATE_CHANGING.value == "state_changing"


def test_policy_scaffold_instantiation():
    engine = McpServerCorePolicyEngine()
    assert engine.rules_count == 0

    rule = PolicyRule(
        rule_id="test:rule-1",
        role="agent:*",
        tool_pattern="aios_mcp_*",
        action_category=PolicyActionCategory.READ_ONLY,
        effect=PolicyEffect.ALLOW,
    )
    engine.add_rule(rule)
    assert engine.rules_count == 1
