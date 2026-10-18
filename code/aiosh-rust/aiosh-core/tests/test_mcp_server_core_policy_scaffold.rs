//! Scaffold tests for MCP Server Core Security Policy Subsystem (T-03125).

use aiosh_core::mcp_server_core_policy::{
    PolicyActionCategory, PolicyEffect, PolicyRule, McpServerCorePolicyEngine,
};

#[test]
fn test_policy_scaffold_types() {
    assert_eq!(PolicyEffect::Allow, PolicyEffect::Allow);
    assert_ne!(PolicyEffect::Allow, PolicyEffect::Deny);
    assert_eq!(PolicyActionCategory::ReadOnly, PolicyActionCategory::ReadOnly);
}

#[test]
fn test_policy_scaffold_instantiation() {
    let mut engine = McpServerCorePolicyEngine::new();
    assert_eq!(engine.rules_count(), 0);

    let rule = PolicyRule::new(
        "test:rule-1",
        "agent:*",
        "aios_mcp_*",
        PolicyActionCategory::ReadOnly,
        PolicyEffect::Allow,
        100,
    )
    .expect("valid rule");

    engine.add_rule(rule).expect("rule added");
    assert_eq!(engine.rules_count(), 1);
}
