//! Unit tests for MCP Server Core Security Policy Subsystem (T-03127).

use aiosh_core::mcp_server_core_policy::{
    PolicyActionCategory, PolicyEffect, PolicyEvaluationRequest, PolicyRule,
    McpServerCorePolicyEngine, MAX_RULES, MAX_RULE_ID_LEN,
};

#[test]
fn test_unit_rule_bounds_validation() {
    assert!(PolicyRule::new(
        "",
        "agent",
        "*",
        PolicyActionCategory::ReadOnly,
        PolicyEffect::Allow,
        100,
    )
    .is_err());

    let oversized_id = "x".repeat(MAX_RULE_ID_LEN + 1);
    assert!(PolicyRule::new(
        oversized_id,
        "agent",
        "*",
        PolicyActionCategory::ReadOnly,
        PolicyEffect::Allow,
        100,
    )
    .is_err());
}

#[test]
fn test_unit_priority_and_tie_breaking() {
    let mut engine = McpServerCorePolicyEngine::new();

    let rule_low = PolicyRule::new(
        "rule:allow-low",
        "agent:*",
        "aios.test.*",
        PolicyActionCategory::Diagnostics,
        PolicyEffect::Allow,
        100,
    )
    .unwrap();

    let rule_high = PolicyRule::new(
        "rule:deny-high",
        "agent:*",
        "aios.test.*",
        PolicyActionCategory::Diagnostics,
        PolicyEffect::Deny,
        200,
    )
    .unwrap();

    engine.add_rule(rule_low).unwrap();
    engine.add_rule(rule_high).unwrap();

    let req = PolicyEvaluationRequest {
        subject_role: "agent:qa".to_string(),
        tool_name: "aios.test.run".to_string(),
        action_category: PolicyActionCategory::Diagnostics,
        capability_token: None,
    };

    let decision = engine.evaluate(&req);
    assert!(!decision.allowed);
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.rule_id, "rule:deny-high");
}

#[test]
fn test_unit_capacity_exhaustion() {
    let mut engine = McpServerCorePolicyEngine::new();
    for i in 0..MAX_RULES {
        let rule = PolicyRule::new(
            format!("rule:{i:03}"),
            "agent",
            "tool",
            PolicyActionCategory::ReadOnly,
            PolicyEffect::Allow,
            100,
        )
        .unwrap();
        engine.add_rule(rule).unwrap();
    }
    assert_eq!(engine.rules_count(), MAX_RULES);

    let overflow = PolicyRule::new(
        "rule:overflow",
        "agent",
        "tool",
        PolicyActionCategory::ReadOnly,
        PolicyEffect::Allow,
        100,
    )
    .unwrap();
    assert!(engine.add_rule(overflow).is_err());
}

#[test]
fn test_unit_invariant_i2_enforcement() {
    let mut engine = McpServerCorePolicyEngine::new();
    engine.load_default_policy().unwrap();

    let req_no_token = PolicyEvaluationRequest {
        subject_role: "operator".to_string(),
        tool_name: "aios_mcp_config_set".to_string(),
        action_category: PolicyActionCategory::StateChanging,
        capability_token: None,
    };
    let dec_no = engine.evaluate(&req_no_token);
    assert!(!dec_no.allowed);
    assert_eq!(dec_no.effect, PolicyEffect::RequireCapability);

    let req_with_token = PolicyEvaluationRequest {
        subject_role: "operator".to_string(),
        tool_name: "aios_mcp_config_set".to_string(),
        action_category: PolicyActionCategory::StateChanging,
        capability_token: Some("token:genuine-12345".to_string()),
    };
    let dec_yes = engine.evaluate(&req_with_token);
    assert!(dec_yes.allowed);
    assert_eq!(dec_yes.effect, PolicyEffect::RequireCapability);
}
