//! AI Control Plane MCP Server Core Security Policy Subsystem (T-03125 scaffold / T-03126 impl).
//!
//! Defines Policy Enforcement Point (PEP) gating, policy rule models, and policy evaluation
//! engine in compliance with SPEC-MCP-SERVER-CORE-POLICY and PoR Invariant I-2.

use serde::{Deserialize, Serialize};

pub const MAX_RULES: usize = 256;
pub const MAX_RULE_ID_LEN: usize = 64;
pub const MAX_ROLE_LEN: usize = 64;
pub const MAX_PATTERN_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionCategory {
    ReadOnly,
    Diagnostics,
    StateChanging,
    Administrative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub role: String,
    pub tool_pattern: String,
    pub action_category: PolicyActionCategory,
    pub effect: PolicyEffect,
    pub priority: i32,
}

impl PolicyRule {
    pub fn new(
        rule_id: impl Into<String>,
        role: impl Into<String>,
        tool_pattern: impl Into<String>,
        action_category: PolicyActionCategory,
        effect: PolicyEffect,
        priority: i32,
    ) -> Result<Self, String> {
        let rule_id = rule_id.into();
        let role = role.into();
        let tool_pattern = tool_pattern.into();

        if rule_id.is_empty() || rule_id.len() > MAX_RULE_ID_LEN {
            return Err(format!("rule_id length must be 1..{MAX_RULE_ID_LEN}"));
        }
        if role.is_empty() || role.len() > MAX_ROLE_LEN {
            return Err(format!("role length must be 1..{MAX_ROLE_LEN}"));
        }
        if tool_pattern.is_empty() || tool_pattern.len() > MAX_PATTERN_LEN {
            return Err(format!("tool_pattern length must be 1..{MAX_PATTERN_LEN}"));
        }

        Ok(Self {
            rule_id,
            role,
            tool_pattern,
            action_category,
            effect,
            priority,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRequest {
    pub subject_role: String,
    pub tool_name: String,
    pub action_category: PolicyActionCategory,
    pub capability_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub rule_id: String,
    pub reason: String,
    pub allowed: bool,
}

#[derive(Debug, Default)]
pub struct McpServerCorePolicyEngine {
    rules: Vec<PolicyRule>,
}

impl McpServerCorePolicyEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }

    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), String> {
        if self.rules.len() >= MAX_RULES {
            return Err(format!("Maximum rules limit ({MAX_RULES}) reached"));
        }
        self.rules.push(rule);
        self.rules.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| match (a.effect, b.effect) {
                    (PolicyEffect::Deny, _) => std::cmp::Ordering::Less,
                    (_, PolicyEffect::Deny) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Equal,
                })
        });
        Ok(())
    }

    fn pattern_matches(pattern: &str, target: &str) -> bool {
        if pattern == "*" || pattern == target {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return target.starts_with(prefix);
        }
        false
    }

    pub fn evaluate(&self, request: &PolicyEvaluationRequest) -> PolicyDecision {
        for rule in &self.rules {
            let role_match = Self::pattern_matches(&rule.role, &request.subject_role);
            let tool_match = Self::pattern_matches(&rule.tool_pattern, &request.tool_name);

            if role_match && tool_match {
                match rule.effect {
                    PolicyEffect::Deny => {
                        return PolicyDecision {
                            effect: PolicyEffect::Deny,
                            rule_id: rule.rule_id.clone(),
                            reason: format!("Matched explicit DENY rule '{}'", rule.rule_id),
                            allowed: false,
                        };
                    }
                    PolicyEffect::RequireCapability => {
                        if let Some(ref token) = request.capability_token {
                            if !token.trim().is_empty() {
                                return PolicyDecision {
                                    effect: PolicyEffect::RequireCapability,
                                    rule_id: rule.rule_id.clone(),
                                    reason: format!("Matched rule '{}' with capability token redeemed", rule.rule_id),
                                    allowed: true,
                                };
                            }
                        }
                        return PolicyDecision {
                            effect: PolicyEffect::RequireCapability,
                            rule_id: rule.rule_id.clone(),
                            reason: format!("Matched rule '{}' but missing capability token", rule.rule_id),
                            allowed: false,
                        };
                    }
                    PolicyEffect::Allow => {
                        if matches!(
                            request.action_category,
                            PolicyActionCategory::StateChanging | PolicyActionCategory::Administrative
                        ) {
                            if request.capability_token.as_ref().map_or(true, |t| t.trim().is_empty()) {
                                return PolicyDecision {
                                    effect: PolicyEffect::RequireCapability,
                                    rule_id: "por:invariant-i2".to_string(),
                                    reason: "Invariant I-2: Consequential actions require capability token".to_string(),
                                    allowed: false,
                                };
                            }
                        }
                        return PolicyDecision {
                            effect: PolicyEffect::Allow,
                            rule_id: rule.rule_id.clone(),
                            reason: format!("Matched ALLOW rule '{}'", rule.rule_id),
                            allowed: true,
                        };
                    }
                }
            }
        }

        match request.action_category {
            PolicyActionCategory::ReadOnly => PolicyDecision {
                effect: PolicyEffect::Allow,
                rule_id: "default:read-only".to_string(),
                reason: "Default allow for read-only actions".to_string(),
                allowed: true,
            },
            PolicyActionCategory::Diagnostics => PolicyDecision {
                effect: PolicyEffect::Allow,
                rule_id: "default:diagnostics".to_string(),
                reason: "Default allow for diagnostic queries".to_string(),
                allowed: true,
            },
            PolicyActionCategory::StateChanging | PolicyActionCategory::Administrative => {
                if let Some(ref token) = request.capability_token {
                    if !token.trim().is_empty() {
                        return PolicyDecision {
                            effect: PolicyEffect::RequireCapability,
                            rule_id: "default:consequential-token".to_string(),
                            reason: "Default permit with valid capability token".to_string(),
                            allowed: true,
                        };
                    }
                }
                PolicyDecision {
                    effect: PolicyEffect::Deny,
                    rule_id: "default:consequential-deny".to_string(),
                    reason: "Invariant I-2: Unprivileged state changing or administrative actions denied without token".to_string(),
                    allowed: false,
                }
            }
        }
    }

    pub fn load_default_policy(&mut self) -> Result<(), String> {
        self.rules.clear();
        self.add_rule(PolicyRule::new(
            "rule:deny-anonymous-admin",
            "anonymous",
            "aios.admin.*",
            PolicyActionCategory::Administrative,
            PolicyEffect::Deny,
            400,
        )?)?;
        self.add_rule(PolicyRule::new(
            "rule:admin-require-token",
            "admin",
            "aios.admin.*",
            PolicyActionCategory::Administrative,
            PolicyEffect::RequireCapability,
            300,
        )?)?;
        self.add_rule(PolicyRule::new(
            "rule:state-changing-require-token",
            "*",
            "aios_mcp_config_set",
            PolicyActionCategory::StateChanging,
            PolicyEffect::RequireCapability,
            200,
        )?)?;
        self.add_rule(PolicyRule::new(
            "rule:diagnostics-allow",
            "*",
            "aios_mcp_test_run",
            PolicyActionCategory::Diagnostics,
            PolicyEffect::Allow,
            100,
        )?)?;
        self.add_rule(PolicyRule::new(
            "rule:read-only-allow",
            "*",
            "aios_mcp_config_get",
            PolicyActionCategory::ReadOnly,
            PolicyEffect::Allow,
            100,
        )?)?;
        Ok(())
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "rules_count": self.rules.len(),
            "rules": self.rules,
        })
    }
}
