"""AI Control Plane MCP Server Core Security Policy Subsystem (T-03125 scaffold / T-03126 impl).

Defines Policy Enforcement Point (PEP) gating, policy rule models, and policy evaluation
engine in compliance with SPEC-MCP-SERVER-CORE-POLICY and PoR Invariant I-2.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

MAX_RULES: int = 256
MAX_RULE_ID_LEN: int = 64
MAX_ROLE_LEN: int = 64
MAX_PATTERN_LEN: int = 128


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_CAPABILITY = "REQUIRE_CAPABILITY"


class PolicyActionCategory(str, Enum):
    READ_ONLY = "read_only"
    DIAGNOSTICS = "diagnostics"
    STATE_CHANGING = "state_changing"
    ADMINISTRATIVE = "administrative"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    role: str
    tool_pattern: str
    action_category: PolicyActionCategory
    effect: PolicyEffect
    priority: int = 100

    def __post_init__(self) -> None:
        if "\x00" in self.rule_id or "\x00" in self.role or "\x00" in self.tool_pattern:
            raise ValueError("PolicyRule fields cannot contain NUL bytes")
        if not self.rule_id or len(self.rule_id) > MAX_RULE_ID_LEN:
            raise ValueError(f"rule_id must be between 1 and {MAX_RULE_ID_LEN} characters")
        if not self.role or len(self.role) > MAX_ROLE_LEN:
            raise ValueError(f"role must be between 1 and {MAX_ROLE_LEN} characters")
        if not self.tool_pattern or len(self.tool_pattern) > MAX_PATTERN_LEN:
            raise ValueError(f"tool_pattern must be between 1 and {MAX_PATTERN_LEN} characters")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "role": self.role,
            "tool_pattern": self.tool_pattern,
            "action_category": self.action_category.value,
            "effect": self.effect.value,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class PolicyEvaluationRequest:
    subject_role: str
    tool_name: str
    action_category: PolicyActionCategory
    capability_token: Optional[str] = None

    def __post_init__(self) -> None:
        if "\x00" in self.subject_role or "\x00" in self.tool_name:
            raise ValueError("Evaluation request cannot contain NUL bytes")
        if len(self.subject_role) > MAX_ROLE_LEN:
            raise ValueError(f"subject_role exceeds {MAX_ROLE_LEN} characters")
        if len(self.tool_name) > MAX_PATTERN_LEN:
            raise ValueError(f"tool_name exceeds {MAX_PATTERN_LEN} characters")
        if self.capability_token is not None:
            if "\x00" in self.capability_token:
                raise ValueError("capability_token cannot contain NUL bytes")
            if len(self.capability_token) > 512:
                raise ValueError("capability_token exceeds 512 characters")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_role": self.subject_role,
            "tool_name": self.tool_name,
            "action_category": self.action_category.value,
            "capability_token": self.capability_token,
        }


@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    rule_id: str
    reason: str
    allowed: bool

    def __post_init__(self) -> None:
        # Hardening: truncate long error/reason messages to 256 characters
        if len(self.reason) > 256:
            object.__setattr__(self, "reason", self.reason[:256])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "effect": self.effect.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "allowed": self.allowed,
        }


class McpServerCorePolicyEngine:
    """Evaluates security policies for MCP Server Core tool invocations."""

    def __init__(self) -> None:
        self._rules: List[PolicyRule] = []

    @property
    def rules_count(self) -> int:
        return len(self._rules)

    def add_rule(self, rule: PolicyRule) -> None:
        if len(self._rules) >= MAX_RULES:
            raise ValueError(f"Maximum rules limit ({MAX_RULES}) reached")
        self._rules.append(rule)
        # Sort descending by priority, then DENY over ALLOW for tie-breaking
        self._rules.sort(
            key=lambda r: (r.priority, 1 if r.effect == PolicyEffect.DENY else 0),
            reverse=True,
        )

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Evaluates policy rules against an incoming request under Invariant I-2."""
        # Find matching rules
        for rule in self._rules:
            role_match = (rule.role == "*") or (rule.role == request.subject_role) or fnmatch.fnmatch(request.subject_role, rule.role)
            tool_match = (rule.tool_pattern == "*") or (rule.tool_pattern == request.tool_name) or fnmatch.fnmatch(request.tool_name, rule.tool_pattern)

            if role_match and tool_match:
                if rule.effect == PolicyEffect.DENY:
                    return PolicyDecision(
                        effect=PolicyEffect.DENY,
                        rule_id=rule.rule_id,
                        reason=f"Matched explicit DENY rule '{rule.rule_id}'",
                        allowed=False,
                    )
                if rule.effect == PolicyEffect.REQUIRE_CAPABILITY:
                    if request.capability_token and request.capability_token.strip():
                        return PolicyDecision(
                            effect=PolicyEffect.REQUIRE_CAPABILITY,
                            rule_id=rule.rule_id,
                            reason=f"Matched rule '{rule.rule_id}' with capability token redeemed",
                            allowed=True,
                        )
                    return PolicyDecision(
                        effect=PolicyEffect.REQUIRE_CAPABILITY,
                        rule_id=rule.rule_id,
                        reason=f"Matched rule '{rule.rule_id}' but missing capability token",
                        allowed=False,
                    )
                if rule.effect == PolicyEffect.ALLOW:
                    # PoR Invariant I-2 enforcement: state_changing or administrative requires capability token regardless of allow rule
                    if request.action_category in (PolicyActionCategory.STATE_CHANGING, PolicyActionCategory.ADMINISTRATIVE):
                        if not request.capability_token or not request.capability_token.strip():
                            return PolicyDecision(
                                effect=PolicyEffect.REQUIRE_CAPABILITY,
                                rule_id="por:invariant-i2",
                                reason="Invariant I-2: Consequential actions require capability token",
                                allowed=False,
                            )
                    return PolicyDecision(
                        effect=PolicyEffect.ALLOW,
                        rule_id=rule.rule_id,
                        reason=f"Matched ALLOW rule '{rule.rule_id}'",
                        allowed=True,
                    )

        # Default fallbacks
        if request.action_category == PolicyActionCategory.READ_ONLY:
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                rule_id="default:read-only",
                reason="Default allow for read-only actions",
                allowed=True,
            )
        if request.action_category == PolicyActionCategory.DIAGNOSTICS:
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                rule_id="default:diagnostics",
                reason="Default allow for diagnostic queries",
                allowed=True,
            )
        if request.action_category in (PolicyActionCategory.STATE_CHANGING, PolicyActionCategory.ADMINISTRATIVE):
            if request.capability_token and request.capability_token.strip():
                return PolicyDecision(
                    effect=PolicyEffect.REQUIRE_CAPABILITY,
                    rule_id="default:consequential-token",
                    reason="Default permit with valid capability token",
                    allowed=True,
                )
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                rule_id="default:consequential-deny",
                reason="Invariant I-2: Unprivileged state changing or administrative actions denied without token",
                allowed=False,
            )

    def load_default_policy(self) -> None:
        """Populates baseline declarative rules adhering to Invariant I-2."""
        self._rules.clear()
        # Rule 5: Explicit deny of admin tools for anonymous
        self.add_rule(
            PolicyRule(
                rule_id="rule:deny-anonymous-admin",
                role="anonymous",
                tool_pattern="aios.admin.*",
                action_category=PolicyActionCategory.ADMINISTRATIVE,
                effect=PolicyEffect.DENY,
                priority=400,
            )
        )
        # Rule 4: Admin tools require capability token for admin role
        self.add_rule(
            PolicyRule(
                rule_id="rule:admin-require-token",
                role="admin",
                tool_pattern="aios.admin.*",
                action_category=PolicyActionCategory.ADMINISTRATIVE,
                effect=PolicyEffect.REQUIRE_CAPABILITY,
                priority=300,
            )
        )
        # Rule 3: State changing tools require capability token
        self.add_rule(
            PolicyRule(
                rule_id="rule:state-changing-require-token",
                role="*",
                tool_pattern="aios_mcp_config_set",
                action_category=PolicyActionCategory.STATE_CHANGING,
                effect=PolicyEffect.REQUIRE_CAPABILITY,
                priority=200,
            )
        )
        # Rule 2: Diagnostic tools permitted for agents
        self.add_rule(
            PolicyRule(
                rule_id="rule:diagnostics-allow",
                role="*",
                tool_pattern="aios_mcp_test_run",
                action_category=PolicyActionCategory.DIAGNOSTICS,
                effect=PolicyEffect.ALLOW,
                priority=100,
            )
        )
        # Rule 1: Read-only tools permitted
        self.add_rule(
            PolicyRule(
                rule_id="rule:read-only-allow",
                role="*",
                tool_pattern="aios_mcp_config_get",
                action_category=PolicyActionCategory.READ_ONLY,
                effect=PolicyEffect.ALLOW,
                priority=100,
            )
        )

    def create_audit_entry(self, request: PolicyEvaluationRequest, decision: PolicyDecision) -> Dict[str, Any]:
        """Creates an audit ring payload capturing the policy evaluation event."""
        return {
            "event": "mcp.policy.evaluate",
            "subject_role": request.subject_role,
            "tool_name": request.tool_name,
            "action_category": request.action_category.value,
            "effect": decision.effect.value,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "allowed": decision.allowed,
            "has_token": bool(request.capability_token and request.capability_token.strip()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rules_count": len(self._rules),
            "rules": [r.to_dict() for r in self._rules],
        }


_GLOBAL_POLICY_ENGINE = McpServerCorePolicyEngine()
_GLOBAL_POLICY_ENGINE.load_default_policy()


def register_mcp_policy_tools(mcp_app: Any) -> None:
    """Register MCP Server Core Security Policy tools with FastMCP (T-03128)."""
    @mcp_app.tool()
    def aios_mcp_policy_evaluate(
        subject_role: str,
        tool_name: str,
        action_category: str = "read_only",
        capability_token: str = "",
    ) -> dict:
        """Evaluate security policy for an MCP tool invocation under Invariant I-2."""
        try:
            category_enum = PolicyActionCategory(action_category.lower())
            request = PolicyEvaluationRequest(
                subject_role=subject_role,
                tool_name=tool_name,
                action_category=category_enum,
                capability_token=capability_token if capability_token else None,
            )
            decision = _GLOBAL_POLICY_ENGINE.evaluate(request)
            audit = _GLOBAL_POLICY_ENGINE.create_audit_entry(request, decision)
            return {
                "ok": True,
                "allowed": decision.allowed,
                "decision": decision.to_dict(),
                "audit": audit,
            }
        except Exception as exc:
            return {"ok": False, "allowed": False, "error": str(exc)}

    @mcp_app.tool()
    def aios_mcp_policy_status() -> dict:
        """Return status and active rules in MCP Server Core Policy Engine."""
        try:
            return {
                "ok": True,
                "status": _GLOBAL_POLICY_ENGINE.to_dict(),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


