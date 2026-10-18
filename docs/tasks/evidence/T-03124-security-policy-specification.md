# Specification Evidence: AI Control Plane MCP Server Core Security Policy (T-03124)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03124-security-policy-specification.md`
- **Spec Document**: `docs/SPEC-MCP-SERVER-CORE-POLICY.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §F-2, PoR Invariant I-2

---

## 1. Executive Summary

This specification establishes the authoritative schema, evaluation contract, and security invariants for `McpServerCorePolicyEngine`.

## 2. API Contract & Data Types

### 2.1 Enums & Types
```python
class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_CAPABILITY = "REQUIRE_CAPABILITY"

class PolicyActionCategory(str, Enum):
    READ_ONLY = "read_only"
    DIAGNOSTICS = "diagnostics"
    STATE_CHANGING = "state_changing"
    ADMINISTRATIVE = "administrative"
```

### 2.2 Policy Rule Schema
```python
@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    role: str
    tool_pattern: str
    action_category: PolicyActionCategory
    effect: PolicyEffect
    priority: int = 100
```

### 2.3 Evaluation Request & Decision
```python
@dataclass(frozen=True)
class PolicyEvaluationRequest:
    subject_role: str
    tool_name: str
    action_category: PolicyActionCategory
    capability_token: Optional[str] = None

@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    rule_id: str
    reason: str
    allowed: bool
```

## 3. Invariant I-2 Proof-of-Restraint Verification
All `state_changing` and `administrative` actions evaluate to `allowed = False` unless a valid capability token is supplied and verified.
Fail-closed error handling guarantees zero escalation.
