# Security Review & Proof-of-Restraint Evidence: MCP Server Core Security Policy (T-03129)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Target**: Security review, threat modeling, abuse scenarios, and PoR Invariant I-2 compliance
- **Bindings**: SPEC-MCP-SERVER-CORE-POLICY, ADR-0035 §D-2, ADR-0035 §F-2, PoR Invariant I-2

---

## 1. Threat Model & Abuse Scenario Matrix

| Scenario ID | Attack Vector / Abuse Pattern | Target Layer | Mitigation / Enforcement Mechanism | Status |
|:---|:---|:---|:---|:---|
| **AS-POL-1** | Privilege Escalation via Role Spoofing | PEP Evaluation Engine | Invariant I-2 enforcement: role matching alone is insufficient. Consequential tools strictly require valid capability tokens regardless of asserted role. | **MITIGATED** |
| **AS-POL-2** | Wildcard / Pattern Confusion Injection | Tool Pattern Matcher | Tool names and role strings bounded to 64/128 characters; NUL bytes and control characters rejected; default-deny on non-matching patterns. | **MITIGATED** |
| **AS-POL-3** | Capability Token Gating Bypass via Whitespace | Token Validation Filter | Whitespace-only or empty capability tokens stripped and rejected; strictly evaluates to `REQUIRE_CAPABILITY` with `allowed=False`. | **MITIGATED** |
| **AS-POL-4** | Denial of Service via Rule Flooding | Policy Rule Catalog | Hard bounds enforced: `MAX_RULES = 256`, `MAX_RULE_ID_LEN = 64`. Rule additions beyond limit raise explicit `ValueError`. | **MITIGATED** |
| **AS-POL-5** | Audit Evasion on Policy Denial | Audit Ring Integration | Every policy evaluation produces a structured audit dictionary (`mcp.policy.evaluate`) recording subject role, tool, effect, and decision reason. | **MITIGATED** |

---

## 2. Proof-of-Restraint Verification (Invariant I-2)

- **Standing Rule Check**: Confirmed that the security policy subsystem enforces Invariant I-2 (`Zero Escalation`) across all tool invocations:
  - `STATE_CHANGING` and `ADMINISTRATIVE` actions evaluate to `allowed = False` unless a non-empty, valid capability token is present.
  - Anonymous callers attempting to execute administrative tools (`aios.admin.*`) match explicit `DENY` rules (Priority 400).
- **Invariant I-2 Status**: Verified. No security policy bypasses remain open.
