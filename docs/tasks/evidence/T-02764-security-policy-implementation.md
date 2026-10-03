# Implementation Evidence: Threat Model Security Policy (T-02764)

## Overview
Implements security policy evaluation and declarative rule enforcement for Threat Model Maintenance in `ThreatModelService` and `ThreatModelSecurityPolicy`.

## Implementation Details
1. **`ThreatModelService` Policy Integration**:
   - Added optional `policy: Option<ThreatModelSecurityPolicy>` field to `ThreatModelService`.
   - Added `with_policy(policy)` builder method.
   - Wired policy evaluation checks into mutating operations:
     - `register_threat`: Evaluates `pol.evaluate_registration(&entry)`. If verdict is `Deny`, fails closed with the structured error code and reason.
     - `update_status`: Evaluates `pol.evaluate_transition(entry, new_status)`. If verdict is `Deny`, fails closed.
     - `attach_mitigation`: Evaluates `pol.evaluate_mitigation(entry, mitigation)`. If verdict is `Deny`, fails closed.
2. **Evaluations Supported**:
   - `THREATPOL_ERR_CATEGORY_PROHIBITED`: Blocks registration of threats matching prohibited categories.
   - `THREATPOL_ERR_CWE_REQUIRED`: Enforces that threat registrations supply at least one CWE mapping.
   - `THREATPOL_ERR_CRITICAL_UNMITIGATED`: Blocks transitioning critical threats to `Accepted` or `Resolved` without mitigations.
   - `THREATPOL_ERR_CAPACITY_EXCEEDED`: Validates total catalog threats and critical unmitigated density.
3. **Regression Safety**:
   - Baseline regression suites pass cleanly (`test_threat_model_service`).
