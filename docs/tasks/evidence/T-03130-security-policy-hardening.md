# Hardening Evidence: AI Control Plane MCP Server Core Security Policy (T-03130)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03130-security-policy-hardening.md`
- **Hardening Test**: `code/aiosh-mcp/tests/test_mcp_server_core_policy_hardening.py`

---

## 1. Hardening Defenses Applied

1. **Embedded NUL Byte Invariant**:
   - `PolicyRule`: Rejects embedded NUL bytes (`\x00`) in `rule_id`, `role`, or `tool_pattern`.
   - `PolicyEvaluationRequest`: Rejects NUL bytes in `subject_role`, `tool_name`, or `capability_token`.
2. **Payload & Length Bounds**:
   - `subject_role`: Capped at 64 characters.
   - `tool_name`: Capped at 128 characters.
   - `capability_token`: Capped at 512 characters.
   - `PolicyDecision.reason`: Truncated at 256 characters to avoid memory blowup and denial-of-service in logging systems.
3. **Fail-Closed Guarantees**:
   - All validation failures throw explicit `ValueError` caught and handled by FastMCP with `ok: false, allowed: false`.

---

## 2. Hardening Test Suite Execution

```
code/aiosh-mcp/tests/test_mcp_server_core_policy_hardening.py ... [100%]
============================== 3 passed in 3.09s ==============================
```
