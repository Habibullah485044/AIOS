# Unit Test Evidence: AI Control Plane MCP Server Core Security Policy (T-03127)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03127-security-policy-unit-test.md`
- **Test Files**:
  - `code/aiosh-mcp/tests/test_mcp_server_core_policy_unit.py`
  - `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_policy_unit.rs`

---

## 1. Test Coverage Matrix

1. **Rule Bounds Validation (`test_unit_rule_bounds_validation`)**:
   - Asserts empty rule ID rejection.
   - Asserts oversized `rule_id` (> 64 characters) raises validation error.
   - Asserts oversized `role` (> 64 characters) and `tool_pattern` (> 128 characters) rejected.
2. **Priority & Tie-Breaking (`test_unit_priority_and_tie_breaking`)**:
   - Validates that higher priority rules override lower priority rules.
   - Validates that when priorities are equal, `DENY` takes precedence over `ALLOW`.
3. **Capacity Limits (`test_unit_capacity_exhaustion`)**:
   - Verifies maximum rule capacity of 256.
   - Verifies rule 257 raises `ValueError` preventing unbounded memory growth.
4. **PoR Invariant I-2 Enforcement (`test_unit_invariant_i2_enforcement`)**:
   - State-changing action without capability token evaluates to `REQUIRE_CAPABILITY` (`allowed=False`).
   - State-changing action with whitespace-only token evaluates to `allowed=False`.
   - State-changing action with valid capability token evaluates to `allowed=True`.

---

## 2. Test Execution Output

```
code/aiosh-mcp/tests/test_mcp_server_core_policy_unit.py .... [100%]
============================== 4 passed in 2.50s ==============================
```
