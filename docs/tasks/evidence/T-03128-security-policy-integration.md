# Integration Evidence: AI Control Plane MCP Server Core Security Policy (T-03128)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03128-security-policy-integration.md`
- **Integrated Surfaces**:
  - `aiosh_mcp.server`: FastMCP tools `aios_mcp_policy_evaluate` and `aios_mcp_policy_status`
  - `code/aiosh-mcp/tests/test_mcp_server_core_policy_integration.py`

---

## 1. Integration Verification

1. **Tool Registration**:
   - `aios_mcp_policy_evaluate` registered with FastMCP tool catalog.
   - `aios_mcp_policy_status` registered with FastMCP tool catalog.
2. **End-to-End Execution**:
   - Executed `aios_mcp_policy_evaluate` for read-only query -> returned `allowed: True` with `ALLOW` decision.
   - Executed `aios_mcp_policy_evaluate` for state-changing query without token -> returned `allowed: False` under PoR Invariant I-2.
   - Executed `aios_mcp_policy_status` -> returned active rule count and catalog snapshot.
3. **Audit Ring Invariant**:
   - Evaluation outputs standardized audit records with `event: "mcp.policy.evaluate"`, `subject_role`, `tool_name`, and `effect`.

---

## 2. Test Execution Output

```
code/aiosh-mcp/tests/test_mcp_server_core_policy_integration.py .... [100%]
============================== 4 passed in 4.87s ==============================
```
