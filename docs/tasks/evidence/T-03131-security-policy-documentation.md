# Documentation Evidence: AI Control Plane MCP Server Core Security Policy (T-03131)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03131-security-policy-documentation.md`
- **Updated Documentation**: [code/aiosh-mcp/README.md](../../code/aiosh-mcp/README.md)

---

## 1. Documentation Updates Summary

1. **Architecture & Role**:
   - Documented the role of MCP Server Core Security Policy Subsystem as a Policy Enforcement Point (PEP) governing all tool calls.
   - Clarified strict enforcement of Proof-of-Restraint Invariant I-2 (`Zero Escalation`).
2. **Tool References & Working Examples**:
   - `aios_mcp_policy_evaluate`: Provided JSON-RPC 2.0 payloads for read-only actions and state-changing actions requiring capability tokens.
   - `aios_mcp_policy_status`: Provided query example for inspecting active engine rules.
3. **Constraints & Known Limitations**:
   - State-changing and administrative tools strictly evaluate to `allowed = false` when capability tokens are missing or blank.
   - Total rules bounded to 256.
   - Embedded NUL bytes rejected fail-closed.
   - Decision reason strings truncated to 256 characters.
4. **Lifecycle & Traceability Links**:
   - Linked specification (`SPEC-MCP-SERVER-CORE-POLICY`) and all task evidence files (`T-03123` through `T-03131`).
