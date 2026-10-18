# Documentation Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03161)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03161-recovery-validation-documentation.md`
- **Updated Documentation**: `code/aiosh-mcp/README.md`
- **Specification Reference**: [SPEC-MCP-SERVER-CORE-RECOVERY](../../docs/SPEC-MCP-SERVER-CORE-RECOVERY.md)

---

## 1. Documentation Updates Summary

1. **Subsystem Architecture & Role**:
   - Documented the purpose of the Recovery & Validation Subsystem: resilience against store corruption, process termination, truncated writes, and syntax errors.
2. **Invariants & Guarantees**:
   - Outlined `MCPRECV-INV1` (accounting sum), `MCPRECV-INV2` (binary health), `MCPRECV-INV3` (non-destructive quarantine), `MCPRECV-INV4` (traversal and ADS rejection), and `MCPRECV-INV5` (PoR Invariant I-2 capability token gating).
3. **Tool Invocation Examples**:
   - Provided JSON-RPC 2.0 payloads for `aios_mcp_recovery_check` and `aios_mcp_recovery_repair`.
4. **Constraints & Known Limitations**:
   - Documented 10 MiB store file size ceiling, 1024-character path limit, and path redaction defense.
5. **Traceability**:
   - Linked all lifecycle evidence artifacts (T-03153 through T-03161).
