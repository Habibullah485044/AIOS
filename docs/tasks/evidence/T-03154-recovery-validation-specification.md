# Specification Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03154)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03154-recovery-validation-specification.md`
- **Specification Document**: [docs/SPEC-MCP-SERVER-CORE-RECOVERY.md](../../SPEC-MCP-SERVER-CORE-RECOVERY.md)

---

## 1. Specification Summary

1. **Contracts Defined**:
   - `McpValidationIssue`: Structured severity, issue code, and message envelope.
   - `McpValidationReport`: Comprehensive audit report enforcing invariant accounting.
   - `McpRecoveryResult`: Atomic quarantine outcome with backup path tracking.
2. **Invariants Specified**:
   - `MCPRECV-INV1`: Sum invariant (`total == valid + invalid`).
   - `MCPRECV-INV2`: Binary health equivalence (`healthy iff issues empty and invalid == 0`).
   - `MCPRECV-INV3`: Non-destructive quarantine (`.bak.<timestamp>` with `0600` permissions).
   - `MCPRECV-INV4`: Path traversal and NUL byte rejection.
   - `MCPRECV-INV5`: PoR Invariant I-2 gating (pure check queries vs. token-gated repairs).
3. **Tool Surface**:
   - Read-only diagnostics via `aios_mcp_recovery_check`.
   - Token-gated recovery via `aios_mcp_recovery_repair`.
