# Integration Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03158)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03158-recovery-validation-integration.md`
- **FastMCP Tools Integrated**: `aios_mcp_recovery_check`, `aios_mcp_recovery_repair` in `code/aiosh-mcp/aiosh_mcp/server.py`
- **Integration Test Suite**: `code/aiosh-mcp/tests/test_mcp_server_core_recovery_integration.py` (4 passed)

---

## 1. System Integration Details

1. **FastMCP Server Registration**:
   - `aios_mcp_recovery_check` registered for non-destructive, read-only health checks and state file validation.
   - `aios_mcp_recovery_repair` registered for state-changing recovery, quarantine, and canonical reinitialization.
2. **Behavior Verification**:
   - `aios_mcp_recovery_check` verifies health status, total record counts, and reports issues without mutating files.
   - `aios_mcp_recovery_repair` strictly requires a capability token (`PoR Invariant I-2`). Calls without capability tokens fail closed with unauthorized errors.
   - Corrupted state files are safely quarantined to `<path>.bak.<timestamp>` with `0600` permissions (`MCPRECV-INV3`), and reinitialized atomically.
3. **Safety & Invariants**:
   - Enforces `MCPRECV-INV1` (accounting sum invariant) and `MCPRECV-INV2` (binary health equivalence).
   - Zero side-effects for check queries; mutations strictly gated under PoR Invariant I-2.
