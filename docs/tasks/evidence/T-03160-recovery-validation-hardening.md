# Hardening Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03160)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03160-recovery-validation-hardening.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-RECOVERY
- **Test Suite**: `code/aiosh-mcp/tests/test_mcp_server_core_recovery_hardening.py` (6 passed)

---

## 1. Hardening & Defenses Implemented

1. **Path Traversal & Injection Rejection**:
   - `validate_store_path` detects `".." in p.parts` and NUL bytes (`\0`), failing closed with `MCPRECV_ERR_INVALID_PATH`.
   - Length capped at `MAX_PATH_LEN = 1024` chars.
2. **Windows Reserved Device Name Immunity**:
   - Explicit check for reserved device stems (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
   - Prevents hangs or OS handle locking attacks.
3. **Alternate Data Stream (ADS) Prevention**:
   - Detects and rejects ADS colon indicators (`:`) after the drive letter, preventing hidden stream execution.
4. **Information Leakage Prevention**:
   - `sanitize_error_message` redacts absolute local path patterns (`[REDACTED_PATH]`) from user-facing error payloads.
5. **Cross-Substrate Parity**:
   - Implemented identically across Python (`aiosh_mcp.mcp_server_core_recovery`) and Rust (`aiosh_core::mcp_server_core_recovery`).
