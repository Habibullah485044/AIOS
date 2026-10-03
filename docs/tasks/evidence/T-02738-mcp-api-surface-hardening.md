# Evidence: T-02738 — Threat Model Maintenance MCP/API Surface Hardening

## Task Metadata
- **Task ID**: T-02738
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Hardening
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02738-mcp-api-surface-hardening.md`

## Objectives
1. Harden the MCP/API surface of Threat Model Maintenance against failure and misuse.
2. Ensure all error pathways return an explicit standard result envelope (`{"ok": false, "error": ...}`) rather than failing silently or crashing.
3. Validate size caps, bounded allocations, and memory exhaustion defenses.
4. Guarantee resource cleanup: ensure zero temp file leaks on error paths.
5. Verify ADR-0035 §F-2 compliance (fail-open or rejected actions record honest audit entries).
6. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-200, CWE-400, CWE-778).

## Hardening Controls & Implementation
1. **Explicit Error Envelopes**:
   - Validated that missing arguments, malformed syntax, or invalid transitions return standard JSON result envelopes with explicit error codes (`ERR_THREAT_INVALID_INPUT`, `ERR_THREAT_NOT_FOUND`, etc.).
2. **Bounds Enforcement**:
   - Oversized string inputs (titles, descriptions, mitigations) are rejected before memory allocation.
   - Files exceeding `MAX_THREAT_MODEL_STORE_SIZE` (1 MiB) are safely blocked by `load_safe_threat_model_service` to avoid memory exhaustion attacks.
3. **Atomic File Persistence with Guaranteed Cleanup**:
   - Atomic file writes use randomized, PID-tagged temporary staging files (`.threats.tmp.<pid>.<nanos>`).
   - In any write or rename failure, staging files are explicitly unlinked and removed, leaving zero residual artifacts.
4. **Audit Reliability**:
   - All errors pass through `dispatch::recorded_call`, writing an immutable trace into SQLite WAL `AuditRing` with `outcome: "error"`.

## Verification Results
- Test: `test_mcp_threat_model_hardening`
  - Validated standard error envelope on missing parameter.
  - Validated rejection of embedded control characters / null bytes.
  - Validated rejection of oversized payload strings.
  - Validated safe loader behavior against oversized store files (> 1 MiB).
  - Validated directory inspection showing zero leaked `.tmp` files.
- Command: `cargo test -p aiosh-mcp -- test_mcp_threat_model_hardening`
- Result: 1 passed; 0 failed.
