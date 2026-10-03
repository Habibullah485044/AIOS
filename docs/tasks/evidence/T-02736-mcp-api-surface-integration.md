# Evidence: T-02736 — Threat Model Maintenance MCP/API Surface Integration

## Task Metadata
- **Task ID**: T-02736
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Integration
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02736-mcp-api-surface-integration.md`

## Objectives
1. Integrate the Threat Model Maintenance MCP surface with the surrounding system infrastructure.
2. Confirm cross-substrate parity where the feature touches the shared SQLite `AuditRing` and canonical JSON persistence.
3. Validate that every consequential action writes an immutable trace entry to SQLite WAL storage.
4. Verify end-to-end accessibility through the production `Server::call_tool` dispatch surface.
5. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-200, CWE-400, CWE-778).

## Integration Architecture & Verification
Added `test_mcp_threat_model_integration` in `code/aiosh-rust/aiosh-mcp/src/main.rs`:
1. **End-to-End Pipeline Execution**:
   - `aios.threat.init`: Bootstraps canonical STRIDE catalog snapshot.
   - `aios.threat.register`: Registers `THREAT-INTEG-01` with CWEs and initial mitigations.
   - `aios.threat.status`: Transitions threat state to `under_review`.
   - `aios.threat.mitigate`: Attaches defense implementation and advances state to `mitigated`.
   - `aios.threat.assess`: Calculates comprehensive risk metrics.
2. **Cross-Substrate Data Integrity**:
   - Direct inspection via `ThreatModelService::load_from_path` confirmed that the MCP server writes byte-identical canonical JSON snapshots that load cleanly into core services.
   - Verified that the mitigated state and all 2 mitigations are faithfully preserved in disk storage.
3. **Cross-Substrate Audit Logging (`AuditRing`)**:
   - Executed queries against SQLite WAL storage (`audit_ring` table) verifying that each consequential MCP operation generates an immutable audit record with tool name, arguments, timestamp, actor, and cryptographic hash chain.

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: Full schema validation in MCP dispatch prevents malformed requests from contaminating the core engine.
- **CWE-22 (Path Traversal)**: Store path validation protects against traversal escapes across all integrated calls.
- **CWE-200 (Information Exposure)**: Audit records scrub secrets and prevent leakage of private keys.
- **CWE-400 (Resource Exhaustion)**: File size and entry limits remain bounded across integration calls.
- **CWE-778 (Insufficient Logging)**: Formally confirmed that all operations write directly into the SQLite `audit_ring` table.

## Verification Results
- Ran: `cargo test -p aiosh-mcp -- test_mcp_threat_model_integration`
- Result: 1 passed; 0 failed.
