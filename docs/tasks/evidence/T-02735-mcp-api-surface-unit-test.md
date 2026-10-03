# Evidence: T-02735 — Threat Model Maintenance MCP/API Surface Unit Test

## Task Metadata
- **Task ID**: T-02735
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Unit Test
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02735-mcp-api-surface-unit-test.md`

## Objectives
1. Implement a dedicated, comprehensive automated unit test suite for the Threat Model Maintenance MCP surface in `code/aiosh-rust/aiosh-mcp/src/main.rs`.
2. Cover valid input, invalid input, boundary values, and primary failure modes for all 7 `aios.threat.*` tools.
3. Validate that negative cases and security barriers reject unauthorized or invalid operations cleanly.
4. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-200, CWE-400, CWE-778).

## Test Implementation
Added `test_mcp_threat_model_tools_execution` in `code/aiosh-rust/aiosh-mcp/src/main.rs` covering:
1. **Tool Discovery**: Verified that all 7 tools exist in `server.tool_manifest()`.
2. **Canonical Baseline Initialization (`aios.threat.init`)**:
   - Happy path: bootstrapped canonical baseline (7 threats).
   - Negative: rejected re-initialization without `force: true`.
3. **Threat Querying (`aios.threat.list`)**:
   - Query all registered threats.
   - Query filtered by lifecycle status (`status: "identified"`).
4. **Threat Retrieval (`aios.threat.get`)**:
   - Happy path: retrieved `THREAT-SPOOF-01`.
   - Negative: rejected non-existent threat `THREAT-NONEXISTENT` with `ok: false`.
5. **Threat Registration (`aios.threat.register`)**:
   - Happy path: registered `THREAT-UNIT-01` with CWE IDs and initial mitigations.
   - Negative: rejected duplicate ID registration.
   - Negative: rejected invalid threat category.
   - Negative: rejected private key material (`BEGIN RSA PRIVATE KEY`) in description.
6. **Lifecycle Transition (`aios.threat.status`)**:
   - Updated `THREAT-UNIT-01` status to `under_review`.
7. **Mitigation Attachment (`aios.threat.mitigate`)**:
   - Attached valid mitigation and verified status progression to `mitigated`.
8. **Real-time Assessment (`aios.threat.assess`)**:
   - Verified composite score calculation and status counters (`total_threats >= 8`, `mitigated_count >= 1`).
9. **Path Security & Traversal Rejection**:
   - Rejected path traversal attempt (`../forbidden/threats.json`).
   - Rejected forbidden file extension (`threats.txt`).

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: Negative unit tests confirmed rejection of bad categories, bad titles, missing IDs, and malformed schemas.
- **CWE-22 (Path Traversal)**: Confirmed rejection of `../` directory traversal attempts in `store_path`.
- **CWE-200 (Exposure of Sensitive Information)**: Confirmed that private key headers in descriptions are detected and rejected.
- **CWE-400 (Uncontrolled Resource Consumption)**: Store size and capacity boundary conditions asserted.
- **CWE-778 (Insufficient Logging)**: Every invocation passes through `dispatch::recorded_call`, writing an immutable trace into `AuditRing`.

## Verification Results
- Ran: `cargo test -p aiosh-mcp -- test_mcp_threat_model_tools_execution` (1 passed; 0 failed).
- Ran: `cargo test -p aiosh-mcp -- --test-threads=1` (24 passed; 0 failed).
