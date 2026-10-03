# Evidence: T-02733 — Threat Model Maintenance MCP/API Surface Scaffold

## Task Metadata
- **Task ID**: T-02733
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Scaffold
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02733-mcp-api-surface-scaffold.md`

## Objectives
1. Implement the tool manifest registration for the 7 `aios.threat.*` tools in `code/aiosh-rust/aiosh-mcp/src/main.rs`.
2. Implement typed scaffold dispatch branches in `call_tool()` routing calls through `dispatch::recorded_call` to enforce PEP evaluation and `AuditRing` recording.
3. Validate compilation with `cargo check -p aiosh-mcp`.
4. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-200, CWE-400, CWE-778).

## Changes Made
- In `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - Registered 7 tools in `tool_manifest()`:
    - `aios.threat.list`
    - `aios.threat.get`
    - `aios.threat.register`
    - `aios.threat.status`
    - `aios.threat.mitigate`
    - `aios.threat.assess`
    - `aios.threat.init`
  - Added schema descriptions and typed input parameters according to `SPEC-THREAT-MODEL-MCP.md`.
  - Added scaffold branches in `call_tool()` returning structured responses or informative stubs while routing through `dispatch::recorded_call`.

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: All input schemas specify expected string properties (`store_path`, `id`, `name`, `stride_category`, `description`, etc.) with default or strict typing.
- **CWE-22 (Path Traversal)**: Store paths will be routed through `ThreatModelService::validate_path` in T-02734 to block directory traversal (`..`, UNC, root slashes).
- **CWE-200 (Exposure of Sensitive Information)**: Private key pattern matching and secret redaction hooks prepared.
- **CWE-400 (Uncontrolled Resource Consumption)**: Store size capped at 1 MiB, entry count capped at 512 entries.
- **CWE-778 (Insufficient Logging)**: Every invocation passes through `dispatch::recorded_call` producing an entry in `AuditRing`.

## Verification & Compilation
- Ran: `cargo check -p aiosh-mcp`
- Output: Finished `dev` profile with 0 errors and 0 warnings.
