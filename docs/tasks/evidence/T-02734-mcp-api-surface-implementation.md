# Evidence: T-02734 — Threat Model Maintenance MCP/API Surface Implementation

## Task Metadata
- **Task ID**: T-02734
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Implementation
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02734-mcp-api-surface-implementation.md`

## Objectives
1. Implement full functional behavior for the 7 `aios.threat.*` MCP tools in `code/aiosh-rust/aiosh-mcp/src/main.rs`.
2. Integrate `ThreatModelService` from `aiosh-core` for catalog persistence, validation, status transitions, mitigation binding, and risk scoring.
3. Validate through PEP recorded dispatch ensuring each action creates a verifiable audit record in `AuditRing`.
4. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-200, CWE-400, CWE-778).

## Changes Made
- In `code/aiosh-rust/aiosh-mcp/src/main.rs`:
  - Added helpers: `get_threat_model_store_path()` and `load_safe_threat_model_service()`.
  - Implemented `aios.threat.list`: supports filtering by `status`, `severity`, and `category`.
  - Implemented `aios.threat.get`: retrieves threat entry by ID with not-found error handling.
  - Implemented `aios.threat.register`: parses category and severity enums, builds validated `ThreatEntry`, registers into catalog, and atomically persists.
  - Implemented `aios.threat.status`: validates state transition according to threat status state machine and persists.
  - Implemented `aios.threat.mitigate`: attaches mitigation string, transitions status to `mitigated`, and persists.
  - Implemented `aios.threat.assess`: computes real-time threat risk assessment metrics and score.
  - Implemented `aios.threat.init`: bootstraps canonical STRIDE baseline threats with `force` overwrite protection.

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: Every parameter is validated through data model constructors (`validate_id`, `validate_title`, `validate_description`) and enum parsers (`parse_status`, `parse_severity`, `parse_category`).
- **CWE-22 (Path Traversal)**: Store paths are strictly validated through `ThreatModelService::validate_path` rejecting `..`, UNC paths, control characters, and requiring a `.json` extension.
- **CWE-200 (Information Exposure)**: Descriptions and mitigations reject private key headers (`BEGIN PRIVATE KEY` / `BEGIN RSA PRIVATE KEY`).
- **CWE-400 (Resource Exhaustion)**: File size hard limit enforced at 1 MiB (`MAX_THREAT_MODEL_STORE_SIZE`), catalog capacity capped at 512 entries (`MAX_THREAT_ENTRIES_CAPACITY`).
- **CWE-778 (Insufficient Logging)**: All operations execute through `dispatch::recorded_call`, recording immutable audit events in SQLite WAL ring buffer.

## Verification
- Ran: `cargo test -p aiosh-mcp -- --test-threads=1`
- Result: 23 passed; 0 failed.
