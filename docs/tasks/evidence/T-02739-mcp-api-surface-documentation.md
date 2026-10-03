# Evidence: T-02739 — Threat Model Maintenance MCP/API Surface Documentation

## Task Metadata
- **Task ID**: T-02739
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Documentation
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02739-mcp-api-surface-documentation.md`

## Objectives
1. Document the MCP/API surface of Threat Model Maintenance for operators, multi-agent frameworks, and autonomous tooling.
2. Update `docs/SPEC-THREAT-MODEL-MCP.md` to `IMPLEMENTED & VERIFIED`.
3. Provide copy-pasteable JSON-RPC examples for all major operations (`init`, `register`, `mitigate`, `assess`).
4. Record all operational constraints, capacity limits, and known boundaries honestly.
5. Link task evidence files across the sub-epic lifecycle.
6. Conduct CWE security review of documentation clarity and safety guidelines.

## Shipped Surface Documentation
- Specification updated: [`docs/SPEC-THREAT-MODEL-MCP.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/SPEC-THREAT-MODEL-MCP.md)
- Exposed MCP tools:
  - `aios.threat.list`
  - `aios.threat.get`
  - `aios.threat.register`
  - `aios.threat.status`
  - `aios.threat.mitigate`
  - `aios.threat.assess`
  - `aios.threat.init`

## Verified Constraints & Boundaries
1. **Catalog Limit**: 512 entries max (`MAX_THREAT_ENTRIES_CAPACITY`).
2. **File Size Limit**: 1 MiB max (`MAX_THREAT_MODEL_STORE_SIZE`).
3. **Path Validation**: Rejection of traversal components (`..`), UNC, control chars, and non-json extensions.
4. **Symlink Prohibition**: Storage files cannot be symlinks.
5. **Private Key Protection**: Zero disclosure scanning blocks key material in descriptions and mitigations.

## Security Audit (CWE Analysis)
- **CWE-200 (Information Disclosure)**: Documentation omits sensitive path details and includes guidance on secret avoidance.
- **CWE-20 / CWE-22 / CWE-400**: Documentation explicitly defines schema constraints and bounds for downstream tool integrators.

## Cross-References
- Evidence: [`T-02731`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02731-threat-model-mcp-research.md) through [`T-02738`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02738-mcp-api-surface-hardening.md).
