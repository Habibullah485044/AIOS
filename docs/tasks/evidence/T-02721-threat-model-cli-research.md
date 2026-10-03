# T-02721: Threat Model Maintenance CLI Surface Research

- **Task**: `T-02721`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Research Objectives & Context
The Threat Model Maintenance CLI surface (`aiosh threat`) serves as the administrative and operator toolchain for querying, mutating, mitigating, and assessing system threats. It integrates directly with `aiosh_core::threat_model_service::ThreatModelService` and guarantees that every invocation emits an append-only audit row to `audit.db` via the AIOS Security Kernel.

## 2. CLI Command Taxonomy & Ergonomics
The CLI subcommands must support the full operational lifecycle:

1. **`aiosh threat list`**:
   - Lists threat entries formatted as a tabular overview (ID, Category, Severity, Status, Title) or JSON.
   - Flags: `--status <status>`, `--severity <sev>`, `--category <cat>`, `--json`, `--path <custom_path>`.
2. **`aiosh threat show <ID>`**:
   - Inspects a single threat in depth, displaying full description, component, CWE list, and mitigations.
   - Flags: `--json`, `--path <custom_path>`.
3. **`aiosh threat register`**:
   - Registers a new threat entry in the catalog.
   - Required flags: `--id`, `--title`, `--desc`, `--cat`, `--sev`, `--component`.
   - Optional flags: `--cwes`, `--mitigations`, `--path <custom_path>`.
4. **`aiosh threat status <ID> <STATUS>`**:
   - Advances threat status through state machine (`Identified`, `UnderReview`, `Mitigated`, `Accepted`, `Resolved`).
   - Flags: `--path <custom_path>`.
5. **`aiosh threat mitigate <ID> <TEXT>`**:
   - Records a mitigation action against the threat and automatically updates status to `Mitigated` if valid.
   - Flags: `--path <custom_path>`.
6. **`aiosh threat assess`**:
   - Calculates real-time composite risk metrics, critical unmitigated counts, and overall risk score.
   - Flags: `--json`, `--path <custom_path>`.
7. **`aiosh threat init`**:
   - Initializes a fresh threat model file populated with the 7 canonical STRIDE baseline threats.
   - Flags: `--path <custom_path>`, `--force`.

## 3. Security & Operational Invariants
- **Audit Logging**: Every command invocation writes an audit record through `Ctx.emit(...)` capturing user actor ID, tool `threat`, command name, arguments, and outcome (`success` or `failure`).
- **Path Sanitization**: All `--path` arguments pass through `ThreatModelService::validate_path` ensuring path traversal defense (`..`, control characters, UNC paths) and symlink rejection.
- **Fail-Closed Exit Codes**:
  - `0`: Success.
  - `1`: Domain or validation failure (illegal transition, unmitigated critical, capacity exceeded).
  - `2`: Syntax or argument usage error (missing required parameters).
  - `3`: Filesystem I/O or JSON parsing error.
