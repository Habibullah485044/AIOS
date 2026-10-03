# T-02724: Threat Model Maintenance CLI Surface Implementation

- **Task**: `T-02724`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Implementation Scope
Implemented the full Threat Model CLI surface (`cmd_threat`) in `code/aiosh-rust/aiosh-cli/src/main.rs`:

1. **Subcommands Implemented**:
   - `aiosh threat list`: Tabular and `--json` catalog listing with filters (`--status`, `--severity`, `--category`, `--path`).
   - `aiosh threat show <ID>`: Detailed entry inspection (`ID`, `Title`, `Category`, `Severity`, `Status`, `Component`, `Description`, `CWEs`, `Mitigations`).
   - `aiosh threat register`: Comprehensive entry creation with required flags (`--id`, `--title`, `--desc`, `--cat`, `--sev`, `--component`) and optional `--cwes` and `--mitigations`.
   - `aiosh threat status <ID> <STATUS>`: Formal lifecycle status progression through the domain state machine.
   - `aiosh threat mitigate <ID> <MITIGATION_TEXT>`: Mitigation attachment with automated transition to `Mitigated` status.
   - `aiosh threat assess`: Real-time composite risk metrics calculation (`total_threats`, counts per status, `critical_unmitigated_count`, `overall_risk_score`).
   - `aiosh threat init`: Initialize or overwrite (`--force`) catalog with the 7 canonical STRIDE baseline threats.

2. **Security & Governance Enforcement**:
   - Early path hygiene check (`validate_path`) rejecting traversal (`..`), UNC paths (`\\\\`, `//`), control characters, and symlinks before loading or writing.
   - Comprehensive audit logging via `classify_and_emit` on every subcommand invocation.
   - Strict exit codes: `0` (Success), `1` (Domain error / constraint violation), `2` (Argument syntax or missing required parameter), `3` (Filesystem I/O or JSON parse error).
