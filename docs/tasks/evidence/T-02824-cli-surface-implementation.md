# T-02824: Compliance Mapping CLI Surface Implementation

- **Task**: `T-02824`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Implementation Scope
Implemented `cmd_compliance` in `code/aiosh-rust/aiosh-cli/src/main.rs`:
1. **`list`**:
   - Query mappings with optional `--framework` and `--status` filters.
   - Outputs table formatted or JSON structure (`--json`).
2. **`show <ID>`**:
   - Displays detailed metadata, mitigation summary, threat links, and timestamps.
   - Fails with code 1 if mapping not found, code 2 if missing argument.
3. **`register`**:
   - Validates all required arguments (`--id`, `--control`, `--framework`, `--target-type`, `--target-ref`, `--mitigation`).
   - Domain validation via `ComplianceMappingEntry::new`.
   - Persists atomically via `save_to_path`.
4. **`status <ID> <STATUS>`**:
   - Updates compliance status with optional `--reason`.
   - Persists state atomically and returns exit code 0 or 1 on invalid transition.
5. **`assess`**:
   - Computes compliance rate, category breakdown, and gap control IDs.
6. **`check-pep <GATES...>`**:
   - Validates coverage across specified PEP gates, returning 0 on full coverage or 1 on uncovered gates.
7. **`init`**:
   - Initializes compliance store with canonical baseline, requiring `--force` to overwrite.
8. **Invariants**:
   - `COMPLYCLI1`: Every command path logs an audit record via `classify_and_emit`.
   - `COMPLYCLI2`: Path hygiene checks against traversal, UNC shares, and forbidden extensions.
   - `COMPLYCLI3`: Terminal output sanitized via `sanitize_terminal_output`.
