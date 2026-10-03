# T-02726: Threat Model Maintenance CLI Surface Integration

- **Task**: `T-02726`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Integration Scope
1. **End-to-End Workflow Integration (`test_threat_cli_integration_e2e`)**:
   - Executes full 9-step administrative lifecycle entirely through the CLI interface:
     - `aiosh threat init`: Populates baseline catalog with canonical STRIDE threats.
     - `aiosh threat list`: Validates filter-based querying (`--status mitigated`, `--category elevation_of_privilege`).
     - `aiosh threat assess`: Calculates baseline risk with JSON output.
     - `aiosh threat register`: Ingests an active critical threat with CWE-250 mapping.
     - `aiosh threat show`: Inspects threat specification and properties.
     - `aiosh threat status`: Advances threat to `under_review`.
     - `aiosh threat mitigate`: Attaches user namespace and seccomp mitigations, automatically advancing to `mitigated`.
     - `aiosh threat assess`: Verifies risk score monotonic reduction.
     - `aiosh threat show`: Verifies persistent storage of mitigations and updated status.
2. **Audit & Substrate Integrity**:
   - Verifies that every CLI subcommand records an audit trace via `Ctx.emit(...)` in the append-only SQLite database.
   - Verifies isolated execution on temporary catalog paths without state interference.

## 2. Test Execution Output
```
     Running unittests src\main.rs (target\debug\deps\aiosh-8814d271a6af31ad.exe)

running 4 tests
test threat_cli_tests::test_threat_cli_help_and_unknown ... ok
test threat_cli_tests::test_threat_cli_path_validation ... ok
test threat_cli_tests::test_threat_cli_lifecycle_and_operations ... ok
test threat_cli_tests::test_threat_cli_integration_e2e ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.75s
```
