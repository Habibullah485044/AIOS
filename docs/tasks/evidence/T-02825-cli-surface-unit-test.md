# T-02825: Compliance Mapping CLI Surface Unit Tests

- **Task**: `T-02825`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Test Coverage
Added comprehensive unit test suite in `code/aiosh-rust/aiosh-cli/src/main.rs`:
- `test_compliance_cli_help_and_unknown`:
  - Verified exit code 0 for empty argv, `--help`, and `-h`.
  - Verified exit code 2 for unknown subcommands (standard and `--json` format).
- `test_compliance_cli_path_validation`:
  - Verified rejection (code 2) of path traversal (`../map.json`), forbidden extensions (`map.txt`), control characters, and UNC shares.
- `test_compliance_cli_lifecycle_and_operations`:
  - Verified `init` creation and overwrite protection (`--force` requirement).
  - Verified `list` filtering across frameworks and statuses.
  - Verified `show` successful retrieval and negative lookup handling (code 1 for missing ID, code 2 for missing arg).
  - Verified `register` validation of required flags, invalid framework/target types, and atomic persistence.
  - Verified `status` transition and rejection of invalid status.
  - Verified `assess` posture calculation across frameworks.
  - Verified `check-pep` coverage assertion and uncovered gate detection.

## 2. Test Execution
All tests passed with zero regressions.
