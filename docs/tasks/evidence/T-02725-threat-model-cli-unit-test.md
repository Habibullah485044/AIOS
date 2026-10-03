# T-02725: Threat Model Maintenance CLI Surface Unit Test

- **Task**: `T-02725`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Unit Test Scope
Authored unit test suite in `code/aiosh-rust/aiosh-cli/src/main.rs` under `threat_cli_tests`:
1. `test_threat_cli_help_and_unknown`:
   - Validates root help response (`aiosh threat`, `--help`, `-h`) returning exit code `0`.
   - Validates unknown subcommands returning exit code `2` with both text and `--json` formatting.
2. `test_threat_cli_path_validation`:
   - Enforces fail-closed rejection of path traversal attempts (`../threats.json` -> code `2`).
   - Enforces rejection of non-json file extensions (`threats.txt` -> code `2`).
   - Rejects control characters in paths (`bad\nthreats.json` -> code `2`).
   - Rejects UNC network paths (`\\\\evil\\share\\t.json` -> code `2`).
3. `test_threat_cli_lifecycle_and_operations`:
   - Validates `init` baseline creation (code `0`), prevents duplicate overwrite without `--force` (code `1`), and permits overwrite with `--force` (code `0`).
   - Validates `list` formatting (tabular and JSON) and filters (`--status`, `--severity`, `--category`).
   - Validates `show` entry display (code `0`), non-existent threat error (code `1`), and missing ID syntax error (code `2`).
   - Validates `register` entry creation (code `0`), missing flag enforcement (code `2`), and invalid category/severity rejection (code `1`).
   - Validates `status` progression (code `0`), invalid status syntax (code `1`), and missing arguments (code `2`).
   - Validates `mitigate` mitigation attachment and automated transition to mitigated (code `0`), and missing argument validation (code `2`).
   - Validates `assess` risk calculation across tabular and JSON outputs (code `0`).

## 2. Test Execution Output
```
     Running unittests src\main.rs (target\debug\deps\aiosh-90f772bf22d7ba62.exe)

running 3 tests
test threat_cli_tests::test_threat_cli_help_and_unknown ... ok
test threat_cli_tests::test_threat_cli_path_validation ... ok
test threat_cli_tests::test_threat_cli_lifecycle_and_operations ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out; finished in 0.05s
```
