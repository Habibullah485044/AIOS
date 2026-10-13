# Evidence: T-03007 Incident Response Runbooks configuration Unit Test

## Summary
- **Task ID**: T-03007
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Area**: Incident Response Runbooks / configuration
- **Type**: Unit Test

## Automated Unit Test Coverage
1. **Valid Inputs & Resolution**:
   - Path hygiene verification on standard paths (`docs/runbook_catalog.json`).
   - Default resolution matching baseline constants.
2. **Invalid Inputs & Security Boundaries**:
   - Empty path and whitespace-only rejection (`RUNBOOKCONF_ERR_VALIDATION`).
   - Path traversal rejection (`..`, `foo/../../bar`) (`RUNBOOKCONF_ERR_PATH_TRAVERSAL`).
   - Path length rejection (> 1024 bytes) (`RUNBOOKCONF_ERR_BOUNDS`).
   - Control character injection rejection (`\x00`, `\x1f`).
3. **Boundary Clamping**:
   - `max_active_sessions`: clamped within `[1, 10000]`.
   - `max_catalog_file_bytes`: clamped within `[4096, 16777216]`.
   - `default_step_timeout_seconds`: clamped within `[1, 86400]`.
4. **Primary Failure Modes & Fail-Closed Behavior**:
   - Config file size > 64 KiB fails closed (`RUNBOOKCONF_ERR_FILE_SIZE`).
   - Corrupted/malformed JSON fails closed (`RUNBOOKCONF_ERR_PARSE`).

## Verification Results
- **Rust Test Run**:
  ```
  cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_runbook_config_unit
  running 5 tests
  test test_unit_hygiene_predicate ... ok
  test test_unit_clamping_boundaries ... ok
  test test_unit_corrupted_json_fails_closed ... ok
  test test_unit_file_resolution_and_oversize_error ... ok
  test test_unit_validate_config_path_boundaries ... ok
  test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
  ```
- **Python Test Run**:
  ```
  pytest code/aiosh-mcp/tests/test_runbook_config_unit.py -v
  5 passed in 0.33s
  ```
