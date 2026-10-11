# T-02917 — Compliance Mapping / Automated Tests: Unit Test

**Task**: T-02917 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Unit Test)
**Depends on**: T-02916 (Implementation — `docs/tasks/evidence/T-02916-automated-tests-implementation.md`)
**Date**: 2026-10-11
**Status**: COMPLETE — Dedicated automated unit test suites authored and running standalone with 100% PASS across both Python and Rust.

---

## 1. Test Matrix & Coverage

| Substrate | Artifact | Test Count | Status |
|---|---|---|---|
| **Python** | `code/aiosh-mcp/tests/test_compliance_automated_unit.py` | 14 | 14 / 14 PASSED |
| **Rust** | `code/aiosh-rust/aiosh-core/tests/test_compliance_automated_unit.rs` | 12 | 12 / 12 PASSED |

### Four Quadrant Verification
1. **Valid Input**:
   - Enumerated framework registration (`nist_sp_800_53_rev5`, `soc2_type2`, `iso_27001_2022`, `cis_controls_v8`, `hipaa_security`, `pci_dss_v4`).
   - Legal status transition chains (`non_compliant` -> `partially_compliant` -> `compliant`).
   - Assessment reporting and gap identification.
2. **Invalid Input**:
   - Unknown actions rejected with `PARAM_INVALID`.
   - Unknown frameworks rejected with `PARAM_INVALID`.
   - Empty/whitespace substrate target refs rejected with `COMPLIANCE_ERR_MISSING_SUBSTRATE_REF`.
   - Transition to compliant without mitigation rejected with `COMPLIANCE_ERR_BOUNDS_EXCEEDED`.
   - Show/status on missing IDs rejected with `COMPLIANCESVC_ERR_NOT_FOUND`.
   - Duplicate ID registrations rejected with `COMPLIANCE_ERR_DUPLICATE_ID`.
3. **Boundary Values**:
   - Identifiers: 64 characters accepted; 65 rejected (`COMPLIANCE_ERR_BOUNDS_EXCEEDED`).
   - Titles: 128 bytes accepted; 129 rejected (`COMPLIANCE_ERR_BOUNDS_EXCEEDED`).
   - Text descriptions: 2048 bytes accepted; 2049 rejected (`COMPLIANCE_ERR_BOUNDS_EXCEEDED`).
   - Array capacities: 16 threat IDs/tags accepted; 17 rejected (`COMPLIANCE_ERR_BOUNDS_EXCEEDED`).
   - Store capacity limit: 1024 entries accepted; 1025th rejected.
4. **Primary Failure Mode**:
   - Directory traversal paths (`../escape.json`, `../../root.json`) rejected fail-closed with `COMPLIANCESVC_ERR_PATH_TRAVERSAL`.
   - Store persistence failure rollback: original file bytes remain bitwise unchanged.

---

## 2. Test Execution Output

### Rust Suite
```text
running 12 tests
test test_unit_boundary_title_lengths ... ok
test test_unit_boundary_identifier_lengths ... ok
test test_unit_boundary_array_capacities ... ok
test test_unit_invalid_input_compliant_without_summary ... ok
test test_unit_invalid_input_duplicate_registration_refused ... ok
test test_unit_invalid_input_empty_substrate_target_ref ... ok
test test_unit_invalid_input_update_nonexistent_mapping ... ok
test test_unit_primary_failure_path_traversal ... ok
test test_unit_valid_input_framework_taxonomy_and_lookups ... ok
test test_unit_valid_input_status_transition_chain ... ok
test test_unit_primary_failure_atomic_save_leaves_file_intact ... ok
test test_unit_boundary_catalog_capacity ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

### Python Suite
```text
14 passed in 0.39s
```
Zero regressions across all existing suites.
