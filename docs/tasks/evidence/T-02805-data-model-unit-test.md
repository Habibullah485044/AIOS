# Unit Test Evidence: Compliance Mapping Data Model (T-02805)

- **Task ID**: T-02805
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / data model
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Test Suite Coverage
Implemented comprehensive unit test cases in `code/aiosh-rust/aiosh-core/tests/test_compliance_data_model.rs`:
- `test_compliance_control_validation`: Asserts valid instantiation and asserts negative rejections on empty identifiers and null/control bytes.
- `test_compliance_mapping_entry_validation`: Tests creation validation rules, enforcing that `Compliant` status requires a non-empty mitigation summary, and checking rejection of blank substrate target references.
- `test_compliance_status_transitions`: Verifies lifecycle progression through `NonCompliant` -> `PartiallyCompliant` -> `Compliant`.
- `test_compliance_snapshot_baseline_and_queries`: Tests pre-populated canonical baseline data and queries by framework, control ID, substrate target, status, and compliance ratio metric calculation.
- `test_compliance_snapshot_duplicate_detection`: Asserts refusal of duplicate mapping IDs (`COMPLIANCE_ERR_DUPLICATE_ID`).
- `test_compliance_snapshot_serde_roundtrip`: Verifies byte-level JSON roundtrip preservation.

## 2. Test Execution
All 6 test cases passed under isolated execution: `cargo test -p aiosh-core --test test_compliance_data_model`.
