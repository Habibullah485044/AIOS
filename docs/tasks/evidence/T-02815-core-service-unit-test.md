# Unit Test Evidence: Compliance Mapping Core Service (T-02815)

- **Task ID**: T-02815
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / core service
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Test Suite Coverage
Implemented focused unit tests in `code/aiosh-rust/aiosh-core/tests/test_compliance_service.rs`:
- `test_compliance_service_save_and_load`: Verifies persistence and retrieval roundtrip on temporary directory stores.
- `test_compliance_service_path_traversal_rejection`: Asserts rejection of path climbing (`..`) and non-json file extensions.
- `test_compliance_service_registration_and_update`: Tests mapping registration, duplicate detection, and lifecycle status transition updates.
- `test_compliance_service_assessment_reporting`: Verifies calculation of percentage compliance, status tallies, and gap control listings.
- `test_compliance_service_pep_coverage`: Tests verification of PEP gate coverage and identification of uncovered gates.

## 2. Test Execution
All 5 test cases passed under isolated execution: `cargo test -p aiosh-core --test test_compliance_service`.
