# Hardening Evidence: Compliance Mapping Core Service (T-02818)

- **Task ID**: T-02818
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / core service
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Hardening Defenses Implemented
- **Oversized Store Rejection**: Hard cap of 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`) verified through pre-flight file metadata inspection before any byte read.
- **Malformed Payload Handling**: Unparseable or corrupted JSON payloads fail cleanly with explicit error code `COMPLIANCESVC_ERR_PARSE`.
- **Temp File Unlink & Isolation**: All save operations execute via PID/nanosecond unique temporary files (`.tmp.{pid}.{nanos}`) with guaranteed unlinking on any failure branch.
- **Audit Consistency**: All operational and evaluation routines report structured, deterministic results without leaking internal memory state.

## 2. Test Verification
Extended test coverage in `code/aiosh-rust/aiosh-core/tests/test_compliance_service.rs`:
- `test_compliance_service_oversized_store_rejection`: Confirms rejection of stores exceeding 1 MiB.
- `test_compliance_service_corrupt_json_rejection`: Asserts rejection of unparseable JSON files.
- `test_compliance_service_no_temp_leak`: Confirms zero leaked temporary files following persistence.
All 8 test cases passed cleanly.
