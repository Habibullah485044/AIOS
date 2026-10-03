# T-02716: Threat Model Maintenance Core Service Integration

- **Task**: `T-02716`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Integration Scope
1. **Public API Re-exports (`aiosh_core::lib.rs`)**:
   - Re-exported `ThreatModelService` and `ThreatRiskAssessment`.
   - Re-exported configuration limits: `DEFAULT_THREAT_MODEL_PATH`, `MAX_THREAT_ENTRIES_CAPACITY`, `MAX_THREAT_MODEL_STORE_SIZE`.
   - Re-exported error constants: `THREATSVC_ERR_NOT_FOUND`, `THREATSVC_ERR_CAPACITY_EXCEEDED`, `THREATSVC_ERR_FILE_SIZE`, `THREATSVC_ERR_PATH_TRAVERSAL`, `THREATSVC_ERR_IO`, `THREATSVC_ERR_PARSE`.

2. **Integration Test Suite (`test_threat_model_service_integration.rs`)**:
   - `test_threat_model_service_end_to_end_integration`:
     - Initializes canonical baseline threats across STRIDE.
     - Performs initial risk calculation (validates identified count and risk score).
     - Exercises state transition lifecycle (`Identified` -> `UnderReview` -> `Mitigated`) with cryptographic mitigation attachment.
     - Confirms aggregate risk score decreases monotonically after mitigation.
     - Registers a new custom threat entry.
     - Performs atomic file persistence (`save_to_path`) and round-trip rehydration (`load_from_path`).
   - `test_threat_model_service_capacity_and_error_handling`:
     - Verifies `THREATSVC_ERR_NOT_FOUND` on unknown threat mutation.
     - Verifies path traversal rejection (`THREATSVC_ERR_PATH_TRAVERSAL`) on malicious save and load paths.

## 2. Test Execution Output
```
   Compiling aiosh-core v0.1.0 (C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-rust\aiosh-core)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 3.26s
     Running tests\test_threat_model_service_integration.rs (target\debug\deps\test_threat_model_service_integration-44efc355a91cf616.exe)

running 2 tests
test test_threat_model_service_capacity_and_error_handling ... ok
test test_threat_model_service_end_to_end_integration ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```
