# Hardening Evidence: Threat Model Automated Tests (T-02758)

## Overview
Documents hardening verification of the Threat Model Maintenance automated tests, confirming size caps, parsing failure modes, timeout ceilings, and zero resource/tempfile leakage on all error paths.

## Hardening Assertions Verified
1. **Oversized Store File Protection**: Files exceeding 1 MiB (`MAX_THREAT_MODEL_STORE_SIZE`) are rejected with `THREATSVC_ERR_FILE_SIZE`, mitigating memory exhaustion / DoS attacks.
2. **Malformed JSON Fail-Closed Behavior**: Corrupted or incomplete JSON inputs are parsed cleanly and rejected with `THREATSVC_ERR_PARSE` without crashing or panicking.
3. **Zero Temp File Leakage Guarantee**: Verified that after executing atomic persistence writes, zero `.tmp.*` temporary files exist in the target directory.
4. **Structured Error Envelopes**: All failure branches produce deterministic error envelopes adhering to ADR-0035 error classification.

## Test Verification Output
```text
running 14 tests
test test_autothreat1_lifecycle_and_transitions ... ok
test test_autothreat3_key_scrubbing ... ok
test test_autothreat2_stride_matrix ... ok
test test_autothreat10_canonical_init ... ok
test test_autothreat6_risk_scoring ... ok
test test_autothreat4_path_traversal ... ok
test test_autothreat8_serialization_roundtrip ... ok
test test_autothreat5_concurrency ... ok
test test_threat_boundary_id_syntax ... ok
test test_threat_boundary_title_and_description ... ok
test test_autothreat7_capacity_bounds ... ok
test test_threat_automated_hardening_zero_leak ... ok
test test_threat_negative_cases ... ok
test test_autothreat9_atomic_persistence ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
```
