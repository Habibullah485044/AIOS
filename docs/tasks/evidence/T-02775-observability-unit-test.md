# Task Evidence: T-02775 (Threat Model Observability Unit Test)

## Overview
Implemented comprehensive unit test suite in `code/aiosh-rust/aiosh-core/tests/test_threat_model_observability.rs` verifying telemetry generation, distributions, invariants, and serialization.

## Tested Scenarios
1. **Empty Threat Catalog**:
   - Asserts 0 totals, empty distribution maps, default unconfigured/healthy state, valid timestamp.
2. **Populated Catalog Distributions**:
   - Asserts accurate counts across STRIDE categories, severity classes, and lifecycle states.
   - Verifies monotonic risk scoring and critical unmitigated counts.
3. **Canonical Baseline Threats**:
   - Asserts accurate indexing of all 7 canonical threats across all STRIDE categories and supply chain risk.
4. **Text Sanitization & Bounds**:
   - Asserts control character stripping and length truncating to `MAX_TELEMETRY_TEXT_LEN` (256 bytes).
5. **Policy Mode Reflection**:
   - Verifies accurate reporting of `Enforcing`, `Permissive`, and `Disabled` states.
6. **Validation Rejections**:
   - Rejection of empty timestamps, non-RFC3339 formats, unsanitized keys, and oversized strings (`THREATOBS_ERR_VALIDATION`).
7. **JSON Serialization Roundtrip**:
   - Validates lossless `to_json` and `from_json` parsing and corruption rejection.

## Test Results
```text
running 7 tests
test test_observability_policy_mode_reflection ... ok
test test_observability_canonical_threats ... ok
test test_observability_json_roundtrip ... ok
test test_observability_empty_catalog ... ok
test test_observability_sanitize_text ... ok
test test_observability_validation_rejections ... ok
test test_observability_populated_catalog ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
