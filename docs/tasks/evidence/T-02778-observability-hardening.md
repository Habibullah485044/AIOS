# Hardening Evidence: Threat Model Observability (T-02778)

## Overview
Documents hardening verification of the Threat Model Observability subsystem (`code/aiosh-rust/aiosh-core/src/threat_model_observability.rs`), confirming cardinality bounds, control character sanitization, and the zero-disclosure invariant.

## Verified Hardening Assertions
1. **Cardinality Ceiling Enforcement (`THREATOBS3`, CWE-400)**:
   - Distribution maps capped at 128 distinct entries (`MAX_OUTCOME_DISTRIBUTION_ENTRIES`).
   - Verified that distribution maps exceeding 128 elements fail closed with `THREATOBS_ERR_VALIDATION`.
2. **Text Sanitization & ANSI Filtering (`THREATOBS2`, CWE-20)**:
   - Verified that control characters (`\x00`..`\x1f`, `\x7f`) and ANSI escape sequences (`\x1b`) are completely stripped from metric label texts.
3. **Zero-Disclosure Invariant (`THREATOBS4`, CWE-532)**:
   - Validated that serialized telemetry output emits only aggregate counts, metric summaries, and safe taxonomy enums. Zero private keys, tokens, or credential fragments are leaked.
4. **Bounded Audit Trail Consumption (`THREATOBS6`)**:
   - Audit event correlation bounded to a maximum of 1,000 tail records, preventing linear slowdowns on large historical databases.

## Test Verification Output
```text
running 8 tests
test test_observability_empty_catalog ... ok
test test_observability_policy_mode_reflection ... ok
test test_observability_canonical_threats ... ok
test test_observability_json_roundtrip ... ok
test test_observability_populated_catalog ... ok
test test_observability_sanitize_text ... ok
test test_observability_validation_rejections ... ok
test test_threat_observability_hardening_and_cardinality ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
