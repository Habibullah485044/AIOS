# Task Evidence: T-02766 (Threat Model Security Policy Integration)

## Overview
Implemented end-to-end service integration test in `code/aiosh-rust/aiosh-core/tests/test_threat_model_policy_integration.rs`, verifying the cross-cutting security enforcement between `ThreatModelService` and `ThreatModelSecurityPolicy`. Added dynamic policy binding helpers (`set_policy`, `policy`, `policy_mut`) to `ThreatModelService`.

## Verified End-to-End Invariants
1. **Registration Enforcement**:
   - Prohibited category rejection fail-closed (`THREATPOL_ERR_CATEGORY_PROHIBITED`).
   - Missing required CWE mapping rejection fail-closed (`THREATPOL_ERR_CWE_REQUIRED`).
   - Successful registration of valid critical threat entry.
2. **Lifecycle Transition Governance**:
   - Rejection of transitioning an unmitigated Critical severity threat to `Accepted` or `Resolved` fail-closed (`THREATPOL_ERR_CRITICAL_UNMITIGATED`).
   - Rejection of empty/blank mitigation entries (`THREATPOL_ERR_DENIED`).
   - Acceptance of valid mitigation text and subsequent valid transition to `Accepted` and `Resolved`.
3. **Dynamic Mode Switching**:
   - Dynamic mode transition from `Enforcing` to `Permissive` allowing previously prohibited actions while emitting warnings.
4. **State Persistence Integrity**:
   - Atomic save and load roundtrip with policy enforcement active, verifying catalog consistency across restarts.

## Test Run Results
```
running 6 tests
test test_threat_policy_defaults_and_validation ... ok
test test_threat_policy_evaluate_assessment ... ok
test test_threat_policy_evaluate_mitigation ... ok
test test_threat_policy_evaluate_registration ... ok
test test_threat_policy_evaluate_transition ... ok
test test_threat_policy_persistence_and_atomic_save ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

running 1 test
test test_threat_policy_end_to_end_service_integration ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s

running 4 tests
test test_threat_service_lifecycle_operations ... ok
test test_threat_service_risk_assessment ... ok
test test_threat_service_initialization_and_canonical_threats ... ok
test test_threat_service_path_validation_and_persistence ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```
