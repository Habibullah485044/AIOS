# Task Evidence: T-02776 (Threat Model Observability Integration)

## Overview
Implemented cross-subsystem end-to-end integration tests in `code/aiosh-rust/aiosh-core/tests/test_threat_model_observability_integration.rs` asserting telemetry generation across `ThreatModelService`, `ThreatModelSecurityPolicy`, persistent disk serialization, and `AuditRing` audit log correlation.

## Verified Integration Points
1. **Catalog & Policy Integration**:
   - Initialized service with canonical baseline threats (7 entries).
   - Applied declarative `ThreatModelSecurityPolicy` in `Enforcing` mode.
2. **Audit Ring Event Correlation**:
   - Recorded multiple tool actions in `AuditRing` (`aios.threat.register`, `aios.threat.status`) alongside unrelated operations (`aios.secret.store`).
   - Verified that `recent_audit_events_count` accurately filters and counts only threat subsystem operations.
3. **Persistence Roundtrip**:
   - Verified saving and reloading catalog state from filesystem while retaining telemetry integrity.
4. **Serialization & Disclosure Invariant**:
   - Verified lossless JSON roundtrip via `to_json` and `from_json`.
   - Verified zero disclosure of private keys or sensitive payloads in emitted telemetry.

## Test Output
```text
running 1 test
test test_threat_observability_end_to_end_integration ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```
