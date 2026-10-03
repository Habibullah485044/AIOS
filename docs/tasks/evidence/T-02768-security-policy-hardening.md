# Hardening Evidence: Threat Model Security Policy (T-02768)

## Overview
Documents hardening verification of the Threat Model Security Policy subsystem (`THREATPOL1` through `THREATPOL7`), confirming size boundaries, denial-of-service protections, atomic file operations, zero resource/tempfile leakage, and fail-closed state invariants.

## Verified Hardening Assertions
1. **Oversized Policy Protection**:
   - Files exceeding 64 KiB (`MAX_THREAT_SECURITY_POLICY_BYTES = 65_536`) are immediately rejected with `THREATPOL_ERR_VALIDATION`, preventing memory exhaustion and denial of service.
2. **Symlink Traversal Prevention**:
   - Policy paths pointing to symbolic links are explicitly detected and denied via `symlink_metadata`, preventing symlink hijacking or unauthorized file read/write (CWE-59).
3. **Atomic File Persistence & Zero Leakage**:
   - Atomic policy writing creates isolated temporary files using PID and system nanoseconds (`.tmp.{pid}.{nanos}`), then performs an atomic filesystem rename.
   - Verified that on both successful and erroneous saves, zero leftover temporary files remain in the target directory.
4. **State Machine Invariant Enforcement**:
   - Critical unmitigated transition denial cannot be bypassed even if the threat has moved through intermediary review states (`UnderReview`).
   - Mitigations containing whitespace, control characters, or empty strings are strictly rejected with `THREATPOL_ERR_DENIED`.

## Test Execution
```text
running 7 tests
test test_threat_policy_evaluate_assessment ... ok
test test_threat_policy_defaults_and_validation ... ok
test test_threat_policy_evaluate_mitigation ... ok
test test_threat_policy_evaluate_registration ... ok
test test_threat_policy_evaluate_transition ... ok
test test_threat_policy_persistence_and_atomic_save ... ok
test test_threat_policy_hardening_and_resilience ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
```
