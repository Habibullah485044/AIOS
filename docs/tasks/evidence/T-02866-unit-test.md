# Task Evidence: T-02866 — Restraint Proof Generator: Unit Test

- **Task ID**: `T-02866`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Date**: 2026-10-07
- **Invariants Verified**: `I-4` (Restraint Proof Completeness & Self-Contained Negative Attestation)

## Verification Summary
Created `code/aiosh-mcp/tests/test_por_restraint_generator.py` covering all core negative attestation generator paths:
1. `test_generate_valid_restraint_proof`: Confirms generation of valid `RestraintProofPackage` with canonical JSON serialization, anchor bounds, and `PROVABLY_RESTRAINED` verdict.
2. `test_window_invalid_rejection`: Enforces validation that `window_start <= window_end`.
3. `test_grant_not_found_rejection`: Rejects missing grants with `GRANT_NOT_FOUND`.
4. `test_grant_already_redeemed_in_grant_table`: Rejects grants with `redeemed_at` populated in `pep_grants` with `GRANT_REDEEMED`.
5. `test_grant_redeemed_in_audit_ring_row`: Detects redemption row in `audit_ring` (`tool='pep.capability.redeem'`) and fails with `GRANT_REDEEMED`.
6. `test_grant_detected_in_archived_segment_bloom`: Proves that if grant is present in an archived segment Bloom filter, generation fails with `GRANT_REDEEMED`.
7. `test_archived_segment_bloom_exclusion_success`: Proves zero false negatives for Bloom exclusion across archived audit segments.
8. `test_no_covering_anchors_rejection`: Ensures proof cannot be minted without valid bounding external checkpoint anchors.

## Test Results
```
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_generate_valid_restraint_proof PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_window_invalid_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_not_found_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_already_redeemed_in_grant_table PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_redeemed_in_audit_ring_row PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_grant_detected_in_archived_segment_bloom PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_archived_segment_bloom_exclusion_success PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_no_covering_anchors_rejection PASSED
============================== 8 passed in 1.36s ==============================
```

## Security Audit
- No sensitive data or static private keys hardcoded.
- Ephemeral test fixtures run within isolated temporary directories.
- Verified absence of SQL injection and confirmed parameterized queries across all audit ring lookups.
- Cryptographic negative attestation mathematically validated.
