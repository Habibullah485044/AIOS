# Task Evidence: T-02869 — Restraint Proof Generator: Hardening

- **Task ID**: `T-02869`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Date**: 2026-10-07
- **Invariants Verified**: `I-3` (External Checkpoints), `I-4` (Self-Contained Restraint Proof)

## Hardening Implemented
1. **Strict Anchor Bounding Enforcement**:
   - Fixed fallback vulnerability in `code/aiosh-mcp/aiosh_mcp/restraint.py` and `code/aiosh-cli/src/restraint.ts`.
   - Now guarantees that $T_{start\_anchor} \le T_{window\_start}$ and $T_{end\_anchor} \ge T_{window\_end}$.
   - If no covering start or end anchor exists in external storage, proof generation immediately fails with `NO_COVERING_ANCHORS`.

2. **Input Validation & Sanitization**:
   - Enforced strict ISO-8601 UTC timestamp parsing for `window_start` and `window_end` (`_validate_iso_timestamp` / `validateIsoTimestamp`).
   - Protected against path traversal and poisoning: disallow NUL bytes (`\0`) in `anchors_path` (`_validate_safe_path` / `validateSafePath`).

3. **Substrate Parity & Testing**:
   - Synchronized logic identically in Python (`restraint.py`) and TypeScript (`restraint.ts`).
   - Added unit test cases verifying invalid timestamp rejection, NUL-byte path rejection, and unbounding anchor rejection.

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
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_invalid_timestamp_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_nul_byte_path_rejection PASSED
code/aiosh-mcp/tests/test_por_restraint_generator.py::test_hardened_unbounding_anchors_rejection PASSED
============================= 11 passed in 0.99s ==============================
```

## Security Audit
- Hardened all input validation and anchor boundary selection.
- Zero TypeScript compiler warnings/errors (`npm run build`).
- Zero regressions across the full PoR test suite (27 passed, 1 skipped).
