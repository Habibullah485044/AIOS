# Task Evidence: T-02879 — Standalone Proof Verifier: Hardening

- **Task ID**: `T-02879`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Date**: 2026-10-07
- **Invariants Verified**: `I-4` (Self-Contained Restraint Proof)
- **Closes Findings**: `TV-POR-05` (JSON bomb / memory exhaustion), `TV-POR-06` (non-normalized ISO-8601 timestamp evasion)

## Hardening Implemented

1. **Payload Size Capping (TV-POR-05)**:
   - Enforced `MAX_PROOF_PAYLOAD_BYTES = 20 MiB` in `_load_proof_dict` (Python) and `loadProof` (TypeScript) for both file-path and raw-JSON-string inputs.
   - Oversized payloads are rejected before parsing with `PAYLOAD_TOO_LARGE` (file size checked via `stat`, string via UTF-8 byte length) — preventing memory-exhaustion DoS on the verifier.

2. **Collection Boundary Caps (TV-POR-05)**:
   - `MAX_SEGMENTS_COUNT = 10_000` on `segments_checked` and `MAX_LIVE_HASHES_COUNT = 100_000` on `live_range.hashes`, both rejected with `VERIFY_FAILED: PROOF_TOO_COMPLEX`.
   - `MAX_BLOOM_BITS = 16_000_000` and `MAX_BLOOM_K = 64` bound Bloom parameters per segment; `MAX_FIELD_STR_LEN = 4_096` bounds `grant_id` length.
   - Structural type guards: `grant`/`window`/`anchors`/`live_range` must be JSON objects, `segments_checked`/`live_range.hashes` must be lists, segment entries must be objects, hash entries must be strings (`INVALID_SCHEMA` otherwise).

3. **Strict ISO-8601 UTC Timestamp Validation (TV-POR-06)**:
   - All window, grant, and anchor timestamps are parsed via `_parse_iso8601_utc` / `parseIso8601Utc` (naive values coerced to UTC, offsets normalized to UTC) and compared as **instants**, never lexicographic strings.
   - Unparseable timestamps are rejected with `VERIFY_FAILED: TIMESTAMP_INVALID`, eliminating window-boundary drift from non-canonical formats (e.g. `+00:00` vs `Z`, non-UTC offsets).

4. **Bloom Filter Decode Hardening**:
   - `bloom_m_bits` must be a positive multiple of 8 within `MAX_BLOOM_BITS`; `bloom_k` must be within `[1, 64]`; `bloom_hex` must be strict hex with exact `m/4` length (TypeScript `Buffer.from(hex)` silently truncates malformed hex, so a regex guard was added to match Python `bytes.fromhex` strictness). Malformed input is rejected with `VERIFY_FAILED: BLOOM_INVALID`.

5. **Substrate Parity & Testing**:
   - Synchronized logic identically in Python (`aiosh_mcp/verifier.py`) and TypeScript (`cli/src/verifier.ts`); zero `tsc` errors.
   - Added 11 hardening unit tests (`test_hardened_*`) covering timestamp rejection, both complexity caps, payload cap, bloom hex/length/m/k bounds, and type guards.

## Test Results
```
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_valid_proof PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_invalid_schema PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_redeemed_grant_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_non_single_use_grant_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_invalid_window_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_untrusted_key_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_tampered_anchor_sig_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_unbounding_anchor_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_bloom_positive_presence_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_chain_head_mismatch_rejected PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_verify_file_loading_roundtrip PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_invalid_timestamp_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_unparseable_anchor_timestamp_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_segments_cap_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_live_hashes_cap_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_bloom_hex_malformed_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_bloom_length_mismatch_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_bloom_k_bounds_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_bloom_m_bounds_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_payload_too_large_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_non_dict_grant_rejection PASSED
code/aiosh-mcp/tests/test_por_verifier.py::test_hardened_non_string_grant_id_rejection PASSED
============================= 25 passed in 2.51s ==============================
```

Full Proof-of-Restraint battery (no regressions):
```
test_por_restraint_generator.py + test_por_restraint_integration.py
+ test_por_verifier.py + test_por_verifier_integration.py
============================= 38 passed, 1 skipped in 3.47s ==================
code/aiosh-cli/tests/test_por_integration.py + test_restraint_mint_redeem.py
============================= 4 passed in 0.45s ==============================
npm run build (tsc -p tsconfig.json): zero errors
```

## Security Audit
- All `TV-POR-05` and `TV-POR-06` findings from T-02878 are closed.
- Zero regressions across the full PoR test suite; both substrates behave identically on malformed, oversized, and hostile proofs (fail closed with `VERIFY_FAILED`).
