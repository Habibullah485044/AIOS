# T-03257 Evidence: Model Backend Adapters Recovery & Validation Unit Test

## Task Metadata
- Task ID: T-03257
- Title: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / recovery & validation: Unit Test
- Status: Completed
- Date: 2026-10-29

## Overview
Created focused automated unit test battery for Model Backend Adapters recovery and validation in `code/aiosh-mcp/tests/test_model_backend_adapters_recovery_unit.py`.

## Test Coverage
1. **Path Validation and Traversal Immunity (`MODRECV-INV3`)**:
   - Valid relative and nested paths.
   - Rejection of directory traversal sequences (`..`, `../`, `nested/../../`).
   - Rejection of NUL bytes, alternate data streams (`:`), and length overflow (>1024).
   - Rejection of Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
   - Path redaction via `sanitize_error_message`.
2. **Structural Invariants (`MODRECV-INV1` & `MODRECV-INV2`)**:
   - `MODRECV-INV1`: Enforcement that `total_models == valid_models + invalid_models`.
   - `MODRECV-INV2`: Enforcement that `is_healthy == (len(issues) == 0 and invalid_models == 0)`.
3. **Configuration Validation**:
   - Non-existent and oversized files.
   - Corrupt JSON syntax (`MODRECV_ERR_CORRUPT_JSON`).
   - Schema violations: missing models array, non-dict entries, invalid model names, unsupported providers, invalid endpoint URLs, negative/invalid token bounds (`MODRECV_ERR_SCHEMA_VIOLATION`).
   - Fully healthy configuration validation.
4. **Recovery Execution & Token Gating (`MODRECV-INV4` & `MODRECV-INV5`)**:
   - Enforces PoR Invariant I-2: recovery without capability token raises `MODRECV_ERR_UNAUTHORIZED`.
   - Atomic backup creation (`.bak.<timestamp>`) and quarantine creation (`.corrupt.<timestamp>`).
   - Synthesizes authoritative default fallback configuration (`mock-fallback`) and verifies restored file is valid and healthy.

## Verification
- Unit test run: 30 passed in 0.73s.
