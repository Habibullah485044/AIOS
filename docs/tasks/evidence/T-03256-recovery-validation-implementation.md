# T-03256 Evidence: Model Backend Adapters Recovery & Validation Implementation

## Task Metadata
- Task ID: T-03256
- Title: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / recovery & validation: Implementation
- Status: Completed
- Date: 2026-10-29

## Overview
Implemented working behavior for Model Backend Adapters recovery and validation in `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_recovery.py`.

## Capabilities Implemented
1. **Config Validation (`validate_config_file`)**:
   - Deep structural and schema inspection enforcing `MODRECV-INV1` (`total_models == valid + invalid`) and `MODRECV-INV2` (`is_healthy == (len(issues) == 0 and invalid == 0)`).
   - Validates JSON parseability, size limits (<= 10 MiB), provider types, endpoint URLs, and token bounds.
   - Operates strictly read-only consuming 0 capability tokens (PoR Invariant I-2).
2. **Config Recovery (`recover_config_file`)**:
   - Gated by mandatory capability token redemption (PoR Invariant I-2); missing/empty token raises `MODRECV_ERR_UNAUTHORIZED`.
   - Atomically backs up target to `<path>.bak.<timestamp>` and quarantines corrupt payload to `<path>.corrupt.<timestamp>`.
   - Generates and writes valid authoritative fallback configuration (`mock-fallback`) via temporary file replace.

## Verification
- Tests: `code/aiosh-mcp/tests/test_model_backend_adapters_recovery_scaffold.py` and `code/aiosh-mcp/tests/test_model_backend_adapters_recovery_impl.py`
- Result: 10 passed in 0.87s.
