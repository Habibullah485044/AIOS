# T-03258 Evidence: Model Backend Adapters Recovery & Validation Integration

## Task Metadata
- Task ID: T-03258
- Title: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / recovery & validation: Integration
- Status: Completed
- Date: 2026-10-29

## Overview
Integrated Model Backend Adapters recovery & validation tools into the production FastMCP tool surface in `code/aiosh-mcp/aiosh_mcp/server.py`.

## Tools Exposed
1. `aios_model_validate_config`:
   - FastMCP endpoint validating target model configuration files.
   - Pure read-only operation consuming 0 capability tokens (PoR Invariant I-2).
   - Enforces `MODRECV-INV1` (record conservation), `MODRECV-INV2` (health consistency), and `MODRECV-INV3` (traversal immunity).
2. `aios_model_recover_config`:
   - FastMCP endpoint performing atomic backup and quarantine of corrupted configuration files before synthesizing an authoritative default fallback configuration.
   - State-changing operation strictly gated by mandatory capability token redemption (PoR Invariant I-2, `MODRECV-INV4`).
   - Forensic quarantine preserved to `<path>.corrupt.<timestamp>` and backup to `<path>.bak.<timestamp>` (`MODRECV-INV5`).

## Verification
- Test file: `code/aiosh-mcp/tests/test_model_backend_adapters_recovery_integration.py`
- Test run: 45 passed in 2.91s across the entire recovery test battery.
