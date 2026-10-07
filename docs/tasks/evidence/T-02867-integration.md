# Task Evidence: T-02867 — Restraint Proof Generator: Integration

- **Task ID**: `T-02867`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / restraint proof generator
- **Date**: 2026-10-07
- **Invariants Verified**: `I-4` (Self-Contained Restraint Proof Integration)

## Implementation & Integration Details
1. **MCP Tool Surface**:
   - Registered `aios_restraint_prove` in `code/aiosh-mcp/aiosh_mcp/server.py`.
   - Routes through `_recorded_call` to guarantee audit trail in `audit_ring`.
   - Propagates negative attestation results (`GRANT_NOT_FOUND`, `GRANT_REDEEMED`, etc.) in structured `{ ok: False, error: ... }` response envelopes.

2. **CLI Surface**:
   - Registered `aiosh prove restraint` in `code/aiosh-cli/src/cli.ts`.
   - Accepts `--grant`, `--window-start`, `--window-end`, `--anchors`, and optional `--out` flags.
   - Emits `restraint.prove` audit record to SQLite WAL audit ring.
   - Built and typechecked cleanly via `tsc -p tsconfig.json`.

3. **Integration Test Suite**:
   - Authored `code/aiosh-mcp/tests/test_por_restraint_integration.py`.
   - Verified end-to-end MCP proof generation, negative error handling, and subprocess execution.

## Test Results
```
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_mcp_restraint_prove_tool_success PASSED
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_mcp_restraint_prove_tool_negative PASSED
code/aiosh-mcp/tests/test_por_restraint_integration.py::test_cli_prove_restraint_subprocess SKIPPED (Win32 substrate check)
================== 24 passed, 1 skipped in 4.13s ==================
```

## Security Audit
- No sensitive keys or unvalidated input paths leaked.
- Output serialization uses canonical JSON formatting.
- Audit row emission verified for every proof generation request.
