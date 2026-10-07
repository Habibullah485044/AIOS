# Task Evidence: T-02877 — Standalone Proof Verifier: Integration

- **Task ID**: `T-02877`
- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / standalone proof verifier
- **Date**: 2026-10-07
- **Invariants Verified**: `I-4` (Self-Contained Verification Integration Across MCP & CLI)

## Integration Deliverables
1. **MCP Tool Integration**:
   - Registered `aios_restraint_verify` in `code/aiosh-mcp/aiosh_mcp/server.py`.
   - Routes through `_recorded_call` to guarantee audit trail in `audit_ring` (`tool='aios.restraint.verify'`).
   - Accepts proof payload (dict or path) and trusted Ed25519 public key whitelist.

2. **CLI Surface Integration**:
   - Added `aiosh prove verify` subcommand in `code/aiosh-cli/src/cli.ts` taking `--proof <path>` and `--pubkey <hex...>`.
   - Rebuilt TypeScript with zero compile or type errors (`npm run build`).

3. **Integration Test Suite**:
   - Created `code/aiosh-mcp/tests/test_por_verifier_integration.py` (3 tests).
   - Validated end-to-end flow from Proof Generator -> Standalone Verifier.
   - Validated MCP tool verification and anti-tampering rejection.

## Test Results
```
code/aiosh-mcp/tests/test_por_verifier_integration.py::test_generator_to_verifier_end_to_end PASSED
code/aiosh-mcp/tests/test_por_verifier_integration.py::test_mcp_restraint_verify_tool_integration PASSED
code/aiosh-mcp/tests/test_por_verifier_integration.py::test_mcp_restraint_verify_tampered_detection PASSED
============================== 3 passed in 2.15s ==============================
```

## Security Audit
- Confirmed zero database calls in verification logic.
- Enforced mandatory trusted key whitelisting.
- All integration surfaces fail closed on tampered or forged proofs.
