# Hardening Evidence: T-02849 — redeem-before-act gate: Hardening

## Task Information
- **Task ID**: `T-02849`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Hardening`
- **Status**: Completed

## Hardening Implemented
1. **Concurrency and Lock Contention**:
   - Added `PRAGMA busy_timeout = 5000;` to `grant_redeem()` in `code/aiosh-mcp/aiosh_mcp/audit_client.py` to gracefully handle concurrent SQLite WAL writers without raising unhandled locks.
2. **Input Hygiene**:
   - Added `grant_id.strip()` and rejection of empty/whitespace identifiers.
   - Enforced maximum string bounds (8192 chars) on `tool` and `command`.
3. **Fail-Closed Exception Isolation in Dispatch**:
   - Wrapped Gate #2.5 redemption call in `aiosh_mcp._dispatch.dispatch()` in a `try...except` block.
   - Any unexpected error during token redemption is trapped, converted to an explicit refusal outcome, and logged to `audit_ring` with bounded `outcome_detail` (<= 1024 chars).
   - Under no condition can an exception in the PEP or audit layer cause the gate to fail open into unauthorized tool execution.
4. **Verification**:
   - Verified integration test suite (`test_por_gate_integration.py`).
   - Verified unit test suite (`test_por_redeem_gate.py`).
   - Verified capability CLI smoke test suite (`test_capability_cli_smoke.py`).
