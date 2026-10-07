# Evidence Artifact: T-02839 — capability mint/redeem records: Hardening

## Task Information
- **Task ID**: `T-02839`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Hardening`
- **Status**: Completed

## Hardening Implemented
Based on the security review recommendations from T-02838, the following defense-in-depth measures were applied in `code/aiosh-cli/src/pep.ts`:

1. **Input Bounding & Payload Denial-of-Service Protection**:
   - Implemented length checks on `tool` and `command` inputs:
     ```typescript
     const MAX_PARAM_LEN = 8192;
     if (tool.length > MAX_PARAM_LEN || command.length > MAX_PARAM_LEN) {
       return { ok: false, reason: "tool or command parameter exceeds maximum allowed length (8192)" };
     }
     ```
   - Prevents memory bloat, oversized SQLite transactions, and log flooding.

2. **Distinct Single-Use vs Multi-Use State Updates**:
   - Single-use grants enforce conditional atomic update:
     ```typescript
     UPDATE pep_grants SET redeemed_at = ? WHERE grant_id = ? AND redeemed_at IS NULL
     ```
   - Multi-use grants update `redeemed_at` to record latest invocation timestamp without locking out future legitimate executions.

3. **Fail-Closed State Rollback on Audit Failure**:
   - Wrapped `ring.write(...)` in a `try...catch` block.
   - If writing the audit record to `audit_ring` fails (e.g. disk quota exhaustion or database constraint violation), the method automatically rolls back `redeemed_at` back to `NULL` before returning `ok: false`.
   - Ensures that database state and audit log never desynchronize.

4. **Verification**:
   - TypeScript build passed cleanly (`npm run build`).
   - Unit test suite (`test_restraint_mint_redeem.py`) passed.
   - Integration test suite (`test_por_integration.py`) passed.
