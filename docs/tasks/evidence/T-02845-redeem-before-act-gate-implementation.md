# Implementation Evidence: T-02845 — redeem-before-act gate: Implementation

## Task Information
- **Task ID**: `T-02845`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Implementation`
- **Status**: Completed

## Implementation Summary
1. Implemented `audit_client.grant_redeem()` in `code/aiosh-mcp/aiosh_mcp/audit_client.py`:
   - Checks validity, unspent status, expiry, and glob scope matches.
   - Executes atomic SQL update on SQLite WAL database:
     ```sql
     UPDATE pep_grants SET redeemed_at = ?
     WHERE grant_id = ? AND redeemed_at IS NULL AND revoked_at IS NULL
     ```
   - Emits `pep.capability.redeem` audit row into `audit_ring` before returning `ok: True`.
   - Incorporates automatic rollback if `write_audit_row` fails (fail-closed guarantee).
2. Wired `grant_redeem()` into `aiosh_mcp._dispatch.dispatch()` in `code/aiosh-mcp/aiosh_mcp/_dispatch.py`:
   - Enforces Gate #2.5: when a grant is supplied, it is atomically redeemed before dispatch returns `ok: True`.
   - If redemption fails (already redeemed, expired, or concurrent collision), dispatch immediately returns `ok: False`, writes a refusal row, and blocks tool invocation entirely.
3. Created test suite `code/aiosh-mcp/tests/test_por_redeem_gate.py`:
   - Verified first dispatch succeeds and commits `pep.capability.redeem`.
   - Verified second dispatch with same single-use token is blocked at Gate #2.5.
   - Verified complete hash chain integrity across all events.

## Test Output
```
[1] Minting single-use grant for pentest.nmap...
[2] Executing first dispatch (should succeed and redeem token)...
[+] First dispatch passed gate
[+] Token atomically marked redeemed and pep.capability.redeem recorded
[3] Executing second dispatch (must be blocked by Invariant I-2)...
[+] Second dispatch blocked: grant gr_gate_test_01 already redeemed at 2026-10-07T00:15:24.260658Z
[4] Verifying complete cryptographic hash chain...
[+] Hash chain verified: 3 rows verified without gaps

[+] REDEEM-BEFORE-ACT GATE IMPLEMENTATION CERTIFIED (T-02845)
```
