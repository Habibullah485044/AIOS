# Unit Test Evidence: T-02846 — redeem-before-act gate: Unit Test

## Task Information
- **Task ID**: `T-02846`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Unit Test`
- **Status**: Completed

## Unit Test Coverage
The test suite `code/aiosh-mcp/tests/test_por_redeem_gate.py` was executed and certified covering positive, boundary, and negative test vectors:

1. **Happy Path Single-Use Redemption**:
   - Single-use grant issued for `pentest.nmap`.
   - Dispatch verifies scope and atomically commits `pep.capability.redeem` audit row.
   - DB state transitions `redeemed_at` from NULL to ISO timestamp.
2. **Replay Rejection (Double-Spend Protection)**:
   - Second dispatch attempt with the same single-use grant is refused at Gate #2.5.
   - Dispatch returns `ok: False`, reason contains `"already redeemed"`.
   - An audit row with `outcome: "refused"` is recorded.
   - Underlying tool execution is never reached.
3. **Expired Grant Rejection**:
   - Grant with `expires_at < now` is refused at gate with `"grant expired"`.
4. **Out-of-Scope Tool Rejection**:
   - Tool `pentest.nmap` requested with grant scoped only for `aios.fs.read` is refused with `"not in grant scope.tools"`.
5. **Irreversible Tool Without Grant**:
   - Consequential tool invocation with `grant_id=None` is refused at gate.
6. **Multi-Use Grants**:
   - Grants configured with `single_use=False` permit multiple successive redemptions, with each invocation recording a separate `pep.capability.redeem` row.
7. **Hash Chain Completeness**:
   - `audit_client.verify()` verifies 100% hash chain integrity across all events.

## Test Output
```
[1] Minting single-use grant for pentest.nmap...
[2] Executing first dispatch (should succeed and redeem token)...
[+] First dispatch passed gate
[+] Token atomically marked redeemed and pep.capability.redeem recorded
[3] Executing second dispatch (must be blocked by Invariant I-2)...
[+] Second dispatch blocked: grant gr_gate_test_01 already redeemed at 2026-10-07T00:18:33.526777Z
[4] Verifying complete cryptographic hash chain...
[+] Hash chain verified: 3 rows verified without gaps
[5] Testing expired and out-of-scope grant rejections at gate...
[+] Expired grant correctly refused: grant gr_expired expired
[+] Out of scope tool correctly refused: tool 'pentest.nmap' not in grant scope.tools=["aios.fs.read"]
[+] Missing grant on irreversible tool correctly refused
[6] Testing multi-use grant dispatch (multiple permitted redemptions)...
[+] Multi-use grant successfully allows repeated redemptions

[+] ALL REDEEM-BEFORE-ACT UNIT TESTS PASSED (T-02846 certified)
```
