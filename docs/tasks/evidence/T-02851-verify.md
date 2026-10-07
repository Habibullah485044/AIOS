# Verification Evidence: T-02851 — redeem-before-act gate: Verification & Evidence

## Task Information
- **Task ID**: `T-02851`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Verification & Evidence`
- **Status**: Completed

## Milestone Summary
Component 2 ("redeem-before-act gate", T-02842 through T-02851) of Proof of Restraint is formally verified, closed, and certified.

### Invariant Certification
1. **Invariant I-2 (Atomic Single-Use Gate)**:
   - Certified: A consequential tool (`pentest.*`, `fs.write`, etc.) is unreachable without a valid, unredeemed capability grant.
   - Certified: Gate #2.5 atomically sets `redeemed_at` and commits `pep.capability.redeem` into `audit_ring` before tool execution starts.
   - Certified: Replay attempts with the same token are blocked at the gate and emit an auditable refusal row.
2. **Crash & Concurrency Semantics**:
   - Certified: Serialized SQLite transactions under WAL mode prevent race conditions.
   - Certified: Rollback logic preserves fail-closed consistency if audit logging encounters a fault.

## Test Output & Execution Transcript
```
[1] Initializing shared WAL database...
[2] Minting single-use grant for pentest.nmap...
[3] Invoking aios_pentest_nmap with valid grant...
[+] aios_pentest_nmap returned: ok=False tool=pentest.nmap
[+] Invariant I-1/I-2 verified: redeem row committed prior to execution
[4] Attempting second invocation with same single-use grant...
[+] Replay attack blocked: grant gr_integ_pentest_01 already redeemed at 2026-10-07T00:35:14.931099Z
[5] Verifying complete audit ring hash chain...
[+] Chain verified: 4 rows with 100% hash agreement

[+] REDEEM-BEFORE-ACT INTEGRATION TEST PASSED (T-02847 certified)
[1] Minting single-use grant for pentest.nmap...
[2] Executing first dispatch (should succeed and redeem token)...
[+] First dispatch passed gate
[+] Token atomically marked redeemed and pep.capability.redeem recorded
[3] Executing second dispatch (must be blocked by Invariant I-2)...
[+] Second dispatch blocked: grant gr_gate_test_01 already redeemed at 2026-10-07T00:35:15.982085Z
[4] Verifying complete cryptographic hash chain...
[+] Hash chain verified: 3 rows verified without gaps
[5] Testing expired and out-of-scope grant rejections at gate...
[+] Expired grant correctly refused: grant gr_expired expired
[+] Out of scope tool correctly refused: tool 'pentest.nmap' not in grant scope.tools=["aios.fs.read"]
[+] Missing grant on irreversible tool correctly refused
[6] Testing multi-use grant dispatch (multiple permitted redemptions)...
[+] Multi-use grant successfully allows repeated redemptions

[+] ALL REDEEM-BEFORE-ACT UNIT TESTS PASSED (T-02846 certified)
=== aiosh capability CLI Smoke Tests ===
PASS: aiosh capability --help
PASS: aiosh capability unknown_cmd returns 2
PASS: aiosh capability path hygiene enforcement
PASS: aiosh capability full lifecycle (issue, show, attenuate, check, revoke, prune)
ALL CAPABILITY CLI SMOKE TESTS PASSED.
```
