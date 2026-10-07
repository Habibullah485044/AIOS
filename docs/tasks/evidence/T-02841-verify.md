# Verification Evidence: T-02841 — capability mint/redeem records: Verification & Evidence

## Task Information
- **Task ID**: `T-02841`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / capability mint/redeem records`
- **Title**: `capability mint/redeem records: Verification & Evidence`
- **Status**: Completed

## Verification Summary
Component 1 ("capability mint/redeem records", T-02832 through T-02841) of Proof of Restraint is formally verified and closed.

### Invariant Certification
1. **Invariant I-1 (Mint-to-Redeem 1:1 Parity)**:
   - Certified: Grant minting records `pep.capability.mint` in the hash chain.
   - Certified: Grant use records exactly one `pep.capability.redeem` in the hash chain.
   - Certified: Single-use grants cannot be redeemed twice.
2. **Invariant I-2 (Atomic Single-Use Gate)**:
   - Certified: Database conditional update locks single-use tokens atomically.
   - Certified: Double-spend attempts are refused with `ok: false`.
3. **Cross-Substrate Parity**:
   - Certified: Canonical JSON encoding produces identical SHA-256 hashes across TypeScript and Python runtimes.

## Test Output & Execution Transcript
```
[1] Minting capability grant with pep.capability.mint audit record...
[+] Mint audit row written: hash=3f7b4ffcde7436d8... seq=1
[2] Checking capability unspent status before redemption...
[+] Grant is unspent and active
[3] Redeeming capability grant with pep.capability.redeem audit record...
[+] Redeem audit row written: hash=4fcc3d42568904c1... seq=2
[4] Attempting second redemption on single-use grant...
[+] Second redemption refused: single-use grant cannot be double-spent
[5] Verifying complete audit ring hash chain...
[+] Audit ring chain intact: checked 2 rows with 100% hash agreement
[6] Testing expired grant redemption rejection...
[+] Expired grant correctly rejected for redemption
[7] Testing cryptographic tamper detection in audit chain...
[+] Tamper detection verified: broken_at=2

[+] ALL RESTRIANT UNIT TESTS PASSED (T-02836 certified)
[1] Initializing shared WAL database...
[2] Minting capability grant (pep.capability.mint)...
[+] Mint row committed: id=1 hash=95b42638a2162454...
[3] Verifying grant unspent status...
[+] Grant is active and unspent
[4] Executing redeem-before-act gate (pep.capability.redeem)...
[+] Redeem row committed: id=2 hash=0eb87417de51cab1...
[5] Verifying replay / double-spend refusal...
[+] Replay blocked: single-use capability cannot be redeemed again
[6] Verifying end-to-end hash chain integrity...
[+] Hash chain verified: 100% cryptographic integrity across all rows

[+] RESTRIANT INTEGRATION TEST PASSED (T-02837 certified)
=== aiosh capability CLI Smoke Tests ===
PASS: aiosh capability --help
PASS: aiosh capability unknown_cmd returns 2
PASS: aiosh capability path hygiene enforcement
PASS: aiosh capability full lifecycle (issue, show, attenuate, check, revoke, prune)
ALL CAPABILITY CLI SMOKE TESTS PASSED.
```
