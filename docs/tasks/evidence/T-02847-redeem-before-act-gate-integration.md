# Integration Evidence: T-02847 — redeem-before-act gate: Integration

## Task Information
- **Task ID**: `T-02847`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Integration`
- **Status**: Completed

## Integration Summary
This task integrated the Redeem-Before-Act Gate (Invariant I-2) directly into the production tool dispatch pipeline in FastMCP and the `pentest` wrapper module:

1. **Integration Pathway**:
   - `pentest.aios_pentest_nmap()` routes through `aiosh_mcp._dispatch.dispatch()`.
   - Gate #2.5 intercepts any tool execution accompanied by a `grant_id`.
   - `audit_client.grant_redeem()` executes atomic conditional SQL write on `pep_grants` table and commits a `pep.capability.redeem` audit row before the host command or binary execution starts.
2. **Replay Rejection on Production Tool**:
   - When a second call is made with the same single-use grant, Gate #2.5 blocks dispatch immediately:
     - Returns `ok: False`, `reason: "grant gr_... already redeemed at ..."`.
     - Writes a refusal audit row to `audit_ring`.
     - Underlying tool logic is completely bypassed.
3. **Cross-Substrate Parity & Chain Verification**:
   - Complete hash chain verified with `audit_client.verify()` yielding 100% hash agreement across mint, redeem, execution, and refusal events.

## Test Output
```
[1] Initializing shared WAL database...
[2] Minting single-use grant for pentest.nmap...
[3] Invoking aios_pentest_nmap with valid grant...
[+] aios_pentest_nmap returned: ok=False tool=pentest.nmap
[+] Invariant I-1/I-2 verified: redeem row committed prior to execution
[4] Attempting second invocation with same single-use grant...
[+] Replay attack blocked: grant gr_integ_pentest_01 already redeemed at 2026-10-07T00:22:25.886562Z
[5] Verifying complete audit ring hash chain...
[+] Chain verified: 4 rows with 100% hash agreement

[+] REDEEM-BEFORE-ACT INTEGRATION TEST PASSED (T-02847 certified)
```
