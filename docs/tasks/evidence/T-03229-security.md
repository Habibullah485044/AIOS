# Security Review: AI Control Plane Model Backend Adapters Security Policy (T-03229)

**Task ID**: T-03229 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / security policy: Security Review)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, PoR Invariant I-2  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Security audit complete. Proof-of-Restraint Invariant I-2 verified, abuse scenarios documented and mitigated, and fail-closed audit trail emission verified.

---

## 1. Threat Modeling & Abuse Scenarios

| Threat ID | Threat Vector | Risk Description | Mitigation | Verified Status |
| :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | Unauthenticated State Mutation | Attacker attempts to invoke mutating actions (`complete`, `register`, `delete`, `reload_config`) without a capability token. | `ModelSecurityPolicy.evaluate()` strictly gates all `MUTATING_ACTIONS` behind a non-empty, non-whitespace capability token. Fails closed with `POLICY_UNAUTHORIZED`. | Mitigated & Tested |
| **THREAT-02** | NUL Byte Injection Attack | Attacker embeds `\0` in prompts or backend registration configurations to cause string truncation or downstream memory unsafety. | `ModelSecurityPolicy.sanitize()` checks `chr(0) in text` and rejects with `POLICY_REJECT_PAYLOAD`. | Mitigated & Tested |
| **THREAT-03** | Denial-of-Service via Oversized Payload | Attacker passes multi-megabyte payloads to exhaust system buffers or inference memory. | `MAX_PAYLOAD_BYTES` (1 MiB) ceiling enforced pre-parsing. Payloads exceeding 1,048,576 bytes are rejected fail-closed. | Mitigated & Tested |
| **THREAT-04** | Secret Disclosure in Audit Trails | Raw API tokens or credential strings logged during evaluation failures. | `redact_secrets()` sanitizes Bearer tokens, `sk-*`, and `ghp_*` tokens across audit records and error outputs. | Mitigated & Tested |
| **THREAT-05** | Audit Bypass on Evaluation Failure | Evaluation failures or policy refusals bypass immutable ledger logging. | Every evaluation branch returns an explicit `PolicyVerdict` with an attached `audit_record` (`verdict: "allow"` or `verdict: "refuse"`), guaranteeing auditable event emission. | Mitigated & Tested |

---

## 2. Proof-of-Restraint Invariant I-2 Standing Rule Verification

- **Standing Rule**: If this component adds or changes any state-changing path, confirm it cannot execute without redeeming a capability token (docs/proof-of-restraint/PLAN.md invariant I-2).
- **Verification**:
  - `MUTATING_ACTIONS = {"complete", "register", "delete", "reload_config"}`
  - When `action in MUTATING_ACTIONS` and `token` is `None` or whitespace:
    - Verdict: `allowed = False`
    - Reason: `POLICY_UNAUTHORIZED: Missing mandatory capability token for mutating action`
    - Audit: `{"action": action, "verdict": "refuse", "reason": "missing_token"}`
  - No bypass path exists. Pure read actions (`READ_ACTIONS = {"list", "show", "health", "ping"}`) require zero tokens.

---

## 3. Residual Risks & Hardening Recommendations

- **Hardening Candidate for T-03230**:
  - Add explicit bounds clamping and timeout constraints in `ModelSecurityPolicy` for long-running policy evaluations.
  - Ensure zero memory leaks or unhandled exceptions under malformed UTF-8 payloads.
