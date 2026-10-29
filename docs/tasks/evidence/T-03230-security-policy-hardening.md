# Hardening Evidence: AI Control Plane Model Backend Adapters Security Policy (T-03230)

**Task ID**: T-03230 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / security policy: Hardening)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0035 §F-2, PoR Invariant I-2  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Hardening defenses verified across payload boundaries, token size limits, NUL-byte rejection in action and token strings, fail-closed exception handling with secret redaction, and standardized ADR-0035 §AF-2 result envelope.

---

## 1. Hardening Mitigations Implemented

1. **Token Boundaries & Injection Prevention**:
   - `sanitize_token()` checks that capability tokens do not exceed `MAX_TOKEN_LEN = 512` characters.
   - Rejects any embedded NUL bytes (`\x00`) in tokens with `POLICY_REJECT_TOKEN`.

2. **Action Sanitization**:
   - `action` parameter validated to be between 1 and 64 characters (`MAX_ACTION_LEN`).
   - Rejects embedded NUL bytes in action identifiers.

3. **ADR-0035 §F-2 Fail-Closed Error Envelopes**:
   - Added `to_envelope()` on `PolicyVerdict` returning `{status, ok, reason, audit, timestamp}`.
   - Any unexpected runtime exception is caught, redacted via `redact_secrets()`, and reported as `POLICY_INTERNAL_ERROR` with an honest refuse audit record.

4. **Payload Ceiling**:
   - Strict 1 MiB (`MAX_PAYLOAD_BYTES = 1048576`) pre-parsing boundary enforced.

---

## 2. Hardening Verification Test Results

```
code\aiosh-mcp\tests\test_model_backend_adapters_security_policy_hardening.py .... [ 33%]
code\aiosh-mcp\tests\test_model_backend_adapters_security_policy_impl.py ...      [ 58%]
code\aiosh-mcp\tests\test_model_backend_adapters_security_policy_integration.py . [ 66%]
code\aiosh-mcp\tests\test_model_backend_adapters_security_policy_scaffold.py ..   [ 83%]
code\aiosh-mcp\tests\test_model_backend_adapters_security_policy_unit.py ..       [100%]

===================== 12 passed, 778 deselected in 6.19s ======================
```
