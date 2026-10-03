# T-02707: Threat Model Maintenance Data Model Security Review

- **Task**: `T-02707`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / data model
- **Date**: 2026-10-03
- **Status**: PASSED (Security Review Complete)

## 1. Threat Modeling & Scope
Audited the `ThreatCategory`, `ThreatSeverity`, `ThreatStatus`, `ThreatEntry`, and `ThreatModelSnapshot` domain structures against the AIOS Threat Model and Common Weakness Enumerations (CWEs).

## 2. CWE Analysis & Audit Matrix

| CWE | Vulnerability Class | Vector & Scenario | Audit Finding & Applied Mitigation | Status |
|---|---|---|---|---|
| **CWE-20** | Improper Input Validation | Attacker or untrusted tool submits path-like (`../../TM01`) or shell metacharacter IDs. | **Mitigated**: `validate_id()` enforces strict ASCII alphanumeric, underscore, and hyphen characters, capped at 64 bytes. | VERIFIED |
| **CWE-150 / CWE-116** | Control Character Injection | Threat titles or descriptions inject ANSI escape sequences (`\x1b`) to manipulate terminal logs. | **Mitigated**: `validate_title()` and `validate_description()` reject non-whitespace control characters fail-closed. | VERIFIED |
| **CWE-400** | Resource Exhaustion (DoS) | Unbounded vectors of mitigations or CWE IDs exhausting memory. | **Mitigated**: `MAX_CWE_COUNT = 16`, `MAX_MITIGATIONS_COUNT = 16`, description bounded to 2048 bytes. | VERIFIED |
| **CWE-840** | State Machine Logic Bypass | Bypassing review or marking threats as `Mitigated` without actual mitigations present. | **Finding for Hardening (T-02708)**: Enforce rule in `transition_to(ThreatStatus::Mitigated)` requiring `!self.mitigations.is_empty()`. | ACTION PLANNED |
| **CWE-200 / CWE-312** | Information Disclosure | Leaking credentials or private keys in threat descriptions or mitigations. | **Finding for Hardening (T-02708)**: Add scanner rejecting obvious secret headers (e.g., `-----BEGIN PRIVATE KEY-----`) in description and mitigations. | ACTION PLANNED |

## 3. Remediation & Hardening Actions for T-02708
1. **Mitigation Requirement on State Transition**: Disallow transitioning an entry to `ThreatStatus::Mitigated` unless at least one mitigation has been recorded.
2. **Secret Pattern Rejection**: Add heuristic validation rejecting private key blocks and common token formats in descriptions and mitigations.
