# Security Review: Compliance Mapping Security Policy (T-02929)

**Task ID**: T-02929  
**Component**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / security policy: Security Review  
**Auditor**: Antigravity Security & PEP Kernel Auditor  
**Date**: 2026-10-11  
**Scope**: `code/aiosh-rust/aiosh-core/src/compliance_policy.rs`, `code/aiosh-mcp/aiosh_mcp/compliance_policy.py`, `code/aiosh-rust/aiosh-core/src/compliance_service.rs`, `code/aiosh-mcp/aiosh_mcp/compliance.py`, unit & integration test suites  
**Normative Spec**: `docs/tasks/evidence/T-02924-spec.md`, `ADR-0035`, `ADR-0036`  

---

## 1. Executive Summary

This security review audits the security policy subsystem of Compliance Mapping (`T-02923`..`T-02932`). The security policy provides declarative governance over control registration, lifecycle transitions (especially marking controls `Compliant`), framework whitelisting, threat linkage enforcement, assessment threshold gates, and capacity limits across both Rust and Python substrates.

The audit verified:
1. **Input Validation Rigor**: Structural policy invariants (`COMPLIANCEPOL1`) require version `"1."` and bounded bounds (`max_catalog_mappings` in `[1, 4096]`, `min_compliant_percentage` in `[0.0, 100.0]`).
2. **Mitigation Enforcement**: Controls cannot be marked `Compliant` without documented mitigation rationale (minimum 3 non-whitespace characters), preventing fraudulent compliance claims.
3. **Framework Whitelisting & Threat Linkage**: Enforces strict framework confinement and mandatory threat ID linking, preventing unapproved framework pollution or orphaned control assertions.
4. **File Bounds & Symlink Protections**: Policy files strictly reject symlinks and enforce pre-read byte limits (`MAX_COMPLIANCE_SECURITY_POLICY_BYTES = 65_536`) with atomic temporary file writes.
5. **[PoR] Proof-of-Restraint Invariant I-2**: Any state-changing modification must redeem a cryptographic capability token (`cap:compliance:admin` / `grant_token`) at the PEP gate before committing state.

---

## 2. Abuse Scenarios & Threat Modeling Analysis

| Abuse ID | Threat Scenario | Attack Vector & Surface | System Defense / Test Coverage | Status |
|---|---|---|---|---|
| **AS-COMPPOL-01** | **Fraudulent Compliance Attestation** | Attacker attempts to mark non-compliant controls as `Compliant` with empty or blank mitigation summaries to bypass audit requirements. | `evaluate_status_transition` and `evaluate_registration` require non-empty `mitigation_summary` (≥ 3 characters) under `require_mitigation_on_compliant`. Fails closed with `COMPLIANCEPOL_ERR_MITIGATION_REQUIRED`. Tested in unit & integration suites. | **VERIFIED PASS** |
| **AS-COMPPOL-02** | **Framework Injection & Scope Pollution** | Attacker registers controls under unauthorized or unregulated frameworks (e.g. HIPAA on a NIST-only system). | `permitted_frameworks` whitelist evaluation rejects non-permitted frameworks fail-closed with `COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED`. Tested in unit & integration suites. | **VERIFIED PASS** |
| **AS-COMPPOL-03** | **Orphaned Control / Missing Threat Linkage** | Attacker registers compliance mappings without linking any threat IDs, breaking risk-to-control traceability. | `require_threat_linkage` rejects entries where `threat_ids` is empty, failing closed with `COMPLIANCEPOL_ERR_THREAT_REQUIRED`. Tested in unit & integration suites. | **VERIFIED PASS** |
| **AS-COMPPOL-04** | **Posture Score Dilution / False Approval** | Attacker claims system compliance approval despite assessment scores falling below enterprise thresholds. | `evaluate_assessment` compares `compliance_percentage` against `min_compliant_percentage`. Sub-threshold assessments return `Deny` with `COMPLIANCEPOL_ERR_THRESHOLD_UNMET`. Tested in unit & integration suites. | **VERIFIED PASS** |
| **AS-COMPPOL-05** | **Unauthorized Canonical Baseline Override** | Attacker attempts to bypass compliance rules by issuing canonical baseline override requests. | `evaluate_override` rejects overrides fail-closed with `COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN` unless `allow_canonical_override: true` is explicitly configured. Tested in unit & integration suites. | **VERIFIED PASS** |
| **AS-COMPPOL-06** | **Symlink Traversal & Size Exhaustion (CWE-59 / CWE-400)** | Attacker replaces policy config file with a symlink to sensitive files, or writes an oversized file to exhaust memory. | Pre-read metadata check rejects symlinks fail-closed with `COMPLIANCEPOL_ERR_IO`. Rejects files exceeding 64 KiB prior to parsing. Atomic temporary file rename prevents partial write corruption. | **VERIFIED PASS** |

---

## 3. Proof-of-Restraint [PoR] Review (Invariant I-2)

- **Requirement**: No state-changing path may execute without redeeming a single-use capability token.
- **Verification**:
  - Updating policy configuration (`save_to_path` / MCP policy update) and mutating compliance entries (`register_mapping`, `update_status`) require valid PEP capability token redemption (`grant_token`).
  - Wire integration tests verify that ungranted mutating requests are refused fail-closed at the PEP gate with zero filesystem state change and a single refusal audit row in `audit_ring`.
- **Finding**: Invariant I-2 holds unconditionally across the compliance mapping security policy subsystem.

---

## 4. Findings & Recommendations for Hardening (T-02930)

- **Finding F-1**: Ensure fail-open behavior is strictly impossible in `Enforcing` mode; any unhandled exception or parsing defect must result in fail-closed `Deny` or explicit error envelopes.
- **Finding F-2**: All temporary files used in atomic file save operations must be cleaned up on error paths to prevent residue accumulation.
- **Status**: Zero blocking vulnerabilities or policy bypasses remain open.
