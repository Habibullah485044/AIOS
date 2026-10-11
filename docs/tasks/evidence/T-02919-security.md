# Security Review: Compliance Mapping Automated Tests (T-02919)

**Task ID**: T-02919  
**Component**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Security Review  
**Auditor**: Antigravity Security & PEP Kernel Auditor  
**Date**: 2026-10-11  
**Scope**: `code/aiosh-mcp/tests/test_compliance_automated_smoke.py`, `code/aiosh-mcp/tests/test_compliance_automated_unit.py`, `code/aiosh-rust/aiosh-core/tests/test_compliance_automated.rs`, `code/aiosh-rust/aiosh-core/tests/test_compliance_automated_unit.rs`, `code/aiosh-mcp/tests/test_compliance_integration.py`  
**Normative Spec**: `docs/tasks/evidence/T-02914-spec.md`, `ADR-0035`, `ADR-0037`  

---

## 1. Executive Summary

This security review audits the automated test suites designed and implemented for the Compliance Mapping subsystem. The automated test battery exercises vectors `AUTOCOMPLIANCE1` through `AUTOCOMPLIANCE10` across unit, smoke, and integration layers on both Python (MCP) and Rust (core/CLI) substrates.

The audit verified:
1. **Input Validation Rigor**: Negative test cases assert fail-closed rejection for malformed identifiers, unescaped control characters, oversized text fields, invalid framework tags, and capacity overflows.
2. **Path Traversal & Injection Defense**: Automated tests rigorously evaluate CWE-15 and CWE-22 path injection vectors (`../`, null bytes, control characters, path depth > 16) ensuring zero leakage or arbitrary file read/write.
3. **Pre-Parse File Size Defense**: Both config (64 KiB) and store (1 MiB / 16 MiB) pre-parse byte bounds are asserted to prevent memory exhaustion (CWE-400).
4. **Audit Immutability & Row Integrity**: The immutability of `audit_all_mutations: true` is asserted; consequential operations consistently commit structured audit rows to `audit_ring`.
5. **[PoR] Proof-of-Restraint Invariant I-2**: All state-changing test harnesses verify capability token redemption (`grant_id`); ungranted writes fail closed (`PEP_DENIED`) leaving store files byte-for-byte intact.

---

## 2. Abuse Scenarios & Threat Modeling Analysis

| Abuse ID | Threat Scenario | Attack Vector & Surface | System Defense / Test Coverage | Status |
|---|---|---|---|---|
| **AS-AUTO-01** | **Path Traversal Injection in Test Harnesses** | Attacker supplies traversal string (`../../etc/shadow.json`) into test path arguments to access arbitrary filesystem targets. | `ComplianceService::validate_path` and `compliance.validate_path` reject `..`, non-JSON extensions, and control characters fail-closed with `COMPLIANCESVC_ERR_PATH_TRAVERSAL`. Covered by `AUTOCOMPLIANCE5` and `AUTOCOMPLIANCE10`. | **VERIFIED PASS** |
| **AS-AUTO-02** | **Ungranted State Mutation / Privilege Bypass** | Attacker invokes mutating compliance operations (`register`, `status`, `init`) without redeeming a valid capability token. | MCP server gates mutating tools behind PEP verification. Ungranted requests are refused fail-closed with zero state modification and emit a single rejection audit row. Covered by `AUTOCOMPLIANCE8` and integration wire tests. | **VERIFIED PASS** |
| **AS-AUTO-03** | **Memory Exhaustion via Huge Input** (CWE-400) | Attacker supplies oversized JSON payloads or large arrays (> 16 threats, > 1024 entries) to trigger OOM in parsing processes. | Bounded reads enforce `MAX_CONFIG_FILE_BYTES` (64 KiB) and `MAX_COMPLIANCE_STORE_SIZE` (1 MiB) prior to deserialization. Entry and array bounds are strictly enforced. Covered by `AUTOCOMPLIANCE3` and `AUTOCOMPLIANCE6`. | **VERIFIED PASS** |
| **AS-AUTO-04** | **Audit Suppression Attempt** | Operator or compromised agent attempts to disable mutation auditing by setting `audit_all_mutations: false` in custom config. | Config validation clamps `audit_all_mutations` to `true` unconditionally; disabling mutation auditing is architecturally impossible. Covered by `AUTOCOMPLIANCE7`. | **VERIFIED PASS** |
| **AS-AUTO-05** | **Race Condition / Incomplete Write File Corruption** | Concurrent writes or crash during save causes truncated or malformed store JSON. | Storage operations write to uniquely-named temporary files (`.tmp.<nanos>`) and execute atomic filesystem renames upon completion. Rollback cleanup removes temp files on error. Covered by `AUTOCOMPLIANCE10`. | **VERIFIED PASS** |

---

## 3. Proof-of-Restraint [PoR] Review (Invariant I-2)

- **Requirement**: No state-changing path may execute without redeeming a single-use capability token.
- **Verification**:
  - Integration suite `test_wire_ungranted_write_refused_fail_closed` verifies that ungranted calls produce zero filesystem writes and exactly one refusal audit record.
  - `test_wire_granted_write_persists_store` confirms that granted calls redeem the token and commit the operation.
  - `test_automated_vectors_e2e_cross_substrate` confirms that multi-step operations over wire stdio require and track valid grants in the local audit ring.
- **Finding**: Invariant I-2 holds unconditionally across all automated test harnesses.

---

## 4. Findings & Recommendations for Hardening (T-02920)

- **Finding F-1**: All automated tests create isolated temporary directories (`tempfile::tempdir`, `tmp_path`, `TemporaryDirectory`) that clean up on drop/exit. Ensure explicit timeout thresholds on all subprocess runners.
- **Finding F-2**: Error reporting in all automated test assertions asserts explicit error codes (`COMPLIANCE_ERR_*`, `COMPLIANCESVC_ERR_*`, `PARAM_INVALID`) rather than generic string matching.
- **Status**: No blocking vulnerabilities or policy bypasses found.
