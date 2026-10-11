# Research: Automated Tests for Compliance Mapping (T-02913)

**Task ID**: T-02913 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Research)  
**Contract**: `docs/tasks/evidence/T-02904-spec.md`, `docs/SPEC-COMPLIANCE-CONFIG.md`  
**Date**: 2026-10-11  
**Status**: COMPLETE — Established facts, constraints, authoritative standards, and prior art for the automated test suite of Compliance Mapping. No code changed.

---

## 1. Authoritative Sources & Regulatory Citations

1. **NIST Special Publication 800-53 Revision 5**:
   *Security and Privacy Controls for Information Systems and Organizations* (Sept 2020, updated Dec 2020). Controls require deterministic traceability between technical security policies, automated PEP rules, and control identifiers (e.g. `AC-3`, `AU-2`, `IA-2`, `SC-7`).
2. **AICPA Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (SOC 2)**:
   TSP section 100 (2017). Requires affirmative controls for logical access (`CC6.1`, `CC6.2`) and system change management (`CC8.1`).
3. **ISO/IEC 27001:2022**:
   *Information security, cybersecurity and privacy protection — Information security management systems*. Annex A controls (A.5.15, A.8.2, A.8.3, A.8.20).
4. **EU Artificial Intelligence Act (Regulation (EU) 2024/1689)**:
   Chapter III (High-Risk AI Systems) Article 9 (Risk Management System) and Article 12 (Record-Keeping & Automated Logging). Mandatory attestation of non-tamperable audit and deterministic access restraint.
5. **AIOS Architectural Decisions**:
   - `ADR-0035`: PEP Architecture & Fail-Closed Gates.
   - `ADR-0037`: Proof of Restraint (Negative Attestation & Capability Token Redemption).

---

## 2. Established Facts vs Assumptions

### Established Facts
- **Fact 1 (Cross-Substrate Parity)**: Compliance Mapping exists on both Rust (`aiosh-core::compliance_service`, `aiosh-core::compliance_config`) and Python (`aiosh_mcp.compliance`, `aiosh_mcp.compliance_config`). They share the same canonical JSON serialization schema (`docs/compliance_map.json`).
- **Fact 2 (PEP Gating & Proof of Restraint)**: Every state-changing action (`init`, `register`, `update_status`, `delete`) is PEP-gated. Under ADR-0037 / Invariant I-2, dispatch requires pre-execution redemption of capability tokens.
- **Fact 3 (Precedence Ladder)**: Store resolution follows the strict 4-level precedence ladder: `--path` (Level 1) > `AIOSH_COMPLIANCE_MAP_PATH` (Level 2) > Config file (Level 3: `--config` / `AIOSH_COMPLIANCE_CONFIG` / `docs/compliance_config.json`) > Default store (Level 4: `docs/compliance_map.json`).
- **Fact 4 (Resource Bounds)**: Config file size is capped at 64 KiB pre-parse. Store file size is capped at 16 MiB. Entries are bounded to 4,096. Identifiers are bounded to 64 bytes.

### Assumptions
- **Assumption 1**: Automated tests should mirror existing Phase 2 patterns (`test_*_automated.rs` in Rust and `test_*_automated_smoke.py` in Python) providing 10 formal automated test vectors (`AUTOCOMPLIANCE1`..`AUTOCOMPLIANCE10`).
- **Assumption 2**: Cross-substrate concurrency and stress testing can be evaluated using temporary directory isolation without relying on global host state.

---

## 3. Prior Art in AIOS

The AIOS test architecture defines high-integrity automated test suites for security components:
- `test_threat_model_automated.rs`: Verifies lifecycle transitions (`Identified` -> `UnderReview` -> `Mitigated` -> `Resolved`), bounds, concurrent mutations, and PEP audit events.
- `test_audit_chain_automated.rs`: Verifies SHA-256 Merkle / hash-chain monotonicity, ancestry proofs, and truncation detection.
- `test_hardware_automated.rs`, `test_package_automated.rs`, `test_pep_grant_automated.rs`: Enforce domain invariants and fail-closed security envelopes.

---

## 4. Proposed Automated Verification Vectors (AUTOCOMPLIANCE1..AUTOCOMPLIANCE10)

| Vector ID | Target Invariant / Property | Description |
|---|---|---|
| **AUTOCOMPLIANCE1** | **Control Lifecycle & Status Transitions** | Tests valid transitions (`not_assessed -> in_progress -> compliant -> non_compliant -> not_applicable`). Rejects `compliant` without summary/reason. |
| **AUTOCOMPLIANCE2** | **Duplicate & ID Collision Prevention** | Rejects duplicate mapping IDs; preserves atomicity on failure. |
| **AUTOCOMPLIANCE3** | **String & Identifier Bounding** | Validates length limits for ID (`<= 64`), title (`<= 256`), summary (`<= 4096`), and rejection of control characters. |
| **AUTOCOMPLIANCE4** | **Precedence Ladder Resolution** | Rigorously asserts Level 1 > Level 2 > Level 3 > Level 4 resolution. |
| **AUTOCOMPLIANCE5** | **CWE-15 / CWE-22 Hygiene Protection** | Verifies rejection of path traversal (`..`), control characters, and length overflows in env variables. |
| **AUTOCOMPLIANCE6** | **Pre-Parse File Size Cap (CWE-400)** | Asserts 64 KiB config cap and 16 MiB store cap fail closed before allocation. |
| **AUTOCOMPLIANCE7** | **PEP Gating & Audit Logging** | Verifies ungranted writes fail closed; granted writes log an honest audit row. |
| **AUTOCOMPLIANCE8** | **Proof-of-Restraint Token Redemption (I-2)** | Proves mutation cannot occur without single-use token consumption. |
| **AUTOCOMPLIANCE9** | **Assessment Report Calculations** | Asserts numerical accuracy of total, compliant, non-compliant, in-progress counts and coverage percentages. |
| **AUTOCOMPLIANCE10** | **Concurrent Mutation & Atomic Replace** | Runs multi-threaded/concurrent reads and writes against temporary stores, verifying zero file corruption and zero `.tmp` leaks. |

---

## 5. Decisions Needed Before Specification (T-02914)

1. **Test Location**:
   - Rust: `code/aiosh-rust/aiosh-core/tests/test_compliance_automated.rs`.
   - Python: `code/aiosh-mcp/tests/test_compliance_automated_smoke.py`.
2. **Substrate Harness**:
   - Both suites will run standalone via `cargo test` and `pytest` using temporary filesystem sandboxes.
