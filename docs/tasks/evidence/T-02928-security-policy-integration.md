# Artifact: T-02928 Compliance Mapping Security Policy Integration

- **Task**: T-02928 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / security policy: Integration)
- **Status**: Complete
- **Rust Substrate Integration**:
  - Bound `policy: Option<ComplianceSecurityPolicy>` directly to `ComplianceService`.
  - Added constructors and helper accessors: `with_policy()`, `set_policy()`, `policy()`, `policy_mut()`, and `assess_framework_with_policy()`.
  - Integrated policy evaluation checks into `register_mapping()` and `update_status()`.
  - Created integration test suite: `code/aiosh-rust/aiosh-core/tests/test_compliance_policy_integration.rs`:
    - Registration policy enforcement (`COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED`, `COMPLIANCEPOL_ERR_THREAT_REQUIRED`).
    - Lifecycle transition policy enforcement (`COMPLIANCEPOL_ERR_MITIGATION_REQUIRED`).
    - Assessment threshold evaluation (`COMPLIANCEPOL_ERR_THRESHOLD_UNMET`).
    - Persistence roundtrip with active policy.
    - Verified: 1/1 passed.
- **Python Substrate Integration**:
  - Integrated policy evaluation into `aiosh_mcp.compliance.register_mapping()` and `update_status()`.
  - Created integration test suite: `code/aiosh-mcp/tests/test_compliance_policy_integration.py`:
    - Full end-to-end flow verified across canonical baseline, custom registrations, status mutations, threshold evaluation, and file storage.
    - Verified: 1/1 passed.
- **Handoff**: T-02929 (Security Review).
