# Artifact: T-02927 Compliance Mapping Security Policy Unit Test

- **Task**: T-02927 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / security policy: Unit Test)
- **Status**: Complete
- **Rust Test Suite**:
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_policy_unit.rs`: 12 tests covering:
    - Default policy validation & defaults
    - Version boundaries (`COMPLIANCEPOL_ERR_VALIDATION`)
    - Capacity and percentage bounds checks
    - Registration evaluation happy path and negative paths (`COMPLIANCEPOL_ERR_THREAT_REQUIRED`, `COMPLIANCEPOL_ERR_MITIGATION_REQUIRED`, `COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED`)
    - Permissive and disabled modes
    - Status transition evaluation
    - Assessment threshold evaluation (`COMPLIANCEPOL_ERR_THRESHOLD_UNMET`)
    - Capacity limit and override evaluation (`COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED`, `COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN`)
    - Atomic JSON file persistence roundtrip
  - Result: 12 passed, 0 failed.
- **Python Test Suite**:
  - `code/aiosh-mcp/tests/test_compliance_policy_unit.py`: 12 tests covering identical invariants across Python/MCP substrate.
  - Result: 12 passed, 0 failed.
- **Handoff**: T-02928 (Integration).
