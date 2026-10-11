# Scaffold Evidence: Compliance Mapping Observability (T-02935)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Observability
- **Task ID**: `T-02935`
- **Files Created / Modified**:
  - `code/aiosh-rust/aiosh-core/src/compliance_observability.rs` (created)
  - `code/aiosh-rust/aiosh-core/src/lib.rs` (registered `compliance_observability` module)
  - `code/aiosh-mcp/aiosh_mcp/compliance_observability.py` (created)
  - `code/aiosh-mcp/aiosh_mcp/compliance.py` (added `stats` action and scaffold dispatch stub)
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_observability_scaffold.rs` (created test stub)
  - `code/aiosh-mcp/tests/test_compliance_observability_scaffold.py` (created test stub)

## 1. Scaffolded Symbols & Interfaces

### 1.1 Constants & Types
- `COMPOBS_ERR_VALIDATION = "COMPOBS_ERR_VALIDATION"`
- `COMPOBS_ERR_SERVICE_INACCESSIBLE = "COMPOBS_ERR_SERVICE_INACCESSIBLE"`
- `MAX_TELEMETRY_TEXT_LEN = 256`
- `MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128`
- `MAX_AUDIT_LOG_TAIL_ITEMS = 1000`
- `ComplianceObservabilityReport`
- `sanitize_telemetry_text(s)`

### 1.2 Verification Runs
- `cargo check --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core`: PASS
- `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_compliance_observability_scaffold`: PASS (1/1 passed)
- `python -m pytest code/aiosh-mcp/tests/test_compliance_observability_scaffold.py`: PASS (1/1 passed)
