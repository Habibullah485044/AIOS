# Documentation Evidence: Threat Model Observability (T-02779)

## Overview
Documents the complete specification, schema, security invariants, operational usage, and test verification suite for the Threat Model Observability subsystem.

## Deliverables
1. **Specification Updated**:
   - [`docs/SPEC-THREAT-MODEL-OBSERVABILITY.md`](../../SPEC-THREAT-MODEL-OBSERVABILITY.md) elevated to `IMPLEMENTED & VERIFIED`.
   - Linked to Rust source modules and unit/integration test suites.
2. **Verification Commands**:
   - Unit Tests:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_observability
     ```
   - Service Integration Tests:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_observability_integration
     ```
   - Full Sub-Epic Regression Suite:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_service --test test_threat_model_policy --test test_threat_model_observability --test test_threat_model_observability_integration
     ```
3. **Operational Constraints & Invariants**:
   - Enforces RFC3339 UTC timestamping format (`THREATOBS1`).
   - All metric labels and keys sanitized and capped at 256 bytes (`THREATOBS2`).
   - Distribution maps bounded to 128 elements to eliminate cardinality memory exhaustion (`THREATOBS3`).
   - Strictly enforces zero-disclosure invariant, preventing any private keys or credentials from entering metrics (`THREATOBS4`).
   - Audit trail inspection bounded to 1,000 log records (`THREATOBS6`).

## Cross References
- Tasks: `T-02771` (Research) through `T-02778` (Hardening).
- Architecture Decisions: ADR-0035 §G-1, ADR-0036 §C-2.
