# Documentation Evidence: Threat Model Security Policy (T-02769)

## Overview
Documents the complete specification, schema, security invariants, operational usage, and test verification suite for the Threat Model Security Policy subsystem.

## Deliverables
1. **Specification Updated**:
   - [`docs/SPEC-THREAT-MODEL-POLICY.md`](../../SPEC-THREAT-MODEL-POLICY.md) elevated to `IMPLEMENTED & VERIFIED`.
   - Linked to Rust source modules and unit/integration test suites.
2. **Verification Commands**:
   - Unit Tests:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_policy
     ```
   - Service Integration Tests:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_policy_integration
     ```
   - Full Threat Model Policy Regression Suite:
     ```bash
     cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_threat_model_service --test test_threat_model_policy --test test_threat_model_policy_integration
     ```
3. **Operational Constraints & Invariants**:
   - Enforces default `Enforcing` mode; transitions fail closed.
   - Requires CWE taxonomy mapping for all admitted threat vectors (`THREATPOL_ERR_CWE_REQUIRED`).
   - Prevents prematurely marking Critical severity threats as `Accepted` or `Resolved` without valid mitigations (`THREATPOL_ERR_CRITICAL_UNMITIGATED`).
   - Caps policy storage size at 64 KiB, denies symlinks, and performs atomic replacement with zero temporary file leaks.

## Cross References
- Tasks: `T-02761` (Research) through `T-02768` (Hardening).
- Architecture Decisions: ADR-0035 §F-2, ADR-0036 §B-1.
