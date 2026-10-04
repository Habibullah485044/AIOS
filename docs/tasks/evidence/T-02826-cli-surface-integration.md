# T-02826: Compliance Mapping CLI Surface Integration

- **Task**: `T-02826`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Integration Scope
1. **Production Dispatch Wiring**:
   - `aiosh compliance` wired into `main.rs` dispatch with aliases `compliance` and `comp`.
   - Discoverable via `aiosh --help` synopsis.
2. **Substrate & Kernel Integration**:
   - Connected with `ComplianceService` in `aiosh-core`.
   - Connected to SQLite WAL audit ring via `classify_and_emit` (`COMPLYCLI1`).
   - Connected to canonical compliance map persistence (`COMPLYCLI5`).
3. **End-to-End Smoke Verification**:
   - Integrated test `test_compliance_cli_integration_smoke` exercises:
     - `init` baseline creation
     - `register` new mapping
     - `show` JSON query
     - `status` transition
     - `assess` framework evaluation
     - `check-pep` coverage verification
