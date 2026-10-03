# Documentation Evidence: Threat Model Automated Tests (T-02759)

## Overview
Documents the automated test vectors, operational instructions, copy-pasteable execution examples, constraints, and limitations for the Threat Model Maintenance automated testing subsystem.

## Deliverables
1. **Specification Update**: [`docs/SPEC-THREAT-MODEL-AUTOMATED-TESTS.md`](../../SPEC-THREAT-MODEL-AUTOMATED-TESTS.md) updated to `IMPLEMENTED & VERIFIED`.
2. **Copy-Pasteable Invocations**:
   - Standalone Automated Vector Suite: `cargo test -p aiosh-core --test test_threat_model_automated`
   - MCP Server End-to-End Vector Integration: `cargo test -p aiosh-mcp -- test_mcp_threat_model_automated_vectors`
   - Comprehensive Threat Model Regression Suite:
     ```bash
     cargo test -p aiosh-core --test test_threat_model_config
     cargo test -p aiosh-core --test test_threat_model_config_integration
     cargo test -p aiosh-core --test test_threat_model_data_model
     cargo test -p aiosh-core --test test_threat_model_service
     cargo test -p aiosh-core --test test_threat_model_service_integration
     cargo test -p aiosh-core --test test_threat_model_integration
     cargo test -p aiosh-mcp -- test_mcp_threat_model
     ```
3. **Operational Constraints Documented**:
   - Capacity bounded at 512 entries default, 4,096 max.
   - Fail-closed secret rejection prevents key leakage into catalogs.
   - Mutex synchronization provides thread-safety across concurrent workers.
   - No hot reload from disk without service re-instantiation.

## Cross References
- Spec: `docs/SPEC-THREAT-MODEL-AUTOMATED-TESTS.md`
- Tasks: T-02751..T-02758 evidence files linked in spec.
