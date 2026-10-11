# Integration Evidence: Compliance Mapping Observability (T-02938)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Observability
- **Task ID**: `T-02938`
- **Files Modified / Created**:
  - `code/aiosh-mcp/aiosh_mcp/server.py` (documented and registered `stats` action on `aios.compliance`)
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_observability_integration.rs` (created Rust E2E test)
  - `code/aiosh-mcp/tests/test_compliance_observability_integration.py` (created Python MCP E2E test)

## 1. End-to-End Integration Verification

1. **MCP Surface Integration**: `aios.compliance` tool supports `action="stats"` without requiring capability tokens, generating structured telemetry reports with audit trails.
2. **Audit Correlation**: Exactly one audit event row is emitted to `audit_ring` with `outcome="ok"` per call.
3. **Cross-Substrate Parity**: Verified report serialization and JSON contract compatibility across Rust and Python runtimes.

## 2. Test Execution Output

### 2.1 Rust Substrate
```text
running 1 test
test test_compliance_observability_end_to_end_integration ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

### 2.2 Python Substrate
```text
code/aiosh-mcp/tests/test_compliance_observability_integration.py . [100%]
1 passed in 1.52s
```
