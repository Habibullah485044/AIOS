# T-02918 — Compliance Mapping / Automated Tests: Integration

**Task**: T-02918 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Integration)
**Depends on**: T-02917 (Unit Test — `docs/tasks/evidence/T-02917-automated-tests-unit-test.md`)
**Date**: 2026-10-11
**Status**: COMPLETE — Automated tests for compliance mapping integrated end-to-end across production surfaces (MCP over wire stdio and Rust CLI).

---

## 1. Integration Scope & Verification

The integration verifies that automated compliance vectors function cohesively through production interfaces:
1. **Production Wire Calling**: Python MCP server running as an out-of-process subprocess (`aiosh_mcp.server`) handling JSON-RPC over stdio.
2. **Capability Token Redemptions**: Mutating compliance operations (`register`, `status`) require a pre-minted capability token (`grant_id`), validated against the PEP gate.
3. **Cross-Substrate Parity & State Propagation**:
   - Initialized store via Rust CLI (`aiosh compliance init`).
   - Registered entry via Python wire MCP (`aios_compliance` `register`).
   - Transitioned status to compliant via Rust CLI (`aiosh compliance status`).
   - Assessed framework coverage via Python wire MCP (`aios_compliance` `assess`), verifying that state mutations from Rust CLI are immediately visible and correctly calculated over wire MCP.
4. **Audit Ring Invariants**:
   - Consequential operations emit corresponding audit rows to the SQLite `audit_ring` table with tool attribution (`aios.compliance`).

---

## 2. Test Execution Output

```text
code/aiosh-mcp/tests/test_compliance_integration.py::test_mcp_stdio_advertises_compliance_tool PASSED [ 12%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_mcp_stdio_read_calls_end_to_end PASSED [ 25%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_wire_ungranted_write_refused_fail_closed PASSED [ 37%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_wire_granted_write_persists_store PASSED [ 50%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_cross_substrate_init_baseline_and_loads PASSED [ 62%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_cross_substrate_register_show_status_assess PASSED [ 75%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_config_ladder_end_to_end_cross_substrate PASSED [ 87%]
code/aiosh-mcp/tests/test_compliance_integration.py::test_automated_vectors_e2e_cross_substrate PASSED [100%]

8 passed in 16.37s
```

All 8 integration test scenarios pass with zero regressions.
