# Evidence: Integration Tests for Incident Response Runbooks Security Policy (T-03028)

**Task ID**: T-03028 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / security policy: Integration)  
**Contract Reference**: `docs/tasks/evidence/T-03027-security-policy-unit-test.md`, `docs/tasks/evidence/T-03026-security-policy-implementation.md`  
**Date**: 2026-10-15  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Verified green across Rust Core (`aiosh-core`) and Python FastMCP (`aiosh-mcp`).

---

## 1. Summary of Integration
- Integrated `_ACTIVE_POLICY` into FastMCP `aios_runbook` action dispatcher:
  - Added read action `"policy"` to inspect active version, mode, and enforcement rules.
  - Wired `_ACTIVE_POLICY.evaluate_runbook_start(spec)` into `start`.
  - Wired `_ACTIVE_POLICY.evaluate_scan_operation(...)` into `execute_scan_action`.
- Validated cross-substrate parity and audit trail emission on policy inspections.

---

## 2. Test Execution Output

### Rust Integration Suite
```text
running 1 test
test test_integration_policy_governance_on_canonical_baseline ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s
```

### Python Integration Suite
```text
code/aiosh-mcp/tests/test_incident_runbook_policy_integration.py ..      [100%]

============================== 2 passed in 2.93s ==============================
```
