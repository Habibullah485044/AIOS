# Evidence: Unit Tests for Incident Response Runbooks Security Policy (T-03027)

**Task ID**: T-03027 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / security policy: Unit Test)  
**Contract Reference**: `docs/tasks/evidence/T-03026-security-policy-implementation.md`, `docs/tasks/evidence/T-03024-spec.md`  
**Date**: 2026-10-15  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Verified green across Rust Core (`aiosh-core`) and Python FastMCP (`aiosh-mcp`).

---

## 1. Summary of Tests Added
- `test_unit_boundary_step_timeouts`: Exact timeout matching boundary passes (30s), exceeding boundary (31s) fails closed.
- `test_unit_boundary_scan_ports_and_depth`: Max ports bound (100) and max file scan depth bound (5) verified with off-by-one rejections.
- `test_unit_disabled_enforcement_mode_bypass`: Disabled mode confirms that security evaluation can be fully bypassed when explicitly requested.
- `test_unit_file_io_invalid_inputs_and_bounds`: Non-existent file, corrupted JSON, and oversized policy files (> 64 KiB) fail with appropriate error codes (`RUNBOOKPOL_ERR_IO`, `RUNBOOKPOL_ERR_VALIDATION`).

---

## 2. Test Execution Output

### Rust Test Suite
```text
running 4 tests
test test_unit_boundary_scan_ports_and_depth ... ok
test test_unit_boundary_step_timeouts ... ok
test test_unit_disabled_enforcement_mode_bypass ... ok
test test_unit_file_io_invalid_inputs_and_bounds ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

### Python Test Suite
```text
code/aiosh-mcp/tests/test_incident_runbook_policy_unit.py ....           [100%]

============================== 4 passed in 2.82s ==============================
```
