# T-02920 — Compliance Mapping / Automated Tests: Hardening

**Task**: T-02920 (Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / automated tests: Hardening)
**Depends on**: T-02919 (Security Review — `docs/tasks/evidence/T-02919-automated-tests-security-review.md`)
**Date**: 2026-10-11
**Status**: COMPLETE — Automated test harnesses and runners hardened against subprocess hangs, resource leaks, file locking, and silent failures.

---

## 1. Hardening Measures Implemented

1. **Robust Windows File Lock & Cleanup Resilience**:
   - Configured `tempfile.TemporaryDirectory(..., ignore_cleanup_errors=True)` across all integration and unit test fixtures in `code/aiosh-mcp/tests/test_compliance_integration.py` and `code/aiosh-mcp/tests/test_compliance_automated_unit.py`.
   - Prevents transient Windows `PermissionError: [WinError 32]` from leaking directories or breaking test harness cleanup when child process SQLite connections or background tasks briefly touch the `.aios` directory.
2. **Subprocess Lifecycle & Timeout Defenses**:
   - Fixed timeouts enforced on all external tool and process calls (`rust(...)` timeout 30s; `wire(...)` deadline 60s; `proc.wait(timeout=10)`).
   - Ensured proper stdin closure (`proc.stdin.close()`) and guaranteed process termination (`proc.kill()`) on exception or timeout in `wire()`.
3. **Explicit Error Envelopes**:
   - Zero silent swallowing of domain or transport errors.
   - Asserted standard spec error envelopes (`PARAM_INVALID`, `COMPLIANCE_ERR_*`, `COMPLIANCESVC_ERR_*`, `PEP_DENIED`).
4. **Fail-Closed Audit Emission (ADR-0035 §F-2)**:
   - Verified that refused or ungranted actions write an honest rejection row to `audit_ring` while keeping the target store bitwise unchanged.

---

## 2. Test Verification Output

### Python Hardened Suites (32/32 Passed)
```text
code/aiosh-mcp/tests/test_compliance_automated_smoke.py (10 passed)
code/aiosh-mcp/tests/test_compliance_automated_unit.py (14 passed)
code/aiosh-mcp/tests/test_compliance_integration.py (8 passed)

32 passed in 17.02s
```

### Rust Automated Suites (22/22 Passed)
```text
test_compliance_automated.rs: 10 passed; 0 failed
test_compliance_automated_unit.rs: 12 passed; 0 failed
```
