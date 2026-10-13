# Hardening Evidence: Incident Response Runbooks & RustSec MCP Surface (T-03000)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / MCP/API surface: Hardening
- **Task ID**: `T-03000`
- **Milestone**: MCP/API Surface (T-02993 .. T-03002)
- **Status**: HARDENED & VERIFIED

---

## 1. Summary of Hardening Implementations
Implemented defense-in-depth hardening across `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py` addressing recommendations from the T-02999 Security Review:

1. **Parameter Count and Value Validation (CWE-20, CWE-22, CWE-78)**:
   - Enforced `MAX_RUNBOOK_PARAMS_COUNT = 32`. Rejects sessions initialized with excessive parameters (`RUNBOOK_ERR_BOUNDS_EXCEEDED`).
   - Validated every parameter value via `validate_parameter_value(k, v)`:
     - Rejects empty values (`RUNBOOK_ERR_INVALID_PARAM_VALUE`).
     - Clamps length to `MAX_RUNBOOK_PARAM_LEN = 256` (`RUNBOOK_ERR_BOUNDS_EXCEEDED`).
     - Prohibits directory traversal `..` (`RUNBOOK_ERR_INVALID_PARAM_VALUE`).
     - Whitelist regex validation `^[a-zA-Z0-9_\-\.:/]+$`.

2. **Confirmation Token and Operator Clamping (CWE-287)**:
   - In `confirm`: validated that `operator_id` and `token` are non-empty and bounded to max 64 characters (`RUNBOOK_ERR_MISSING_CONFIRMATION`).

3. **Standard Result Envelopes on All Failure Paths (PoR Invariant I-2)**:
   - All errors caught in `_recorded_mcp_call` commit an honest outcome `error` audit row to the SQLite WAL `audit_ring`.
   - Returns structured envelope `{"ok": False, "action": action_name, "error": detail, "audit_id": row.id}` preventing unhandled framework leakage.

4. **Resource Bounds & Cleanup (DoS Defense)**:
   - Socket connection sweeps close sockets in `finally` blocks, clamping port counts (max 10,000) and timeouts `[10ms, 10,000ms]`.
   - File searches bound recursion depth (`[1, 32]`), file size cap (16 MiB), and match count (1,000).
   - In-memory session store locked by mutex with 1,000 session capacity limit.

---

## 2. Test Execution Output
```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-mcp
collected 12 items

code\aiosh-mcp\tests\test_incident_runbook_mcp_scaffold.py ..            [ 16%]
code\aiosh-mcp\tests\test_incident_runbook_mcp_unit.py ........          [ 83%]
code\aiosh-mcp\tests\test_incident_runbook_mcp_integration.py ..         [100%]

============================= 12 passed in 3.42s ==============================
```
