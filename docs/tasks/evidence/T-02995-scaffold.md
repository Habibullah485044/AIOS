# Scaffold Evidence: Incident Response Runbooks & RustSec MCP Surface (T-02995)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / MCP/API surface: Scaffold
- **Task ID**: `T-02995`
- **Milestone**: MCP/API Surface (T-02993 .. T-03002)
- **Status**: SCAFFOLDED & VERIFIED

---

## 1. Summary of Scaffold Changes

1. **New Module `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py`**:
   - Defined `execute_runbook_action` and `execute_scan_action` interfaces.
   - Defined `register_runbook_tools(mcp: FastMCP)` registering `aios_runbook` and `aios_scan`.
   - Wired in-memory thread-safe session dictionary `_ACTIVE_SESSIONS` with `_SESSION_STORE_LOCK`.
   - Scaffolded function bodies cleanly raise `NotImplementedError` awaiting implementation in `T-02996`.

2. **Server Registration in `code/aiosh-mcp/aiosh_mcp/server.py`**:
   - Imported `incident_runbook_mcp` module.
   - Called `incident_runbook_mcp.register_runbook_tools(mcp)` on the FastMCP instance.

3. **Scaffold Unit Tests**:
   - Authored `code/aiosh-mcp/tests/test_incident_runbook_mcp_scaffold.py`.
   - Verified that `aios_runbook` and `aios_scan` are registered on `mcp`.
   - Verified scaffold signatures raise `NotImplementedError`.

---

## 2. Test Verification Output
```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-mcp
collected 2 items

code\aiosh-mcp\tests\test_incident_runbook_mcp_scaffold.py ..            [100%]

============================== 2 passed in 2.85s ==============================
```
