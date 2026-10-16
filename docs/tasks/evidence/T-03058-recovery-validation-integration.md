# Integration: Incident Response Runbooks Recovery & Validation Subsystem (T-03058)

**Task ID**: T-03058 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / recovery & validation: Integration)  
**Contract Reference**: `docs/tasks/evidence/T-03054-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Cross-substrate recovery workflows integrated with FastMCP tools surface and audit logging.

---

## 1. Integration Scope & Architecture

1. **FastMCP Integration**:
   - `aios_runbook` extended with recovery actions:
     - `action="recovery_check"`: non-destructive state inspection.
     - `action="recovery_repair"`: atomic repair with quarantine and baseline rollback.
     - `action="recovery_snapshot"`: `.bak` snapshot creation.
   - Wrapped inside `_recorded_mcp_call` ensuring every check, repair, and snapshot commits an immutable audit row with unique `audit_id`.

2. **Dual-Substrate Parity**:
   - Rust Core and Python MCP implement identical file layout conventions:
     - Temporary sibling writes (`.{name}.tmp.{pid}.{nanos}`) with `rename(2)`.
     - Timestamped quarantine files (`{name}.corrupt.{pid}.{nanos}`).
     - Quarantine pruning at `MAX_QUARANTINE_FILES = 10`.
     - Standard JSON schema matching `RunbookCatalogSnapshot::canonical_baseline()`.

---

## 2. Test Execution Results

- **Rust Integration Suite**: `code/aiosh-rust/aiosh-core/tests/test_incident_runbook_recovery_integration.rs`
  - Result: 1 passed; 0 failed (3.39s build + 0.07s run).
- **Python Integration Suite**: `code/aiosh-mcp/tests/test_incident_runbook_recovery_integration.py`
  - Result: 1 passed; 0 failed (2.34s).
