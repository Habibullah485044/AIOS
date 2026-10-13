# Integration Evidence: Incident Response Runbooks Core Service (T-02978)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / core service
- **Task ID**: `T-02978`
- **Specification**: `docs/SPEC-INCIDENT-RUNBOOK-SERVICE.md`

## 1. Summary of Integration Tests
- Validated end-to-end incident containment workflows across Rust (`test_incident_runbook_service_integration.rs`) and Python (`test_incident_runbook_service_integration.py`):
  - Ingested realistic security alert parameters (`INC-2026-ALERT-991`, `MalwareContainment`, `target_pid: 4567`, `target_uid: 1005`).
  - Successfully auto-matched the canonical baseline runbook (`RB-IR-MALWARE-01`).
  - Executed full sequence: Step 1 (`Process: Freeze`), Step 2 (`Network: Quarantine`), Step 3 (`AuditRing: Snapshot checkpoint`).
  - Verified final session state transition to `completed` with immutable timestamp records.
- Cross-wire session format continuation:
  - Initialized multi-phase unauthorized access session (`RB-IR-ACCESS-01`).
  - Stepped through automated token revocation, then halted at operator confirmation gate (`awaiting_confirmation`).
  - Serialized active in-flight session to JSON wire format and rehydrated it across substrates without state loss.
  - Confirmed operator gate and verified completion of rehydrated session.

## 2. Test Execution
- **Rust Core**: 2/2 passed.
- **Python MCP**: 2/2 passed.
