# Research Evidence: Incident Response Runbooks Core Service (T-02973)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / core service
- **Task ID**: `T-02973`
- **Scope**: Execution engine, parameter binding, state transitions, PEP integration, and audit receipts

---

## 1. Architectural Role & Context

While the Incident Response Runbooks data model (`T-02963..T-02972`) formalized the taxonomy and schema, the **Core Service** provides the active orchestration runtime:
1. **Dynamic Matching & Triggering**: Matches incident events to the most specific runbook based on category, target entity, and severity.
2. **Deterministic Step State Machine**: Orchestrates sequential step execution (`Pending` -> `Running` -> `AwaitingConfirmation` -> `Completed` / `Failed` / `TimedOut`).
3. **PEP Mediation & Substrate Dispatch**: Ensures remediation actions are authorized against active capability grants before dispatching to substrate handlers (process management, network filtering, token revocation, audit checkpointing).
4. **Dual-Custody / Confirmation Guard**: Enforces asynchronous operator sign-off on steps flagged `requires_confirmation: true` or classified as high-risk.
5. **Proof-of-Receipt (PoR Invariant I-2)**: Writes tamper-evident receipts to the audit ring for every phase transition, execution result, and operator confirmation.

---

## 2. Invariants & Guarantees (IR-SVC1..IR-SVC5)

- `IR-SVC1` (**State Machine Determinism**): Monotonic state progression with strict terminal handling. Failed steps halt execution unless marked optional.
- `IR-SVC2` (**PEP Capability Verification**): Actions targeting substrates require specific capabilities (`runbook:execute`, `process:signal`, `network:isolate`, `identity:revoke`).
- `IR-SVC3` (**Safe Parameter Interpolation**): Parameter substitution (`{var}`) accepts only sanitized alphanumeric values.
- `IR-SVC4` (**Bounded Step Execution Timeouts**): Step execution enforced with bounded timeout limits (`MAX_RUNBOOK_STEP_TIMEOUT_SECONDS`).
- `IR-SVC5` (**Audit Ring Receipts**): All lifecycle transitions generate verifiable audit records with SHA-256 state hashes.

---

## 3. Implementation Targets

- Rust Core: `code/aiosh-rust/aiosh-core/src/incident_runbook_service.rs`
- Python MCP: `code/aiosh-mcp/aiosh_mcp/incident_runbook_service.py`
- Test Suites:
  - Scaffold: `test_incident_runbook_service_scaffold.rs` / `.py`
  - Unit: `test_incident_runbook_service_unit.rs` / `.py`
  - Integration: `test_incident_runbook_service_integration.rs` / `.py`
