# Specification: Incident Response Runbooks Core Service (SPEC-INCIDENT-RUNBOOK-SERVICE)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-12
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks Core Service
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §I-1, ADR-0037 §D-1, PoR Invariant I-2
- **Source Code Targets**:
  - Rust Core: `code/aiosh-rust/aiosh-core/src/incident_runbook_service.rs`
  - Python MCP: `code/aiosh-mcp/aiosh_mcp/incident_runbook_service.py`

---

## 1. Domain Types & Execution States

### 1.1 StepExecutionStatus
- `pending`: Step queued for execution.
- `running`: Step actively executing against substrate.
- `awaiting_confirmation`: High-risk or confirmed step awaiting operator token.
- `completed`: Step succeeded with zero exit code.
- `failed`: Step failed with non-zero exit code or error.
- `timed_out`: Step exceeded allotted execution timeout (`RUNBOOK_ERR_TIMEOUT_EXCEEDED`).
- `skipped`: Step bypassed per policy or operator directive.

### 1.2 RunbookExecutionStatus
- `pending`: Session created but not started.
- `running`: Session active with steps progressing.
- `awaiting_confirmation`: Session halted pending operator authorization.
- `completed`: All steps executed successfully.
- `failed`: One or more non-optional steps failed.
- `aborted`: Session terminated by operator or security kernel.

---

## 2. Structural Schemas

### 2.1 StepExecutionRecord
```rust
pub struct StepExecutionRecord {
    pub step_id: String,
    pub status: StepExecutionStatus,
    pub command_rendered: String,
    pub started_at: String,
    pub completed_at: String,
    pub exit_code: Option<i32>,
    pub output: String,
    pub error_message: Option<String>,
}
```

### 2.2 RunbookExecutionSession
```rust
pub struct RunbookExecutionSession {
    pub session_id: String,
    pub runbook_id: String,
    pub incident_id: String,
    pub status: RunbookExecutionStatus,
    pub current_step_index: usize,
    pub step_records: Vec<StepExecutionRecord>,
    pub parameters: HashMap<String, String>,
    pub operator_confirmed: bool,
    pub started_at: String,
    pub completed_at: String,
}
```

---

## 3. Invariants & Security Guarantees

- `IR-SVC1` (**Monotonic State Progression**): States progress deterministically (`pending` -> `running` -> `completed` / `failed` / `aborted`). A session waiting for confirmation cannot execute without valid operator credentials and confirmation token. Advancing a terminal session is strictly rejected (`RUNBOOK_ERR_INVALID_TRANSITION`).
- `IR-SVC2` (**PEP Capability Enforcement**): Prior to executing each step, the execution service checks required capability matching substrate (`process:signal`, `network:isolate`, `identity:revoke`, `audit:checkpoint`).
- `IR-SVC3` (**Safe Parameter Interpolation & Whitelisting**): Template variables `{var}` are matched against parameters dictionary and validated against strict positive character whitelists (`^[a-zA-Z0-9_\-\.:/]+$`). Shell metacharacters, subshells (`$(...)`), and path traversal sequences (`..`) are rejected (`RUNBOOK_ERR_INVALID_PARAM_VALUE`).
- `IR-SVC4` (**Strict Timeout Enforcement**): Every step execution is guarded by a timer clamped to `MAX_RUNBOOK_STEP_TIMEOUT_SECONDS` (3600). Timed out steps record exit code 124 and mark the session as `failed`.
- `IR-SVC5` (**Proof-of-Receipt Audit Ring Logging**): Session start, step completions, and confirmations generate cryptographically verifiable audit events committed to the append-only audit ring.

---

## 4. Hardening & Bounds Constraints

- **Maximum Parameter Length (`MAX_RUNBOOK_PARAM_LEN = 256`)**: Individual parameter values exceeding 256 characters are rejected with `RUNBOOK_ERR_BOUNDS_EXCEEDED`.
- **Maximum Parameter Count (`MAX_RUNBOOK_PARAMS_COUNT = 32`)**: Session parameter sets with more than 32 entries are rejected with `RUNBOOK_ERR_BOUNDS_EXCEEDED` to prevent memory exhaustion / DoS.
- **Path Traversal Sanitization**: Parameter values containing `..` are immediately rejected with `RUNBOOK_ERR_INVALID_PARAM_VALUE` to prevent directory traversal in rendered file/path templates.
- **Operator Identity & Token Hardening**: Confirmation calls (`confirm_with_token`) require non-empty operator ID and confirmation token bounded to 64 characters (`RUNBOOK_ERR_MISSING_CONFIRMATION`).

---

## 5. Execution State Machine & Methods

### 5.1 RunbookExecutionSession Methods
- `init_from_spec(spec, incident_id, parameters)`: Instantiates a new execution session with rendered commands and pre-allocated step records.
- `advance_step(spec, simulate_success)`: Evaluates confirmation gating. If the next step requires confirmation and `operator_confirmed` is false, transitions to `AwaitingConfirmation`. Otherwise, dispatches the step and advances monotonic step pointer.
- `confirm_with_token(operator_id, token)`: Verifies operator credentials and authorization token, lifting the confirmation gate and returning status to `Running`.
- `abort(reason)`: Immediately terminates session execution, marking remaining steps as `Skipped` and setting session status to `Aborted`.
- `timeout_current()`: Handles execution watchdog expiration, recording exit code 124 and failing session.
- `is_terminal()`: Checks whether session is in a terminal status (`Completed`, `Failed`, `Aborted`).

### 5.2 Catalog Matching
- `match_runbook(catalog, category, severity)`: Resolves candidate runbook matching incident category and optional severity level from catalog snapshot.

---

## 6. Serialization & Wire Format Parity
Both Rust (`aiosh-core`) and Python (`aiosh-mcp`) share 100% wire-compatible JSON serialization:
- CamelCase/snake_case mapping handled via serde / dataclass serialization.
- Cross-language rehydration verified in integration suites: a session exported to JSON from Rust can be resumed by Python, and vice-versa.

---

## 7. Verification & Evidence Artifacts

- Research: `docs/tasks/evidence/T-02973-research.md`
- Specification: `docs/tasks/evidence/T-02974-specification.md`
- Scaffold: `docs/tasks/evidence/T-02975-scaffold.md`
- Implementation: `docs/tasks/evidence/T-02976-implementation.md`
- Unit Test: `docs/tasks/evidence/T-02977-unit-test.md`
- Integration: `docs/tasks/evidence/T-02978-integration.md`
- Security Review: `docs/tasks/evidence/T-02979-security-review.md`
- Hardening: `docs/tasks/evidence/T-02980-hardening.md`
- Documentation: `docs/tasks/evidence/T-02981-documentation.md`
