# Specification: Incident Response Runbooks Core Service (SPEC-INCIDENT-RUNBOOK-SERVICE)

- **Status**: SPECIFIED
- **Date**: 2026-10-11
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

- `IR-SVC1` (**Monotonic State Progression**): States progress deterministically (`pending` -> `running` -> `completed` / `failed`). A session waiting for confirmation cannot execute without valid confirmation token.
- `IR-SVC2` (**PEP Capability Enforcement**): Prior to executing each step, the execution service checks required capability matching substrate (`process:signal`, `network:isolate`, `identity:revoke`, `audit:checkpoint`).
- `IR-SVC3` (**Safe Parameter Interpolation**): Template variables `{var}` are matched against parameters dictionary and sanitized. Parameter values must not contain dangerous shell metacharacters (`$(...)`, `;`, `|`, `&`, `\n`).
- `IR-SVC4` (**Strict Timeout Enforcement**): Every step execution is guarded by a timer clamped to `MAX_RUNBOOK_STEP_TIMEOUT_SECONDS` (3600).
- `IR-SVC5` (**Proof-of-Receipt Audit Ring Logging**): Session start, step completions, and confirmations generate cryptographically verifiable audit events committed to the append-only audit ring.
