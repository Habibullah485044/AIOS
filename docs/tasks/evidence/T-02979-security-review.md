# Security Review: Incident Response Runbooks Core Service (T-02979)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / core service
- **Task ID**: `T-02979`
- **Specification**: `docs/SPEC-INCIDENT-RUNBOOK-SERVICE.md`
- **Standards**: NIST SP 800-61 Rev. 2, OWASP ASVS v4.0, PoR Invariant I-2

---

## 1. Threat Modeling & Attack Surface

The Incident Response Runbooks Core Service is the critical operational actuator responsible for executing high-privilege containment actions (process termination, network socket dropping, capability token revocation, and forensic snapshotting). Vulnerabilities in this orchestration layer could allow an adversary to either neutralize containment or achieve privilege escalation.

### Primary Threat Scenarios:
1. **Malicious Parameter Injection (CWE-78)**: Injecting metacharacters via alert parameters (e.g., alert PID, IP, session ID) to execute arbitrary commands.
2. **Confirmation Bypass (CWE-863)**: Forcing automated execution of sensitive/destructive steps (such as storage unmounting or operator eviction) without human operator sign-off.
3. **State Machine Desynchronization (CWE-372)**: Advancing sessions backwards or skipping critical forensic checkpointing steps.
4. **Denial of Service / Hanging Execution (CWE-400)**: Unbounded step execution freezing response threads during active incidents.

---

## 2. Vulnerability Analysis & Findings

| Vulnerability / Risk | CWE | Severity | Status | Mitigation & Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Command Injection in Action Templates** | CWE-78 | High | Mitigated | `render_action_template` verifies parameter keys and values. Shell metacharacters (`;`, `\|`, `&`, ``` ` ```, `$`, `\n`) are rejected with `RUNBOOK_ERR_INVALID_TEMPLATE`. |
| **Bypass of Operator Confirmation Gate** | CWE-863 | High | Mitigated | `advance_step` strictly checks `(requires_confirmation || is_high_risk()) && !operator_confirmed`. Premature execution is prevented; returns `AwaitingConfirmation`. |
| **Invalid State Transitions** | CWE-372 | Medium | Mitigated | Terminal states (`completed`, `failed`, `aborted`) cannot be advanced. Violations return `RUNBOOK_ERR_INVALID_TRANSITION`. |
| **Unbounded Command Execution Timeouts** | CWE-400 | Medium | Mitigated | Steps enforce bounded timeout (`MAX_RUNBOOK_STEP_TIMEOUT_SECONDS`). Exceeded timeouts set exit code 124 (`timed_out`) and halt execution. |
| **Audit Non-Repudiation** | PoR I-2 | High | Verified | Session state transitions, parameters, and outputs are structured for cryptographic commit to the append-only audit ring. |

---

## 3. Hardening Recommendations for T-02980

1. **Parameter Value Whitelisting**: Replace blacklist character filtering with strict positive character whitelist (`^[a-zA-Z0-9_\-\.:/]+$`) and reject all quotes, spaces, and path traversal sequences (`..`).
2. **Confirmation Token Cryptographic Validation**: Validate that confirmation requests require a non-empty operator token / identifier.
3. **Maximum Parameter Value Length**: Enforce a strict length ceiling on parameter values (e.g. `MAX_RUNBOOK_PARAM_LEN = 256`) to guard against memory exhaustion.
