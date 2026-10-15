# Specification: Incident Response Runbooks Security Policy Subsystem (SPEC-INCIDENT-RUNBOOK-POLICY)

- **Status**: SHIPPED
- **Date**: 2026-10-15
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks / security policy
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §C-2, ADR-0036 §B-1, Proof-of-Restraint (PoR) Invariant I-2
- **Shipped Implementations**:
  - Rust Core Substrate: `code/aiosh-rust/aiosh-core/src/incident_runbook_policy.rs`
  - Python MCP Fabric: `code/aiosh-mcp/aiosh_mcp/incident_runbook_policy.py`
- **Evidence Trail**:
  - Research: [T-03023-research.md](tasks/evidence/T-03023-research.md)
  - Specification: [T-03024-spec.md](tasks/evidence/T-03024-spec.md)
  - Scaffold: [T-03025-scaffold.md](tasks/evidence/T-03025-scaffold.md)
  - Implementation: [T-03026-security-policy-implementation.md](tasks/evidence/T-03026-security-policy-implementation.md)
  - Unit Tests: [T-03027-security-policy-unit.md](tasks/evidence/T-03027-security-policy-unit.md)
  - Integration: [T-03028-security-policy-integration.md](tasks/evidence/T-03028-security-policy-integration.md)
  - Security Review: [T-03029-security-policy-security-review.md](tasks/evidence/T-03029-security-policy-security-review.md)
  - Hardening: [T-03030-security-policy-hardening.md](tasks/evidence/T-03030-security-policy-hardening.md)

---

## 1. Subsystem Architecture & Enforcement Modes

The Security Policy layer governs all execution entry points for incident response runbooks and diagnostic scanning tools.

### 1.1 Enforcement Modes

| Mode | Identifier | Confirmation Gating | Resource Clamping | Audit Emission |
|:---|:---|:---:|:---:|:---:|
| **Enforcing** (Default) | `enforcing` | Fail-closed (`RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED`) | Hard rejection if bounds exceeded | Standard audit row |
| **Permissive** | `permissive` | Bypass permitted | Soft warning; execution proceeds | Honest audit row (`audit_row_required=True` per ADR-0035 AF-2) |
| **Disabled** | `disabled` | All policy checks bypassed | Unbounded | Audit bypass row emitted |

---

## 2. Policy Parameters & Enforced Bounds

All policy configurations enforce strict boundary validation on load and serialization:

| Parameter | Type | Default Value | Hard Clamping Boundary | Description |
|:---|:---|:---:|:---:|:---|
| `version` | `String` | `"1.0.0"` | Semver string | Policy schema version. |
| `mode` | `RunbookEnforcementMode` | `Enforcing` | `enforcing`, `permissive`, `disabled` | Active evaluation regime. |
| `require_operator_confirmation_for_high_risk` | `bool` | `true` | Boolean | Invariant I-2 gate for destructive containment steps. |
| `max_step_timeout_seconds` | `u64` / `int` | `60` | $[1, 300]$ seconds | Watchdog timeout per runbook step. |
| `max_active_sessions` | `u32` / `int` | `100` | $[1, 10000]$ | Maximum active runbook executions in state engine. |
| `disallowed_categories` | `Vec<IncidentCategory>` | `[]` | Enum values | Incident categories strictly forbidden from execution. |
| `disallowed_substrates` | `Vec<RunbookTargetSubstrate>` | `[]` | Enum values | Substrates (e.g., Disk, Kernel) disallowed in any step. |
| `max_scanned_ports` | `usize` / `int` | `10,000` | $[1, 65535]$ | Maximum ports allowed in single network scan action. |
| `max_file_scan_depth` | `usize` / `int` | `16` | $[1, 32]$ | Maximum directory traversal recursion depth. |
| `max_file_scan_size_bytes` | `u64` / `int` | `16 MiB` | $\le 100$ MiB | File content inspection budget. |
| `require_pep_grant` | `bool` | `true` | Boolean | Requires cryptographic capability token grant. |

---

## 3. Evaluation Result Envelope (`PolicyResultEnvelope`)

All evaluation operations yield explicit, structured envelopes:

```rust
pub struct PolicyResultEnvelope {
    pub ok: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub audit_row_required: bool,
}
```

Standard error codes:
- `RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED`: Step requires explicit operator confirmation token.
- `RUNBOOKPOL_ERR_CATEGORY_DISALLOWED`: Runbook category forbidden by administrator policy.
- `RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED`: Substrate (Disk, Kernel, etc.) forbidden by policy.
- `RUNBOOKPOL_ERR_POLICY_VIOLATION`: Step timeout exceeds max permitted duration.
- `RUNBOOKPOL_ERR_SCAN_BOUNDS`: Scan parameters exceed port/depth budget.
- `RUNBOOKPOL_ERR_VALIDATION`: Corrupt JSON or configuration values outside hard bounds.
- `RUNBOOKPOL_ERR_IO`: File size exceeds 64 KiB cap or I/O failure.

---

## 4. Copy-Pasteable Usage Examples

### 4.1 Python FastMCP Tool Query

Query active policy via FastMCP tool call:

```python
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action

# Inspect active policy rules
result = execute_runbook_action(action="policy")
print(result)
# Output:
# {
#   "policy": {
#     "version": "1.0.0",
#     "mode": "enforcing",
#     "require_operator_confirmation_for_high_risk": True,
#     "max_step_timeout_seconds": 60,
#     "max_active_sessions": 100,
#     "max_scanned_ports": 10000,
#     "max_file_scan_depth": 16
#   }
# }
```

### 4.2 Rust Programmatic Policy Evaluation

```rust
use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;

fn check_containment_step(step: &RunbookStep, operator_confirmed: bool) {
    let policy = RunbookSecurityPolicy::default();
    let result = policy.evaluate_step_with_envelope(step, operator_confirmed);

    if !result.ok {
        eprintln!(
            "Policy Gate Blocked: [{}] {}",
            result.error_code.unwrap(),
            result.error_message.unwrap()
        );
    } else {
        println!("Policy Gate Cleared. Proceeding with containment step.");
    }
}
```

---

## 5. Constraints & Known Limitations

1. **Max Policy File Size Cap**: Policy files cannot exceed 64 KiB (`MAX_RUNBOOK_POLICY_BYTES`). Oversized files are rejected immediately on open.
2. **Atomic Write Replacement**: `save_to_file` writes to a process-isolated temporary file before atomic renaming. Filesystems lacking POSIX/Win32 atomic rename guarantees may experience contention.
3. **In-Memory Policy Defaults**: If a policy file is missing or unreadable, the subsystem fails closed by falling back to the canonical `Enforcing` default rather than allowing silent unbounded access.
