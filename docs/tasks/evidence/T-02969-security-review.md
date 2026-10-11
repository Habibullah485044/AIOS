# Security Review: Incident Response Runbooks Data Model (T-02969)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / data model
- **Task ID**: `T-02969`
- **Specification**: `docs/SPEC-INCIDENT-RUNBOOKS.md`
- **Standards**: NIST SP 800-61 Rev. 2, OWASP ASVS v4.0, PoR Invariant I-2

---

## 1. Threat Modeling & Attack Surface

The Incident Response Runbook subsystem defines the authoritative containment and remediation protocols executed when security alerts or system compromises are detected. Compromise or manipulation of runbook specifications poses severe risks:
1. **Malicious Containment Evasion**: Disabling or neutering containment steps (e.g. removing process freeze or network isolation).
2. **Arbitrary Command Execution / Injection**: Exploiting template parameters (`action_template`) to execute unauthorized root/kernel operations.
3. **Denial of Service & Resource Starvation**: Registering runaway step definitions or unbounded catalog sizes that crash memory or block threads.
4. **Audit Trail Poisoning**: Injecting control characters or escape sequences to mask attack activity in log rings.

---

## 2. Vulnerability Analysis & CWE Mapping

| Threat / Vulnerability | CWE | Severity | Mitigation in Data Model |
| :--- | :--- | :--- | :--- |
| **Command Injection in Action Templates** | CWE-78 | High | Action templates must only permit strict parameter placeholders `{variable}` matching `^[a-zA-Z0-9_]+$`. In execution phase, arguments must be bound as discrete `argv` vectors rather than shell string expansion (`sh -c`). |
| **Improper Input Validation & Memory Exhaustion** | CWE-20, CWE-400 | Medium | Strict bounds enforcement: max ID length 64, max title length 128, max description length 2048, max 32 steps per runbook, max 16 tags, max 256 runbooks per catalog. |
| **Log Injection & Control Character Tampering** | CWE-116, CWE-117 | Medium | Disallow all ASCII control characters (`ord(c) < 32`) in IDs and titles (`RUNBOOK_ERR_CONTROL_CHARS`). Restrict description control characters strictly to harmless whitespace (`\n`, `\r`, `\t`). |
| **Duplicate Step or Runbook Confusion** | CWE-697 | Low | Duplicate step IDs (`RUNBOOK_ERR_DUPLICATE_ID`) and duplicate runbook catalog entries are strictly prohibited and rejected during instantiation. |
| **Bypassing Operator Authorization** | CWE-269 | High | Runbook steps clearly partition `automated: bool` and `requires_confirmation: bool`. Destructive steps must enforce operator confirmation before PEP dispatch. |

---

## 3. PoR Invariant I-2 & Audit Alignment

Under Proof-of-Receipt (PoR Invariant I-2):
- Any modification to the Runbook Catalog (adding, updating, or deleting runbooks) alters the catalog state and must produce a signed snapshot receipt.
- In `RunbookCatalogSnapshot`, the `generated_at` timestamp updates upon any catalog mutation (`add_runbook`, `remove_runbook`).
- The canonical baseline guarantees predefined, verified containment steps for immediate zero-trust incident handling.

---

## 4. Hardening Recommendations for T-02970

1. **Template Placeholder Hygiene**: Add a validator in the data model verifying that all template parameters enclosed in `{...}` adhere to valid identifier syntax `^[a-zA-Z0-9_]+$`.
2. **Timeout Clamping**: Enforce a maximum execution timeout ceiling (e.g., `MAX_RUNBOOK_TIMEOUT_SECONDS = 3600`) to prevent infinite or excessively prolonged step execution.
3. **Confirmation Default on High Impact Substrates**: Ensure that critical steps targeting identity revocation or storage unmount enforce validation checks or confirmation safety flags.
