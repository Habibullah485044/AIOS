# SPEC-MODEL-BACKEND-ADAPTERS-SECURITY-POLICY: Security Policy Engine Specification

- **Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-SECURITY-POLICY
- **Status**: APPROVED / ACTIVE
- **Lifecycle Target**: T-03223..T-03232 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / security policy)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0035 §F-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Security Policy Engine** (`ModelSecurityPolicy`) provides centralized capability token enforcement, input payload sanitization, secret redaction, and fail-closed audit trail emission across all model backend operations in AIOS.

It governs all inference dispatches, dynamic endpoint registrations, configuration updates, and inspection routines across both userspace CLI and MCP wire surfaces.

---

## 2. Invariants & Certified Security Rules

| Invariant | Scope | Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODSEC-INV1`** | Proof-of-Restraint (PoR Invariant I-2) | Mutating actions strictly require capability tokens; read actions require 0 tokens | State-mutating actions (`complete`, `register`, `delete`, `reload_config`) fail closed with `POLICY_UNAUTHORIZED` if token is missing or whitespace. Read actions (`list`, `show`, `health`, `ping`) proceed with zero tokens. |
| **`MODSEC-INV2`** | Fail-Closed Error Handling | All failure pathways return explicit refusals with audit rows | Any syntax error, exception, or validation failure emits a structured `PolicyVerdict` with `allowed: False` and `verdict: "refuse"`. |
| **`MODSEC-INV3`** | Secret & Telemetry Redaction | Never leak credentials in errors or audit logs | API keys (`sk-*`, `ghp_*`, Bearer tokens) are cleansed using `redact_secrets()` before recording in verdicts or logs. |
| **`MODSEC-INV4`** | Input Hygiene & Sanitization | NUL byte and control character rejection | Payload strings and capability tokens containing `\x00` are rejected immediately. |
| **`MODSEC-INV5`** | Bounded Payload Ceilings | Hard size limits across all fields | Payloads capped at 1 MiB (`MAX_PAYLOAD_BYTES`), tokens capped at 512 chars (`MAX_TOKEN_LEN`), and action names capped at 64 chars (`MAX_ACTION_LEN`). |

---

## 3. Policy Engine API & Signatures

```python
class ModelSecurityPolicy:
    def __init__(self, require_tokens: bool = True):
        ...

    def sanitize(self, text: str) -> str:
        """Sanitizes text, rejecting NUL bytes and validating size limits."""
        ...

    def sanitize_token(self, token: Optional[str]) -> Optional[str]:
        """Validates token bounds and rejects NUL bytes."""
        ...

    def evaluate(
        self,
        action: str,
        token: Optional[str] = None,
        payload: Optional[str] = None
    ) -> PolicyVerdict:
        """Evaluates action against PoR invariants and returns a PolicyVerdict."""
        ...
```

### 3.1 `PolicyVerdict` Data Model

```python
@dataclass
class PolicyVerdict:
    allowed: bool
    reason: Optional[str] = None
    audit_record: Optional[Dict[str, Any]] = None

    def to_envelope(self) -> Dict[str, Any]:
        """Returns standard ADR-0035 §AF-2 result envelope."""
        ...
```

---

## 4. Copy-Pasteable Usage Examples

### 4.1 Evaluating a Read Operation (Zero Token Consumption)
```python
from aiosh_mcp.model_backend_adapters_security_policy import ModelSecurityPolicy

policy = ModelSecurityPolicy()
verdict = policy.evaluate(action="list")

print(verdict.allowed)  # True
print(verdict.audit_record)  # {'action': 'list', 'verdict': 'allow'}
```

### 4.2 Evaluating an Unauthorized Mutation (Missing Token)
```python
from aiosh_mcp.model_backend_adapters_security_policy import ModelSecurityPolicy

policy = ModelSecurityPolicy()
verdict = policy.evaluate(action="complete", payload="Generate malicious code")

print(verdict.allowed)  # False
print(verdict.reason)   # POLICY_UNAUTHORIZED: Missing mandatory capability token for mutating action
print(verdict.to_envelope())
# {
#   "status": "rejected",
#   "ok": False,
#   "reason": "POLICY_UNAUTHORIZED: Missing mandatory capability token for mutating action",
#   "audit": {"action": "complete", "verdict": "refuse", "reason": "missing_token"},
#   "timestamp": 1730238300.0
# }
```

### 4.3 Evaluating an Authorized Mutation (With Valid Capability Token)
```python
from aiosh_mcp.model_backend_adapters_security_policy import ModelSecurityPolicy

policy = ModelSecurityPolicy()
verdict = policy.evaluate(
    action="complete",
    token="grant_cap_token_9921",
    payload="Summarize audit log"
)

print(verdict.allowed)  # True
print(verdict.audit_record)  # {'action': 'complete', 'verdict': 'allow'}
```

---

## 5. Constraints & Known Limitations Honestly Stated

1. **Token Cryptographic Validation Boundary**: `ModelSecurityPolicy` enforces structural presence, length boundaries, and sanitization; signature verification and replay prevention are delegated to PEP grant redemption tables in `audit.db`.
2. **Payload Size Limit**: Payloads cannot exceed 1 MiB (`1024 * 1024` bytes); larger files must be streamed or referenced by cryptographic digest.
3. **Action Taxonomy**: Action identifiers must be alphanumeric or snake_case, bounded between 1 and 64 characters.

---

## 6. Lifecycle Evidence Links

- **T-03223 (Research)**: [`docs/tasks/evidence/T-03223-security-policy-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03223-security-policy-research.md)
- **T-03224 (Specification)**: [`docs/tasks/evidence/T-03224-security-policy-specification.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03224-security-policy-specification.md)
- **T-03225 (Scaffold)**: [`docs/tasks/evidence/T-03225-security-policy-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03225-security-policy-scaffold.md)
- **T-03226 (Implementation)**: [`docs/tasks/evidence/T-03226-security-policy-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03226-security-policy-implementation.md)
- **T-03227 (Unit Test)**: [`docs/tasks/evidence/T-03227-security-policy-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03227-security-policy-unit-test.md)
- **T-03228 (Integration)**: [`docs/tasks/evidence/T-03228-security-policy-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03228-security-policy-integration.md)
- **T-03229 (Security Review)**: [`docs/tasks/evidence/T-03229-security-policy-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03229-security-policy-security-review.md)
- **T-03230 (Hardening)**: [`docs/tasks/evidence/T-03230-security-policy-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03230-security-policy-hardening.md)
- **T-03231 (Documentation)**: [`docs/tasks/evidence/T-03231-security-policy-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03231-security-policy-documentation.md)
