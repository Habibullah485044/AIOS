# SPEC-MODEL-BACKEND-ADAPTERS-SECURITY-POLICY: Security Policy Engine Specification

- **Status**: APPROVED
- **Lifecycle Task**: `T-03224`
- **Bindings**: ADR-0035 §D-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Policy Contract

```python
class ModelSecurityPolicy:
    def evaluate(self, action: str, token: Optional[str] = None, payload: Optional[str] = None) -> PolicyVerdict
```

## 2. Invariants

- **`MODSEC-INV1` (PoR Invariant I-2)**: State mutations (`complete`, `register`) strictly require token; read actions consume 0 tokens.
- **`MODSEC-INV2` (Fail-Closed)**: Any policy evaluation error results in immediate refusal.
- **`MODSEC-INV3` (Secret Redaction)**: All logged strings cleansed of API keys.
- **`MODSEC-INV4` (Input Sanitization)**: Rejects NUL bytes and control characters.
