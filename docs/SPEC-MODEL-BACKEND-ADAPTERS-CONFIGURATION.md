# SPEC-MODEL-BACKEND-ADAPTERS-CONFIGURATION: AI Control Plane Model Backend Configuration

- **Status**: APPROVED
- **Lifecycle Task**: `T-03204`
- **Bindings**: ADR-0035 §D-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-DATA-MODEL

---

## 1. Overview & Data Model

`ModelBackendConfig` encapsulates complete runtime settings for backend dispatch:

```json
{
  "version": "1.0",
  "default_provider": "mock",
  "default_timeout_ms": 30000,
  "max_fallback_depth": 5,
  "rate_limit_rpm": 60,
  "require_capability_tokens": true,
  "endpoints": {
    "mock-primary": {
      "backend_id": "mock-primary",
      "provider": "mock",
      "model_name": "mock-general",
      "base_url": null,
      "timeout_ms": 5000,
      "fallbacks": ["mock-fallback"]
    }
  }
}
```

## 2. Invariants

- **`MODCONF-INV1` (Schema Integrity)**: Validates provider types, timeout ranges `[1000, 300000]`, and backend identifier syntax.
- **`MODCONF-INV2` (PoR Invariant I-2)**: `require_capability_tokens` defaults to `True`. Mutating calls fail if token is omitted.
- **`MODCONF-INV3` (Acyclic Fallbacks)**: Fallback chains must be strictly acyclic with maximum depth <= 5.
- **`MODCONF-INV4` (Secret Hygiene)**: API keys in configuration are never serialized in `to_dict(safe=True)` or log strings.
