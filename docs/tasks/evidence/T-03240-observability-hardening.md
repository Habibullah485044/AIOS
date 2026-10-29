# Hardening Evidence: AI Control Plane Model Backend Adapters Observability (T-03240)

**Task ID**: T-03240 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / observability: Hardening)  
**Contract Reference**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-OBSERVABILITY.md`, ADR-0035 §AF-2, ADR-0035 §F-2, PoR Invariant I-2  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Hardening defenses verified across provider capacity bounding, duration clamping, token boundary enforcement, thread concurrency, and fail-closed snapshot calculation.

---

## 1. Hardening Mitigations Delivered

1. **Provider Key Capacity Ceiling**:
   - `MAX_TRACKED_PROVIDERS = 64` enforced on `_provider_counts` dictionary.
   - Any excess providers beyond 64 are safely collapsed into an `"other"` aggregate key, preventing memory exhaustion attacks from dynamically generated provider names.

2. **Duration and Token Clamping**:
   - Durations clamped to `[0.0, 3600000.0]` ms (`MAX_DURATION_MS = 1 hour`).
   - Token additions clamped to `[0, 10000000]` (`MAX_TOKENS_PER_RECORD`).
   - Negative durations or negative tokens automatically normalized to `0`.

3. **Thread Safety & Concurrent Execution**:
   - Concurrency validated across multiple concurrent threads recording completions and failures simultaneously without race conditions or data corruption.

4. **ADR-0035 §F-2 Fail-Closed Snapshot Fallback**:
   - If an unexpected error occurs during snapshot computation or validation, `get_snapshot()` catches the exception, logs it, and returns an honest fallback snapshot marked `CRITICAL` with `provider_breakdown={"error": 1}`.

---

## 2. Hardening Test Execution Output

```
code\aiosh-mcp\tests\test_model_backend_adapters_observability_hardening.py ...   [ 20%]
code\aiosh-mcp\tests\test_model_backend_adapters_observability_impl.py ...        [ 40%]
code\aiosh-mcp\tests\test_model_backend_adapters_observability_integration.py . [ 46%]
code\aiosh-mcp\tests\test_model_backend_adapters_observability_scaffold.py ..    [ 60%]
code\aiosh-mcp\tests\test_model_backend_adapters_observability_unit.py ......    [100%]

===================== 15 passed, 790 deselected in 22.91s =====================
```
