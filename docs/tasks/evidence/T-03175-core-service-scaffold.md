# Scaffold Evidence: AI Control Plane Model Backend Adapters Core Service (T-03175)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03175-core-service-scaffold.md`
- **Scaffold Modules**:
  - Python: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_service.py`
  - Rust: `code/aiosh-rust/aiosh-core/src/model_backend_adapters_service.rs`
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_service_scaffold.py` (4 passed)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Scaffold Deliverables Summary

1. **Python Implementation**:
   - `BaseModelAdapter` abstract base class defining `complete()`.
   - `MockModelAdapter` providing deterministic completion, simulated latency, configurable failure modes (`timeout`, `rate_limit`, `unavailable`), and token usage generation.
   - `ModelBackendService` managing adapter registrations (`MODSERV-INV1`), fallback chain progression (`MODSERV-INV3`), and read-only operational health checks.
   - Standard error constants: `MODSERV_ERR_UNKNOWN_BACKEND`, `MODSERV_ERR_TIMEOUT`, `MODSERV_ERR_RATE_LIMIT`, `MODSERV_ERR_AUTH`, `MODSERV_ERR_UNAVAILABLE`, `MODSERV_ERR_FALLBACK_EXHAUSTED`, `MODSERV_ERR_UNSUPPORTED_PROVIDER`.
2. **Rust Parity Scaffold**:
   - `MockModelAdapter` with `complete()` returning `Result<ModelResponse, String>`.
   - Error code definitions and `ModelServiceHealth` struct.
   - Registered in `aiosh-core/src/lib.rs`.
3. **Verification**:
   - Unit test suite `test_model_backend_adapters_service_scaffold.py` passed with 4/4 passing tests.
