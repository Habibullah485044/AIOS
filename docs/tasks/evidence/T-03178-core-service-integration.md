# Integration Evidence: AI Control Plane Model Backend Adapters Core Service (T-03178)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03178-core-service-integration.md`
- **Integrated Server**: `code/aiosh-mcp/aiosh_mcp/server.py`
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_service_integration.py` (4 passed)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. FastMCP Integration & Invariant I-2 Enforcement

1. **`aios_model_complete`**:
   - Registered as state-mutating inference invocation tool.
   - Strictly validates `capability_token`: empty/whitespace tokens fail closed with `MODSERV_ERR_UNAUTHORIZED`.
   - Dispatches parsed `ModelRequest` across `ModelBackendService` adapters and fallback backends.
   - Returns serialized `ModelResponse` with `ModelUsage` token accounting.
2. **`aios_model_service_health`**:
   - Registered as pure read-only operational query.
   - Enforces PoR Invariant I-2: executes without requiring any capability tokens (0 tokens consumed).
   - Returns total endpoints, active endpoints, and adapter readiness.
3. **Verification**:
   - All 4 tests in `test_model_backend_adapters_service_integration.py` passed against the live FastMCP server instance.
