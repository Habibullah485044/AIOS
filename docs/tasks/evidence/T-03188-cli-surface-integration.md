# Integration Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03188)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03188-cli-surface-integration.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-CLI

---

## 1. Integration Verification Scenarios

Task `T-03188` validates end-to-end integration workflows across the Model Backend Adapters CLI surface and the underlying runtime services:

1. **End-to-End Operational Lifecycle**:
   - `list` -> Query initial endpoint catalogue.
   - `register` -> Dynamically register new endpoint with `--token` (PoR I-2).
   - `show` -> Verify registered endpoint configuration and timeout bounds.
   - `health` -> Verify operational readiness of newly registered adapter.
   - `complete` -> Dispatch inference query through new endpoint and receive valid response.

2. **Multi-Endpoint Fallback Progression**:
   - Evaluates chained fallback dispatch when primary and intermediate endpoints are inactive or missing.
   - Verified that request gracefully falls back to available secondary backend.

3. **Entrypoint & Exit Code Integration**:
   - Tests `main()` entrypoint returning exact process exit codes (`0`, `1`, `2`, `3`).
   - Verifies stdout message rendering and secret scrubbing on console output streams.

---

## 2. Test Execution Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_cli_scaffold.py .... [ 16%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_impl.py ......   [ 40%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_unit.py ............ [ 88%]
code\aiosh-mcp\tests\test_model_backend_adapters_cli_integration.py ...   [100%]
25 passed in 0.74s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
