# Integration Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03198)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03198-mcp-api-surface-integration.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-MCP-API

---

## 1. Integration Verification Scenarios

Task `T-03198` validates end-to-end integration workflows across the Model Backend Adapters MCP/API surface and the host server:

1. **FastMCP Server Registration**:
   - Verified that `model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, and `model_backend_register` are registered on the FastMCP application in `aiosh_mcp.server`.

2. **End-to-End Operational Lifecycle**:
   - `list` -> Query initial endpoint catalogue.
   - `register` -> Dynamically register new endpoint with capability token (PoR I-2). Missing token rejected with code `-32003`.
   - `show` -> Verify registered endpoint configuration and timeout bounds.
   - `health` -> Verify operational readiness of newly registered adapter.
   - `complete` -> Dispatch inference query through new endpoint requiring capability token.

3. **Multi-Endpoint Fallback Progression**:
   - Evaluates chained fallback dispatch when primary backend is missing or inactive.
   - Verified that request gracefully falls back to available secondary backend (`mock-default`).

4. **JSON-RPC 2.0 Parity & Secret Redaction**:
   - Verifies standard JSON-RPC 2.0 envelope formats (`jsonrpc`, `id`, `result` or `error`).
   - Verifies secret scrubbing (`[REDACTED_SECRET]`) for Bearer tokens and `sk-*` API keys.

---

## 2. Test Execution Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_api_scaffold.py .... [ 16%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_impl.py ....... [ 44%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_unit.py .......... [ 84%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_integration.py .... [100%]
25 passed in 5.63s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
