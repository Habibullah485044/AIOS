# Unit Test Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03197)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03197-mcp-api-surface-unit-test.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-MCP-API

---

## 1. Test Suite Coverage & Invariants

Task `T-03197` establishes unit test coverage across both Python (`test_model_backend_adapters_api_unit.py`) and Rust (`model_backend_adapters_api::tests`) implementations:

1. **`MODAPI-INV1` (Wire Tool Schemas & Input Parameter Validation)**:
   - Validates proper parameter validation across endpoints: `show` (requires valid endpoint_id), `complete` (requires prompt, checks prompt size limits up to 1 MiB), `register` (requires endpoint_id and provider).
   - Verifies rejection of missing or empty required parameters.

2. **`MODAPI-INV2` (Proof-of-Restraint Gating)**:
   - Validates that pure read operations (`list`, `show`, `health`, `ping`) consume 0 capability tokens.
   - Validates that state-mutating operations (`complete`, `register`) strictly require `capability_token`, failing closed with error code `-32003` (`ERR_UNAUTHORIZED`) if missing or empty.

3. **`MODAPI-INV3` (Standardized Result Envelopes & JSON-RPC 2.0 Error Mapping)**:
   - Validates taxonomy: `-32600` (Invalid Request), `-32601` (Method Not Found), `-32602` (Invalid Params), `-32003` (Unauthorized), `-32004` (Timeout), `-32005` (Execution Failed).
   - Validates JSON-RPC 2.0 envelope parity (`jsonrpc: "2.0"`, `id`, `result` or `error`).

4. **`MODAPI-INV4` (Secret & Telemetry Redaction)**:
   - Validates redaction of Bearer tokens, `sk-*` keys, and `ghp_*` tokens across error messages and response payloads.

5. **`MODAPI-INV5` (Fallback & Execution Bounds)**:
   - Tests fallback depth limits (maximum depth <= 5) and timeout bounds clamping `[1000, 300000]` ms.

---

## 2. Test Execution Verification

### Python Substrate
```
code\aiosh-mcp\tests\test_model_backend_adapters_api_scaffold.py .... [ 19%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_impl.py ....... [ 52%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_unit.py .......... [100%]
21 passed in 1.17s
```

### Rust Substrate
```
running 4 tests
test model_backend_adapters_api::tests::test_rust_api_list_and_show ... ok
test model_backend_adapters_api::tests::test_rust_api_ping ... ok
test model_backend_adapters_api::tests::test_rust_api_request_dispatch ... ok
test model_backend_adapters_api::tests::test_rust_api_por_token_gating ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; finished in 0.08s
```

Evidence integrity checked via `tools/check_evidence.py`.
