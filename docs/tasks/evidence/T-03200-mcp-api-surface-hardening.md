# Hardening Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03200)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03200-mcp-api-surface-hardening.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-MCP-API

---

## 1. Hardening Defenses Implemented

Task `T-03200` addresses the findings from the security review (`T-03199`), implementing strict input bounding, anti-traversal defenses, and fail-closed validation across Python and Rust substrates:

1. **Positional Identifier Defenses**:
   - Bounds: Length capped at 64 characters (`<= 64`).
   - Anti-Traversal: Rejects `..`, `/`, and `\` in identifiers with JSON-RPC error code `-32602` (`ERR_INVALID_PARAMS`).
   - Control Characters: Prohibits ASCII control characters and NUL bytes (`\0`).
   - Enforced across `handle_show`, `handle_health`, `handle_complete`, and `handle_register`.

2. **Payload Size Clamping & Injection Defense**:
   - Maximum prompt size strictly capped at 1 MiB (`1024 * 1024` bytes).
   - Prompt scanned for prohibited NUL bytes (`\0`), returning `-32602` on injection attempts.

3. **Fallback Chain Depth Clamping**:
   - Restricts `fallbacks` list to `MAX_FALLBACK_DEPTH = 5`. Attempts to provide more than 5 fallbacks reject with `-32602`.
   - Each fallback identifier in the array is rigorously validated against path traversal and character injection.

4. **Timeout Boundary Clamping**:
   - Requires `timeout_ms` in `handle_register` to fall strictly within `[1000, 300000]` ms (1s to 5m), preventing integer underflow/overflow or resource exhaustion.

5. **Temperature Boundary Clamping**:
   - Clamped to valid range `[0.0, 2.0]`. Out-of-bounds values return `-32602` immediately.

6. **Fail-Closed Result Envelopes & Secret Redaction**:
   - All errors return standard JSON-RPC 2.0 error envelopes with sanitized messages via `redact_secrets()`, ensuring no API keys or Bearer tokens leak over wire responses.

---

## 2. Test Execution Verification

### Python Substrate
```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_api_scaffold.py .... [ 12%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_impl.py ....... [ 34%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_unit.py .......... [ 65%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_integration.py .... [ 78%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_hardening.py ....... [100%]
32 passed in 3.53s
```

### Rust Substrate
```
running 5 tests
test model_backend_adapters_api::tests::test_rust_api_hardening ... ok
test model_backend_adapters_api::tests::test_rust_api_list_and_show ... ok
test model_backend_adapters_api::tests::test_rust_api_ping ... ok
test model_backend_adapters_api::tests::test_rust_api_por_token_gating ... ok
test model_backend_adapters_api::tests::test_rust_api_request_dispatch ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; finished in 0.07s
```

Evidence validated with `tools/check_evidence.py`.
