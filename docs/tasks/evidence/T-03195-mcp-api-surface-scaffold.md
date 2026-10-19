# Scaffold Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03195)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03195-mcp-api-surface-scaffold.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, MCP Schema 2025-06-18, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-MCP-API

---

## 1. Scaffold Implementations

1. **Python Substrate**:
   - File: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_api.py`
   - Registered in `code/aiosh-mcp/aiosh_mcp/__init__.py`
   - Defines JSON-RPC 2.0 error mapping constants: `ERR_SUCCESS=0`, `ERR_INVALID_PARAMS=-32602`, `ERR_UNAUTHORIZED=-32003`, `ERR_NOT_FOUND=-32004`, `ERR_TIMEOUT=-32005`
   - Implements `ModelBackendApiHandler` with PoR Invariant I-2 gating: pure reads cost 0 tokens; `handle_complete` and `handle_register` strictly require `capability_token`.
   - Wire envelopes protected with `redact_secrets()`.

2. **Rust Substrate**:
   - File: `code/aiosh-rust/aiosh-core/src/model_backend_adapters_api.rs`
   - Registered in `code/aiosh-rust/aiosh-core/src/lib.rs`
   - Implements `ModelBackendApiHandler` handling wire methods with identical error envelopes and token enforcement.

3. **Scaffold Tests**:
   - File: `code/aiosh-mcp/tests/test_model_backend_adapters_api_scaffold.py`
   - Verifies wire constants, envelope constructors, ping liveness, and PoR Invariant I-2 gating.

---

## 2. Test Execution Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_api_scaffold.py .... [100%]
4 passed in 3.41s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
