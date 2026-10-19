# Implementation Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03196)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03196-mcp-api-surface-implementation.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, MCP Schema 2025-06-18, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-MCP-API

---

## 1. Implementation Overview

Task `T-03196` delivers the full implementation of the Model Backend Adapters MCP/API surface:

### Wire Handlers Implemented

1. **`model_backend_list`**:
   - Enumerates registered endpoints from `ModelBackendService`.
   - Supports provider filtering (`--provider`) and active filtering (`--active-only`).
   - Token requirement: 0 tokens (pure read).

2. **`model_backend_show`**:
   - Inspects target endpoint configuration (`backend_id`).
   - Returns full metadata and capabilities. Returns `-32004` (`ERR_NOT_FOUND`) if nonexistent.
   - Token requirement: 0 tokens (pure read).

3. **`model_backend_health`**:
   - Reports operational readiness across all registered adapters or for a specific target endpoint.
   - Token requirement: 0 tokens (pure read).

4. **`model_backend_complete`**:
   - Executes completion requests via `ModelBackendService.complete`.
   - Enforces PoR Invariant I-2: strictly requires `capability_token`, returning `-32003` (`ERR_UNAUTHORIZED`) if missing.
   - Validates temperature bounds `[0.0, 2.0]` and fallback depths (`<= 5`).

5. **`model_backend_register`**:
   - Dynamically registers new inference endpoint into registry.
   - Enforces PoR Invariant I-2: strictly requires `capability_token`, returning `-32003` (`ERR_UNAUTHORIZED`) if missing.
   - Validates provider string and timeout parameters `[1000, 300000]` ms.

6. **FastMCP Integration Helper**:
   - `register_model_backend_tools(app, service)` mounts all 5 tools on any FastMCP server.

---

## 2. Test Execution Verification

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
code\aiosh-mcp\tests\test_model_backend_adapters_api_scaffold.py .... [ 36%]
code\aiosh-mcp\tests\test_model_backend_adapters_api_impl.py ....... [100%]
11 passed in 1.08s
```

`cargo check -p aiosh-core` passed with zero errors.
Evidence validated with `tools/check_evidence.py`.
