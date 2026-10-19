# Documentation Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03201)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03201-mcp-api-surface-documentation.md`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-MCP-API.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Documentation Overview

Task `T-03201` updates and solidifies the operator-facing and developer documentation for the Model Backend Adapters MCP/API surface:

1. **JSON-RPC 2.0 & FastMCP Wire Invocation Reference**:
   - Comprehensive request/response schema specifications for `model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, and `model_backend_register`.
   - Copy-pasteable JSON examples for both raw JSON-RPC 2.0 frames and FastMCP tool invocations.

2. **Proof-of-Restraint Invariant I-2 Guidelines**:
   - Explicit operational instructions for read-only vs. state-mutating actions.
   - Explains zero-token queries (`list`, `show`, `health`, `ping`) and `capability_token` requirements for `complete` and `register`.

3. **Standardized Error Code Taxonomy**:
   - Details `0` (Success), `-32602` (Invalid Params), `-32003` (Unauthorized), `-32004` (Not Found), `-32005` (Timeout), and `-32603` (Internal).

4. **Hardened Boundary Constraints & Limitations**:
   - Explicitly records payload limits (1 MiB), NUL byte rejection, identifier length limits (64 chars), directory traversal defenses, temperature bounds `[0.0, 2.0]`, timeout bounds `[1000, 300000] ms`, and fallback depth limits (5).
   - Acknowledges that streaming primitive is deferred to future sprint milestones per ADR-0035 §5.

---

## 2. Verification

- Documentation updated in `docs/SPEC-MODEL-BACKEND-ADAPTERS-MCP-API.md` and `code/aiosh-mcp/README.md`.
- All dual-substrate test batteries pass (32 Python tests, 5 Rust tests).
- Validated with `tools/check_evidence.py`.
