# Documentation Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03101)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Developer and operator documentation, copy-pasteable wire examples, and limitation disclosures
- **Bindings**: SPEC-MCP-SERVER-CORE-API, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Documentation Overview

1. Updated `code/aiosh-mcp/README.md` with the new section **MCP Server Core Wire API (`aios_mcp_api_*`)**.
2. Documented endpoints:
   - `aios_mcp_api_ping`: Protocol liveness check returning version `2025-06-18`.
   - `aios_mcp_api_jsonrpc`: Raw JSON-RPC 2.0 message dispatch (`initialize`, `ping`, `tools/list`, `tools/call`).
3. Included complete JSON-RPC copy-pasteable request/response schemas.
4. Honestly recorded limitations and boundaries:
   - 1 MiB payload clamp (`MAX_ARGUMENTS_SIZE`).
   - Rejection of NUL bytes in arguments.
   - Capability grant requirement on `aios.admin.*` tools.
