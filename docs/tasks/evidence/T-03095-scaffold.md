# Scaffold Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03095)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Wire protocol skeleton, JSON-RPC 2.0 message parsing, and scaffold verification
- **Bindings**: ADR-0035 §D-2, SPEC-MCP-SERVER-CORE-API, PoR Invariant I-2

---

## 1. Scaffold Deliverables

1. Module `code/aiosh-mcp/aiosh_mcp/mcp_server_core_api.py`:
   - `McpApiHandler` class with JSON-RPC 2.0 routing.
   - Handlers for `ping`, `initialize`, `tools/list`, and `tools/call`.
   - Security perimeter checks: NUL byte detection, 1 MiB argument bounds (`MAX_ARGUMENTS_SIZE`), and capability token validation on `aios.admin.*`.
2. Scaffold Test `code/aiosh-mcp/tests/test_mcp_server_core_api_scaffold.py`:
   - Validates handshake, session initialization, and ping responses.
   - 100% pass rate in automated test suite.
