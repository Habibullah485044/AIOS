# Integration Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03098)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Server registration, FastMCP tool integration, and end-to-end integration smoke testing
- **Bindings**: ADR-0035 §D-2, SPEC-MCP-SERVER-CORE-API, PoR Invariant I-2

---

## 1. Integration Scope & Surface Wiring

1. Registered `aios_mcp_api_ping` and `aios_mcp_api_jsonrpc` in `code/aiosh-mcp/aiosh_mcp/server.py` via `mcp_server_core_api_mod.register_mcp_api_tools(mcp)`.
2. Verified live MCP server registration: tools are visible in `list_tools()` catalog and executable via `call_tool`.
3. Verified parity between Python FastMCP endpoints and underlying `McpServerCoreService`.

---

## 2. Automated Integration Smoke Suite

- Executed `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_api_integration.py`.
- **Result**: PASSED (2 passed in 4.48s).
- All integrated calls cleanly parsed and routed without regression.
