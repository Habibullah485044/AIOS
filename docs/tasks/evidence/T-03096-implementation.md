# Implementation Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03096)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Minimal working behavior across Python and Rust for JSON-RPC 2.0 wire dispatch, capability gating, and bounds enforcement
- **Bindings**: ADR-0035 §D-2, SPEC-MCP-SERVER-CORE-API, PoR Invariant I-2

---

## 1. Implemented Components

1. **Python Implementation (`code/aiosh-mcp/aiosh_mcp/mcp_server_core_api.py`)**:
   - `McpApiHandler`: Implements `ping`, `initialize`, `tools/list`, and `tools/call`.
   - Security controls: JSON-RPC 2.0 protocol validation, NUL byte rejection, `MAX_ARGUMENTS_SIZE` (1 MiB), and capability token validation for `aios.admin.*`.
   - Full integration with `McpServerCoreService`.
2. **Rust Implementation (`code/aiosh-rust/aiosh-core/src/mcp_server_core_api.rs`)**:
   - `McpApiHandler<'a>`: Wire protocol handler interoperable with `McpServerCoreService`.
   - Complete JSON-RPC 2.0 routing and validation.
   - Clean compilation in `aiosh-core`.

---

## 2. Test Verification

- `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_api_scaffold.py`: PASSED (1/1)
- `cargo check --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core`: PASSED (0 warnings/errors)
