# Unit Test Evidence: AI Control Plane MCP Server Core MCP/API Surface (T-03097)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: 4-case testing battery covering valid input, invalid input, boundary values, and primary failure modes across Python and Rust
- **Bindings**: SPEC-MCP-SERVER-CORE-API, PoR Invariant I-2

---

## 1. Unit Test Coverage Matrix

1. **Case 1: Valid API Requests**:
   - `ping` -> 200/JSON-RPC ok with protocol version.
   - `initialize` -> capability negotiation, session initialization.
   - `tools/list` -> catalog enumeration.
   - `tools/call` -> safe execution.
2. **Case 2: Invalid API Inputs**:
   - Malformed JSON string (`-32700`).
   - Unsupported `jsonrpc` protocol version (`ERR_INVALID_REQUEST`).
   - Missing `method` field (`ERR_INVALID_REQUEST`).
   - Non-existent method routing (`ERR_METHOD_NOT_FOUND`).
   - Prohibited NUL byte injection (`ERR_INVALID_PARAMS`).
3. **Case 3: Boundary Values**:
   - Empty argument payload `{}` correctly handled.
   - Oversized argument payload (`> 1 MiB`) triggers `ERR_BOUNDS_EXCEEDED`.
4. **Case 4: Primary Failure Modes**:
   - Non-existent tool call rejected.
   - Privileged tool (`aios.admin.*`) without capability token fails closed with `ERR_UNAUTHORIZED` (`-32002`).
   - Privileged tool with valid capability token succeeds.

---

## 2. Test Execution Batteries

- **Python Battery**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_api_unit.py` -> 4/4 passed (0.28s).
- **Rust Battery**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_api_unit` -> 4/4 passed (0.11s).
