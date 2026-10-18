# Integration Evidence: AI Control Plane MCP Server Core CLI Surface (T-03088)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Task ID**: `T-03088`
- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`

## 1. Integration Verification Summary
Validated end-to-end integration between CLI argument parsing, execution routing, `McpServerCoreService`, active session lifecycle, and `AuditRing` event logging:
1. **Catalog Query Integration**:
   - `aiosh mcp list --json` and `aiosh mcp show <TOOL> --json` accurately query and present metadata from the in-memory tool catalog.
2. **Safe Dispatch Roundtrip**:
   - Invocations with complex JSON payloads parse, clamp timeouts to safe operational windows, execute through `safe_dispatch_with_timeout`, and return ADR-0035 §AF-2 result envelopes.
3. **Session Lifecycle & Pruning**:
   - Creating, terminating, and pruning sessions via `aiosh mcp sessions --prune 0` correctly cleans dead sessions and reports eviction tallies.
4. **PoR Invariant I-2 Audit Trail Emission**:
   - Verified that CLI dispatch operations commit structured, immutable audit rows (`AuditRowInput`) into `AuditRing` with sequential monotonicity and SHA-256 hash chaining.

## 2. Test Execution
- **Rust Suite**: `cargo test -p aiosh-core --test test_mcp_server_core_cli_integration`: 1/1 passed.
- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_cli_integration.py`: 1/1 passed.
