# Scaffold Evidence: AI Control Plane MCP Server Core CLI Surface (T-03085)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Task ID**: `T-03085`
- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`

## 1. Scaffold Implementations
1. **Rust Core CLI Substrate (`aiosh-core/src/mcp_server_core_cli.rs`)**:
   - Implemented `mcp_server_core_cli` module in `code/aiosh-rust/aiosh-core/src/mcp_server_core_cli.rs`.
   - Defined data models: `McpCliSubcommand` (`List`, `Show`, `Dispatch`, `Sessions`, `Ping`) and `McpCliOutput`.
   - Defined core function signatures and validation bounds:
     - `parse_mcp_cli_args(&args)`
     - `execute_mcp_cli(&cmd, &service)`
   - Exported module in `code/aiosh-rust/aiosh-core/src/lib.rs`.

2. **Python MCP Fabric CLI Substrate (`aiosh_mcp/mcp_server_core_cli.py`)**:
   - Implemented `mcp_server_core_cli` module in `code/aiosh-mcp/aiosh_mcp/mcp_server_core_cli.py`.
   - Defined symmetric parsing, exit codes (`0..4`), and execution routing for dual-substrate parity.
   - Exported in `code/aiosh-mcp/aiosh_mcp/__init__.py`.

## 2. Test Verification
- Ran `cargo test -p aiosh-core --test test_mcp_server_core_cli_scaffold`: 1/1 tests passed (`test_mcp_cli_scaffold_types_and_ping`).
- Ran `pytest code/aiosh-mcp/tests/test_mcp_server_core_cli_scaffold.py`: 1/1 tests passed in 0.77s.
