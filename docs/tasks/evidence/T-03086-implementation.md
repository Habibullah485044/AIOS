# Implementation Evidence: AI Control Plane MCP Server Core CLI Surface (T-03086)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Task ID**: `T-03086`
- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`

## 1. Implementation Summary
1. **Shell CLI Dispatch Integration (`aiosh-cli/src/main.rs`)**:
   - Integrated `aiosh mcp` command handler into userspace binary dispatcher.
   - Implemented `cmd_mcp(args: &[String]) -> i32` supporting subcommands:
     - `aiosh mcp ping [--json]`
     - `aiosh mcp list [--filter <GLOB>] [--json]`
     - `aiosh mcp show <TOOL> [--json]`
     - `aiosh mcp dispatch <TOOL> [--args <JSON>] [--grant <TOKEN>] [--timeout <SECS>] [--json]`
     - `aiosh mcp sessions [--prune <SECS>] [--json]`
   - Connected `classify_and_emit` to guarantee Proof-of-Restraint audit event logging to `audit.db` on every invocation (`mcp.core.execute`, `mcp.core.parse`).
   - Added unit test suite `test_mcp_cli_commands` in `main.rs` covering help, ping, list, show, privileged dispatch authorization gates, sessions pruning, and error handling.

2. **Python MCP Fabric CLI Integration (`aiosh_mcp/mcp_server_core_cli.py`)**:
   - Functional CLI arguments parsing (`parse_mcp_cli_args`) and dispatch execution (`execute_mcp_cli`).
   - Complete parity on exit codes `0..4` and ADR-0035 §AF-2 result envelope formatting.

## 2. Test Verification
- Executed `cargo test -p aiosh-cli test_mcp_cli_commands`: 1/1 passed.
- Executed `pytest code/aiosh-mcp/tests/test_mcp_server_core_cli_scaffold.py`: 1/1 passed.
