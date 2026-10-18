# Unit Test Evidence: AI Control Plane MCP Server Core CLI Surface (T-03087)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface
- **Task ID**: `T-03087`
- **Specification Document**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`

## 1. Unit Test Matrix Execution
Testing battery covers 4 distinct cases per AIOS standards:
1. **Case 1 (Valid Input)**:
   - Ping (`aiosh mcp ping --json`): verifies server connectivity and JSON payload.
   - List (`aiosh mcp list --json`): verifies tool enumerations.
   - Show (`aiosh mcp show aios.fs.read --json`): verifies schema formatting.
   - Dispatch (`aiosh mcp dispatch aios.fs.read --args '...'`): verifies bounded execution and return code 0.
   - Sessions (`aiosh mcp sessions --prune 0 --json`): verifies session eviction.
2. **Case 2 (Invalid Input)**:
   - Empty args rejected (`EXIT_USAGE = 2`).
   - Unknown subcommand rejected (`EXIT_USAGE = 2`).
   - Unknown flags rejected (`EXIT_USAGE = 2`).
   - Missing required positional parameters rejected (`EXIT_USAGE = 2`).
3. **Case 3 (Boundary Values)**:
   - Oversized arguments exceeding `MAX_ARGUMENTS_SIZE = 1 MiB` rejected (`EXIT_USAGE = 2`).
   - Timeout bounds clamped to upper limit (300s) on execution.
4. **Case 4 (Primary Failure Modes)**:
   - Tool not found returns `EXIT_FAILURE = 1`.
   - Dispatch to missing tool returns `EXIT_FAILURE = 1`.
   - Privileged tool call (`aios.admin.*`) without capability token fails closed with `EXIT_UNAUTHORIZED = 3` in conformance with PoR Invariant I-2.

## 2. Test Battery Results
- **Rust Suite**: `cargo test -p aiosh-core --test test_mcp_server_core_cli_unit`
  - 4/4 tests PASSED in 0.03s.
- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_cli_unit.py`
  - 4/4 tests PASSED in 0.56s.
