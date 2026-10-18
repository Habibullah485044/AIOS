# Hardening Evidence: AI Control Plane MCP Server Core CLI Surface (T-03090)

**Task ID**: T-03090 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface: Hardening)  
**Contract Reference**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`, ADR-0035 §AF-2, PoR Invariant I-2  
**Date**: 2026-10-18  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Hardened argument parsing (rejection of NUL bytes across all flags and positional parameters), structured JSON error envelopes (`McpCliOutput.failure_with_json`), bounded argument sizing (`MAX_ARGUMENTS_SIZE = 1 MiB`), and timeout clamping verified across Rust (`aiosh-core`) and Python (`aiosh-mcp`).

---

## 1. Hardening Mitigations Delivered

1. **NUL Byte Injection Rejection (MCPCLI-INV2)**:
   - Added strict NUL byte checking across subcommands, options, and positional parameters in both Rust (`parse_mcp_cli_args`) and Python (`parse_mcp_cli_args`).
   - Prevents null-byte truncation attacks in tool names, filters, grants, and JSON argument payloads.

2. **Standardized JSON Error Envelopes (MCPCLI-INV4 & ADR-0035 §AF-2)**:
   - Updated `execute_mcp_cli()` to return uniform JSON error envelopes via `failure_with_json` whenever `--json` is supplied on error paths (tool not found, unauthorized, syntax error, usage error).
   - Invariant: machine clients parsing JSON never receive malformed or unparsable error strings.

3. **Input Bounding and Timeout Bounds (MCPCLI-INV2)**:
   - Strict size cap of 1 MiB (`MAX_ARGUMENTS_SIZE`) on `--args` payload.
   - Execution timeout bounds clamped to `[1, 300]` seconds.
   - Privileged administrative tools (`aios.admin.*`) strictly fail closed with exit code `3` (`EXIT_UNAUTHORIZED`) when `--grant` is absent.

---

## 2. Hardening Test Battery Execution

- **Rust Suite**: `cargo test -p aiosh-core --test test_mcp_server_core_cli_hardening`
  ```
  running 2 tests
  test test_hardening_json_error_envelopes ... ok
  test test_hardening_nul_byte_rejection ... ok
  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
  ```

- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_cli_hardening.py`
  ```
  code\aiosh-mcp\tests\test_mcp_server_core_cli_hardening.py .. [100%]
  2 passed in 1.17s
  ```
