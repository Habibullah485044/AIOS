# Verification Evidence: AI Control Plane MCP Server Core CLI Surface (T-03092)

**Task ID**: T-03092 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface: Verification & Evidence)  
**Contract Reference**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`, ADR-0035 §AF-2, PoR Invariant I-2  
**Date**: 2026-10-18  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — 100% green verification across Rust (`aiosh-core`, `aiosh-cli`) and Python (`aiosh-mcp`), with Proof of Restraint conformance validated and full milestone closeout for the CLI surface subsystem (`T-03083`..`T-03092`).

---

## 1. Subsystem Scope & Invariants Certified

This milestone completes the **MCP Server Core CLI Surface** subsystem (`aiosh mcp`), exposing operational inspection and tool execution:
- `MCPCLI-INV1`: Standard exit codes (0: success, 1: error/not found, 2: usage error, 3: unauthorized, 4: timeout).
- `MCPCLI-INV2`: Bounded input arguments (`MAX_ARGUMENTS_SIZE = 1 MiB`), timeout bounds `[1, 300]`, NUL byte rejection across all argument tokens.
- `MCPCLI-INV3`: Privileged administrative tools (`aios.admin.*`) strictly gate on `--grant <TOKEN>` and fail closed with code 3.
- `MCPCLI-INV4`: Structured `McpCoreResultEnvelope` output in `--json` mode for success and failure conditions.
- `MCPCLI-INV5`: Every invocation emits an audit row into `audit.db` via `classify_and_emit` (`AuditRing`).

---

## 2. Test Execution Batteries

### 2.1 Python Test Battery (`aiosh-mcp`)
```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\OBSESSION\Desktop\AIOS_MERGED\code\aiosh-mcp
configfile: pyproject.toml
plugins: anyio-4.14.2
collected 7 items

code\aiosh-mcp\tests\test_mcp_server_core_cli_unit.py ....               [ 57%]
code\aiosh-mcp\tests\test_mcp_server_core_cli_hardening.py ..            [ 85%]
code\aiosh-mcp\tests\test_mcp_server_core_cli_integration.py .           [100%]

============================== 7 passed in 4.03s ==============================
```

### 2.2 Rust Test Battery (`aiosh-core`)
```
     Running tests\test_mcp_server_core_cli_hardening.rs
running 2 tests
test test_hardening_json_error_envelopes ... ok
test test_hardening_nul_byte_rejection ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests\test_mcp_server_core_cli_unit.rs
running 4 tests
test test_unit_case1_valid_cli_commands ... ok
test test_unit_case2_invalid_cli_inputs ... ok
test test_unit_case3_boundary_values ... ok
test test_unit_case4_primary_failure_modes ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

### 2.3 Proof of Restraint Demonstration (`demo_por.py`)
```
AIOS — Proof of Restraint milestone demo (T-02892)
=== DEMO RESULT ===
PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.
```

---

## 3. Milestone Conclusion

The CLI Surface subsystem is verified, hardened, documented, and fully integrated with `AuditRing` and `McpServerCoreService`. The next subsystem is **MCP Server Core / MCP/API surface** (`T-03093`..`T-03102`).
