# Hardening Evidence: AI Control Plane MCP Server Core Data Model (T-03070)

**Task ID**: T-03070 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Hardening)  
**Contract Reference**: `docs/tasks/evidence/T-03064-spec.md`, ADR-0035 §AF-2  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Hardened safe parsers, bounded memory allocations, and ADR-0035 §AF-2 result envelopes verified across Rust (`aiosh-core`) and Python (`aiosh-mcp`).

---

## 1. Hardening Mitigations Delivered

1. **Panic-Free & Exception-Free Envelope Parsers**:
   - Rust: `safe_parse_request_envelope()` and `safe_validate_tool_envelope()` return `McpCoreResultEnvelope<T>` directly.
   - Python: `safe_parse_request_envelope()` and `safe_validate_tool_envelope()` catch all validation and parsing exceptions, formatting them into `McpCoreResultEnvelope`.
2. **Payload Boundary Enforcement**:
   - Messages exceeding `MAX_PAYLOAD_SIZE = 10 MiB` are rejected before memory allocation, returning `ERR_BOUNDS_EXCEEDED (-32002)`.
3. **Control Character & Identifier Sanitization**:
   - Rejection of Trojan Source bidirectional overrides and control characters returning `ERR_SANITIZATION_FAILED (-32003)`.

---

## 2. Hardening Test Battery Execution

- **Rust Suite**: `cargo test --test test_mcp_server_core_data_model_hardening`
  ```
  running 2 tests
  test test_hardening_safe_validate_tool_envelope ... ok
  test test_hardening_safe_parse_envelope ... ok
  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
  ```
- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_data_model_hardening.py`
  ```
  code/aiosh-mcp/tests/test_mcp_server_core_data_model_hardening.py .. [100%]
  2 passed in 0.29s
  ```
