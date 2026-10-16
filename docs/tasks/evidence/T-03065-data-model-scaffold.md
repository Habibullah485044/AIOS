# Scaffold Evidence: AI Control Plane MCP Server Core Data Model (T-03065)

**Task ID**: T-03065 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Scaffold)  
**Contract Reference**: `docs/tasks/evidence/T-03064-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Skeletons, domain types, error codes, and exports instantiated across Rust (`aiosh-core`) and Python (`aiosh-mcp`). All test stubs compile and pass.

---

## 1. Modules Scaffolded

1. **Rust Core**:
   - Source: `code/aiosh-rust/aiosh-core/src/mcp_server_core_data_model.rs`
   - Exports: Registered in `code/aiosh-rust/aiosh-core/src/lib.rs`
   - Test Stub: `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_data_model_scaffold.rs`
   - Verification: `cargo test --test test_mcp_server_core_data_model_scaffold` -> PASSED (1/1).

2. **Python Substrate**:
   - Source: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_data_model.py`
   - Exports: Registered in `code/aiosh-mcp/aiosh_mcp/__init__.py`
   - Test Stub: `code/aiosh-mcp/tests/test_mcp_server_core_data_model_scaffold.py`
   - Verification: `pytest code/aiosh-mcp/tests/test_mcp_server_core_data_model_scaffold.py` -> PASSED (1/1).

---

## 2. Invariant Baseline

- `MCPDM-INV1`: Pinned `PROTOCOL_VERSION = "2025-06-18"` wired across both substrates.
- `MCPDM-INV2`: Sizing constants defined (`MAX_TOOL_NAME_LEN`, `MAX_PAYLOAD_SIZE`, `MAX_ARGUMENTS_SIZE`).
- `MCPDM-INV4`: Result envelopes declared with ADR-0035 §AF-2 compliance.
