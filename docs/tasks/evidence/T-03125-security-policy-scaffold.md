# Scaffold Evidence: AI Control Plane MCP Server Core Security Policy (T-03125)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy
- **Artifact**: `docs/tasks/evidence/T-03125-security-policy-scaffold.md`
- **Files Created**:
  - `code/aiosh-mcp/aiosh_mcp/mcp_server_core_policy.py`
  - `code/aiosh-rust/aiosh-core/src/mcp_server_core_policy.rs`
  - `code/aiosh-mcp/tests/test_mcp_server_core_policy_scaffold.py`
  - `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_policy_scaffold.rs`

---

## 1. Scaffold Implementation Details

1. **Python Substrate**:
   - Implemented `PolicyEffect` (`ALLOW`, `DENY`, `REQUIRE_CAPABILITY`).
   - Implemented `PolicyActionCategory` (`READ_ONLY`, `DIAGNOSTICS`, `STATE_CHANGING`, `ADMINISTRATIVE`).
   - Implemented `PolicyRule`, `PolicyEvaluationRequest`, and `PolicyDecision` with frozen dataclass schemas and validation rules.
   - Implemented `McpServerCorePolicyEngine` with rule prioritization, glob pattern matching, and Invariant I-2 gating.
   - Exported through `code/aiosh-mcp/aiosh_mcp/__init__.py`.

2. **Rust Substrate**:
   - Defined corresponding structs and enums in `code/aiosh-rust/aiosh-core/src/mcp_server_core_policy.rs`.
   - Pattern matching and priority sorting with strict bounds checking.
   - Exported in `code/aiosh-rust/aiosh-core/src/lib.rs` via `pub mod mcp_server_core_policy;`.

---

## 2. Test Execution

- **Python**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_policy_scaffold.py` -> 2 passed.
- **Rust**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_policy_scaffold` -> 2 passed.
