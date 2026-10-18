# Unit Test Evidence: AI Control Plane MCP Server Core Configuration Subsystem (T-03107)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Focus**: 4-case testing battery covering valid input, invalid input, boundary values, and primary failure modes across Python and Rust
- **Bindings**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Unit Test Coverage Matrix

1. **Case 1: Valid Configuration**:
   - Default configurations verified against invariants.
   - Custom configurations validated with full parameter overrides.
   - Roundtrip JSON serialization byte-level equality.
2. **Case 2: Invalid Inputs**:
   - Empty `store_path` triggers `MCPCFG-INV1` error.
   - Path traversal (`..`) and NUL bytes in path trigger `MCPCFG-INV1` error.
   - Out-of-bounds `max_active_sessions` (< 1) triggers `MCPCFG-INV2` error.
3. **Case 3: Boundary Values**:
   - Tested exact boundary minimums: sessions=1, idle_timeout=60, exec_timeout=1, args_size=1024, tools_count=1.
   - Tested exact boundary maximums: sessions=512, idle_timeout=86400, exec_timeout=300, args_size=10MiB, tools_count=1024.
   - Tested out-of-bounds values above maximum triggering refusal.
4. **Case 4: Primary Failure Modes**:
   - Missing configuration files throw explicit `FileNotFoundError`.
   - Oversized configuration files (> 64 KiB) throw `McpConfigError`.
   - Hierarchical precedence verified: CLI flags override environment variables.

---

## 2. Test Execution Batteries

- **Python Battery**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_config_unit.py` -> 4/4 passed.
- **Rust Battery**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_config_unit` -> 4/4 passed.
