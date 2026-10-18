# Scaffold Evidence: AI Control Plane MCP Server Core Configuration Subsystem (T-03105)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Focus**: Configuration parameters, validation skeletons, and scaffold verification across Python and Rust
- **Bindings**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Scaffold Deliverables

1. **Python Subsystem (`code/aiosh-mcp/aiosh_mcp/mcp_server_core_config.py`)**:
   - `McpServerCoreConfig` dataclass with complete default values and `validate()` method.
   - Serialization to/from dictionary and JSON configuration files.
   - Scaffold verification test in `code/aiosh-mcp/tests/test_mcp_server_core_config_scaffold.py`.
2. **Rust Subsystem (`code/aiosh-rust/aiosh-core/src/mcp_server_core_config.rs`)**:
   - `McpServerCoreConfig` struct matching Python data model.
   - Clean export in `aiosh_core::lib.rs` with zero warnings/errors.
