# Hardening & Security Audit Evidence: AI Control Plane MCP Server Core Configuration Subsystem (T-03110)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Target**: Fault tolerance, temp file cleanup, atomic writes, size bounds, and explicit error handling
- **Bindings**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §F-2, PoR Invariant I-2

---

## 1. Hardening & Fault Tolerance Measures

1. **Atomic File Persistence with Guaranteed Cleanup**:
   - In both Python (`mcp_server_core_config.py`) and Rust (`mcp_server_core_config.rs`), disk persistence uses an isolated, PID-tagged temporary file (`.tmp.<pid>`).
   - If an I/O error, invalid JSON encoding, or permission exception occurs, the temporary file is unlinked immediately in the error path.
   - Atomic rename (`os.replace` / `fs::rename`) guarantees readers never see partial or truncated configuration files.
2. **Pre-flight Size Limits**:
   - File size is checked against `MAX_CONFIG_FILE_BYTES` (64 KiB) before reading file content, preventing unbounded heap allocation and memory denial of service.
3. **Structured Error Handling**:
   - Replaced unhandled `json.JSONDecodeError` with explicit `McpConfigError` indicating malformed JSON.
   - Non-dictionary configuration JSON is rejected with explicit envelope error.
4. **Boundary Invariants Hardening**:
   - Normalization of path separators (`\\` -> `/`) ensures cross-platform traversal prevention across both Windows and POSIX systems.

---

## 2. Test Verification

- **Python Tests**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_config_unit.py code/aiosh-mcp/tests/test_mcp_server_core_config_integration.py` -> 7/7 passed.
- **Rust Tests**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_config_unit` -> 4/4 passed.
