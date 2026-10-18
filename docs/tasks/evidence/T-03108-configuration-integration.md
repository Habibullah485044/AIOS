# Integration & Security Audit Evidence: AI Control Plane MCP Server Core Configuration Subsystem (T-03108)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Target**: Production server integration with FastMCP (`aiosh_mcp.server`) and runtime validation tools
- **Spec Reference**: SPEC-MCP-SERVER-CORE-CONFIG, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Production Integration Surface

The configuration subsystem has been integrated into the central server dispatch and discovery registry:
1. **Tool Registrations**:
   - `aios_mcp_config_get`: Exposes active resolved configuration (store path, timeouts, session bounds, and admin grant flags) formatted in standard JSON envelope.
   - `aios_mcp_config_validate`: Exposes pre-flight candidate configuration validator verifying `MCPCFG-INV1..MCPCFG-INV8` before committing mutations.
2. **FastMCP Integration**:
   - Registered in `code/aiosh-mcp/aiosh_mcp/server.py` via `mcp_server_core_config_mod.register_mcp_config_tools(mcp)`.
   - Accessible via MCP stdio wire protocol and programmatic API callers.

---

## 2. Security Audit & Invariant Review

- **SA-1 (Parameter Injection & Traversal)**:
  - Audited `aios_mcp_config_validate` and `aios_mcp_config_get` against traversal sequences (`..`), non-printable characters, and NUL byte injections.
  - Path inputs containing directory traversal (`..`) or embedded `\0` are rejected immediately with `MCPCFG-INV1 violation`.
- **SA-2 (State Protection & PoR Invariant I-2)**:
  - Configuration exposure (`aios_mcp_config_get`) is read-only.
  - Candidate validation (`aios_mcp_config_validate`) is a pure function without disk side-effects.
  - Mutable operations remain gated and restricted to administrative capabilities requiring explicit capability token redemption.
- **SA-3 (Denial of Service & Resource Caps)**:
  - Config files are strictly capped at 64 KiB (`MAX_CONFIG_FILE_BYTES`).
  - Active sessions are strictly bounded to `[1, 512]` (`MCPCFG-INV2`).
  - Execution timeouts are strictly bounded to `[1, 300]` seconds (`MCPCFG-INV4`).

---

## 3. Automated Test Verification

- **Integration Battery**: `code/aiosh-mcp/tests/test_mcp_server_core_config_integration.py`
  - `test_mcp_config_integration_tools_registered` (PASS)
  - `test_mcp_config_integration_get` (PASS)
  - `test_mcp_config_integration_validate` (PASS)
- Output: 3 passed in 3.90s.
- **Rust Parity Battery**:
  - `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_config_unit`: 4 passed (0.00s).
