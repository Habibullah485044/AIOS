# Specification: AI Control Plane MCP Server Core Configuration Subsystem

**Document ID**: SPEC-MCP-SERVER-CORE-CONFIG  
**Lifecycle Target**: T-03103..T-03112 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Configuration Subsystem** defines the configuration parameters, validation rules, persistence contracts, and resolution hierarchy for the AIOS AI Control Plane MCP server.

Both Python (`aiosh_mcp.mcp_server_core_config`) and Rust (`aiosh_core::mcp_server_core_config`) implement this specification with byte-level schema parity.

---

## 2. Configuration Parameters & Invariants

| Invariant | Field | Type | Default | Bounds / Constraints | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MCPCFG-INV1** | `store_path` | `PathBuf` / `str` | `.aios/mcp_store.json` | Non-empty, no `..` traversal, no NUL bytes | Persistent state store file |
| **MCPCFG-INV2** | `max_active_sessions` | `usize` / `int` | `64` | `[1, 512]` | Concurrency limit on active client sessions |
| **MCPCFG-INV3** | `session_idle_timeout_seconds` | `u64` / `int` | `3600` | `[60, 86400]` | Inactivity period before session auto-pruning |
| **MCPCFG-INV4** | `default_execution_timeout_seconds` | `u64` / `int` | `30` | `[1, 300]` | Default tool execution timeout |
| **MCPCFG-INV5** | `max_arguments_size_bytes` | `usize` / `int` | `1048576` (1 MiB) | `[1024, 10485760]` (1 KiB..10 MiB) | Maximum argument payload allowed per call |
| **MCPCFG-INV6** | `max_tools_count` | `usize` / `int` | `256` | `[1, 1024]` | Maximum registered tools in memory catalog |
| **MCPCFG-INV7** | `require_admin_grant` | `bool` | `true` | Boolean flag | Mandatory PoR capability gating for admin tools |
| **MCPCFG-INV8** | `auto_prune_terminated` | `bool` | `true` | Boolean flag | Automatically evict terminated sessions |

---

## 3. Resolution Precedence

Configuration values are resolved strictly according to the following order:
1. **Explicit CLI Flags** (e.g., `--timeout <SECS>`, `--max-sessions <COUNT>`).
2. **Environment Variables**:
   - `AIOS_MCP_STORE_PATH`
   - `AIOS_MCP_MAX_SESSIONS`
   - `AIOS_MCP_IDLE_TIMEOUT`
   - `AIOS_MCP_EXECUTION_TIMEOUT`
   - `AIOS_MCP_MAX_ARGS_SIZE`
   - `AIOS_MCP_REQUIRE_ADMIN_GRANT`
3. **JSON Configuration File** (`.aios/mcp_server_core_config.json`):
   - Bounded to `MAX_CONFIG_FILE_BYTES = 65,536` bytes.
4. **Hardcoded Defaults** (Section 2).

---

## 4. Failure Modes & Audit Logging

- Malformed or out-of-bounds configuration values throw explicit validation errors (`McpConfigError` / `ValueError`).
- Modification of persistent configuration emits an audit event to `audit.db` via `AuditRing` (`mcp.config.update`).
