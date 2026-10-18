# Research Document: AI Control Plane MCP Server Core Configuration Subsystem (T-03103)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / configuration
- **Focus**: Configuration Schema, Resolution Precedence, Boundary Constraints, and Security Invariants
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, PoR Invariant I-2
- **Author**: Codebuff (Antigravity Autonomous Pair)
- **Date**: 2026-10-18

---

## 1. Executive Summary & Objective

The **MCP Server Core Configuration Subsystem** establishes deterministic, multi-source configuration management for the AIOS AI Control Plane MCP server.

It provides centralized runtime limits, filesystem store targets, session pool thresholds, and security enforcement flags governing `McpServerCoreService` and `McpApiHandler`.

---

## 2. Facts vs. Assumptions

### 2.1 Authoritative Facts
1. **Existing Limits in Code**:
   - `MAX_ACTIVE_SESSIONS = 64`
   - `SESSION_IDLE_TIMEOUT_SECONDS = 3600`
   - `DEFAULT_EXECUTION_TIMEOUT_SECONDS = 30`
   - `MAX_EXECUTION_TIMEOUT_SECONDS = 300`
   - `MAX_ARGUMENTS_SIZE = 1,048,576` (1 MiB)
   - `MAX_TOOLS_COUNT = 256`
2. **File Size Bound**: Standard AIOS configuration files enforce a 64 KiB cap (`MAX_CONFIG_FILE_BYTES = 65,536`) to protect against parsing DoS and memory exhaustion.
3. **Multi-Source Hierarchy**: Consistent with AIOS architecture (e.g. `session_config.rs`, `toolchain_config.rs`), configuration must follow strict precedence:
   `CLI Flags > Environment Variables > JSON Config File > Hardcoded Defaults`.
4. **Security Policy**: Privileged tools (`aios.admin.*`) must require capability token redemption by default (`require_admin_grant = true`).

### 2.2 Assumptions Validated
1. **Store File Format**: JSON canonical serialization with atomic update semantics (`.tmp` + `os.replace` / atomic rename).
2. **Substrate Parity**: Both Python (`aiosh_mcp.mcp_server_core_config`) and Rust (`aiosh_core::mcp_server_core_config`) must implement identical validation invariants and defaults.

---

## 3. Security Audit & Threat Modeling (SC-1..SC-5)

1. **SC-1 (Store Path Traversal & Injection)**:
   - *Risk*: Malicious or misconfigured `store_path` targeting root directories, system paths (`/etc/shadow`), or containing path traversal (`../`).
   - *Audit Control*: Strict path validation rejecting parent traversal, NUL bytes, and unauthorized root mutations.
2. **SC-2 (Exhaustion via Excessive Session Quotas)**:
   - *Risk*: Setting unbounded session limits (`max_active_sessions: 1,000,000`), leading to heap exhaustion.
   - *Audit Control*: Mandatory clamping to `[1, 512]` sessions maximum.
3. **SC-3 (Deadlock / DoS via Infinite Timeout Configuration)**:
   - *Risk*: Configuring timeout to 0 or infinity, causing stuck workers or thread starvation.
   - *Audit Control*: Strict bound validation clamping `default_execution_timeout_seconds` into `[1, 300]` seconds.
4. **SC-4 (Unbounded Arguments Payload Allocation)**:
   - *Risk*: Configuring argument size cap to gigabyte scales.
   - *Audit Control*: `max_arguments_size_bytes` clamped to `[1024, 10 * 1024 * 1024]` (1 KiB to 10 MiB maximum).
5. **SC-5 (Silent Configuration Fallback / Misconfiguration)**:
   - *Risk*: Invalid configuration quietly falling back without operator awareness.
   - *Audit Control*: Explicit fail-loud validation errors on invalid values.

---

## 4. Key Architectural Decisions Needed

1. **Decision D-1 (Environment Variable Prefix)**:
   - *Resolution*: Use `AIOS_MCP_*` prefix (e.g., `AIOS_MCP_STORE_PATH`, `AIOS_MCP_MAX_SESSIONS`, `AIOS_MCP_TIMEOUT_SECS`).
2. **Decision D-2 (Config File Location)**:
   - *Resolution*: Default configuration file location is `.aios/mcp_server_core_config.json`.
3. **Decision D-3 (Auto-Prune Automation)**:
   - *Resolution*: Enable `auto_prune_terminated = true` by default to prevent session leaks during continuous operation.

---

## 5. Citations & References
- Model Context Protocol: `https://spec.modelcontextprotocol.io/`
- AIOS Session Configuration Architecture: `code/aiosh-rust/aiosh-core/src/session_config.rs`
- ADR-0035 §AF-2: AI Control Plane Execution Invariants
- PoR Invariant I-2: Capability Grant Redemption Mandate
