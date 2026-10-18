# Documentation Evidence: AI Control Plane MCP Server Core CLI Surface (T-03091)

**Task ID**: T-03091 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / CLI surface: Documentation)  
**Contract Reference**: `docs/SPEC-MCP-SERVER-CORE-CLI.md`, ADR-0035 §AF-2, PoR Invariant I-2  
**Date**: 2026-10-18  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Operators and agent documentation completed with runnable command examples, parameter definitions, invariant mapping, hardening guarantees, and honest boundary limits.

---

## 1. Documentation Updates Delivered

1. **Updated Specification (`docs/SPEC-MCP-SERVER-CORE-CLI.md`)**:
   - Complete documentation of the `aiosh mcp` command suite (`ping`, `list`, `show`, `dispatch`, `sessions`).
   - Standardized exit code mapping table (`0..4`).
   - Detailed parameter tables with boundary constraints (`MAX_ARGUMENTS_SIZE = 1 MiB`, timeout clamp `[1, 300]`).
   - Full copy-pasteable command examples with expected payloads.
   - Explicit recording of constraints, assumptions, and known limitations.
   - Comprehensive cross-links to all lifecycle evidence files (`T-03083` through `T-03091`).

2. **Codebase Docstrings Synchronized**:
   - Rust: `code/aiosh-rust/aiosh-core/src/mcp_server_core_cli.rs` and `aiosh-cli/src/main.rs`.
   - Python: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_cli.py`.

---

## 2. Working CLI Invocations (Copy-Pasteable)

### 2.1 Health Probe
```bash
aiosh mcp ping --json
```
Output:
```json
{
  "status": "ok",
  "tools_count": 4,
  "version": "2025-06-18"
}
```

### 2.2 Catalog Filtering & Inspection
```bash
aiosh mcp list --filter "aios.fs" --json
aiosh mcp show aios.fs.read --json
```

### 2.3 Privileged Bounded Dispatch
```bash
aiosh mcp dispatch aios.admin.reboot --grant "gr_admin_token_123" --timeout 15 --json
```

### 2.4 Session Eviction & Maintenance
```bash
aiosh mcp sessions --prune 60 --json
```

---

## 3. Constraints & Known Limitations Recorded Honestly

- **Local Process Boundary**: In-process or CLI-local execution against `McpServerCoreService`; remote network wire protocols (stdio/SSE/HTTP) are handled in the MCP/API Surface milestone (`T-03093..T-03102`).
- **Memory & Wire Bounds**: CLI arguments capped at `1 MiB` (`MAX_ARGUMENTS_SIZE`).
- **Capability Tokens**: PEP tokens must be acquired and provided for privileged tools under `aios.admin.*`.
