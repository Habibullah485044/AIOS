# T-02731: Threat Model Maintenance MCP/API Surface Research

- **Task**: `T-02731`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Objective & Architectural Context
Research and establish architectural contracts for exposing the Threat Model Maintenance subsystem over the Model Context Protocol (MCP) in `code/aiosh-rust/aiosh-mcp`.

## 2. MCP Surface Specifications & Contracts

### Authoritative Facts
1. **MCP Transport & Dispatch**:
   - Model Context Protocol (MCP) tools operate via JSON-RPC 2.0 over standard I/O.
   - Every tool execution is evaluated by PEP rules and emitted to the immutable `AuditRing` audit log.
2. **Namespace Standard**:
   - The canonical tool prefix is `aios.threat.*` to avoid collision with other subsystems.
3. **Target Tools**:
   - `aios.threat.list`: Query catalog with optional filters (`status`, `severity`, `category`, `store_path`).
   - `aios.threat.get`: Retrieve individual threat metadata and attributes (`id`, `store_path`).
   - `aios.threat.register`: Ingest new threat entry into catalog (`id`, `title`, `description`, `category`, `severity`, `component`, `cwes`, `mitigations`, `store_path`).
   - `aios.threat.status`: Advance lifecycle state (`id`, `status`, `store_path`).
   - `aios.threat.mitigate`: Record mitigations and update status to `mitigated` (`id`, `mitigation`, `store_path`).
   - `aios.threat.assess`: Return real-time composite risk scoring metrics (`store_path`).
   - `aios.threat.init`: Initialize or re-populate canonical baseline threats (`store_path`, `force`).
4. **Security & Input Validation Invariants**:
   - Every tool call accepting `store_path` must pass through `ThreatModelService::validate_path` to reject path traversal (`..`), UNC paths (`\\\\`, `//`), control characters, and symlinks.
   - Input fields must enforce length caps (ID <= 64 bytes, Title <= 128 bytes, Description <= 2048 bytes).
   - Zero disclosure of credentials or private key blocks.

## 3. Findings for Specification (T-02732)
- Formalize JSON schemas for all 7 tools in `Server::tool_manifest()`.
- Standardize tool response structure: `{ "ok": true, ... }` on success and `{ "ok": false, "error": "<msg>" }` on failure.
