# Specification: AI Control Plane MCP Server Core Recovery & Validation Subsystem

**Document ID**: SPEC-MCP-SERVER-CORE-RECOVERY  
**Lifecycle Target**: T-03153..T-03162 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-CONFIG  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Recovery & Validation Subsystem** guarantees resilience against state file corruption, truncated writes, syntax violations, and uncoordinated process exits. It provides deep offline/online validation of MCP Server configuration and session store files, along with non-destructive quarantine and automatic self-healing.

Both Python (`aiosh_mcp.mcp_server_core_recovery`) and Rust (`aiosh_core::mcp_server_core_recovery`) implement this specification with byte-level schema parity.

---

## 2. Recovery Invariants & Contracts

| Invariant | Target | Bounds / Validation | Description |
| :--- | :--- | :--- | :--- |
| **`MCPRECV-INV1`** | Accounting | `total == valid + invalid` | Strict conservation of evaluated records |
| **`MCPRECV-INV2`** | Health | `healthy == (errors.is_empty() and invalid == 0)` | Binary health determination |
| **`MCPRECV-INV3`** | Quarantine | Atomic copy to `<path>.bak.<timestamp>` with `0600` | Non-destructive forensics preservation |
| **`MCPRECV-INV4`** | Traversal | No `..`, `/`, `\`, `\0` in relative paths | Path traversal and injection immunity |
| **`MCPRECV-INV5`** | PoR I-2 | Gated mutation vs. pure read query | Mutations require capability grant token |

---

## 3. Data Model

### 3.1 `McpValidationIssue`
- `severity`: `"ERROR"`, `"WARNING"`, `"INFO"`
- `code`: Standard error identifier (e.g. `"INVALID_JSON"`, `"BOUNDS_EXCEEDED"`, `"FILE_MISSING"`, `"TRAVERSAL_DETECTED"`)
- `message`: Human-readable description (max 256 chars, path-redacted)
- `path`: Target file path

### 3.2 `McpValidationReport`
- `store_path`: Checked file path
- `is_healthy`: Boolean health verdict
- `total_records`: Evaluated item count
- `valid_records`: Valid item count
- `invalid_records`: Invalid item count
- `issues`: List of `McpValidationIssue`
- `validated_at_utc`: RFC3339 timestamp

### 3.3 `McpRecoveryResult`
- `ok`: Boolean success flag
- `action_taken`: `"QUARANTINE_AND_RESET"`, `"NONE"`, `"FILE_CREATED"`
- `backup_path`: Optional path to preserved quarantine backup
- `report`: Resulting `McpValidationReport`
- `error`: Optional error string if recovery failed

---

## 4. Exposed FastMCP Tools

1. **`aios_mcp_recovery_check`** (Read-Only):
   - Arguments: `path: Optional[str] = None`
   - Returns: `McpValidationReport`
2. **`aios_mcp_recovery_repair`** (State-Changing, PEP Gated):
   - Arguments: `path: str`, `capability_token: str`
   - Returns: `McpRecoveryResult`
