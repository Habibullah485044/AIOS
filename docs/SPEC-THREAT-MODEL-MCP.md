# Specification: Threat Model Maintenance MCP/API Surface (SPEC-THREAT-MODEL-MCP)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance MCP Surface
- **Binding**: ADR-0035 §D-2, ADR-0036 §B-1

## 1. Overview
Exposes the Threat Model Maintenance subsystem over the Model Context Protocol (MCP) in `code/aiosh-rust/aiosh-mcp`, allowing authorized agents and autonomous LLMs to query threat catalogs, inspect vulnerabilities, register new threats, update mitigation states, and compute risk assessments over standard JSON-RPC.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATMCP1` | **Audit Completeness** | Every execution passes through `dispatch::recorded_call`, writing an immutable trace into `AuditRing`. |
| `THREATMCP2` | **Path Traversal Hygiene** | Optional `store_path` arguments are validated via `ThreatModelService::validate_path` rejecting traversal (`..`), UNC paths, control characters, and symlinks. |
| `THREATMCP3` | **Fail-Closed Envelope** | Results return `{ "ok": true, ... }` on success or `{ "ok": false, "error": "<message>" }` on error. |
| `THREATMCP4` | **Storage Boundaries** | Enforces `MAX_THREAT_ENTRIES_CAPACITY = 512` and `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB`. |
| `THREATMCP5` | **Zero Disclosure** | Raw private keys or token patterns are strictly rejected from entries and outputs. |

## 3. Tool Manifest & Schemas

### `aios.threat.list`
- **Description**: Query and list registered threats with optional filtering.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "status": { "type": "string", "enum": ["identified", "under_review", "mitigated", "accepted", "resolved"] },
      "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
      "category": { "type": "string", "enum": ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege", "supply_chain_risk"] },
      "store_path": { "type": "string" }
    },
    "additionalProperties": false
  }
  ```

### `aios.threat.get`
- **Description**: Retrieve detailed threat specification and mitigations by ID.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "id": { "type": "string" },
      "store_path": { "type": "string" }
    },
    "required": ["id"],
    "additionalProperties": false
  }
  ```

### `aios.threat.register`
- **Description**: Register a new threat entry in the threat model catalog.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "id": { "type": "string" },
      "title": { "type": "string" },
      "description": { "type": "string" },
      "category": { "type": "string", "enum": ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege", "supply_chain_risk"] },
      "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
      "component": { "type": "string" },
      "cwes": { "type": "array", "items": { "type": "string" } },
      "mitigations": { "type": "array", "items": { "type": "string" } },
      "store_path": { "type": "string" }
    },
    "required": ["id", "title", "description", "category", "severity", "component"],
    "additionalProperties": false
  }
  ```

### `aios.threat.status`
- **Description**: Advance or update lifecycle status of a threat.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "id": { "type": "string" },
      "status": { "type": "string", "enum": ["identified", "under_review", "mitigated", "accepted", "resolved"] },
      "store_path": { "type": "string" }
    },
    "required": ["id", "status"],
    "additionalProperties": false
  }
  ```

### `aios.threat.mitigate`
- **Description**: Attach a mitigation to an identified threat and advance status to mitigated.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "id": { "type": "string" },
      "mitigation": { "type": "string" },
      "store_path": { "type": "string" }
    },
    "required": ["id", "mitigation"],
    "additionalProperties": false
  }
  ```

### `aios.threat.assess`
- **Description**: Calculate real-time composite risk scoring and metrics across the threat catalog.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "store_path": { "type": "string" }
    },
    "additionalProperties": false
  }
  ```

### `aios.threat.init`
- **Description**: Initialize or reset the threat catalog with canonical STRIDE baseline threats.
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "force": { "type": "boolean" },
      "store_path": { "type": "string" }
    },
    "additionalProperties": false
  }
  ```

## 4. Usage Examples

### 4.1. Initialize Canonical Baseline
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "aios.threat.init",
    "arguments": {
      "force": true
    }
  },
  "id": 1
}
```
**Response**:
```json
{
  "ok": true,
  "initialized": true,
  "count": 7
}
```

### 4.2. Register a New Threat
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "aios.threat.register",
    "arguments": {
      "id": "THREAT-MCP-01",
      "title": "Untrusted MCP Payload Ingestion",
      "description": "Adversary injects maliciously large tool arguments to exhaust memory",
      "category": "tampering",
      "severity": "high",
      "component": "aiosh-mcp",
      "cwes": ["CWE-20", "CWE-400"],
      "mitigations": ["Apply 1 MiB bounded stream parsing"]
    }
  },
  "id": 2
}
```

### 4.3. Attach Mitigation
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "aios.threat.mitigate",
    "arguments": {
      "id": "THREAT-MCP-01",
      "mitigation": "Enforce bounded JSON parsing in aiosh-mcp main server"
    }
  },
  "id": 3
}
```

### 4.4. Calculate Risk Assessment
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "aios.threat.assess",
    "arguments": {}
  },
  "id": 4
}
```

## 5. Constraints & Known Limitations
1. **Catalog Capacity Bound**: The maximum number of threats is strictly capped at `512` (`MAX_THREAT_ENTRIES_CAPACITY`).
2. **Store File Size**: Catalog files exceeding `1 MiB` (`MAX_THREAT_MODEL_STORE_SIZE`) are rejected.
3. **No Symlinks**: Store paths must resolve to regular files; symbolic links are rejected to avoid link-redirection attacks.
4. **Zero Disclosure**: Private keys (`BEGIN PRIVATE KEY`) in descriptions and mitigations are blocked by input validators.
5. **State Transition Ordering**: Cannot transition to `mitigated` without at least one mitigation recorded.

## 6. Task Evidence Cross-References
- Research: [`T-02731-threat-model-mcp-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02731-threat-model-mcp-research.md)
- Specification: `SPEC-THREAT-MODEL-MCP.md` (this file)
- Scaffold: [`T-02733-mcp-api-surface-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02733-mcp-api-surface-scaffold.md)
- Implementation: [`T-02734-mcp-api-surface-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02734-mcp-api-surface-implementation.md)
- Unit Tests: [`T-02735-mcp-api-surface-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02735-mcp-api-surface-unit-test.md)
- Integration: [`T-02736-mcp-api-surface-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02736-mcp-api-surface-integration.md)
- Security Review: [`T-02737-mcp-api-surface-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02737-mcp-api-surface-security-review.md)
- Hardening: [`T-02738-mcp-api-surface-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-02738-mcp-api-surface-hardening.md)
