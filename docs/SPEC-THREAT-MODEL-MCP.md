# Specification: Threat Model Maintenance MCP/API Surface (SPEC-THREAT-MODEL-MCP)

- **Status**: SPECIFIED
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
      "category": { "type": "string" },
      "severity": { "type": "string" },
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
- **Description**: Attach a mitigation and advance status to mitigated.
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
- **Description**: Calculate real-time composite risk scoring metrics.
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
- **Description**: Initialize catalog with canonical STRIDE baseline threats.
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
