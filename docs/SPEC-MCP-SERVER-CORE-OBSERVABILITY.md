# Specification: AI Control Plane MCP Server Core Observability Subsystem

**Document ID**: SPEC-MCP-SERVER-CORE-OBSERVABILITY  
**Lifecycle Target**: T-03133..T-03142 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Observability Subsystem** aggregates runtime operational metrics, session utilization, dispatch performance, error counters, and audit trail correlation for the AI Control Plane.

Both Python (`aiosh_mcp.mcp_server_core_observability`) and Rust (`aiosh_core::mcp_server_core_observability`) implement this specification with byte-level schema parity.

---

## 2. Telemetry Invariants & Contracts

| Invariant | Field | Type | Bounds / Validation | Description |
| :--- | :--- | :--- | :--- | :--- |
| **MCPOBS-INV1** | `generated_at_utc` | `String` | Non-empty, RFC3339 ISO format | Snapshot capture timestamp |
| **MCPOBS-INV2** | `uptime_seconds` | `f64` / `float` | $\ge 0.0$ | Continuous service uptime |
| **MCPOBS-INV3** | `total_tools_registered` | `usize` / `int` | `[0, 1024]` | Count of registered tools |
| **MCPOBS-INV4** | `active_sessions_count` | `usize` / `int` | `[0, 512]` | Currently open client sessions |
| **MCPOBS-INV5** | `capacity_utilization_percent` | `f64` / `float` | `[0.0, 100.0]` | Percent utilization of max sessions |
| **MCPOBS-INV6** | `total_dispatches` | `u64` / `int` | `successful + failed` | Cumulative dispatch attempts |
| **MCPOBS-INV7** | `health_status` | `HealthStatus` | `HEALTHY`, `DEGRADED`, `CRITICAL` | Calculated system health state |
| **MCPOBS-INV8** | Read-Only Invariant | Trait / PEP | Pure query | No mutations to audit DB or policies |

---

## 3. Health Calculation Rules

1. **`HEALTHY`**:
   - `capacity_utilization_percent` $< 85.0\%$
   - Failure rate ($failed / total$) $< 5.0\%$ (when $total \ge 20$)
2. **`DEGRADED`**:
   - `capacity_utilization_percent` $\ge 85.0\%$ and $< 98.0\%$
   - OR failure rate between $5.0\%$ and $20.0\%$
3. **`CRITICAL`**:
   - `capacity_utilization_percent` $\ge 98.0\%$
   - OR failure rate $\ge 20.0\%$
