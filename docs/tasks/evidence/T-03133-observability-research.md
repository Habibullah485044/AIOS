# Research & Security Audit Evidence: AI Control Plane MCP Server Core Observability (T-03133)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability
- **Target**: Facts, constraints, telemetry architectures, and prior art for MCP Server Core Observability
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-API

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **MCP Observability Requirements**:
   - As the operational AI Control Plane, MCP Server Core requires structured telemetry to monitor tool dispatch rates, session lifecycles, latency histograms, error rates, and security policy rejections.
   - Observability endpoints must be queryable programmatically via FastMCP (`aios_mcp_observability_snapshot`) and stdio JSON-RPC.
2. **Dual-Substrate Parity**:
   - Python substrate (`aiosh_mcp.mcp_server_core_observability`): Telemetry collector, moving window metrics, and report serialization.
   - Rust substrate (`aiosh-core::mcp_server_core_observability`): High-throughput atomic counters, microsecond timing, and memory-safe snapshot generators.
3. **Audit Trail Correlation**:
   - Observability snapshots must record total events logged to SQLite WAL audit ring and current audit sequence numbers to verify continuous non-repudiation.
4. **Proof-of-Restraint Gating**:
   - Observability queries are strictly read-only (`READ_ONLY` category).
   - Metrics collection must never alter security policies, mint capability tokens, or flush audit logs.

### 1.2 Identified Constraints
1. **Zero Contention**: Telemetry capture must not introduce blocking locks into the critical dispatch path.
2. **Bounded Memory Overhead**: Counters and sliding window records must be bounded (e.g. maximum 1024 data points per histogram, telemetry strings capped at 256 chars).
3. **Fail-Safe Sanitization**: Telemetry text strings must be sanitized of non-printable ASCII and zero-width unicode characters (`\u200b`, `\ufeff`).

---

## 2. Telemetry Architecture

The observability engine consists of:
1. **`McpCoreMetricsSnapshot`**:
   - `generated_at_utc`: RFC3339 timestamp.
   - `uptime_seconds`: Continuous server uptime.
   - `total_tools_registered`: Registered tool catalog count.
   - `active_sessions_count`: Currently active client sessions.
   - `session_capacity_utilization_percent`: `(active / max_capacity) * 100`.
   - `total_dispatches`: Total tool call attempts.
   - `successful_dispatches`: Total dispatches returning `ok=True`.
   - `failed_dispatches`: Dispatches returning errors or timeouts.
   - `policy_denials`: Invariant I-2 and rule-based authorization denials.
   - `average_dispatch_latency_ms`: Mean duration of tool calls.
   - `health_status`: `HEALTHY`, `DEGRADED`, or `CRITICAL`.
2. **`McpServerCoreObservabilityService`**:
   - Coordinates metric recording hooks (`record_dispatch()`, `record_session_event()`, `record_policy_denial()`).
   - Generates immutable point-in-time snapshots.

---

## 3. Decisions & Implementation Roadmap

- **Decision 1**: Implement `mcp_server_core_observability.py` in `aiosh_mcp` and `mcp_server_core_observability.rs` in `aiosh-core`.
- **Decision 2**: Expose `aios_mcp_observability_snapshot` as a read-only FastMCP tool.
- **Decision 3**: Standard library implementations only; no external time-series dependencies.
