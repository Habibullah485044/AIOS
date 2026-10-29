# Research Evidence: AI Control Plane Model Backend Adapters Observability (T-03233)

**Task ID**: T-03233 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / observability: Research)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, OpenTelemetry semantic conventions for Generative AI, PoR Invariant I-2  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Observability facts, constraints, prior art, and architectural decisions established.

---

## 1. Facts vs Assumptions

### 1.1 Established Facts (Codebase & Upstream Standards)
1. **Existing Patterns**: AIOS MCP subsystems (`mcp_server_core_observability.py`, `incident_runbook_observability.py`, `compliance_observability.py`) follow an in-memory aggregation model generating immutable metrics snapshots (`@dataclass(frozen=True)`).
2. **OpenTelemetry GenAI Standards**: Upstream OpenTelemetry specifications (`gen_ai.system`, `gen_ai.usage.prompt_tokens`, `gen_ai.usage.completion_tokens`, `gen_ai.request.duration`) establish standard metric dimensions for LLM observability.
3. **Proof-of-Restraint Invariant I-2**: Read-only queries of operational status and metrics consume 0 tokens. Metrics snapshots must never leak confidential prompts, unredacted secrets, or capability tokens.
4. **Token Conservation Invariant**: Across all providers (Mock, OpenAI, Anthropic, Gemini, Ollama), total token count must obey `total_tokens == prompt_tokens + completion_tokens`.
5. **Sanitization Requirement**: Telemetry strings must be sanitized against ASCII control characters, NUL bytes, and unicode zero-width spaces (`\u200b`, `\ufeff`).

### 1.2 Assumptions (Explicitly Listed)
1. **In-Memory Volatility**: Point-in-time metrics counters reset upon daemon restart; durable long-term metrics history is preserved separately in SQLite audit records (`audit.db`).
2. **FastMCP Wire Integration**: Metrics will be queryable over the MCP wire via `aios_model_observability_snapshot` as a pure read tool.

---

## 2. Authoritative Sources & Citations

- **OpenTelemetry Semantic Conventions for Generative AI Systems** (v1.28.0): Canonical definitions for request count, token usage, fallback attempts, and latency histograms.
- **ADR-0035 §AF-2**: Standard result envelope format (`status`, `ok`, `data`, `error_code`, `error_message`, `timestamp`).
- **ADR-0037**: Proof-of-Restraint standing rules and zero-token consumption for operational telemetry.
- **`code/aiosh-mcp/aiosh_mcp/model_backend_adapters_service.py`**: Existing `redact_secrets()` utility and multi-provider adapter implementation.

---

## 3. Decisions Needed Before Implementation (T-03234 Spec)

1. **Snapshot Data Model**:
   - `ModelBackendMetricsSnapshot` fields:
     - `uptime_seconds`: float
     - `total_requests`: int
     - `successful_requests`: int
     - `failed_requests`: int
     - `total_prompt_tokens`: int
     - `total_completion_tokens`: int
     - `total_tokens`: int
     - `fallback_triggers_count`: int
     - `average_latency_ms`: float
     - `health_status`: `HealthStatus` (`HEALTHY`, `DEGRADED`, `CRITICAL`)
     - `provider_breakdown`: Dict[str, int]
2. **Health Status Classification Criteria**:
   - `HEALTHY`: Error rate < 5% and at least 1 provider available.
   - `DEGRADED`: Error rate between 5% and 25%, or multiple fallback progressions active.
   - `CRITICAL`: Error rate >= 25% or all primary providers unavailable.
3. **Telemetry Sanitization**:
   - Text sanitization with a 256-character ceiling, stripping control characters and zero-width spaces.
